#!/usr/bin/env bash
# Requires Always-on + Lockdown enabled in Android UI on a DISPOSABLE emulator.
set -euo pipefail
cd "$(dirname "$0")/.."
export ANDROID_HOME="${ANDROID_HOME:-/workspace/toolchains/android-sdk}"
adb="$ANDROID_HOME/platform-tools/adb"
serial="${ANDROID_SERIAL:-emulator-5554}"
[[ "$serial" =~ ^emulator-[0-9]+$ ]] || { echo 'Disposable emulator required' >&2; exit 1; }
read_setting() { "$adb" -s "$serial" shell settings get secure "$1" | tr -d '\r'; }
[[ "$(read_setting always_on_vpn_app)" == org.suite.security && "$(read_setting always_on_vpn_lockdown)" == 1 ]] || {
  echo 'Enable Android Firewall Always-on AND Block connections without VPN in Android VPN settings first.' >&2
  exit 1
}
artifacts="${1:-/tmp/firewall-lockdown-evidence}"
mkdir -p "$artifacts"
artifacts=$(cd "$artifacts" && pwd)
: > "$artifacts/failures.txt"
server_args=()
hosts=(10.0.2.2)
if [[ "${FIREWALL_IPV6:-0}" == 1 ]]; then server_args+=(--ipv6); hosts+=(fec0::2); fi
python3 scripts/traffic-endpoint.py "${server_args[@]}" > "$artifacts/endpoint.jsonl" 2> "$artifacts/endpoint-errors.log" &
endpoint_pid=$!
canary_pid=
restore_deep_disabled=0
cleanup() {
  if [[ -n "$canary_pid" ]]; then
    kill "$canary_pid" 2>/dev/null || true
    "$adb" -s "$serial" shell am force-stop org.suite.firewallprobe >/dev/null 2>&1 || true
  fi
  "$adb" -s "$serial" shell dumpsys deviceidle unforce >/dev/null 2>&1 || true
  if [[ "$restore_deep_disabled" == 1 ]]; then "$adb" -s "$serial" shell dumpsys deviceidle disable deep >/dev/null 2>&1 || true; fi
  "$adb" -s "$serial" shell dumpsys battery reset >/dev/null 2>&1 || true
  "$adb" -s "$serial" shell input keyevent 224 >/dev/null 2>&1 || true
  "$adb" -s "$serial" shell cmd connectivity airplane-mode disable >/dev/null 2>&1 || true
  "$adb" -s "$serial" shell svc wifi enable >/dev/null 2>&1 || true
  kill "$endpoint_pid" 2>/dev/null || true
}
trap cleanup EXIT
python3 - "$artifacts/endpoint.jsonl" "$endpoint_pid" <<'PY'
import json, os, sys, time
from pathlib import Path
for _ in range(50):
    os.kill(int(sys.argv[2]), 0)
    p = Path(sys.argv[1])
    if p.exists() and p.read_text().strip():
        assert json.loads(p.read_text().splitlines()[0])["ready"]
        break
    time.sleep(.1)
else:
    raise SystemExit("Endpoint failed to start")
PY
check_blocked() {
  local phase="$1" index=0
  for host in "${hosts[@]}"; do
    index=$((index+1))
    "$adb" -s "$serial" shell am instrument -w -r -e expected blocked -e host "$host" -e protocols tcp,udp,dns,dns-tcp,dot,doh \
      org.suite.firewallprobe.test/androidx.test.runner.AndroidJUnitRunner > "$artifacts/$phase-$index.txt"
    python3 - "$artifacts/$phase-$index.txt" <<'PY'
import re, sys
s = open(sys.argv[1]).read()
assert re.search(r"OK \(1 test\)", s) and not re.search(r"FAILURES|INSTRUMENTATION_FAILED|shortMsg=", s), s
PY
  done
}
wait_underlay() {
  python3 - "$adb" "$serial" "$artifacts/$1.txt" <<'PYCODE'
import os, re, subprocess, sys, time
end = time.monotonic() + 90
while time.monotonic() < end:
    s = subprocess.check_output([sys.argv[1], '-s', sys.argv[2], 'shell', 'dumpsys', 'connectivity'], text=True, timeout=10)
    line = next((line for line in s.splitlines() if re.search(r'NetworkAgentInfo\{[^\n]*type: WIFI[^\n]*state: CONNECTED/CONNECTED', line)), '')
    if '0.0.0.0/0' in line and (os.environ.get('FIREWALL_IPV6') != '1' or '::/0' in line):
        open(sys.argv[3], 'w').write(s)
        break
    time.sleep(1)
else:
    raise SystemExit('Underlying Wi-Fi/default routes did not become ready; negative test would be inconclusive')
PYCODE
}
wait_underlay before
check_blocked vpn-enabled
if [[ "${FIREWALL_CRASH:-0}" == 1 ]]; then
  canary_hosts=10.0.2.2
  if [[ "${FIREWALL_IPV6:-0}" == 1 ]]; then canary_hosts+=,fec0::2; fi
  "$adb" -s "$serial" shell am instrument -w -r -e mode udp-canary -e duration 60000 -e hosts "$canary_hosts" \
    org.suite.firewallprobe.test/androidx.test.runner.AndroidJUnitRunner > "$artifacts/crash-canary.txt" &
  canary_pid=$!
  python3 - "$artifacts/crash-canary.txt" <<'PYCODE'
import sys, time
from pathlib import Path
p = Path(sys.argv[1])
end = time.monotonic() + 90
while time.monotonic() < end:
    if p.exists() and 'CANARY_STARTED' in p.read_text():
        break
    time.sleep(.2)
else:
    raise SystemExit('UDP canary never confirmed live routing')
PYCODE
  old_pid=$("$adb" -s "$serial" shell pidof org.suite.security | tr -d '\r')
  [[ "$old_pid" =~ ^[0-9]+$ ]] || { echo 'No live firewall process to crash' >&2; exit 1; }
  printf '%s\n' "$old_pid" > "$artifacts/crashed-pid.txt"
  # Only the lab controller is privileged. Both application UIDs must stay ordinary/distinct.
  [[ "$("$adb" -s "$serial" shell id -u | tr -d '\r')" == 0 ]] || { echo 'SIGKILL scenario requires adb root on the disposable AOSP emulator' >&2; exit 1; }
  "$adb" -s "$serial" shell ps -A -o PID,UID,NAME > "$artifacts/process-uids.txt"
  python3 - "$artifacts/process-uids.txt" <<'PYCODE'
import sys
uids = {}
for line in open(sys.argv[1]):
    parts = line.split()
    if len(parts) == 3 and parts[2] in {'org.suite.security', 'org.suite.firewallprobe'}:
        uids[parts[2]] = int(parts[1])
assert len(uids) == 2 and min(uids.values()) >= 10000 and len(set(uids.values())) == 2, uids
PYCODE
  "$adb" -s "$serial" shell kill -9 "$old_pid"
  wait "$canary_pid"
  canary_pid=
  python3 - "$artifacts/crash-canary.txt" <<'PYCODE'
import re, sys
s = open(sys.argv[1]).read()
assert 'CANARY_DONE' in s and re.search(r'OK \(1 test\)', s) and 'FAILURES' not in s, s
PYCODE
  new_pid=$("$adb" -s "$serial" shell pidof org.suite.security | tr -d '\r' || true)
  if [[ "$new_pid" =~ ^[0-9]+$ && "$new_pid" != "$old_pid" ]]; then
    printf '%s\n' "$new_pid" > "$artifacts/restarted-pid.txt"
  else
    echo 'FAIL: automatic process restart not observed after SIGKILL' | tee -a "$artifacts/failures.txt" >&2
    "$adb" -s "$serial" shell dumpsys activity services org.suite.security > "$artifacts/restart-failure-service.txt"
    # Explicit operator recovery only; retain the failure and continue independent security checks.
    "$adb" -s "$serial" shell am start-foreground-service -n org.suite.security/.FirewallService > "$artifacts/manual-recovery.txt"
  fi
  wait_underlay after-crash
  check_blocked after-crash
fi
if [[ "${FIREWALL_DOZE:-0}" == 1 ]]; then
  "$adb" -s "$serial" shell dumpsys deviceidle > "$artifacts/device-idle-before.txt"
  if rg -q "mDeepEnabled=false" "$artifacts/device-idle-before.txt"; then
    restore_deep_disabled=1
    "$adb" -s "$serial" shell dumpsys deviceidle enable deep > "$artifacts/enable-deep-idle.txt"
  fi
  "$adb" -s "$serial" shell dumpsys battery unplug > "$artifacts/battery-unplug.txt"
  "$adb" -s "$serial" shell input keyevent 223
  "$adb" -s "$serial" shell dumpsys deviceidle force-idle > "$artifacts/force-idle.txt"
  "$adb" -s "$serial" shell dumpsys deviceidle > "$artifacts/device-idle.txt"
  python3 - "$artifacts/device-idle.txt" <<'PYCODE'
import re, sys
assert re.search(r'mState=IDLE\b', open(sys.argv[1]).read()), 'Doze was not actually entered'
PYCODE
  check_blocked during-doze
  "$adb" -s "$serial" shell dumpsys connectivity > "$artifacts/during-doze-network.txt"
  "$adb" -s "$serial" shell dumpsys deviceidle unforce > "$artifacts/unforce-idle.txt"
  "$adb" -s "$serial" shell dumpsys battery reset
  "$adb" -s "$serial" shell input keyevent 224
fi
"$adb" -s "$serial" shell am force-stop org.suite.security
# Prove that this measurement includes a no-VPN interval, not just a restarted sink.
python3 - "$adb" "$serial" "$artifacts/after-force-stop.txt" <<'PY'
import re, subprocess, sys, time
for _ in range(30):
    s = subprocess.check_output([sys.argv[1], '-s', sys.argv[2], 'shell', 'dumpsys', 'connectivity'], text=True, timeout=10)
    if not re.search(r'NetworkAgentInfo\{[^\n]*type: VPN', s):
        open(sys.argv[3], 'w').write(s)
        break
    time.sleep(.5)
else:
    raise SystemExit('VPN restarted immediately; no-VPN Lockdown boundary not established')
PY
check_blocked after-force-stop
"$adb" -s "$serial" shell cmd connectivity airplane-mode enable
"$adb" -s "$serial" shell cmd connectivity airplane-mode disable
"$adb" -s "$serial" shell svc wifi enable
"$adb" -s "$serial" shell cmd wifi connect-network AndroidWifi open
wait_underlay after-network-change
check_blocked after-network-change
if [[ "${FIREWALL_REBOOT:-0}" == 1 ]]; then
  "$adb" -s "$serial" reboot
  python3 - "$adb" "$serial" <<'PY'
import subprocess, sys, time
for _ in range(180):
    try:
        r = subprocess.run([sys.argv[1], '-s', sys.argv[2], 'shell', 'getprop', 'sys.boot_completed'], capture_output=True, text=True, timeout=5)
        if r.stdout.strip() == '1':
            break
    except subprocess.TimeoutExpired:
        pass
    time.sleep(5)
else:
    raise SystemExit('Software emulator reboot did not complete in time')
PY
  [[ "$(read_setting always_on_vpn_app)" == org.suite.security && "$(read_setting always_on_vpn_lockdown)" == 1 ]]
  wait_underlay after-reboot
  check_blocked after-reboot
fi
python3 - "$artifacts/endpoint.jsonl" <<'PY'
import json, sys
records = [json.loads(s) for s in open(sys.argv[1])]
assert not [r for r in records if b'blocked-' in bytes.fromhex(r.get('payloadHex', ''))], 'Lockdown leak reached endpoint'
print('No marked test payload reached endpoints in the sampled Lockdown checks; Lockdown remains enabled')
PY

if [[ -s "$artifacts/failures.txt" ]]; then
  echo 'Privacy checks completed, but the recorded availability failure keeps this run FAILED.' >&2
  exit 1
fi
