#!/usr/bin/env bash
# Destructive network tests only on a disposable Android emulator, never a real phone.
set -euo pipefail
cd "$(dirname "$0")/.."
export ANDROID_HOME="${ANDROID_HOME:-/workspace/toolchains/android-sdk}"
adb="$ANDROID_HOME/platform-tools/adb"
serial="${ANDROID_SERIAL:-}"
if [[ -z "$serial" ]]; then
  serial=$("$adb" devices | awk '$1 ~ /^emulator-/ && $2 == "device" {print $1}')
fi
if [[ ! "$serial" =~ ^emulator-[0-9]+$ ]]; then
  echo 'Select exactly one disposable emulator with ANDROID_SERIAL.' >&2
  exit 1
fi
lockdown=$("$adb" -s "$serial" shell settings get secure always_on_vpn_lockdown | tr -d '\r')
if [[ "$lockdown" == 1 ]]; then
  echo 'Normal-mode tests require Lockdown OFF. Use a fresh disposable emulator.' >&2
  exit 1
fi
artifacts="${1:-/tmp/firewall-device-evidence}"
mkdir -p "$artifacts"
artifacts=$(cd "$artifacts" && pwd)
./scripts/gradle.sh :app:assembleDebug :app:assembleDebugAndroidTest :probe:assembleDebug :probe:assembleDebugAndroidTest
"$adb" -s "$serial" install -r probe/build/outputs/apk/debug/probe-debug.apk
"$adb" -s "$serial" install -r app/build/outputs/apk/debug/app-debug.apk
"$adb" -s "$serial" install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
"$adb" -s "$serial" install -r probe/build/outputs/apk/androidTest/debug/probe-debug-androidTest.apk
server_args=()
instrumentation_args=()
if [[ "${FIREWALL_IPV6:-0}" == 1 ]]; then
  server_args+=(--ipv6)
  instrumentation_args+=(-e hosts 10.0.2.2,fec0::2)
fi
python3 scripts/traffic-endpoint.py "${server_args[@]}" > "$artifacts/endpoint.jsonl" 2> "$artifacts/endpoint-errors.log" &
endpoint_pid=$!
trap 'kill "$endpoint_pid" 2>/dev/null || true' EXIT
python3 - "$artifacts/endpoint.jsonl" "$endpoint_pid" <<'PY'
import json, os, sys, time
from pathlib import Path
path, pid = Path(sys.argv[1]), int(sys.argv[2])
for _ in range(50):
    os.kill(pid, 0)
    if path.exists() and path.read_text().strip():
        assert json.loads(path.read_text().splitlines()[0])["ready"]
        break
    time.sleep(.1)
else:
    raise SystemExit("Endpoint failed to start")
PY
"$adb" -s "$serial" shell getprop > "$artifacts/device-properties.txt"
"$adb" -s "$serial" shell am instrument -w -r "${instrumentation_args[@]}" \
  -e class org.suite.security.DeviceSmokeTest,org.suite.security.FirewallIntegrationTest \
  org.suite.security.test/androidx.test.runner.AndroidJUnitRunner | tee "$artifacts/instrumentation.txt"
"$adb" -s "$serial" shell am instrument -w -r -e expected allowed \
  org.suite.firewallprobe.test/androidx.test.runner.AndroidJUnitRunner | tee "$artifacts/independent-control.txt"
python3 - "$artifacts" <<'PY'
import json, re, sys, os
from pathlib import Path
root = Path(sys.argv[1])
result = (root / "instrumentation.txt").read_text()
match = re.search(r"OK \((\d+) tests?\)", result)
assert match and int(match[1]) >= 8, "Android test run failed or incomplete"
assert not re.search(r"FAILURES|INSTRUMENTATION_FAILED|shortMsg=", result), "Instrumentation failure"
independent = (root / "independent-control.txt").read_text()
assert re.search(r"OK \(1 test\)", independent) and "FAILURES" not in independent, "Independent baseline failed"
records = [json.loads(line) for line in (root / "endpoint.jsonl").read_text().splitlines()]
seen = {r.get("kind") for r in records}
assert {"tcp", "udp", "dns", "dns-tcp", "dot", "doh"} <= seen, f"Missing successful baseline: {seen}"
if os.environ.get("FIREWALL_IPV6") == "1":
    seen_v6 = {r.get("kind") for r in records if b"control-v6-" in bytes.fromhex(r.get("payloadHex", ""))}
    assert {"tcp", "udp", "dns", "dns-tcp", "dot", "doh"} <= seen_v6, f"IPv6 baseline incomplete: {seen_v6}"
leaks = [r for r in records if b"blocked-" in bytes.fromhex(r.get("payloadHex", ""))]
assert not leaks, f"Endpoint observed blocked traffic: {leaks}"
print("PASS: Android tests and independent endpoint receipt checks")
PY
