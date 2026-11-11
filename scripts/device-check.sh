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
./scripts/gradle.sh :app:assembleDebug :app:assembleDebugAndroidTest :probe:assembleDebug
"$adb" -s "$serial" install -r probe/build/outputs/apk/debug/probe-debug.apk
"$adb" -s "$serial" install -r app/build/outputs/apk/debug/app-debug.apk
"$adb" -s "$serial" install -r app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk
python3 scripts/traffic-endpoint.py > "$artifacts/endpoint.jsonl" 2> "$artifacts/endpoint-errors.log" &
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
"$adb" -s "$serial" shell am instrument -w -r \
  -e class org.suite.security.DeviceSmokeTest,org.suite.security.FirewallIntegrationTest \
  org.suite.security.test/androidx.test.runner.AndroidJUnitRunner | tee "$artifacts/instrumentation.txt"
python3 - "$artifacts" <<'PY'
import json, re, sys
from pathlib import Path
root = Path(sys.argv[1])
result = (root / "instrumentation.txt").read_text()
match = re.search(r"OK \((\d+) tests?\)", result)
assert match and int(match[1]) >= 6, "Android test run failed or incomplete"
assert not re.search(r"FAILURES|INSTRUMENTATION_FAILED|shortMsg=", result), "Instrumentation failure"
records = [json.loads(line) for line in (root / "endpoint.jsonl").read_text().splitlines()]
seen = {r.get("kind") for r in records}
assert {"tcp", "udp", "dns", "dot", "doh"} <= seen, f"Missing successful baseline: {seen}"
leaks = [r for r in records if b"blocked-" in bytes.fromhex(r.get("payloadHex", ""))]
assert not leaks, f"Endpoint observed blocked traffic: {leaks}"
print("PASS: Android tests and independent endpoint receipt checks")
PY
