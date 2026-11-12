#!/usr/bin/env bash
# Runs inside the emulator (reactivecircus/android-emulator-runner). Reports whether the
# firewall service comes back after kill -9 with Always-on VPN set. Informational: exits 0
# once the kill phase ran; exits 1 only if the precondition (service up before kill) failed.
set -u
PKG=org.suite.security
OUT=${RESULT_FILE:-emulator-result.md}
WAIT=60
log() { echo "$*" | tee -a "$OUT"; }
pid() { adb shell pidof "$PKG" | tr -d '\r'; }
tun() { adb shell ip -o link | grep -q ': tun[0-9]*[:@]' && echo up || echo down; }

: > "$OUT"
adb root >/dev/null; adb wait-for-device
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell appops set "$PKG" ACTIVATE_VPN allow
adb shell settings put secure always_on_vpn_app "$PKG"
log "always_on_vpn_app=$(adb shell settings get secure always_on_vpn_app | tr -d '\r')"
adb shell am start-foreground-service -n "$PKG/.FirewallService" >/dev/null

old=""
for _ in $(seq 1 12); do
  old=$(pid); [[ -n "$old" && "$(tun)" == up ]] && break; old=""; sleep 5
done
if [[ -z "$old" ]]; then
  log "PRECONDITION FAILED: service/tun not up before kill (no result about restart)."
  adb shell dumpsys activity services "$PKG" | head -40 >> "$OUT"
  exit 1
fi
log "before kill: pid=$old tun=up"
adb shell kill -9 "$old"
back=""
for t in $(seq 5 5 "$WAIT"); do
  sleep 5
  p=$(pid); l=$(tun)
  log "t=${t}s pid=${p:-none} tun=$l"
  if [[ -n "$p" && "$p" != "$old" && -z "$back" ]]; then back=$t; fi
done
if [[ -n "$back" ]]; then log "RESULT: service came back (first seen at t=${back}s, new pid)."
else log "RESULT: service did NOT come back within ${WAIT}s after kill -9."; fi
exit 0
