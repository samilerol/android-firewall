# Reproducible validation

Use one Gradle process per checkout. JVM tests do not prove Android VPN routing.
Never perform disruptive tests on a personal phone or a VPN needed for access.

## Host checks

```sh
./scripts/check.sh
./scripts/gradle.sh :app:assembleRelease :app:testReleaseUnitTest :app:lintRelease
./scripts/gradle.sh :app:assembleDebugAndroidTest :probe:assembleDebug :probe:lintDebug
python3 scripts/test-traffic-endpoint.py
bash -n scripts/*.sh
```

Dependency locking and SHA-256 verification are enforced by default. Do not use
`--write-locks` or `--write-verification-metadata` to make an unexpected failure
vanish. Review upstream changes first; regenerate only for an intended dependency
change. The fixture has no release variant. The firewall release is unsigned;
a maintainer's release signing/upgrade continuity is a separate release gate.

Reports: `app/build/reports/tests/test{Debug,Release}UnitTest/`,
`app/build/test-results/`, `app/build/reports/lint-results-{debug,release}.html`,
`probe/build/reports/lint-results-debug.html`. APKs: each module's
`build/outputs/apk/`. Record exact revision and toolchain with evidence.

## Emulator integration

Install SDK `emulator`, an AOSP system image, and create a disposable AVD. Hardware
acceleration is strongly recommended. Set `ANDROID_AVD_HOME` explicitly when
using a custom user directory. Wait for `adb shell getprop sys.boot_completed`
to return `1`. Then:

```sh
export ANDROID_SERIAL=emulator-5554
FIREWALL_IPV6=1 ./scripts/device-check.sh /tmp/firewall-device-evidence
```

The script requires a single emulator serial and refuses a real device or existing
Lockdown configuration. It installs the separately signed-debug `probe`, firewall,
and instrumentation APKs, then runs `DeviceSmokeTest` and
`FirewallIntegrationTest`. It starts only local host endpoints, no remote DNS
resolver or paid service. Endpoints bind host loopback; the emulator reaches them
through `10.0.2.2` and, with the IPv6 flag, `fec0::2`. Ensure those ports are free before running.

| Probe | Local host port | What it establishes if the full test passes |
| --- | --- | --- |
| TCP echo | 18080 | Selected vs unselected IPv4/IPv6 TCP UID routing |
| UDP echo | 18081 | Selected vs unselected IPv4/IPv6 UDP UID routing |
| DNS/UDP and DNS/TCP | 1053 | Real wire-format DNS questions/responses on a controlled test port |
| DoT | 1853 | Certificate-verified TLS carrying length-prefixed DNS |
| DoH | 18443 | Certificate-verified HTTPS POST carrying DNS wire messages |

These nonstandard test ports deliberately avoid requiring privileged host binds.
They do not test standard-port rules, an external resolver, Android Private DNS,
system DNS delegation/cache behavior, HTTP/2, QUIC/HTTP3, or domain filtering.
Every traffic test requires a successful baseline. An absent/unauthorized probe
receiver is a failure, never successful blocking. Synthetic NXDOMAIN responses
validate transport without any upstream DNS request. TLS validation remains on.

The host verifies baseline receipts for every protocol and rejects **any** receipt
of a nonce prefixed `blocked-`. This is independent of the client timeout. Pre-existing TCP connections are also tested across activation, and a second
application actually revokes VPN authorization using `VpnService.prepare`. Other
Android tests exercise empty/missing-rule safety mode, actual descriptor duplication
ownership, repeated restarts/stops and reader/FD cleanup. The test key is public,
restricted to the test fixture, and must never be installed as a trusted device CA.

Artifacts: `instrumentation.txt`, synthetic `endpoint.jsonl`, endpoint errors and
device properties under the chosen evidence directory. Do not infer successful
execution from APK compilation. A failing baseline means a test is blocked/failed,
not that the firewall succeeded. No tests should be disabled to hide failure.

## Automated Lockdown lifecycle checks

First enable Always-on AND Block connections without VPN in Android Settings on
the disposable emulator. Install the APKs with the normal-mode script beforehand.
For the optional SIGKILL scenario only, an AOSP lab controller needs `adb root`;
the firewall and separate probe must remain distinct ordinary application UIDs.
The production app needs no root.

```sh
FIREWALL_IPV6=1 FIREWALL_CRASH=1 FIREWALL_DOZE=1 FIREWALL_REBOOT=1 \
  scripts/lockdown-check.sh /tmp/firewall-lockdown-evidence
```

Every phase runs six transports from an independent application UID with endpoint
receipt checks. The crash phase runs a 60-second dual-stack UDP canary across
SIGKILL, and separately asserts automatic process restart. A restart failure is
recorded, followed by explicit operator recovery so other checks can proceed;
the run still exits failed. Do not discard this availability result.

The script verifies actual deep Doze state (temporarily enables emulator deep
idle if disabled, restores it afterward), a no-VPN interval after force-stop,
network readiness after airplane mode, persistent settings and blocking after
reboot. It waits for Wi-Fi/connectivity services and reconnects the emulator
WLAN before evaluating post-boot blocking. A system-server watchdog or absent
underlay makes that phase inconclusive, never successful blocking. It leaves
Lockdown enabled. Reboot checks are **after boot completion**,
not proof of blocking before unlock. Software-emulated timing is not a physical
battery/performance measurement. Failures and raw logs must accompany results.

## Lockdown / physical-device acceptance matrix

Use a disposable device/profile, known-good dual-stack endpoints with receipt logs,
and selected/unselected clients. Record OS build, UID, network, VPN interface,
Lockdown settings, timestamp, baseline and receipts. Recheck after each transition.

- Normal mode: new and pre-existing IPv4/IPv6 TCP/UDP connections; DNS 53 UDP/TCP,
  Android resolver, Private DNS/DoT, DoH/HTTP2/QUIC; verify unselected controls.
- Always-on **and** Lockdown: verify Android's no-VPN block during force-stop,
  process crash, boot/before-unlock, failed establishment, permission loss and
  explicit stop. Re-enable protection and verify actual routing/status afterward.
  With this sink, unselected UIDs also lose access; never expect useful selective
  forwarding while Lockdown is on.
- Rule changes under continuous logged traffic, rapid restart/stop, no selections,
  missing/reinstalled/shared-UID packages and another VPN replacing authorization.
- Wi-Fi/cellular handover, airplane mode/off, IPv6-only/NAT64, captive portal,
  OEM battery restrictions, screen off/Doze, memory pressure and background kills.
- MTU/PMTU, large packets, IPv4 fragments, IPv6 extensions/fragments, malformed
  headers and checksums under load. All captured packets must remain discarded;
  parser output must never become a grant decision.
- Monitor degradation/EOF/error while TUN ownership remains, high-rate traffic,
  bounded samples, FD/thread growth and a 24-hour physical-device battery/thermal
  soak. Check OS routing and endpoint receipts, not only the UI indicator.

A failed IPv6 baseline is untested IPv6, not successful leak prevention. Kernel
Lockdown belongs to Android; shell-only traffic does not exercise an application
UID. Check multiple supported Android releases and OEMs. Exact execution results
and remaining blockers are recorded in [SECURITY_REVIEW.md](SECURITY_REVIEW.md).
