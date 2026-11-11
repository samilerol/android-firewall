# Execution record — 2026-11-11

Repository: `samilerol/android-firewall`; branch `feature/firewall-security-validation`.
Base: `18a7f30af571f2b0d90522280ec54596e9a0beaa`. Main was not merged.
**Release decision: NOT production-ready.** See [security review](../SECURITY_REVIEW.md).

## Host evidence

Final host run included debug/release APK assembly, both JVM variants, both app
lint variants, instrumentation APKs and probe lint: **BUILD SUCCESSFUL**, 201 tasks.
Each JVM variant: **24 tests, 0 failures/errors/skips**. App lint: no errors, six
visible dependency-version warnings. [Build log](evidence/host-build.txt).
JDK 21.0.9, Gradle 8.10.2, AGP 8.7.3, Kotlin 2.0.21, SDK 35/build-tools 34.0.0.
Dependency verification remained strict; no metadata-writing flags were used.
Release APK permission inspection found no `INTERNET` or test-probe permission;
archive inspection found no fixture cert/key/probe paths. Release is unsigned.

## Device evidence

A disposable AOSP API 30 x86_64 emulator ran without KVM, using software CPU
emulation. This is actual Android execution, not a mocked JVM networking test.
No physical device was available. [Final test summary](evidence/normal-final/summary.json). An API 35 Google APIs image could not be
extracted within available disk; API 30 AOSP was used instead.

Final normal-mode repeat at `93bb503`, after platform recovery and restoring
Always-on OFF / Lockdown OFF: **8 firewall instrumentation tests + 1 independent
UID test passed again**. APK digests matched the final host-build artifacts. Controls and selected-UID blocks covered IPv4/IPv6 TCP, UDP, wire DNS
UDP/TCP, certificate-verified TLS DNS and HTTPS DNS. Additional scenarios: existing
TCP across activation, real VPN authorization revocation by another app, missing
and empty rules, duplicate TUN ownership, 12 start/stop resource checks.
[Instrumentation](evidence/normal-final/instrumentation.txt),
[independent control](evidence/normal-final/independent-control.txt),
[endpoint receipts](evidence/normal-final/endpoint.jsonl),
[emulator properties](evidence/normal-final/device-properties.txt).
All six baseline transports appeared for each address family; **zero marked
blocked payloads** appeared in receipts. Tests use local nonstandard ports and
HTTP/1.1 DoH; they do not prove system DNS, Private DNS, standard port rules,
HTTP/2, QUIC or domain filtering.

The earlier [failing run](evidence/before-routing-barrier/instrumentation.txt)
recorded a real [blocked TCP receipt](evidence/before-routing-barrier/endpoint.jsonl)
before Android routing readiness was established. It also exposed an incorrect
`stopService` assumption for a system-bound VPN in the test harness. Routing
observation and the real service STOP action replaced those assumptions; later
full runs passed. A startup gap still requires Android Lockdown for enforcement.

### SIGKILL and Lockdown — mixed availability result

Always-on and Block connections without VPN were enabled through Android Settings.
A separate ordinary application UID sent dual-stack UDP canaries every ~50 ms
for 60 seconds while the firewall process was killed with SIGKILL. The privileged
ADB lab controller performed the kill; application UIDs stayed ordinary/distinct.

- [Run A](evidence/crash-no-restart/crash-canary.txt): 1,710 sends attempted,
  58 locally accepted, 1,652 denied; no marked payload at endpoints. **Automatic
  restart FAILED**: process remained absent, with the service still start-requested.
  [Service evidence](evidence/crash-no-restart/service-after-crash.txt).
  Manual operator recovery was required. The old harness's `pidof` caused an
  early exit; the current harness explicitly records failure, continues other
  phases after operator recovery, and still exits failed.
- [Run B](evidence/crash-restarted/crash-canary.txt): 1,634 attempts, 1,391 locally
  accepted, 243 denied; no marked payload at endpoints. PID changed from
  [7648](evidence/crash-restarted/crashed-pid.txt) to
  [7807](evidence/crash-restarted/restarted-pid.txt); automatic restart observed.
  This successful retry does not resolve Run A's intermittent availability defect.

Socket acceptance is not delivery; endpoint receipts independently check delivery.
No finite sampled canary proves every packet or every device is leak-free.
Android Lockdown, not a resurrecting user-space FD, enforced the no-VPN boundary.
Without Lockdown the ordinary VPN is explicitly fail-open after process loss.

### Remaining lifecycle phases

The separate remaining-phases run retained the earlier failed crash result;
it did not rerun or erase it. IPv4 and IPv6 each exercised all six transports:

| Phase | Observed result |
| --- | --- |
| VPN enabled / Lockdown enabled | Independent UID connections blocked |
| Deep Doze (`mState=IDLE` verified) | Independent UID connections blocked |
| Force-stop, no VPN network verified | Independent UID connections blocked |
| Airplane-mode round trip, underlay/default routes restored | Independent UID connections blocked |
| Reboot | Initial run failed underlay readiness after Android system-server watchdog; after platform recovery and explicit Wi-Fi reconnect, both families/all six transports blocked |

[Lifecycle transcripts and network snapshots](evidence/lockdown-lifecycle/)
retain the initial runner failure. The
[Android watchdog report](evidence/lockdown-lifecycle/android-watchdog.txt) shows
`android.fg` blocked in `IInstalld.createAppData` during user unlock/package data
reconciliation; the app is not identified as the blocking stack. Causality is
not conclusively established. Boot-completed alone did not establish a healthy
platform: Wi-Fi/connectivity services were temporarily absent. After service
recovery, explicit Wi-Fi reconnect, and verified dual-stack default routes,
[post-boot measurements](evidence/postboot-continued/) passed. Always-on/Lockdown
persisted and a VPN network was observed again. **Continuous boot/before-unlock
protection and a clean end-to-end reboot run remain unverified.** The harness now
waits for network services and reconnects the emulator WLAN after boot; this
updated reboot path was not rerun end-to-end in this session. The continuation
record contains a later harness error (`_blocked: command not found`): the running
shell script was edited while executing, shifting its input offsets. Its completed
post-boot and force-stop instrumentation results remain observations; that overall
run is **failed**, not a passing suite. The final fixed harness was then run without
editing it during execution: **6 independent-UID tests passed**, covering all six
transports on both address families with VPN enabled, with no VPN after force-stop,
and after an airplane-mode round trip. Zero marked blocked endpoint receipts and
no recorded availability failures in that run (SIGKILL/Doze/reboot were separate
runs, not repeated in this final run). See
[final stable harness evidence](evidence/lockdown-stable-final/).

The initial deep-Doze attempt failed setup because the emulator had deep idle
disabled; the corrected harness temporarily enabled it and asserted real IDLE.
The matrix above is from actual completed instrumentation phases, not setup alone.

## Remaining release gates

The engine is a sink. IP/port/protocol allow/deny rules, DNS domain filtering and
useful selective forwarding under Lockdown are **absent**. A pinned audited
forwarding engine is required. The sink blocks unselected apps under Lockdown too.
Intermittent post-kill recovery remains unresolved. Physical/OEM Android 8–9 and
14/15, before-unlock, cellular handover, IPv6-only/NAT64, delegated/shared UIDs,
MTU/fragments/checksums under actual load, failure injection, and long battery,
thermal/memory-pressure tests remain unverified. Parser unit tests do not substitute
for these measurements.

Offline dependency comparison found 62 tooling/test version-advisory candidates,
including upstream HIGH/CRITICAL labels, and zero release-runtime candidates.
This is not full reachability triage or a CVE-free claim. See
[component assessment](COMPONENT_REVIEW.md) and [candidate JSON](DEPENDENCY_ADVISORIES.json).
Maintainer signing, upgrade validation and compatible toolchain advisory remediation
are also required before production release.
