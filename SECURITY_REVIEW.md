# Security and release-readiness review

**Status: experimental; NOT production-ready.** No penetration-test certification,
CVE-free claim, complete Codex Security scan, or device-independent fail-closed
claim is made. Review date: 2026-11-11. Starting revision: `18a7f30`.
Target: `samilerol/android-firewall`, branch `feature/firewall-security-validation`.
The target repository was empty; the exact starting history was imported locally
from the previous `android-security-suite` checkout. Main was not changed.

## Scope and boundaries

Read all first-party Kotlin implementations, manifest/resources/backup rules,
Gradle/build/bootstrap/network scripts, existing tests and licensing documents;
reviewed new Kotlin/Python/shell fixtures and resolved dependency inputs. A fresh
read-only investigator and a separate read-only patch reviewer examined the VPN
boundary. The Codex Security skill's referenced helper resources were unavailable
in this session, so its canonical automated scan was not completed. Android lint,
JVM tests and direct source review are the actual static/automated evidence.

| Boundary | Source-backed behavior / assumption |
| --- | --- |
| Android VPN authorization | User/system consent; service is non-exported and requires `BIND_VPN_SERVICE`. Exported launcher ignores untrusted intent data. |
| Routing / process death | Android owns network enforcement; app descriptors cannot survive process death. User-enabled Always-on AND Lockdown are necessary for no-VPN blocking. |
| Application identity | VPN application lists are UID-based. Shared/delegated UIDs, package lifecycle, other profiles and other VPNs require device acceptance. |
| Packet input | Untrusted bytes enter a bounded buffer, metadata parser and bounded sample list. All captured packets are dropped regardless of parser result or checksum. No forwarding sockets exist. |
| Local state | App-private preferences, no backup/transfer, no exported rule editing API. Desired saved rules can differ from a retained old session after an update error; UI reports that distinction. |
| APK input | Untrusted URI stream copied with a 100 MiB cap; archive index bounded before `ZipFile`; Android package parser still belongs to OS trust boundary. No APK execution or independent signature verification. |
| Dependencies | Explicit versions, transitive locks and SHA-256 metadata; trusted initial download via platform TLS. Offline OSV Maven comparison recorded separately; toolchain matches remain open. No upstream security guarantee. |
| Test fixture | Separate debug-only network UID, signature-protected receiver restricted to controlled emulator host/ports, public fixture CA/key; never part of firewall release. |

## Changes and evidence

1. **Premature tunnel release on update:** old source closed the only TUN before
   `Builder.establish()`. Replacement now retains the old session until successful
   establishment. On failure, previous rules remain when possible and new selections
   are explicitly unconfirmed. Android/OEM routing handover needs endpoint evidence;
   source ordering alone does not prove atomic enforcement.
2. **Reader failure released the owning FD / stale status:** old `FileInputStream`
   owned the TUN's raw FD. Reader now owns a `ParcelFileDescriptor.dup`; EOF/error
   retains the original and reports monitoring loss. Session-identity checks under
   one lock prevent stale counters/failure callbacks from overwriting a replacement.
   A generation check invalidates establishment if revoke/destroy wins concurrently.
3. **No process/reboot enforcement:** opted into Android Always-on support and
   sticky service restart; UI links to VPN settings and reports API 29+ system flags.
   App does not enable Lockdown itself. Without system Lockdown, fail-open risk
   remains. With this sink, Lockdown also blocks unselected apps: useful selective
   forwarding is **not** implemented. Missing/empty rule sets enter explicit all-app
   safety capture rather than silently dropping missing package rules.
4. **Resource pressure / metadata correctness:** metadata work capped at 20 samples/s,
   40 retained headers, 32,767-byte buffer, 500 ms idle poll / publication interval.
   IPv6 extension walk capped at 8 headers / 2 KiB, handles fragment offsets and
   rejects truncated chains. JVM tests cover TCP/UDP/DNS metadata, options, fragments,
   declared lengths, opaque ESP/no-next-header, checksum opacity and 10,000 seeded
   malformed packets. This is metadata hardening, not a new filtering engine.
5. **APK archive indexing allocation:** preflight validates central bounds, actual
   record count, EOCD consistency and directory budget before `ZipFile` allocates
   entry objects. A new negative test initially caught trusting the declared count;
   the implementation was corrected and focused tests rerun successfully. This
   bounds one allocation path, not a proof that every platform APK parser is safe.
6. **Build provenance/reproducibility:** committed dependency locks and SHA-256
   artifact verification. Full debug/release validation passed again without
   metadata-writing flags. These controls detect unexpected artifact/version changes,
   not malicious code in an initially trusted upstream release.

7. **Reported active before Android enforced routes:** a real endpoint received a
   blocked TCP payload while the VPN network was still CONNECTING. Protection is
   now reported active only after Android announces the matching VPN network and
   both default routes, identified by a unique per-session IPv6 address. Integration
   tests await this routing barrier, not a UI flag or empty counter. Successful
   reruns had no marked blocked receipts. Callers must not treat `starting` as
   protection; ordinary VPN startup still requires Lockdown for no-VPN enforcement.
8. **Manual recovery with no saved selections:** the Start button now permits
   all-app safety capture with an empty rule set, instead of requiring a saved
   selection before manual recovery. This is not an automatic-restart guarantee.

## Execution evidence

- Debug and unsigned release APK assembly: passed.
- Debug JVM suite: 24 tests (19 packet/security + 5 archive), zero failures/skips.
- Release JVM suite: same 24 tests, zero failures/skips.
- App debug/release lint and probe debug lint: passed; six dependency-version
  warnings remain visible in the app report. No lint rule or test was disabled.
- Debug instrumentation APK and separate probe APK: compiled successfully.
- Local fixture controls: TCP, UDP, DNS/UDP, DNS/TCP, certificate-verified DoT
  and DoH passed with no upstream DNS/network request.
- AOSP API 30 x86_64 emulator, software CPU emulation (KVM unavailable): **8 app
  instrumentation tests plus 1 independent-UID control passed**. IPv4 and IPv6
  controls and blocking covered TCP, UDP, DNS/UDP, DNS/TCP, verified DoT and HTTPS
  DoH on local nonstandard ports. Existing TCP connections, real VPN authorization
  revocation, empty/missing selections, duplicated FD ownership and 12 lifecycle
  repetitions were exercised. Endpoint receipts contained no marked blocked payload.
- Lockdown: a 60-second dual-stack UDP canary across actual SIGKILL passed endpoint
  checks in two completed canary runs. One run did **not** automatically restart
  the firewall process; the next did. The unresolved intermittent availability
  failure remains a release blocker, even though Android Lockdown blocked traffic.
  The lab controller used ADB root to kill the process; app and probe remained
  distinct ordinary UIDs. The production app has no root requirement.
- Deep Doze (actual IDLE), force-stop with no VPN, and airplane-mode recovery:
  independent UID checks blocked all six transports on both address families.
  Initial reboot run failed underlay readiness after a system-server watchdog in
  package-data preparation. After platform recovery and Wi-Fi reconnect, post-boot
  checks blocked both families/all six transports and settings persisted. A clean
  continuous boot/before-unlock result is **not established**. Raw watchdog,
  transcripts and snapshots are retained in the execution record below.
- Dependency POM inventory: 373 records / 85 runtime graph records, no missing
  runtime license declarations. Offline OSV Maven snapshot: 7,257 records,
  62 version/advisory candidates in build/test/tooling, zero release-runtime
  candidates. Toolchain candidates include upstream HIGH/CRITICAL labels and are
  **not remediated**; reachability/compatible upgrade needs further work. See
  [component assessment](docs/COMPONENT_REVIEW.md).

Failures retained in the work record: an initial new archive regression failed,
then passed after validating actual records; lint flagged indentation, corrected
with explicit blocks; API 35 Google APIs system-image extraction exhausted disk
and a concurrent release task could not create its output directory. That build
was excluded; subsequent full debug/release runs passed after space recovery.
Other initially failed device runs exposed a disconnected emulator underlay,
unprepared VPN consent, asynchronous recovery/barrier assumptions, and Android
network-denial `IOException` classification in the crash fixture. Those fixture
issues were corrected and their scenarios rerun. The first forced-Doze attempt
failed because emulator deep idle was disabled; the harness now explicitly enables
it temporarily and still asserts actual IDLE. A local endpoint self-check attempted from the restricted sandbox while lifecycle
endpoints were active failed; an outer-executor rerun after teardown passed.
The automatic-restart failure is **not fixed**. No failure was converted to an
ignored test or disabled lint rule.

## Release blockers and required manual validation

- Full IP/port/protocol policy enforcement and domain filtering need a validated
  forwarding engine. They are absent, not silently accepted controls. See the
  [component/license assessment](docs/COMPONENT_REVIEW.md).
- Resolve intermittent automatic service recovery observed after SIGKILL; Android
  Lockdown prevented the sampled leak but does not guarantee app availability.
- Extend Android Lockdown validation to boot/before-unlock, process death, intentional stop,
  permission revocation, reader faults and update failure under continuous logged
  selected/unselected UID traffic. No user-space code can guarantee blocking after
  loss of VPN authorization if Android permits bypass.
- Real IPv6/IPv6-only/NAT64 routing, IPv4/IPv6 fragments and MTU/PMTU under real
  traffic; existing connections across updates; Android resolver/Private DNS and
  standard DNS ports; DoH/HTTP2/QUIC and delegated requests remain acceptance gates.
- Android 8–9, modern Android 14/15 foreground-service/background restrictions,
  multiple OEMs/profiles, Wi-Fi/cellular handover, airplane mode, Doze and a physical
  device battery/thermal/memory-pressure soak are not established by a single emulator.
- Review/update aging AndroidX/toolchain inputs with compatibility tests and current
  vulnerability advisories. Unsigned release APKs are not deployable production
  releases; maintainer signing and upgrade testing remain necessary.

See [execution record](docs/VALIDATION_RESULTS.md) and [TESTING.md](TESTING.md) for concrete commands and the full matrix. Do not treat
passing JVM/lint checks, retained descriptors, or a VPN icon as proof that these
release gates passed. Physical device testing has not been performed.
