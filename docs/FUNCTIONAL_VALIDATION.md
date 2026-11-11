# Beta2 full-function validation

This record extends the MVP acceptance at `22140db`. It exercises the implemented screens and primary controls. It does not certify absence of all defects or add
an IP/port/domain forwarding engine. Final execution results are recorded below.

## Confirmed fixes

- A real Android disk-write fault demonstrated that SharedPreferences changed its
  in-memory policy even when commit returned false. The exact regression failed
  before the fix and passed afterward. Rule readers/writers now share a monitor;
  failed saves restore the previous configuration before any Rules reader returns.
  Disk failure still requires storage recovery; this is not a power-loss guarantee.
- APK analysis now accepts Android cancellation, closes its owned input stream,
  cancels provider opening, checks between copy/archive stages, and removes the
  temporary copy in finally. The UI exposes Cancel and clears its busy state.
  Closing the ViewModel also cancels its signal. Platform package parsing may
  return before cancellation can finish; instant interruption is not promised.
- Missing document/VPN-authorization handlers produce actionable messages.
- Filter labels are usable checkbox targets; tab changes return to the controls.
  Consent/storage errors and retry controls precede long explanatory text.

## Function matrix

| Function | Actual automated coverage |
| --- | --- |
| Overview / refresh / root indicators | Real UI refresh and displayed heuristic result; no integrity guarantee |
| Empty initial selection | Disabled parent control; no accidental all-app VPN |
| Selected applications / explicit all-app mode | Independent UID, real IPv4/IPv6 protocols and recovery |
| Draft/apply/cancel/recreation | Real UI and unchanged persisted/applied policy assertions |
| Last selection / unavailable package | Confirmed clear-and-stop; real uninstall/reinstall quarantine/recovery |
| Search / Internet/system filters / permissions | Text editing, label clicks, expanded grant metadata |
| VPN authorization denial | Real system consent cancellation where the system handler exists |
| VPN settings navigation | System activity round trip or explicit unavailable-handler message |
| Start / stop / retry/status infrastructure | Readiness, repeated lifecycle, no side-effect status, retained-owner source review |
| Notification Stop | Real notification PendingIntent, not a substituted service call |
| Activity | Real blocked TCP metadata rendered in the UI |
| APK picker | Actual Downloads document selection on a full image; cancel / absent-provider handling |
| APK analysis | Own signed APK, real content URI/FD, invalid/missing/oversized files |
| Analysis cancellation | Signature-restricted slow pipe provider; UI cancel, writer closure, no temp copies, recovery |
| Persistence / migration / failure | Mode+packages, legacy settings, real unwritable-directory failure and rollback |
| Packet/archive limits | Existing JVM malformed-input, fragment/extension and ZIP-index regressions retained |

The separate debug-only document fixture is signature restricted, read only,
limited to its own APK and bounded slow pipes. It adds no provider, permission,
network path, key or dependency to the firewall release.

## Execution

Final host run: **BUILD SUCCESSFUL**, 201 tasks; debug and release JVM suites each
29 tests, zero failures/errors/skips. Debug/release application lint and probe lint
pass with warnings retained in `evidence/beta2/host-summary.txt`. Python fixture
self-tests pass for TCP, UDP, DNS/UDP, DNS/TCP, certificate-verified DoT and DoH.
Shell syntax and diff whitespace checks pass. Release manifest inspection confirms
no INTERNET or TEST_PROBE permission and no test document provider; the normal
AndroidX initialization provider remains. APK SHA-256 values are retained.

API35 final device run: **27/27 application tests pass**, both independent IPv4
and IPv6 preflights pass all six protocols, final independent control passes.
The endpoint recorded 53 successful control receipts and **zero blocked nonces**.
Raw artifacts are in `evidence/beta2/api35-final/`. This is the beta2 production
code and test source committed at `4c5019b`; APK hashes identify exact binaries.
API30 clean full-image validation at `4d81202`: **27/27 application tests pass**,
both IPv4/IPv6 six-protocol preflights and the final independent control pass.
The endpoint recorded 52 successful control receipts and **zero blocked nonces**.
The run includes real Settings navigation, real consent cancellation and native
Downloads keyboard selection. Raw evidence: `evidence/beta2/api30-final/`.
Production code is identical to the passing API35 run; the later commit changes
only the native UI test helper.
The previous full-image run completed 27 tests with 3 failures: two blocked by an
observed System UI ANR, one native file-row activation failure. All are retained in
`evidence/beta2/api30-systemui-and-picker-failure/`. After selecting the observed
system dialog's Wait action, subsequent tests progressed. No test was disabled.

Focused actual Downloads selection passes at `4d81202`: the native file row takes
keyboard focus and Enter returns a real URI; the app renders the APK report and
removes its temporary copy. Accessibility-click and synthetic-touch attempts did
not activate the file row on this full image; their failures remain in
`evidence/beta2/picker-touch-failure/`. This positive result validates native file
selection/URI handling with keyboard activation, not physical-device touch gestures.
Those gestures remain a manual acceptance requirement. Restarting only the stale
native picker process and using its native keyboard navigation changed no firewall
runtime code or Android enforcement settings.
The earlier expanded API30/API35 failures are retained with the final results.
API35 AOSP ATD has no DocumentsUI/full Settings app: its explicit missing-handler
branches do **not** demonstrate a real document selection or Settings round trip.
A full API30 image is required for those positive cases.

The API35 emulator initially refused local host TCP even with the firewall off.
Its `netsimd` raw-TCP adapter inherited the host HTTP proxy; local `no_proxy`
exceptions did not restore it. Restarting **only the disposable emulator process**
without proxy variables restored all six application-UID IPv4/IPv6 positive
controls. Ordinary dependency/Git tooling retains its normal network settings.
No routing test uses adb reverse or a loopback bypass. The official SDK image hash
and sparse extraction provenance are recorded; software emulation has no KVM.
Because the workspace disk is only 7.9 GiB, the API35 image/AVD were temporarily
RAM-backed and removed after their successful run; API30 tooling is preserved.
Reproduction on a larger workspace can use the standard official SDK image install.
ATD images without a picker do not require a Downloads fixture; full images must
successfully stage that file and exercise the actual picker, or the run fails.

## Current Lockdown lifecycle result — FAILED overall

The same beta2 APK was tested with Always-on + Lockdown enabled through real
Android Settings on API30. Stored settings and actual VPN routes are captured.
**11/11 independent-UID traffic checks pass**: dual-stack six-protocol checks
with VPN active, after SIGKILL, during verified deep Doze, after force-stop with
an actual no-VPN interval, and after airplane-mode/network recovery; plus a
60-second dual-stack UDP canary spanning SIGKILL. No marked blocked payload was
received by the controlled endpoints. The network underlay was verified.

**Automatic process restart was not observed within the 60-second crash window.**
The service snapshot reports an absent app process. The script records the
failure, explicitly starts the foreground service to recover, continues independent
privacy checks, and exits **1**. Manual recovery is not automatic recovery. Both
application UIDs were ordinary and distinct; root belonged only to the disposable
ADB lab controller. The original deep-idle configuration is restored by cleanup.
All raw evidence is in `evidence/beta2/lockdown-final/`; system/event log excerpts
are filtered, not complete logs. No app-code root cause has been established and
no watchdog or false recovery guarantee was added. The earlier availability risk
is **reproduced, unresolved**, and blocks a production-readiness claim.

The reboot phase was not repeated in this beta2 run. Earlier qualified post-boot
results remain in [VALIDATION_RESULTS.md](VALIDATION_RESULTS.md); they do not
establish before-unlock continuity or universal restart reliability.

## Boundaries that cannot be removed by passing tests

The engine remains a sink. Useful selective forwarding under Lockdown and granular
IP/port/domain/DNS policy require an audited forwarding architecture; they are
not implemented by this pass. Ordinary VPN process loss can allow traffic.
Android Lockdown supplies no-VPN blocking and also blocks unselected UIDs with
this design. The previously observed intermittent automatic restart failure is
not an automatic-recovery guarantee in beta2.

The Retry UI path after a real reader fault, the unavailable-rule removal button,
and complete OS/version combinations are not individually certified by this suite.
Physical/OEM devices, before-unlock continuity, cellular/NAT64 and sustained
battery/load tests remain separate acceptance requirements. Release signing
needs a maintainer-controlled identity. Existing tooling advisory candidates
remain open. Test APKs and emulator results do not close those release gates.
