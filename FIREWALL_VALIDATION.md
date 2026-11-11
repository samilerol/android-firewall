> Historical Mission 2 evidence at `18a7f30`. Current behavior changed; see [SECURITY_REVIEW.md](SECURITY_REVIEW.md) and [TESTING.md](TESTING.md).

# Mission 2: firewall validation

Base: `d101a4a563bcaa9e2695a110f4fa33138d618808`.

## Security contract and source review

This is a selected-UID, sink-only VPN. `FirewallService` adds IPv4 and IPv6
default routes, assigns addresses for both families, and supplies a DNS sink
(`192.0.2.1`). Only installed selected packages enter the tunnel. The suite's
own package is excluded. Captured packets are read and discarded; metadata
parsing does not decide whether a packet is dropped. No forwarding sockets,
`allowBypass`, or `allowFamily` calls are present.

These source properties are not proof of Android routing or absence of leaks.
Delegated traffic and shared UIDs remain limitations.

The documented contract is fail-open: stop, revoke, process death, reboot,
failed establishment, and rule replacement can restore ordinary connectivity.
Rule replacement closes the old tunnel before establishing the new one.
Always-on support is explicitly disabled in the manifest. There is no
fail-closed guarantee and this mission does not change that product contract.

Lifecycle review: STOP, onDestroy, and revoke close the descriptor and cancel
the reader. A token identifies each reader so an old reader's exception cannot
shut down a replacement tunnel. Unexpected EOF exits the reader without
updating status; whether this occurs on a supported Android runtime needs a
device reproduction before treating it as a confirmed security defect.

## Required device evidence

Use two network-capable client packages, one selected and one unselected, and
a controlled dual-stack endpoint with server access logs. Establish successful
baseline connections first; a failed baseline cannot prove blocking. Record
Android version, device, network, package UIDs, VPN state, timestamps, and
server observations. Test Wi-Fi and cellular where supported.

| Scenario | Expected result |
| --- | --- |
| Active VPN, selected client, literal IPv4 TCP/UDP | No endpoint receipt; captured counter rises |
| Active VPN, selected client, literal IPv6 TCP/UDP | No endpoint receipt on a baseline-working IPv6 network |
| Selected client, fresh random DNS names over UDP/TCP 53 | No authoritative-query receipt or successful lookup |
| Selected client, DoT/DoH | Connections blocked like other selected-UID traffic |
| Unselected client, same probes | Baseline connectivity remains available |
| Connections established before VPN activation | No continued selected-client endpoint traffic after activation |
| Rule replacement, including removed packages | Observe and record transition gap; do not claim atomic blocking |
| Stop from UI and notification | VPN disappears, inactive status, connectivity returns |
| Permission revoke or competing VPN | Inactive status and ordinary connectivity; no stale reader interference |
| Process kill, reboot | Fail-open; no automatic protection claimed |
| Screen off, background, network handover | Verify VPN remains effective while service is alive |
| Rapid repeated start/update/stop | Correct final state, no stale status or descriptor failures |
| All selected packages removed, consent denied | Clear inactive/error state; no accidental device-wide capture |

Emulator tests cannot establish cellular behavior. DNS cache hits are not leak
tests; use fresh names and endpoint logs. IPv6 without a successful baseline
must be recorded as untested. Shell traffic alone does not exercise a selected
application UID. Existing connected smoke tests cover package inventory, APK
inspection, and rule persistence, not this traffic matrix.

## Automated coverage

`SecurityTest` adds DNS with IPv4 options, trailing bytes outside declared
packet bounds, truncated IPv6 payloads, and ICMPv6 metadata regressions.
Run `./scripts/check.sh` for build, JVM tests, and lint, then
`./gradlew connectedDebugAndroidTest` with the installed SDK and a device.
Execution results for this run are recorded below.

## Execution evidence (2026-11-11 UTC)

- Shell access succeeded. The checkout was initially absent; cloning the
  requested branch outside the sandbox succeeded and HEAD matched the base.
- Installed the checksum-pinned SDK/JDK through `scripts/bootstrap.sh`.
  The sandbox proxy was unreachable; approved outer-executor commands worked.
- JVM run: 11 tests, 0 failures, 0 errors, 0 skipped, including the three new
  regressions (`TEST-org.suite.security.SecurityTest.xml`).
- Debug application and instrumentation APK compilation succeeded.
- Connected test execution was attempted with `scripts/check.sh
  connectedDebugAndroidTest`; Android reported `DeviceException: No connected
  devices!`. `adb devices -l` independently returned an empty device list.
- No emulator executable, configured AVD, or `/dev/kvm` was supplied. Emulator
  traffic testing was not performed; software emulation was not provisioned.
- An initial overlapping bootstrap/check build failed on a missing intermediate
  resource. That run is excluded as acceptance evidence. A subsequent serial
  build, JVM test, and lint invocation succeeded, followed by cleaning and a
  fresh serial rebuild.

Verdict: packet metadata regressions pass. No runtime security defect was
confirmed. IPv4/IPv6/DNS leak prevention, fail-open transitions, and lifecycle
behavior remain **unvalidated on Android**. This is not firewall certification
or evidence of fail-closed protection. Complete the device matrix above before
relying on the prototype for blocking.
