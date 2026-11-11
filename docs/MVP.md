> Historical beta1 acceptance. Beta2 changes and current evidence: [FUNCTIONAL_VALIDATION.md](FUNCTIONAL_VALIDATION.md).

# Android Firewall 0.2.0-beta1 — MVP

This MVP is an unprivileged local **app blocker**, not a forwarding firewall or a
production-ready security product. Application source stays Apache-2.0. No
new runtime dependency, INTERNET permission, telemetry, remote VPN, paid API or
native network stack was introduced.

## Delivered behavior

- Select applications and apply a batch of edits once. Each toggle no longer
  rebuilds the VPN. Pending edits are clearly distinguished from saved/applied
  configuration, and drafts/mode/tab/search survive activity recreation.
- An explicit all-app mode preserves individual selections and requires a
  confirmation explaining device-wide network loss.
- Clearing the last manual selection asks to clear and stop. It never silently
  converts an ordinary edit to all-app blocking. Android Always-on startup with
  empty/missing rules still enters conservative all-app quarantine.
- Persist packages and mode together before starting the service. Storage failure
  is shown instead of claiming that rules were saved. Legacy package-only settings
  load as selected-app mode; the package name and signing identity remain unchanged.
- Stop is available when the foreground service exists but establishment failed.
  Retry is available for lost/unconfirmed routing, reader loss or failed updates.
  Failed-update messages survive routing callbacks while prior rules are retained.
- Selected-package removal/reinstallation automatically refreshes the VPN UID list.
  Removal enters quarantine; reinstallation resolves the new UID and reapplies
  the saved selections. An inactive service does not restart on package events.
- A status refresh cannot accidentally establish a VPN. Empty inactive status
  requests stop their temporary service instead of leaving an idle sticky service.
- Search and Internet/system-app filters make the list usable; shared UID effects
  are explained. Existing local permissions/APK inspection is retained.

## MVP acceptance

| Check | Evidence / status |
| --- | --- |
| Selected UID blocked; unselected UID allowed | Real dual-stack integration tests; current execution below |
| Explicit all-app mode; return to selective mode | Added real TCP/UDP device regression with independent UID |
| Saving does not apply a replacement | Existing live traffic regression now checks before explicit apply |
| Clear last selection / all-app confirmation / cancel | Added real Android accessibility UI tests |
| Draft survives activity recreation | Added real ActivityScenario/accessibility test |
| Stop, revoke, existing flows, repeated starts, resource checks | Existing device regressions retained |
| Selected package removed/reinstalled | Added real fixture uninstall/reinstall device regression |
| Empty/missing system configuration remains conservative | Five capture-plan JVM tests plus existing real-device quarantine test |
| Release/debug build, lint, all JVM tests | Current execution below |

## Current execution — 2026-11-11

**Scoped MVP acceptance passed on the disposable API 30 emulator. This is not a
production-readiness decision.** Tested source: `9e54878` (production source
`1cbb147`); the later report commit changes documentation/evidence only.

- Debug and unsigned release assemblies, app debug/release lint and probe lint:
  passed. Six existing newer-dependency warnings remain visible; no lint was disabled.
- JVM tests: **29 debug + 29 release**, zero failures/errors/skips. Includes five
  new capture-policy regressions as well as the previous packet/archive suites.
- Android: **14 app tests + 1 independent-UID test passed**. The app set contains
  two smoke tests, nine real VPN/lifecycle tests and three real accessibility UI
  flows. Mode confirmation, cancel, activity recreation, last-selection clearing,
  and Stop visible without scrolling were actually exercised.
- IPv4/IPv6 TCP, UDP, DNS/UDP, DNS/TCP, certificate-verified DoT and HTTPS DoH:
  positive controls passed, selected traffic blocked, and **zero marked blocked
  payloads reached the local endpoint**. This finite sample is not a universal
  zero-leak claim. All-app mode/recovery and an actual probe uninstall/reinstall
  also passed. Fixture self-checks passed with TLS verification enabled.
- Release APK inspection: no INTERNET/test-probe permission and no fixture
  certificate/private-key paths. No new runtime dependencies were introduced.

[Machine-readable result and APK SHA-256](evidence/mvp/final/summary.json),
[device transcript](evidence/mvp/final/instrumentation.txt),
[independent control](evidence/mvp/final/independent-control.txt),
[endpoint receipts](evidence/mvp/final/endpoint.jsonl),
[build log](evidence/mvp/host-build.txt),
[overview screenshot](evidence/mvp/overview.png).

An initial device run had **13 passes and one UI failure**: its widget-class/
checked-state lookup did not find the probe switch. The switch now has an
application-specific accessibility label, and the test uses that label while
retaining the confirmation, persistence and no-accidental-VPN assertions. Start/
Stop controls were also moved above long explanations; the UI test now requires
Stop to be visible without scrolling. The **whole suite was rerun and passed**;
no failing test was ignored or removed. [Initial failure](evidence/mvp/first-ui-failure/instrumentation.txt).

The reused software-emulated AVD initially had ownerless locks from a defunct
process. Only those locks were removed. Its cold boot also encountered an Android
system restart/DeadSystemException before the MVP APK was installed; testing
waited for network services and user unlock, reconnected the emulator WLAN, and
dismissed the queued system ANR with Wait. A post-test `am start -W` also reported
a display-wait timeout; the subsequent UI dump/screenshot showed the Overview.
No physical startup-time measurement is claimed. These setup failures are not passing
boot/security tests. No physical device, KVM acceleration, modern Android/OEM
matrix, battery benchmark, or continuous boot guarantee is claimed.

## Artifacts and reproduction

```sh
./scripts/gradle.sh :app:assembleDebug :app:assembleRelease \
  :app:testDebugUnitTest :app:testReleaseUnitTest :app:lintDebug :app:lintRelease \
  :app:assembleDebugAndroidTest :probe:lintDebug
FIREWALL_IPV6=1 ANDROID_SERIAL=emulator-5554 \
  ./scripts/device-check.sh /tmp/firewall-mvp-device-evidence
```

The device script installs/builds fixtures, pushes the exact disposable probe APK
for its uninstall/reinstall regression, and requires an emulator with Lockdown OFF.
It bounds instrumentation time and fails on missing tests, failed baselines or
marked endpoint receipts. It must not be run on a personal phone.

Installable **debug test build**:
`app/build/outputs/apk/debug/app-debug.apk` (versionCode 2, versionName 0.2.0-beta1).
The unsigned release at `app/build/outputs/apk/release/app-release-unsigned.apk`
needs maintainer signing before distribution. The debug key is not a production
release identity.

## Deliberate boundaries

In selective mode, unselected apps use Android's ordinary network only when
Lockdown is OFF. Loss of the ordinary VPN can allow traffic. Android Always-on
requests restart, while **Lockdown** supplies no-VPN blocking. With this sink-only
engine, Lockdown blocks unselected apps too; it cannot provide useful selective
forwarding. This limitation is shown in the UI rather than hidden behind a setting.

An intermittent automatic restart failure after SIGKILL remains unresolved from
the previous validation. This MVP adds explicit manual recovery, not a watchdog or
an automatic restart guarantee. A clean continuous boot/before-unlock check,
physical/OEM devices and a battery/load soak remain release gates. IP/port/domain
filtering, DNS forwarding, QUIC/HTTP2 inspection and a validated forwarding engine
are not part of this MVP. Existing tooling advisory candidates remain open; no
upstream versions changed in this iteration.

[Previous security review](../SECURITY_REVIEW.md),
[historical execution evidence](VALIDATION_RESULTS.md),
[reproduction commands](../TESTING.md).
