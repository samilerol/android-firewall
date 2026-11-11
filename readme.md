# Android Firewall

Free, open-source (Apache-2.0) Android 8+ app firewall. Version 0.2.0-beta2 is a
scoped MVP: block selected applications, or explicitly block every application.
Local APK/permission inspection remains available. See [current functional validation](docs/FUNCTIONAL_VALIDATION.md)
and [initial MVP acceptance](docs/MVP.md).
**Experimental; not production-ready.** There is no paid API, advertising,
telemetry, account, remote VPN, or runtime `INTERNET` permission in the firewall.

The current engine is a **packet sink**, not a general traffic forwarder. Selected
application UIDs enter a local `VpnService`; captured packets are discarded.
IPv4/IPv6, TCP/UDP and encrypted DNS traffic reaching that interface are dropped
without inspecting TLS. Unselected applications normally use their own network.
Actual routing verification and remaining release gates are in
[SECURITY_REVIEW.md](SECURITY_REVIEW.md) and [TESTING.md](TESTING.md).

## Quick start

1. Open **Apps**, keep **Selected apps**, and select the apps to block.
2. Tap **Apply and start**, then accept Android's VPN authorization request.
3. Wait for **Android routing confirmed** on Overview before relying on blocking.
4. Edit selections and apply once to change rules. Use **Stop firewall** to stop.
5. To deliberately disconnect every app, choose **Block all apps**, apply, and
   confirm. To allow unselected apps again, apply **Selected apps** and verify
   Android Lockdown is OFF.

App switches edit a draft; they do not themselves prove an app is blocked. Failed
updates keep prior protection when possible and expose Retry. With no selections,
the normal Start button stays disabled; choose apps or the explicit all-app mode.

## Protection modes — read before enabling

| Configuration | Behavior and limits |
| --- | --- |
| Ordinary VPN | Blocks selected UIDs while the tunnel exists. Process death, stop, reboot or permission loss can allow traffic. **Not fail-closed.** |
| Android Always-on only | Requests restart by Android; does not itself prevent bypass while the VPN is absent. |
| Always-on + **Block connections without VPN** (Lockdown) | Android enforces the no-VPN network block for the current user/profile. Only the user/device administrator can enable this system setting. |
| Lockdown with this sink-only engine | **Unselected apps also lose connectivity.** Apps outside the VPN application list cannot bypass Lockdown, and selected apps enter the sink. This is a device/profile-wide network block, not useful selective forwarding. |
| Explicit **Block all apps** | After confirmation, captures and discards every application's traffic. Individual selections are preserved for later. |
| Manual clear of the last selection | **Clear rules and stop** asks for confirmation. It does not activate all-app capture. Android Lockdown, if enabled, continues blocking outside the app. |
| System startup with empty rules, or any missing saved package | Safety mode captures and discards **all apps'** traffic. Apply installed selections to narrow the application list. |

For crash/reboot protection: enable the firewall, open **Android VPN settings**,
then enable both **Always-on VPN** and **Block connections without VPN** for
Android Firewall. Check the system setting yourself. The beta2 emulator crash test again failed to observe automatic restart within
60 seconds after SIGKILL; manually apply selections again, or choose **Apps → Block all apps →
Apply and start**, then confirm to restore all-app capture. Lockdown blocking and service
availability are separate requirements. Runtime setting detection
is available from Android 10; Android 8–9 display an unknown status. Some OEMs
manage these settings differently. Another VPN cannot run simultaneously.
Revoking authorization or disabling system Lockdown changes the security boundary;
the app cannot override the user or Android. Before first unlock after reboot,
Lockdown must provide the block while credential-encrypted rules are unavailable.

A replacement tunnel is established before the old owner is released. Failed
updates retain previous rules when possible and explicitly report that new rules
are unconfirmed. Packet reader failure retains the owning descriptor and reports
monitoring loss, rather than intentionally releasing routing. These controls
**do not replace Android Lockdown** and do not prove zero-loss handover on all OEMs.

## Features and limits

- Persistent per-application block selections and an explicit all-app mode.
- Edit a draft, then **Apply and start** once. Toggling app switches does not
  rebuild the VPN or silently change protection. Drafts survive activity recreation;
  closing/discarding a draft does not save it. Removing the last selection requires
  confirmation to clear and stop. All-app mode also requires confirmation.
- Selected-package removal/reinstall events refresh UID routing while the service
  runs; missing selections enter safety mode until resolved. Only Android Lockdown
  protects transition windows after process/network loss.
- Search and Internet/system-app filters; shared UID impact is shown when known.
- Failed disk writes restore prior in-memory rules before readers can observe the
  attempted configuration. Free storage and retry; this is not a power-loss guarantee.
- Separate saved/applied status, visible retry after monitoring/update failure,
  and Stop even if establishment failed. Shared UIDs affect multiple packages.
- Bounded in-memory activity: all read packets/bytes counted, at most 20 metadata
  samples/second, latest 40 samples retained. No payload storage or app attribution.
- IPv4 options and bounded IPv6 extension/fragment metadata parsing. Parsing and
  checksums never grant access: even malformed packets reaching the sink are discarded.
- Installed app/permission inventory and informational root heuristics.
- Cancellable local APK analysis with owned-stream closure and temporary-copy cleanup.
  Invalid, missing and oversized documents report errors and allow another attempt.
- Local APK metadata, SHA-256 and signer certificate fingerprints; no installation,
  execution, uploads, malware verdicts or independent signature verification.
  APK input <=100 MiB, directory <=8 MiB, <=20,000 central records, manifest <=4 MiB;
  unsupported ZIP64/split archives are rejected before `ZipFile` indexing.

**Not implemented:** selective IP/port/protocol allow/deny rules, domain blocklists,
DNS forwarding/filtering, TCP/IP forwarding, connection migration or per-flow
accounting. DoT/DoH destinations are blocked with their selected UID; encrypted
hostnames are not decoded. Those features require an audited forwarding engine,
not a metadata-parser switch. See [component review](docs/COMPONENT_REVIEW.md).

Delegated traffic from another UID can escape ordinary application rules. Package
inventory/rules cover the current Android user/profile. System app rules may
break device services. No root, bootloader unlock or privileged runtime access is
required. Battery performance, OEM background restrictions and real cellular
handover still require physical-device validation.

## Build and tests

Requires JDK 17/21, Android SDK 35 and build tools 34.0.0. Gradle, dependencies and
resolved transitive versions/checksums are pinned. Downloaded bytes are checked
against committed SHA-256 metadata. Initial metadata was bootstrapped through
TLS from configured upstream repositories; this is reproducibility control, not
independent proof that upstream packages have no vulnerabilities.

```sh
./scripts/bootstrap.sh       # first-time SDK/JDK setup; accepts development SDK licenses
./scripts/check.sh           # firewall debug APK, JVM tests, lint
./scripts/gradle.sh :app:assembleRelease :app:testReleaseUnitTest :app:lintRelease
python3 scripts/test-traffic-endpoint.py
./scripts/device-check.sh    # disposable emulator + independent local traffic receipts
```

Use `scripts/gradle.sh` for arbitrary ordered tasks (for example, `:app:clean`
before build tasks). Do not run multiple builds in the same working tree.
Set `ANDROID_HOME`, `ANDROID_USER_HOME`, `GRADLE_USER_HOME`/`JAVA_HOME` for an
existing toolchain. See [TESTING.md](TESTING.md) for setup, artifacts and gaps.

The `probe` module is a separate test-only UID with network permission, a pinned
local test certificate, signature-protected receiver and read-only APK document fixture. It cannot be a release
variant and is never a dependency of the firewall. Its public fixture private key
must never be deployed. The firewall release does not contain that permission,
certificate, receiver, or private key. Release APKs are unsigned until a maintainer
uses their own release signing configuration; debug APKs are not production releases.

## Licensing and privacy

See [LICENSE](LICENSE), [THIRD_PARTY.md](THIRD_PARTY.md), and
[component assessment](docs/COMPONENT_REVIEW.md). No GPL forwarding code was copied.
Rules are private local preferences with backup/transfer excluded. App data is
removed on uninstall; activity metadata is memory-only. Test logs contain synthetic
local test traffic and are not a runtime product telemetry feature.
