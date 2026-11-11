# Android Security Suite

A free, Apache-2.0 Android 8+ prototype written in Kotlin and Jetpack Compose. No ads, telemetry, accounts, cloud services, or `INTERNET` permission.

- Dashboard with local firewall state, app inventory and root indicators.
- Rootless firewall: selected application UIDs route to a local `VpnService` TUN; captured IPv4/IPv6 packets are discarded. Unselected applications bypass the VPN normally. Rules persist locally; applying rules restarts the tunnel.
- Installed package search, system-app filter, declared permissions and Android-reported grant flags. Sensitive permission indicators are informational, not malware verdicts.
- Read-only root heuristics (visible `su`/Magisk artifacts, test build keys).
- Document-picker APK inspection: SHA-256, package/SDK metadata, signer certificate fingerprints, permission declarations, debuggable/cleartext flags, DEX/native library counts. APKs are never installed/executed; temporary private copies are deleted. 100 MiB input limit.
- Bounded network monitor: captured packet/byte counters and the latest 40 destination/protocol/port headers in memory. No packet payload persistence, interception certificates, DNS lookups, or TLS decryption.

## Build

Requires JDK 17 or 21, Android SDK platform 35, build tools 34.0.0, and Linux x86-64 for the bootstrap defaults. Gradle 8.10.2 is pinned with a distribution checksum. Dependencies are downloaded at build time; the installed app operates offline.

```sh
./scripts/bootstrap.sh   # installs the pinned SDK under /workspace/toolchains, builds, tests and lints
./scripts/check.sh       # repeat checks using the installed SDK
```

For an existing Android development machine, set `ANDROID_HOME` to its SDK and run `./gradlew assembleDebug testDebugUnitTest lintDebug`. Bootstrap uses `curl`, `unzip`, Python 3 and a trusted host Java runtime, downloading a checksum-pinned open-source Temurin JDK 21 when no compiler is available. It preserves TLS/artifact verification and accepts SDK development licenses. No system package installation or rooting occurs.

APK: `app/build/outputs/apk/debug/app-debug.apk` (debug signed; not a production release). Unit results: `app/build/reports/tests/testDebugUnitTest/index.html`. Lint: `app/build/reports/lint-results-debug.html`.

With an Android device/emulator connected: `./gradlew connectedDebugAndroidTest` runs device smoke tests. Install using `adb install -r app/build/outputs/apk/debug/app-debug.apk`.

## Device acceptance checks

1. Open the app. On Apps, select an expendable network client; leave another client allowed. Enable the firewall and approve Android's VPN dialog.
2. New IPv4 and IPv6 requests from the blocked client should fail. Its captured packets should appear in Activity. The allowed client should still connect. Test Wi-Fi and cellular separately, including DNS and existing connections.
3. Change selection while active; stop via the dashboard/notification and confirm normal connectivity returns. Revoke VPN permission in Settings and verify the stopped status.
4. Inspect a known APK and compare its SHA-256 with `sha256sum`. Review sensitive permission declarations and grant flags against Android Settings.

These are required device acceptance checks before trusting the prototype as a firewall. JVM tests do not prove Android VPN routing behavior.

## Limits

This is an experimental app, not a malware scanner, integrity attestation service, remote VPN, or anonymity tool. Root hiding can evade the checks, and development ROMs can trigger false positives. Static APK metadata cannot establish safety; signature fingerprints are metadata, not independent cryptographic signature verification. APK splits/bundles and full code analysis are unsupported. No numerical security score is invented.

VPN blocking applies only while the foreground service is alive. The firewall is **fail-open** on stop, process death, reboot, permission revocation or rule-transition gaps. Always-on/lockdown is deliberately unsupported. Another VPN cannot run simultaneously. Shared-UID packages may be affected together, and traffic delegated to another UID may escape an app's rule. System app rules can disrupt connectivity or services. Package inventory is limited to the current Android user/profile. There is no app attribution for captured packets, historical usage, allowed traffic visibility, or IPv6 extension-header transport parsing. Uninstall clears rules. Packet metadata is memory-only and bounded; counters reset on tunnel restart. No root, bootloader unlock, flashing, or privileged shell commands are used.

## Open-source research and licensing

Reviewed [NetGuard](https://github.com/M66B/NetGuard), [TrackerControl](https://github.com/TrackerControl/tracker-control-android), and [AFWall+](https://github.com/ukanth/afwall) for their local VPN/firewall approaches and licensing. NetGuard and TrackerControl's richer forwarding/filtering engines are substantially larger than this MVP; AFWall+ requires root. No GPL project source or assets were copied. The app uses original sink-only VPN code and the public Android APIs, reusing Apache-licensed AndroidX/Compose libraries through Gradle. See [THIRD_PARTY.md](THIRD_PARTY.md) and [LICENSE](LICENSE).
