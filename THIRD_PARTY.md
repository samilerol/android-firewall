# Third-party components

Application source: Apache License 2.0 (see LICENSE).

Runtime dependencies: AndroidX Activity, Compose, Lifecycle and transitives (Apache-2.0); Kotlin standard library and kotlinx.coroutines (Apache-2.0). Test-only JUnit 4 (EPL-1.0), Hamcrest (BSD-3-Clause), AndroidX Test (Apache-2.0). Gradle wrapper/build system: Apache-2.0; Android Gradle Plugin: Apache-2.0. Components retain their upstream notices/licenses in distributed artifacts; consult resolved dependency artifacts for full notices. Android SDK tooling is a development prerequisite governed by its own license, not bundled in the APK.

Research references only; no code copied:
- https://github.com/M66B/NetGuard — GPL-3.0; local VpnService firewall design.
- https://github.com/TrackerControl/tracker-control-android — GPL-3.0; local network filtering and limitations.
- https://github.com/ukanth/afwall — GPL-3.0; root-dependent firewall contrast.

No tracker databases, third-party signatures, native forwarding engines, logos, or project assets are included.

The `probe` APK and Python server are separate local test fixtures, not runtime dependencies. Their certificate/private key are public test data and are not shipped in the firewall. See [docs/COMPONENT_REVIEW.md](docs/COMPONENT_REVIEW.md) for current engine and dependency assessment.
