# Project Instructions

Canonical, tool-agnostic file (Claude Code reads it via `CLAUDE.md`). Keep under 100 lines.

## What this is
Android Firewall: free, open-source (Apache-2.0) Android 8+ per-app blocker. Selected app UIDs go into a local `VpnService`; their packets are captured and **dropped** (packet sink, no forwarding, no `INTERNET` permission, no telemetry). Version 0.2.0-beta2, **experimental, not production-ready**. Goal: grow into a firewall+VPN app for Play/App Store.

## Stack
Kotlin 2.0.21, AGP 8.7.3, Jetpack Compose (BOM 2024.12.01), Java 17 target, minSdk 26 / target+compile 35. Gradle Kotlin DSL. Modules: `:app` (firewall), `:probe` (separate-UID test fixture, debug-only, never shipped). Package `org.suite.security`.

## Commands (always via the wrapper script)
- Quick check (build+unit+lint): `./scripts/check.sh`
- Release gates: `./scripts/gradle.sh :app:assembleRelease :app:testReleaseUnitTest :app:lintRelease`
- One unit test class: `./scripts/gradle.sh :app:testDebugUnitTest --tests 'org.suite.security.SecurityTest'`
- Fixture + androidTest APKs: `./scripts/gradle.sh :app:assembleDebugAndroidTest :probe:assembleDebug :probe:lintDebug`
- Python fixture test: `python3 scripts/test-traffic-endpoint.py`; shell syntax: `bash -n scripts/*.sh`
- Emulator integration (emulator ONLY, never a real device): `ANDROID_SERIAL=emulator-5554 FIREWALL_IPV6=1 ./scripts/device-check.sh /tmp/evidence`
- Wrapper `scripts/gradle.sh` expects toolchains under `/workspace/toolchains`; set `ANDROID_HOME`/`JAVA_HOME` if elsewhere. One Gradle process per checkout.

## Layout
- `app/src/main/java/org/suite/security/`: `FirewallService.kt` (VpnService, tunnel lifecycle), `FirewallRules.kt` (rule model/persistence), `Packet.kt` (bounded parser), `MainActivity.kt` (Compose UI), `ApkAnalyzer.kt`/`ArchiveLimits.kt`/`SecurityChecks.kt` (local APK inspection)
- Tests: `app/src/test` (JVM), `app/src/androidTest` (emulator: `DeviceSmokeTest`, `FirewallIntegrationTest`, `MvpFlowTest`)
- `scripts/` build/validation/fixtures; `docs/` validation + advisories; `docs/evidence/` recorded results (read-only history)
- Security/validation context: `SECURITY_REVIEW.md`, `TESTING.md`, `FIREWALL_VALIDATION.md`. Read the relevant one before touching VPN/routing code.

## Principles
1. **Think before coding:** state assumptions, ask when unclear, mention simpler alternatives first.
2. **Simplicity first:** only what the task needs; no speculative features or abstractions.
3. **Surgical changes:** touch only what is needed; match style; clean only your own leftovers.
4. **Goal-driven:** checkable goal (failing test first), loop until it passes.

## Rules (security-critical project)
- Never add the `INTERNET` permission, analytics, ads, accounts, remote servers, or any forwarding socket to the firewall. Packets stay a sink unless the user explicitly changes the architecture.
- Fail closed: any error path must keep or restore blocking, never silently release routing. A replacement tunnel is established **before** the old one is closed.
- Treat packet bytes, APK files and stored policy as untrusted: keep size/bounds limits; no unbounded reads.
- Do not claim blocking works from JVM tests; routing claims need emulator evidence (`device-check.sh`). Never run disruptive tests on a personal device or a VPN the user depends on.
- Dependencies are locked (`gradle.lockfile`) and SHA-256 verified. Never use `--write-locks` / `--write-verification-metadata` to silence a failure; ask first, regenerate only for an intended dependency change.
- Never edit `docs/evidence/**` or generated files; add new evidence, don't rewrite old.
- `:probe` is test-only; never make `:app` depend on it.
- Never add a dependency without asking. Every behavior change needs a test; one test first, full `check.sh` before finishing.
- Android Lockdown/Always-on are user/system settings; do not write UI text that overclaims protection (match the readme's "Protection modes" table).

## Known pitfalls
- Always-on auto-restart after SIGKILL was **not** observed on the emulator in beta2; do not assume it works.
- Another VPN cannot run simultaneously; APIs for Lockdown detection exist only from Android 10.
- VPN app lists are UID-based: shared UIDs, work profiles and OEM behavior need device acceptance.
- Before first unlock, credential-encrypted rules are unavailable; startup with empty/missing rules enters capture-all safety mode.

## Definition of done
1. `./scripts/check.sh` green; release gates when touching build/deps/manifest.
2. Security-relevant change: `code-reviewer` run, and emulator evidence if routing behavior changed.
3. Docs (`readme.md` protection modes, `SECURITY_REVIEW.md`) updated if guarantees change.
4. `PROGRESS.md` updated for multi-session work.
