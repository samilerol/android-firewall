# Android Firewall — agent rules

Goal: a small, reliable Android local-VPN firewall (Kotlin, Compose). Keep changes minimal and focused.

## Working rules
- Do ONE task per session, then run the checks, write a one-paragraph summary and stop.
- For any new feature: write a plan of at most 10 lines first and wait for approval.
- At most 2 attempts on a failing step; then stop and report what you tried.
- Do NOT: set up emulators, write device/instrumentation tests, run device-check or lockdown scripts,
  commit logs or "evidence" files, or write reports/reviews unless explicitly asked.
- Do NOT touch dependency locking, license inventory or security review docs unless asked.
- `docs/` and the root `*_VALIDATION.md`, `SECURITY_REVIEW.md`, `TESTING.md` are historical. Do not read them unless the task names them.
- Never read whole large files or whole directories; use grep to find the relevant lines first.
- Device testing is done by the owner on a real phone. Ask for a short result description instead.

## Principles
1. Think before coding: state assumptions, ask if unclear, mention simpler options first.
2. Simplicity first: only what the task needs; no extra features or abstractions.
3. Surgical changes: touch only what is needed; match existing style; clean only your own leftovers.
4. Goal-driven: set a checkable goal (e.g. failing test first) and loop until it passes.

## Build and check (JVM only, no device)
- Once per environment: `scripts/bootstrap.sh` (installs JDK/SDK; needs dl.google.com, maven and gradle hosts).
- Every change: `scripts/check.sh` (assembleDebug + unit tests + lint). CI runs the same on GitHub Actions.

## Code layout
- `app/src/main/java/org/suite/security/`: `FirewallService` (VpnService), `Packet` (header parser),
  `FirewallRules` (rules + CapturePlan), `MainActivity` (Compose UI), `ApkAnalyzer`.
- `probe/` is a test-only helper app. Ignore it unless asked.

## Design invariants (do not break)
- Fail closed: on any error or missing/invalid rules, capture traffic rather than letting it bypass.
- Metadata only: never store payloads, never inspect TLS.
- The release APK must not request the INTERNET permission unless the task explicitly adds a feature that needs it.
