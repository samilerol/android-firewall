# Architecture (read only when touching structure or VPN logic)

## Overview
Compose UI (`MainActivity`) edits a *draft* rule set. "Apply" persists rules (`FirewallRules`) and tells `FirewallService` (a non-exported `VpnService`, `BIND_VPN_SERVICE`) to build a TUN whose application list is the selected UIDs (or all apps in explicit/safety mode). A reader loop reads packets from the TUN, parses bounded metadata (`Packet`) and **drops everything**. No forwarding sockets exist.

## Data flow
UI draft -> Apply -> persist rules (app-private prefs, no backup) -> `Builder.establish()` new TUN -> release old TUN -> reader loop (drop) -> status reported to UI ("Android routing confirmed" only after verification).

## Modes
Selected apps | Block all apps (explicit, confirmed) | Safety mode (boot with empty/missing rules -> capture all). See readme "Protection modes".

## Local APK inspection
`ApkAnalyzer` + `ArchiveLimits` + `SecurityChecks`: 100 MiB stream cap, archive index bounded before `ZipFile`; no execution, no independent signature verification.

## Test layers
JVM (`app/src/test`) proves parsing/rules/limits only. Routing proof = emulator `device-check.sh` with local endpoints (TCP 18080, UDP 18081, DNS 1053, DoT 1853, DoH 18443) and the separate-UID `:probe` fixture.

## Non-obvious constraints
- Process death / reboot can release routing; only Always-on + Lockdown (user-enabled) make it fail-closed.
- Updates must keep the old session until the new one is established; on failure report rules as "unconfirmed".
- Dependency locking + SHA-256 verification are enforced.
