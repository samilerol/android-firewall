# Stored-policy corruption follow-up

This follow-up does not supersede the open production gates in
[FUNCTIONAL_VALIDATION.md](FUNCTIONAL_VALIDATION.md).

A present unknown mode previously fell back to SELECTED_APPS, and mixed-type
selection sets silently dropped non-string entries. Corrupt app-private state
could consequently narrow the intended capture set. This is not evidence of a
remote attacker being able to write app-private preferences.

Loading now distinguishes the absent legacy mode from an invalid present mode.
Invalid fields produce empty selected rules, which CapturePlan resolves to all-app
quarantine. No stored entries are partially trusted. A valid legacy set and both
valid explicit modes retain their behavior. Raw preferences are not rewritten by
loading; an explicit successful rule save selects the replacement policy.

The five new JVM regressions ran against the old decoding behavior: three failed,
two passed. The before log is retained. Final host execution passes: debug/release builds, 34 JVM tests per variant
(zero failures/errors/skips), app debug/release lint, probe build/lint and device-test
APK compilation. Lint warnings remain visible in the retained log. Shell/diff
checks pass. Logs and APK hashes are in `evidence/stored-policy/`. Existing API30/API35 device evidence predates this patch;
no new emulator, physical-device or restart-recovery success is claimed here.

The automatic-restart timeout remains unresolved. Selective forwarding under
Lockdown and IP/port/domain filtering remain unimplemented. Physical/OEM,
before-unlock, cellular/NAT64, touch and sustained battery acceptance remain open.
The project must not be marked production-ready on this evidence.
