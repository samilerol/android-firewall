---
name: verification-before-completion
description: Use before claiming any task is done, fixed, passing or ready. Requires fresh evidence (command output) instead of assumptions.
---

# Verify before you say "done"

Never report success from memory or from reading the code. Evidence first.

1. State what "done" means for this task (expected behavior, in one line).
2. Run the check that proves it, fresh, now: the specific test, the build, the lint/typecheck, or the actual command/endpoint. Prefer the `test-runner` subagent for noisy suites.
3. Read the real output. A green exit code with zero tests run is not a pass.
4. For bug fixes: confirm the regression test fails without the fix and passes with it.
5. Check the diff for unrelated changes, debug leftovers, and unintended file edits.
6. Report with evidence: command run + result in one line each. If something could not be verified, say exactly what and why.

Forbidden phrasing without evidence: "should work", "looks correct", "that fixes it".
