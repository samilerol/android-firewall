---
name: debug-systematic
description: Use when diagnosing a bug, failing test, crash or unexpected behavior. Enforces reproduce, isolate, hypothesize, verify before changing code.
---

# Systematic debugging

1. **Reproduce** with the smallest command/test. If you cannot reproduce, say so and ask for details; do not guess-fix.
2. **Read the actual error** fully (message, stack top frames). Do not skim.
3. **Isolate**: bisect by input, by recent commits (`git log -p -n 5 -- <path>`), or by disabling components.
4. **Hypothesize** 1-3 causes, ranked. State the evidence that would confirm each.
5. **Verify** the top hypothesis with a log, assertion or test, not by editing production code.
6. **Fix** the root cause, smallest change. No symptom patches, no try/catch swallowing.
7. **Lock in** with a regression test that failed before the fix.
8. Report: root cause (1 line), fix (1 line), test added.

Stop and ask if after 3 hypotheses nothing is confirmed.
