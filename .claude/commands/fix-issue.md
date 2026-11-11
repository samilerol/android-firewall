---
description: Fix a bug or GitHub issue with a test-first loop
argument-hint: <issue number or description>
---

Issue: $ARGUMENTS

1. If a number, fetch it with `gh issue view $ARGUMENTS`.
2. Use `explorer` to find the relevant code.
3. Write a failing test that reproduces it; confirm it fails.
4. Make the smallest fix; confirm the test passes via `test-runner`.
5. Run `code-reviewer` on the diff. Summarize in 3 lines.
