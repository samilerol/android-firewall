---
description: Review current changes with an isolated reviewer
---

Run the `code-reviewer` subagent on the current git diff and the `test-runner` subagent in parallel.
Merge results into one list: blocking issues first, then minor. Do not fix anything until I confirm which findings to address.
