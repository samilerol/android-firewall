---
name: pr-ready
description: Use before committing or opening a PR to run the final quality gate and write the commit/PR text.
---

# PR readiness gate

1. `git status` / `git diff --stat`: remove unrelated or accidental changes (debug prints, formatting-only churn, stray files).
2. Run lint + typecheck + tests (use the `test-runner` subagent; failures only).
3. Run the `code-reviewer` subagent; resolve high-severity findings.
4. Confirm: no secrets, no new dependency without approval, docs/`PROGRESS.md` updated if behavior changed.
5. Write the commit message: imperative subject under 72 chars, body explains *why*. PR body: summary, how tested, risks.

Do not push or open the PR unless asked.
