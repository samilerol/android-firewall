@AGENTS.md

# Claude Code specifics

## Token discipline
- Do not read whole files when a range or grep is enough. Search first (Grep/Glob), then Read with offset/limit.
- Never read: `node_modules`, `dist`, `build`, `.next`, `coverage`, lockfiles, minified/generated files, large logs.
- Delegate broad exploration ("where is X used", "how does Y work across the repo") to the `explorer` subagent; it returns a short summary, keeping this context clean.
- Pipe noisy command output through `| tail -n 40` or `| head -n 60`; show only failures for test runs.
- Do not re-read a file you just edited. Do not restate large code blocks in replies; reference `path:line`.
- Final replies: what changed, what was verified, one next step. No recaps of steps.

## Workflow
- Non-trivial task (3+ files or unclear approach): use plan mode or `/plan` first, get approval, then implement.
- Trivial task: just do it.
- Long task: keep `PROGRESS.md` current (done / next / decisions) so a fresh session can resume with `/resume-task`.
- Context getting long or switching topic: `/compact` with focus instructions, or `/clear` and resume from `PROGRESS.md`.

## Skills (load when relevant)
- `test-driven-development` for logic with testable behavior; `debug-systematic` for bugs; `verification-before-completion` before ever saying "done"; `pr-ready` before commit/PR.

## Models
- Default is Sonnet. Use Haiku subagents for search/test-running, Opus only for hard architecture or deep debugging.

## Subagents available
- `explorer` — read-only codebase search/summary (Haiku)
- `test-runner` — runs tests, returns only failures (Haiku)
- `code-reviewer` — reviews a diff for bugs/security/style (Sonnet)
- `architect` — design options and trade-offs, no edits (Opus)
