#!/usr/bin/env python3
"""PreToolUse hook: block edits to secrets, lockfiles, build output and .git.
Exit code 2 blocks the tool call and shows stderr to Claude."""
import json
import re
import sys

try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)

path = (data.get("tool_input") or {}).get("file_path", "") or ""
p = path.replace("\\", "/")

BLOCKED = [
    (r"(^|/)\.env(\.|$)", "environment/secret file"),
    (r"(^|/)secrets?/", "secrets directory"),
    (r"(^|/)\.git/", ".git internals"),
    (r"(^|/)node_modules/", "dependency directory"),
    (r"(^|/)(dist|build|\.next|coverage|\.gradle|\.kotlin)/", "build output"),
    (r"(^|/)gradle\.lockfile$", "Gradle dependency lock (regenerate only for an intended dependency change, with user approval)"),
    (r"(^|/)gradle/verification-metadata\.xml$", "dependency SHA-256 verification metadata (needs user approval)"),
    (r"(^|/)docs/evidence/", "recorded validation evidence (add new, never rewrite)"),
    (r"\.apk$", "binary APK"),
    (r"(^|/)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|poetry\.lock|Cargo\.lock|go\.sum)$", "lockfile (use the package manager)"),
]

for pattern, why in BLOCKED:
    if re.search(pattern, p):
        print(f"Blocked: {path} is a {why}. Edit the source or use the proper tool instead; ask the user if this is intentional.", file=sys.stderr)
        sys.exit(2)

sys.exit(0)
