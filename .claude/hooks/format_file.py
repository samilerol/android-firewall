#!/usr/bin/env python3
"""PostToolUse hook: auto-format the edited file with the project's formatter, if one exists.
Silent and non-blocking: any failure or missing tool is ignored. Saves tokens by avoiding
formatting-only follow-up edits."""
import json
import os
import shutil
import subprocess
import sys

try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)

path = (data.get("tool_input") or {}).get("file_path", "") or ""
if not path or not os.path.isfile(path):
    sys.exit(0)

root = os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd())
ext = os.path.splitext(path)[1].lower()


def run(cmd):
    try:
        subprocess.run(cmd, cwd=root, timeout=20, check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


if ext in {".js", ".jsx", ".ts", ".tsx", ".json", ".css", ".scss", ".md", ".html", ".yaml", ".yml"}:
    prettier = os.path.join(root, "node_modules", ".bin", "prettier")
    if os.path.exists(prettier):
        run([prettier, "--write", path])
elif ext == ".py":
    if shutil.which("ruff"):
        run(["ruff", "format", path])
    elif shutil.which("black"):
        run(["black", "-q", path])
elif ext == ".go":
    if shutil.which("gofmt"):
        run(["gofmt", "-w", path])
elif ext == ".rs":
    if shutil.which("rustfmt"):
        run(["rustfmt", path])

sys.exit(0)
