#!/usr/bin/env python3
"""Reject known-dangerous patterns in tracked files (CLAUDE.md §22, SPEC-0001 SEC-08/21/22).

Fails closed: an empty list of tracked files is a violation.
"""

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SELF = Path(__file__).resolve().relative_to(REPO_ROOT).as_posix()

# (path prefix, file suffixes, pattern, reason)
RULES = [
    ("backend/", (".py",), r"\bcsrf_exempt\b", "csrf_exempt is forbidden (CWE-352)"),
    ("backend/", (".py",), r"verify\s*=\s*False", "TLS verification must stay on (CWE-295)"),
    ("backend/", (".py",), r"shell\s*=\s*True", "shell=True is forbidden (CWE-78)"),
    ("backend/", (".py",), r"\b(eval|exec)\s*\(", "eval/exec is forbidden (CWE-94)"),
    (".github/", (".yml", ".yaml"), r"\bpull_request_target\b", "pull_request_target is forbidden"),
    (
        "",
        (".ts", ".tsx", ".js", ".mjs", ".json", ".yaml", ".yml", ".env", ".example"),
        r"NEXT_PUBLIC_\w*(SECRET|TOKEN|PASSWORD|KEY)\b",
        "NEXT_PUBLIC_ variables are shipped to browsers and must not hold secrets",
    ),
    (
        "frontend/src/",
        (".ts", ".tsx"),
        r"dangerouslySetInnerHTML",
        "dangerouslySetInnerHTML requires a SPEC exception (CWE-79)",
    ),
]


def rules_for(path: str) -> list[tuple[str, str]]:
    return [
        (pattern, reason)
        for prefix, suffixes, pattern, reason in RULES
        if path.startswith(prefix) and path.endswith(suffixes)
    ]


def check_file(path: str, text: str) -> list[str]:
    errors = []
    for pattern, reason in rules_for(path):
        for number, line in enumerate(text.splitlines(), start=1):
            if re.search(pattern, line):
                errors.append(f"{path}:{number}: {reason}")
    return errors


def tracked_files() -> list[str]:
    return subprocess.run(
        ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout.splitlines()


def check_tracked(paths: list[str]) -> list[str]:
    if not paths:
        return ["no tracked files to scan"]
    errors = []
    for path in paths:
        if path == SELF or not rules_for(path):
            continue
        errors.extend(check_file(path, (REPO_ROOT / path).read_text(errors="replace")))
    return errors


def main() -> int:
    errors = check_tracked(tracked_files())
    for error in errors:
        print(f"policy violation: {error}", file=sys.stderr)
    if not errors:
        print("forbidden patterns: ok")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
