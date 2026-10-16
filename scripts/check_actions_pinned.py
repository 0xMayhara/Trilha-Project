#!/usr/bin/env python3
"""Every GitHub Action must be pinned to a full commit SHA (SPEC-0001 SEC-22, CWE-494)."""

import re
import sys
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"
USES = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)")
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


def main() -> int:
    errors = []
    for workflow in sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")]):
        for number, line in enumerate(workflow.read_text().splitlines(), start=1):
            match = USES.match(line)
            if not match:
                continue
            ref = match.group(1)
            if ref.startswith("./") or (ref.startswith("docker://") and "@sha256:" in ref):
                continue
            if not PINNED.match(ref):
                errors.append(f"{workflow.name}:{number}: {ref} is not pinned to a commit SHA")
    for error in errors:
        print(f"policy violation: {error}", file=sys.stderr)
    if not errors:
        print("actions pinning: ok")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
