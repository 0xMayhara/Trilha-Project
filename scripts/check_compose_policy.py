#!/usr/bin/env python3
"""Enforce container hardening rules (SPEC-0001 SEC-16, SEC-17).

Usage:
    docker compose --env-file .env.example config --format json \
        | python3 scripts/check_compose_policy.py [--dev]

--dev accepts the compose.dev.yaml override, whose extra ports must bind to 127.0.0.1.
"""

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PUBLISHING_SERVICE = "proxy"
READ_ONLY_SERVICES = {"proxy", "frontend", "backend", "worker", "migrate"}
# Images whose default user is already unprivileged.
NON_ROOT_IMAGES = ("docker.io/nginxinc/nginx-unprivileged:",)
ROOT_USERS = {"", "root", "0", "0:0"}


def check_services(config: dict, dev: bool) -> list[str]:
    errors: list[str] = []
    for name, service in sorted(config.get("services", {}).items()):
        if "ALL" not in service.get("cap_drop", []):
            errors.append(f"{name}: cap_drop must include ALL")
        if "no-new-privileges:true" not in service.get("security_opt", []):
            errors.append(f"{name}: security_opt must include no-new-privileges:true")
        if service.get("privileged"):
            errors.append(f"{name}: privileged mode is forbidden")
        if service.get("network_mode") == "host":
            errors.append(f"{name}: host networking is forbidden")
        for volume in service.get("volumes", []):
            if "docker.sock" in str(volume.get("source", "")):
                errors.append(f"{name}: mounting the container runtime socket is forbidden")
        if name in READ_ONLY_SERVICES and not service.get("read_only"):
            errors.append(f"{name}: root filesystem must be read-only")

        image = service.get("image", "")
        if "build" not in service:
            if "@sha256:" not in image:
                errors.append(f"{name}: image must be pinned by digest")
            if str(service.get("user", "")) in ROOT_USERS and not image.startswith(NON_ROOT_IMAGES):
                errors.append(f"{name}: must run as a non-root user")

        for port in service.get("ports", []):
            host_ip = port.get("host_ip", "")
            if name == PUBLISHING_SERVICE:
                continue
            if not dev:
                errors.append(f"{name}: only the {PUBLISHING_SERVICE} service may publish ports")
            elif host_ip != "127.0.0.1":
                errors.append(f"{name}: development ports must bind to 127.0.0.1")
    return errors


def check_dockerfiles() -> list[str]:
    errors: list[str] = []
    for dockerfile in sorted(REPO_ROOT.glob("*/Dockerfile")):
        lines = [line.strip() for line in dockerfile.read_text().splitlines()]
        stages = set()
        for line in lines:
            match = re.match(r"FROM\s+(\S+)(?:\s+AS\s+(\S+))?", line, re.IGNORECASE)
            if not match:
                continue
            image, stage = match.groups()
            if image not in stages and "@sha256:" not in image:
                errors.append(f"{dockerfile.relative_to(REPO_ROOT)}: {image} not pinned by digest")
            if stage:
                stages.add(stage)
        users = [line.split(maxsplit=1)[1] for line in lines if line.upper().startswith("USER ")]
        if not users or users[-1] in ROOT_USERS:
            errors.append(f"{dockerfile.relative_to(REPO_ROOT)}: final stage must set a non-root USER")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dev", action="store_true", help="allow loopback ports from the override")
    args = parser.parse_args()

    errors = check_services(json.load(sys.stdin), args.dev) + check_dockerfiles()
    for error in errors:
        print(f"policy violation: {error}", file=sys.stderr)
    if not errors:
        print("compose policy: ok")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
