#!/usr/bin/env python3
"""Enforce container hardening rules (SPEC-0001 SEC-16, SEC-17).

Usage:
    docker compose --env-file .env.example config --format json \
        | python3 scripts/check_compose_policy.py [--dev]

--dev accepts the compose.dev.yaml override, whose extra ports must bind to 127.0.0.1.
Fails closed: input without services, or a repository without Dockerfiles, is a violation.
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PUBLISHING_SERVICE = "proxy"
READ_ONLY_SERVICES = {"proxy", "frontend", "backend", "worker", "migrate"}
# Images whose default user is already unprivileged.
NON_ROOT_IMAGES = ("docker.io/nginxinc/nginx-unprivileged:",)
DOCKERFILE_NAMES = {"Dockerfile", "Containerfile"}


def is_root_user(user: str) -> bool:
    return user.split(":", 1)[0] in {"", "root", "0"}


def check_services(config: dict, dev: bool) -> list[str]:
    services = config.get("services")
    if not services:
        return ["compose config has no services"]
    errors: list[str] = []
    for name, service in sorted(services.items()):
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
            if is_root_user(str(service.get("user", ""))) and not image.startswith(NON_ROOT_IMAGES):
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


def check_dockerfile(name: str, text: str) -> list[str]:
    errors: list[str] = []
    stages: set[str] = set()
    final_stage_users: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        match = re.match(r"FROM\s+(\S+)(?:\s+AS\s+(\S+))?", line, re.IGNORECASE)
        if match:
            image, stage = match.groups()
            if image not in stages and "@sha256:" not in image:
                errors.append(f"{name}: {image} not pinned by digest")
            if stage:
                stages.add(stage)
            # USER does not carry across stages: only the last stage's USER applies at runtime.
            final_stage_users = []
        elif line.upper().startswith("USER "):
            final_stage_users.append(line.split(maxsplit=1)[1])
    if not final_stage_users or is_root_user(final_stage_users[-1]):
        errors.append(f"{name}: final stage must set a non-root USER")
    return errors


def tracked_dockerfiles() -> list[Path]:
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout.splitlines()
    return [REPO_ROOT / path for path in tracked if Path(path).name in DOCKERFILE_NAMES]


def check_dockerfiles(dockerfiles: list[Path]) -> list[str]:
    if not dockerfiles:
        return ["no tracked Dockerfiles found"]
    errors: list[str] = []
    for dockerfile in sorted(dockerfiles):
        name = dockerfile.relative_to(REPO_ROOT).as_posix()
        errors.extend(check_dockerfile(name, dockerfile.read_text()))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dev", action="store_true", help="allow loopback ports from the override")
    args = parser.parse_args()

    errors = check_services(json.load(sys.stdin), args.dev)
    errors += check_dockerfiles(tracked_dockerfiles())
    for error in errors:
        print(f"policy violation: {error}", file=sys.stderr)
    if not errors:
        print("compose policy: ok")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
