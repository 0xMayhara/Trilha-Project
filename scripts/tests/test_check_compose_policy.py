"""Compose and Dockerfile policy (SPEC-0001 SEC-16, SEC-17). The gate must fail closed."""

import unittest

from support import load_script

policy = load_script("check_compose_policy")

DIGEST = "@sha256:" + "0" * 64


def hardened(**overrides):
    service = {
        "image": f"docker.io/library/redis:8-alpine{DIGEST}",
        "user": "redis",
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
    }
    service.update(overrides)
    return service


class CheckServicesTests(unittest.TestCase):
    def test_hardened_service_passes(self):
        self.assertEqual(policy.check_services({"services": {"redis": hardened()}}, dev=False), [])

    def test_config_without_services_fails_closed_cwe_636(self):
        for config in ({}, {"services": {}}, {"services": None}):
            with self.subTest(config=config):
                self.assertEqual(
                    policy.check_services(config, dev=False), ["compose config has no services"]
                )

    def test_missing_cap_drop_is_rejected(self):
        errors = policy.check_services({"services": {"redis": hardened(cap_drop=[])}}, dev=False)
        self.assertIn("redis: cap_drop must include ALL", errors)

    def test_missing_no_new_privileges_is_rejected(self):
        errors = policy.check_services(
            {"services": {"redis": hardened(security_opt=[])}}, dev=False
        )
        self.assertIn("redis: security_opt must include no-new-privileges:true", errors)

    def test_privileged_host_network_and_runtime_socket_are_rejected(self):
        service = hardened(
            privileged=True,
            network_mode="host",
            volumes=[{"source": "/var/run/docker.sock"}],
        )
        errors = policy.check_services({"services": {"redis": service}}, dev=False)
        self.assertIn("redis: privileged mode is forbidden", errors)
        self.assertIn("redis: host networking is forbidden", errors)
        self.assertIn("redis: mounting the container runtime socket is forbidden", errors)

    def test_unpinned_image_is_rejected_cwe_494(self):
        service = hardened(image="docker.io/library/redis:8-alpine")
        errors = policy.check_services({"services": {"redis": service}}, dev=False)
        self.assertIn("redis: image must be pinned by digest", errors)

    def test_root_users_are_rejected_cwe_250(self):
        for user in ("", "root", "0", "0:0", "root:root"):
            with self.subTest(user=user):
                errors = policy.check_services(
                    {"services": {"redis": hardened(user=user)}}, dev=False
                )
                self.assertIn("redis: must run as a non-root user", errors)

    def test_application_services_need_read_only_root_filesystem(self):
        service = hardened(build={"context": "backend"})
        errors = policy.check_services({"services": {"backend": service}}, dev=False)
        self.assertIn("backend: root filesystem must be read-only", errors)

    def test_only_proxy_publishes_ports(self):
        port = {"published": "5432", "host_ip": "127.0.0.1"}
        proxy = hardened(ports=[port], read_only=True)
        config = {"services": {"db": hardened(ports=[port]), "proxy": proxy}}
        self.assertEqual(
            policy.check_services(config, dev=False),
            ["db: only the proxy service may publish ports"],
        )

    def test_dev_ports_must_bind_to_loopback(self):
        exposed = {"published": "5432", "host_ip": "0.0.0.0"}  # noqa: S104 - policy input, not a bind
        config = {"services": {"db": hardened(ports=[exposed])}}
        self.assertEqual(
            policy.check_services(config, dev=True),
            ["db: development ports must bind to 127.0.0.1"],
        )
        config["services"]["db"]["ports"][0]["host_ip"] = "127.0.0.1"
        self.assertEqual(policy.check_services(config, dev=True), [])


class CheckDockerfileTests(unittest.TestCase):
    def test_pinned_multi_stage_with_non_root_final_user_passes(self):
        text = (
            f"FROM python:3.13{DIGEST} AS build\nRUN true\nFROM python:3.13{DIGEST}\nUSER 10001\n"
        )
        self.assertEqual(policy.check_dockerfile("Dockerfile", text), [])

    def test_stage_reference_does_not_need_a_digest(self):
        text = f"FROM node:24{DIGEST} AS deps\nFROM deps AS build\nUSER node\n"
        self.assertEqual(policy.check_dockerfile("Dockerfile", text), [])

    def test_unpinned_base_image_is_rejected_cwe_494(self):
        errors = policy.check_dockerfile("Dockerfile", "FROM python:3.13\nUSER 10001\n")
        self.assertEqual(errors, ["Dockerfile: python:3.13 not pinned by digest"])

    def test_missing_or_root_user_is_rejected_cwe_250(self):
        for text in (
            f"FROM a{DIGEST}\n",
            f"FROM a{DIGEST}\nUSER root\n",
            f"FROM a{DIGEST}\nUSER 0:0\n",
        ):
            with self.subTest(text=text):
                self.assertEqual(
                    policy.check_dockerfile("Dockerfile", text),
                    ["Dockerfile: final stage must set a non-root USER"],
                )

    def test_user_from_an_earlier_stage_does_not_count_cwe_250(self):
        text = f"FROM a{DIGEST} AS build\nUSER 10001\nFROM a{DIGEST}\nRUN true\n"
        self.assertEqual(
            policy.check_dockerfile("Dockerfile", text),
            ["Dockerfile: final stage must set a non-root USER"],
        )

    def test_no_dockerfiles_fails_closed_cwe_636(self):
        self.assertEqual(policy.check_dockerfiles([]), ["no tracked Dockerfiles found"])

    def test_repository_dockerfiles_are_found_at_any_depth(self):
        found = {
            path.relative_to(policy.REPO_ROOT).as_posix() for path in policy.tracked_dockerfiles()
        }
        self.assertTrue({"backend/Dockerfile", "frontend/Dockerfile"} <= found, found)


if __name__ == "__main__":
    unittest.main()
