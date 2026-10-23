"""Forbidden patterns in tracked files (CLAUDE.md §22, SPEC-0001 SEC-08/21/22).

The scanner only reads tracked files under the rule's path prefix, so the patterns quoted
in this test module do not trigger it.
"""

import unittest

from support import load_script

patterns = load_script("check_forbidden_patterns")


class CheckFileTests(unittest.TestCase):
    def assert_rejected(self, path, line, reason_fragment):
        errors = patterns.check_file(path, f"ok = 1\n{line}\n")
        self.assertEqual(len(errors), 1, errors)
        self.assertTrue(errors[0].startswith(f"{path}:2: "), errors)
        self.assertIn(reason_fragment, errors[0])

    def test_backend_python_rules(self):
        cases = [
            ("@csrf_exempt", "CWE-352"),
            ("requests.get(url, verify=False)", "CWE-295"),
            ("subprocess.run(cmd, shell=True)", "CWE-78"),
            ("eval(payload)", "CWE-94"),
            ("exec (payload)", "CWE-94"),
        ]
        for line, reason in cases:
            with self.subTest(line=line):
                self.assert_rejected("backend/apps/core/views.py", line, reason)

    def test_similar_but_safe_backend_code_passes(self):
        text = "value = ast.literal_eval(raw)\nscore = evaluate(item)\nexecutor = make()\n"
        self.assertEqual(patterns.check_file("backend/apps/core/views.py", text), [])

    def test_operational_scripts_never_delete_volumes(self):
        for line in (
            "podman-compose down -v",
            "docker compose down --volumes",
            "podman volume rm trilha_db-data",
            "docker volume prune -f",
            "psql -c 'DROP DATABASE trilha'",
        ):
            with self.subTest(line=line):
                self.assert_rejected("deploy/postgres/backup.sh", line, "SEC-18")
        safe = "compose down\nDROP ROLE trilha_app;\n"
        self.assertEqual(patterns.check_file("deploy/postgres/rollback-runtime-role.sh", safe), [])

    def test_backend_rules_do_not_apply_outside_backend(self):
        self.assertEqual(patterns.check_file("frontend/src/lib/x.ts", "eval(payload)\n"), [])

    def test_pull_request_target_is_rejected(self):
        self.assert_rejected(
            ".github/workflows/ci.yml", "  pull_request_target:", "pull_request_target"
        )

    def test_secret_like_next_public_variables_are_rejected(self):
        for name in ("NEXT_PUBLIC_API_KEY", "NEXT_PUBLIC_SECRET", "NEXT_PUBLIC_AUTH_TOKEN"):
            with self.subTest(name=name):
                self.assert_rejected("frontend/.env.example", f"{name}=x", "NEXT_PUBLIC_")

    def test_non_secret_next_public_variable_passes(self):
        self.assertEqual(
            patterns.check_file("frontend/.env.example", "NEXT_PUBLIC_APP_NAME=x\n"), []
        )

    def test_dangerously_set_inner_html_is_rejected_cwe_79(self):
        line = "<div dangerouslySetInnerHTML={{ __html: text }} />"
        self.assert_rejected("frontend/src/app/page.tsx", line, "CWE-79")

    def test_browser_storage_is_forbidden_in_frontend(self):
        for line in (
            'localStorage.setItem("session", id)',
            "const s = window.sessionStorage;",
            'indexedDB.open("auth")',
        ):
            with self.subTest(line=line):
                self.assert_rejected("frontend/src/lib/auth.ts", line, "CWE-922")


class CheckTrackedTests(unittest.TestCase):
    def test_no_tracked_files_fails_closed_cwe_636(self):
        self.assertEqual(patterns.check_tracked([]), ["no tracked files to scan"])

    def test_repository_is_clean(self):
        self.assertEqual(patterns.check_tracked(patterns.tracked_files()), [])


if __name__ == "__main__":
    unittest.main()
