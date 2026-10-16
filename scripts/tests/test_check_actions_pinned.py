"""GitHub Actions pinning (SPEC-0001 SEC-22, CWE-494). The gate must fail closed."""

import unittest

from support import load_script

pinning = load_script("check_actions_pinned")

SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"


class CheckWorkflowTests(unittest.TestCase):
    def test_sha_pinned_actions_pass(self):
        text = (
            f"      - uses: actions/checkout@{SHA} # v7.0.1\n"
            f"      - uses: github/codeql-action/init@{SHA}\n"
            f"    uses: org/repo/.github/workflows/reusable.yml@{SHA}\n"
        )
        self.assertEqual(pinning.check_workflow("ci.yml", text), [])

    def test_local_actions_and_digest_pinned_images_pass(self):
        text = (
            "      - uses: ./.github/actions/setup\n"
            "      - uses: docker://alpine@sha256:" + "0" * 64 + "\n"
        )
        self.assertEqual(pinning.check_workflow("ci.yml", text), [])

    def test_tag_branch_and_short_sha_refs_are_rejected_cwe_494(self):
        for ref in ("actions/checkout@v7", "actions/checkout@main", "actions/checkout@3d3c42e"):
            with self.subTest(ref=ref):
                errors = pinning.check_workflow("ci.yml", f"      - uses: {ref}\n")
                self.assertEqual(errors, [f"ci.yml:1: {ref} is not pinned to a commit SHA"])

    def test_quoted_refs_are_checked(self):
        errors = pinning.check_workflow("ci.yml", '      - uses: "actions/checkout@v7"\n')
        self.assertEqual(errors, ["ci.yml:1: actions/checkout@v7 is not pinned to a commit SHA"])

    def test_unpinned_docker_image_is_rejected(self):
        errors = pinning.check_workflow("ci.yml", "      - uses: docker://alpine:3\n")
        self.assertEqual(errors, ["ci.yml:1: docker://alpine:3 is not pinned to a commit SHA"])

    def test_no_workflows_fails_closed_cwe_636(self):
        errors = pinning.check_workflows([])
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith("no workflows found"))

    def test_repository_workflows_are_pinned(self):
        workflows = [*pinning.WORKFLOWS.glob("*.yml"), *pinning.WORKFLOWS.glob("*.yaml")]
        self.assertTrue(workflows)
        self.assertEqual(pinning.check_workflows(workflows), [])


if __name__ == "__main__":
    unittest.main()
