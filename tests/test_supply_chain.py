from __future__ import annotations

import re
import unittest
from pathlib import Path


PYTHON_BASE_RE = re.compile(
    r"^FROM python:\d+\.\d+\.\d+-alpine\d+\.\d+@sha256:[0-9a-f]{64}$",
    re.MULTILINE,
)
ATTEST_BUILD_PROVENANCE_RE = re.compile(
    r"^\s*uses:\s*actions/attest-build-provenance@v(\d+)\s*$",
    re.MULTILINE,
)


class SupplyChainTests(unittest.TestCase):
    def test_runtime_images_pin_python_patch_alpine_and_manifest_digest(self) -> None:
        root = Path(__file__).resolve().parents[1]
        bases: list[str] = []
        for name in ("Dockerfile", "Dockerfile.dashboard"):
            text = (root / name).read_text(encoding="utf-8")
            match = PYTHON_BASE_RE.search(text)
            self.assertIsNotNone(
                match,
                f"{name} must pin an exact Python patch, Alpine release, and sha256 digest",
            )
            assert match is not None
            bases.append(match.group(0))
            self.assertIn("HEALTHCHECK", text)
            self.assertIn("org.opencontainers.image.source", text)

        self.assertEqual(
            bases[0],
            bases[1],
            "core and dashboard images must use the same pinned Python base",
        )

    def test_dashboard_dependency_is_exactly_pinned(self) -> None:
        root = Path(__file__).resolve().parents[1]
        requirements = (root / "requirements-dashboard.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("geoip2==5.3.0", requirements)
        self.assertNotIn("geoip2>=", requirements)

    def test_dependabot_monitors_pip_docker_and_actions(self) -> None:
        root = Path(__file__).resolve().parents[1]
        config = (root / ".github" / "dependabot.yml").read_text(encoding="utf-8")
        for ecosystem in ("pip", "docker", "github-actions"):
            self.assertIn(f"package-ecosystem: {ecosystem}", config)
        self.assertIn("timezone: America/Costa_Rica", config)
        self.assertIn("dependency-name: python", config)
        self.assertIn("version-update:semver-minor", config)
        self.assertIn("version-update:semver-major", config)

    def test_ci_avoids_duplicate_pr_runs_and_gates_releases(self) -> None:
        root = Path(__file__).resolve().parents[1]
        ci = (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        release = (root / ".github" / "workflows" / "docker-publish.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("push:\n    branches:\n      - main", ci)
        self.assertIn("pull_request:", ci)
        self.assertNotIn('branches:\n      - "**"', ci)
        self.assertIn("workflow_call:", ci)
        self.assertIn("name: Shared Python lint", ci)
        self.assertRegex(
            ci,
            r"uses: dwightmulcahy/repo-template/\.github/workflows/"
            r"reusable-python-ci\.yml@[0-9a-f]{40}",
        )
        self.assertIn("python -m ruff check --select F hotpot dashboard tests .github/scripts", ci)
        self.assertIn("python -m pyflakes hotpot dashboard tests .github/scripts", ci)
        self.assertGreaterEqual(ci.count("-m unittest discover -s tests -v"), 2)
        self.assertIn("uses: ./.github/workflows/ci.yml", release)
        self.assertRegex(release, r"(?ms)^  ci:\n.*?^    needs: validate-tag$")
        self.assertRegex(release, r"(?ms)^  publish:\n.*?^    needs: \[ci, validate-tag\]$")
        self.assertRegex(release, r"(?ms)^  release:\n.*?^    needs: \[publish, publish-dashboard\]$")

    def test_release_publishes_semver_aliases_and_grouped_github_release(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github" / "workflows" / "docker-publish.yml").read_text(
            encoding="utf-8"
        )
        shared = "dwightmulcahy/repo-template/.github/workflows/reusable-docker-publish.yml@"
        self.assertEqual(workflow.count(shared), 2)
        self.assertIn("image: dwightmulcahy/hotpot", workflow)
        self.assertIn("image: dwightmulcahy/hotpot-dashboard", workflow)
        self.assertIn("dockerfile: Dockerfile.dashboard", workflow)
        self.assertIn("needs: [publish, publish-dashboard]", workflow)
        self.assertIn("Generate conventional release notes", workflow)
        self.assertIn('gh release create "${GITHUB_REF_NAME}"', workflow)
        self.assertIn("--notes-file RELEASE_NOTES.md", workflow)

    def test_release_images_publish_sbom_provenance_and_github_attestations(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github" / "workflows" / "docker-publish.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("reusable-docker-publish.yml@", workflow)
        for alias in ("publish_major", "publish_minor", "publish_latest"):
            self.assertEqual(workflow.count(f"      {alias}: "), 2)
            self.assertIn(f"needs.validate-tag.outputs.{alias}", workflow)
        self.assertNotIn("is_latest: true", workflow)
        self.assertEqual(workflow.count("HOTPOT_VERSION="), 2)
        self.assertEqual(workflow.count("HOTPOT_GIT_SHA="), 2)


if __name__ == "__main__":
    unittest.main()
