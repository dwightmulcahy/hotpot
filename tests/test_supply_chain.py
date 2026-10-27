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
        self.assertIn("name: Ruff and Pyflakes", ci)
        self.assertIn("python -m ruff check --select F hotpot dashboard tests .github/scripts", ci)
        self.assertIn("python -m pyflakes hotpot dashboard tests .github/scripts", ci)
        self.assertGreaterEqual(ci.count("-m unittest discover -s tests -v"), 2)
        self.assertIn("uses: ./.github/workflows/ci.yml", release)
        self.assertRegex(release, r"(?ms)^  ci:\n.*?^    needs: validate-tag$")
        self.assertRegex(release, r"(?ms)^  publish:\n.*?^    needs: ci$")
        self.assertRegex(release, r"(?ms)^  release:\n.*?^    needs: publish$")

    def test_release_publishes_semver_aliases_and_grouped_github_release(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github" / "workflows" / "docker-publish.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn('tags:\n      - "v*.*.*"', workflow)
        self.assertIn("^v[0-9]+\\.[0-9]+\\.[0-9]+$", workflow)
        for docker_tag in (
            "type=semver,pattern={{version}}",
            "type=semver,pattern={{major}}.{{minor}}",
            "type=semver,pattern={{major}}",
            "type=raw,value=latest",
        ):
            self.assertEqual(
                sum(
                    1
                    for line in workflow.splitlines()
                    if line.strip() == docker_tag
                ),
                2,
                f"both published images must receive Docker tag alias {docker_tag}",
            )
        self.assertIn("push: true", workflow)
        self.assertIn("python scripts/standard_release_notes.py", workflow)
        self.assertIn("Generate release notes from Conventional Commits", workflow)
        self.assertIn('gh release create "${GITHUB_REF_NAME}"', workflow)
        self.assertIn("--notes-file RELEASE_NOTES.md", workflow)

        release_script = (
            root / "scripts" / "standard_release_notes.py"
        ).read_text(encoding="utf-8")
        for group in (
            '"feat"',
            '"fix"',
            '"perf"',
            '"security"',
            '"refactor"',
            '"docs"',
            '"test"',
            '"build"',
            '"ci"',
            '"chore"',
        ):
            self.assertIn(group, release_script)

    def test_release_images_publish_sbom_provenance_and_github_attestations(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github" / "workflows" / "docker-publish.yml").read_text(
            encoding="utf-8"
        )
        self.assertGreaterEqual(workflow.count("sbom: true"), 2)
        self.assertGreaterEqual(workflow.count("provenance: mode=max"), 2)
        attest_majors = [int(value) for value in ATTEST_BUILD_PROVENANCE_RE.findall(workflow)]
        self.assertEqual(len(attest_majors), 2)
        self.assertTrue(
            all(major >= 3 for major in attest_majors),
            "attest-build-provenance must use major version 3 or newer",
        )
        self.assertIn("id-token: write", workflow)
        self.assertIn("attestations: write", workflow)
        self.assertIn("id: hotpot-build", workflow)
        self.assertIn("id: dashboard-build", workflow)
        self.assertIn("steps.hotpot-build.outputs.digest", workflow)
        self.assertIn("steps.dashboard-build.outputs.digest", workflow)


if __name__ == "__main__":
    unittest.main()
