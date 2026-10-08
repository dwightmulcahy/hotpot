from __future__ import annotations

import re
import unittest
from pathlib import Path


PYTHON_BASE_RE = re.compile(
    r"^FROM python:\d+\.\d+\.\d+-alpine\d+\.\d+@sha256:[0-9a-f]{64}$",
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

    def test_release_images_publish_sbom_provenance_and_github_attestations(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github" / "workflows" / "docker-publish.yml").read_text(
            encoding="utf-8"
        )
        self.assertGreaterEqual(workflow.count("sbom: true"), 2)
        self.assertGreaterEqual(workflow.count("provenance: mode=max"), 2)
        self.assertEqual(workflow.count("actions/attest-build-provenance@v3"), 2)
        self.assertIn("id-token: write", workflow)
        self.assertIn("attestations: write", workflow)
        self.assertIn("id: hotpot-build", workflow)
        self.assertIn("id: dashboard-build", workflow)
        self.assertIn("steps.hotpot-build.outputs.digest", workflow)
        self.assertIn("steps.dashboard-build.outputs.digest", workflow)


if __name__ == "__main__":
    unittest.main()
