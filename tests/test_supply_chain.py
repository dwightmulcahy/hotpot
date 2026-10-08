from __future__ import annotations

import unittest
from pathlib import Path


class SupplyChainTests(unittest.TestCase):
    def test_runtime_images_pin_python_patch_alpine_and_manifest_digest(self) -> None:
        root = Path(__file__).resolve().parents[1]
        for name in ("Dockerfile", "Dockerfile.dashboard"):
            text = (root / name).read_text(encoding="utf-8")
            self.assertIn(
                "FROM python:3.12.15-alpine3.24@sha256:7a63cb93468d7ce5f24b1332a8f7a27f444b3221b0a3d6b5573036b78d937c78",
                text,
            )
            self.assertIn("HEALTHCHECK", text)
            self.assertIn("org.opencontainers.image.source", text)

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


if __name__ == "__main__":
    unittest.main()
