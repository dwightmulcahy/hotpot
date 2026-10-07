from __future__ import annotations

import unittest
from pathlib import Path


class DashboardArchitectureTests(unittest.TestCase):
    def test_single_runtime_entrypoint_and_static_enhancements(self) -> None:
        root = Path(__file__).resolve().parents[1]
        app = (root / "dashboard" / "app.py").read_text(encoding="utf-8")
        dockerfile = (root / "Dockerfile.dashboard").read_text(encoding="utf-8")
        security_js = (root / "dashboard" / "static" / "security.js").read_text(
            encoding="utf-8"
        )
        observability_js = (
            root / "dashboard" / "static" / "observability.js"
        ).read_text(encoding="utf-8")
        self.assertIn("class DashboardApplication(ProductionDashboard)", app)
        self.assertNotIn(".replace(", app)
        self.assertIn("partition(\"</head>\")", app)
        self.assertIn("add_static", app)
        self.assertIn('CMD ["python", "-m", "dashboard.app"]', dockerfile)
        self.assertIn("X-Hotpot-CSRF", security_js)
        self.assertIn("/api/notifications/test", observability_js)
        self.assertIn("Investigation timeline", observability_js)

    def test_old_entrypoints_are_compatibility_shims_not_layers(self) -> None:
        root = Path(__file__).resolve().parents[1] / "dashboard"
        secure = (root / "secure_production.py").read_text(encoding="utf-8")
        observability = (root / "observability_production.py").read_text(
            encoding="utf-8"
        )
        routed = (root / "routed_production.py").read_text(encoding="utf-8")
        for text in (secure, observability, routed):
            self.assertIn("from .app import", text)
            self.assertNotIn("class ", text)


if __name__ == "__main__":
    unittest.main()
