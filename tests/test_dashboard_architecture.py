from __future__ import annotations

import unittest
from pathlib import Path


class DashboardArchitectureTests(unittest.TestCase):
    def test_single_runtime_entrypoint_and_static_enhancements(self) -> None:
        root = Path(__file__).resolve().parents[1]
        server = (root / "dashboard" / "server.py").read_text(encoding="utf-8")
        dockerfile = (root / "Dockerfile.dashboard").read_text(encoding="utf-8")
        security_js = (root / "dashboard" / "static" / "security.js").read_text(
            encoding="utf-8"
        )
        observability_js = (
            root / "dashboard" / "static" / "observability.js"
        ).read_text(encoding="utf-8")
        campaigns_js = (
            root / "dashboard" / "static" / "campaigns.js"
        ).read_text(encoding="utf-8")
        self.assertIn("class DashboardApplication(TransactionalProductionDashboard)", server)
        self.assertNotIn(".replace(", server)
        self.assertIn("partition(\"</head>\")", server)
        self.assertIn("add_static", server)
        self.assertIn("register_api_routes(app, dashboard)", server)
        self.assertIn("/static/campaigns.js", server)
        self.assertIn('CMD ["python", "-m", "dashboard.server"]', dockerfile)
        self.assertIn("X-Hotpot-CSRF", security_js)
        self.assertIn("/api/notifications/test", observability_js)
        self.assertIn("Investigation timeline", observability_js)
        self.assertIn("/api/campaign/", campaigns_js)
        self.assertIn("data-campaign-actor", campaigns_js)
        self.assertIn("Observational only", campaigns_js)

    def test_old_entrypoints_are_compatibility_shims_not_layers(self) -> None:
        root = Path(__file__).resolve().parents[1] / "dashboard"
        secure = (root / "secure_production.py").read_text(encoding="utf-8")
        observability = (root / "observability_production.py").read_text(
            encoding="utf-8"
        )
        routed = (root / "routed_production.py").read_text(encoding="utf-8")
        for text in (secure, observability, routed):
            self.assertIn("from .server import", text)
            self.assertNotIn("class ", text)

    def test_legacy_dashboard_module_remains_import_compatible(self) -> None:
        root = Path(__file__).resolve().parents[1] / "dashboard"
        legacy = (root / "app.py").read_text(encoding="utf-8")
        self.assertIn("class Dashboard:", legacy)
        self.assertIn("def aggregate", legacy)


if __name__ == "__main__":
    unittest.main()
