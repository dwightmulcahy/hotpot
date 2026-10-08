from __future__ import annotations

import unittest
from pathlib import Path


class PolicyDeploymentTests(unittest.TestCase):
    def test_dashboard_example_documents_policy_reconciliation(self) -> None:
        root = Path(__file__).resolve().parents[1]
        env = (root / "dashboard.env.example").read_text(encoding="utf-8")
        self.assertIn("HOTPOT_DASHBOARD_POLICY_RECONCILE_SECONDS=60", env)
        self.assertIn("HOTPOT_ALLOW_CIDRS", env)
        self.assertIn("last-known-good", env)

    def test_policy_runbook_preserves_manual_enforcement_and_lkg_semantics(self) -> None:
        root = Path(__file__).resolve().parents[1]
        guide = (root / "docs" / "policy-control-plane.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("0.0.0.0/0", guide)
        self.assertIn("::/0", guide)
        self.assertIn("/_hotpot/api/policy", guide)
        self.assertIn("/api/manual-response/preview", guide)
        self.assertIn("/api/manual-response/apply", guide)
        self.assertIn("last-known-good", guide)
        self.assertIn("Cloudflare enforcement remains approval-only", guide)


if __name__ == "__main__":
    unittest.main()
