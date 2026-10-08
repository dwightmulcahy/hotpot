from __future__ import annotations

import unittest
from pathlib import Path


class PolicyUiTests(unittest.TestCase):
    def test_policy_assets_are_static_and_control_plane_is_visible(self) -> None:
        root = Path(__file__).resolve().parents[1]
        runtime = (root / "dashboard" / "policy_runtime.py").read_text(encoding="utf-8")
        script = (root / "dashboard" / "static" / "policy.js").read_text(
            encoding="utf-8"
        )
        css = (root / "dashboard" / "static" / "policy.css").read_text(
            encoding="utf-8"
        )

        self.assertIn('/static/policy.css', runtime)
        self.assertIn('/static/policy.js', runtime)
        self.assertNotIn("BASE_DASHBOARD_HTML.replace", runtime)
        self.assertIn('partition("</head>")', runtime)
        self.assertIn('rpartition("</body>")', runtime)
        self.assertIn("Policy control plane", script)
        self.assertIn("/api/policies", script)
        self.assertIn("policy-create", script)
        self.assertIn("policy-disable", script)
        self.assertIn("policy-reconcile", script)
        self.assertIn("Policy decision", script)
        self.assertIn("policy-layout", css)

    def test_threat_drawer_has_preview_first_manual_actions(self) -> None:
        root = Path(__file__).resolve().parents[1]
        script = (root / "dashboard" / "static" / "policy.js").read_text(
            encoding="utf-8"
        )
        main = (root / "dashboard" / "main.py").read_text(encoding="utf-8")

        for label in (
            "Challenge",
            "Block 1h",
            "Block 24h",
            "Long block",
            "Allowlist",
            "Suppress actor",
            "Suppress scanner",
        ):
            self.assertIn(label, script)
        preview = script.index("/api/manual-response/preview")
        apply = script.index("/api/manual-response/apply")
        self.assertLess(preview, apply)
        self.assertIn("renderPlan", script)
        self.assertIn("Expression:", script)
        self.assertIn("X-Hotpot-Action':'manual-response", script)
        self.assertIn('/api/manual-response/preview', main)
        self.assertIn('/api/manual-response/apply', main)

    def test_candidate_policy_preview_is_non_writing(self) -> None:
        root = Path(__file__).resolve().parents[1]
        runtime = (root / "dashboard" / "policy_runtime.py").read_text(encoding="utf-8")
        self.assertIn('"candidate" in payload', runtime)
        self.assertIn('"writes": False', runtime)
        self.assertIn("Preview only. No policy has been persisted", runtime)


if __name__ == "__main__":
    unittest.main()
