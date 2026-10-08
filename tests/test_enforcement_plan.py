from __future__ import annotations

import unittest
from pathlib import Path

from dashboard.cloudflare_enforcement import CloudflareConfig, CloudflareTarget
from dashboard.enforcement_plan import build_enforcement_plan


class EnforcementPlanTests(unittest.TestCase):
    def config(self) -> CloudflareConfig:
        return CloudflareConfig(
            enabled=True,
            api_token="not-used-by-plan",
            targets={
                "one": CloudflareTarget("one", "zone123456789", ("example.com",)),
                "two": CloudflareTarget("two", "zone123456789", ("www.example.com",)),
            },
        )

    def test_ip_plan_matches_host_scoped_block_without_network_writes(self) -> None:
        plan = build_enforcement_plan(
            {
                "recommendation_id": "rec_1234567890abcdef",
                "actor_key": "34.62.82.165",
                "action": "recommend_block",
                "target_type": "ip",
                "target_value": "34.62.82.165",
                "duration_hours": 24,
                "evidence": {"instance_ids": ["one", "two"]},
            },
            self.config(),
        )
        self.assertEqual(plan["cloudflare_action"], "block")
        self.assertFalse(plan["writes_performed"])
        self.assertFalse(plan["network_calls_performed"])
        self.assertEqual(plan["zone_count"], 1)
        expression = plan["zones"][0]["expression"]
        self.assertIn("ip.src eq 34.62.82.165", expression)
        self.assertIn('http.host eq "example.com"', expression)
        self.assertIn('http.host eq "www.example.com"', expression)

    def test_worker_plan_uses_worker_zone_field(self) -> None:
        plan = build_enforcement_plan(
            {
                "recommendation_id": "rec_worker",
                "action": "recommend_challenge",
                "target_type": "cloudflare-worker-zone",
                "target_value": "worker.example",
                "evidence": {"instance_ids": ["one"]},
            },
            self.config(),
        )
        self.assertEqual(plan["cloudflare_action"], "managed_challenge")
        self.assertIn('cf.worker.upstream_zone eq "worker.example"', plan["zones"][0]["expression"])

    def test_dashboard_ui_surfaces_non_writing_preview(self) -> None:
        root = Path(__file__).resolve().parents[1]
        script = (root / "dashboard" / "static" / "campaigns.js").read_text(
            encoding="utf-8"
        )
        self.assertIn("Preview rule", script)
        self.assertIn("No writes performed", script)
        self.assertIn("/plan", script)


if __name__ == "__main__":
    unittest.main()
