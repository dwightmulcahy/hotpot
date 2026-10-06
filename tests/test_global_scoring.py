from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from dashboard import runtime as core
from dashboard.global_scoring import GlobalCentralStore, score_attacker
from dashboard.production import PRODUCTION_HTML
from dashboard.runtime import Instance


class GlobalScoreTests(unittest.TestCase):
    def test_levels_reward_cross_app_correlation(self) -> None:
        isolated = score_attacker(
            severity_score=3,
            hits=1,
            app_count=1,
            category_count=1,
        )
        self.assertEqual(isolated.level, 1)
        self.assertEqual(isolated.score, 3)

        two_apps = score_attacker(
            severity_score=6,
            hits=2,
            app_count=2,
            category_count=2,
        )
        self.assertEqual(two_apps.level, 2)
        self.assertGreater(two_apps.score, isolated.score)

        three_apps = score_attacker(
            severity_score=9,
            hits=3,
            app_count=3,
            category_count=3,
        )
        self.assertEqual(three_apps.level, 3)

        four_apps = score_attacker(
            severity_score=12,
            hits=4,
            app_count=4,
            category_count=4,
        )
        self.assertEqual(four_apps.level, 4)

    def test_volume_bonus_is_bounded(self) -> None:
        result = score_attacker(
            severity_score=5,
            hits=1_000_000,
            app_count=1,
            category_count=1,
        )
        self.assertEqual(result.volume_bonus, 20)
        self.assertEqual(result.score, 25)
        self.assertEqual(result.level, 4)  # hit threshold still catches a flood


class GlobalCentralStoreTests(unittest.IsolatedAsyncioTestCase):
    async def test_exact_global_score_counts_cross_app_and_suppressed_activity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = GlobalCentralStore(Path(tmp))
            instances = [
                Instance("one", "One", "http://one"),
                Instance("two", "Two", "http://two"),
                Instance("three", "Three", "http://three"),
                Instance("four", "Four", "http://four"),
            ]
            events = [
                {"id": 1, "ts": "2026-01-01T00:00:00+00:00", "client_ip": "203.0.113.10", "path": "/.env", "category": "secret", "scanner": "Nuclei", "action": "tarpit", "severity": 5, "escalation_level": 1, "suppressed_before": 5},
                {"id": 1, "ts": "2026-01-01T00:01:00+00:00", "client_ip": "203.0.113.10", "path": "/.git/config", "category": "git", "scanner": "Nuclei", "action": "tarpit", "severity": 4, "escalation_level": 2},
                {"id": 1, "ts": "2026-01-01T00:02:00+00:00", "client_ip": "203.0.113.10", "path": "/wp-login.php", "category": "wordpress", "scanner": "Nuclei", "action": "tarpit", "severity": 3, "escalation_level": 2},
                {"id": 1, "ts": "2026-01-01T00:03:00+00:00", "client_ip": "203.0.113.10", "path": "/phpmyadmin", "category": "admin", "scanner": "Nuclei", "action": "tarpit", "severity": 3, "escalation_level": 3},
            ]
            for instance, event in zip(instances, events):
                await store.ingest(instance, [event], 1)

            snapshot = await store.snapshot(
                [{"id": item.instance_id, "name": item.name, "healthy": True} for item in instances]
            )
            offender = snapshot["top_offenders"][0]
            self.assertEqual(offender["ip"], "203.0.113.10")
            self.assertEqual(offender["persisted_hits"], 4)
            self.assertEqual(offender["hits"], 9)
            self.assertEqual(offender["app_count"], 4)
            self.assertEqual(offender["category_count"], 4)
            self.assertEqual(offender["global_level"], 4)
            self.assertEqual(len(offender["apps"]), 4)
            self.assertEqual(snapshot["summary"]["level3_plus"], 1)
            self.assertEqual(snapshot["summary"]["global_level4"], 1)
            self.assertEqual(snapshot["global_scoring"]["version"], 1)

            detail = await store.attacker_snapshot("203.0.113.10")
            self.assertIsNotNone(detail)
            assert detail is not None
            self.assertEqual(detail["global_level"], 4)
            self.assertEqual(detail["hits"], 9)
            self.assertEqual(len(detail["recent"]), 4)

    async def test_existing_dashboard_database_is_migrated_in_place(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            base = core.CentralStore(path)
            await base.ingest(
                Instance("one", "One", "http://one"),
                [{"id": 1, "ts": "2026-01-01T00:00:00+00:00", "client_ip": "203.0.113.20", "path": "/.env", "category": "secret", "scanner": "unknown", "action": "deceive", "severity": 5, "escalation_level": 1}],
                1,
            )

            upgraded = GlobalCentralStore(path)
            snapshot = await upgraded.snapshot([{"id": "one", "name": "One", "healthy": True}])
            self.assertEqual(snapshot["top_offenders"][0]["ip"], "203.0.113.20")
            self.assertEqual(snapshot["top_offenders"][0]["hits"], 1)

    def test_dashboard_surfaces_global_score_and_level(self) -> None:
        self.assertIn("Global L3+", PRODUCTION_HTML)
        self.assertIn("global_level", PRODUCTION_HTML)
        self.assertIn("global_score", PRODUCTION_HTML)
        self.assertIn("category_count", PRODUCTION_HTML)


if __name__ == "__main__":
    unittest.main()
