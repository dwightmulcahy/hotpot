from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dashboard.global_scoring import CLOUDFLARE_WORKER_SHARED_IP, LEGACY_WORKER_KEY
from dashboard.response_recommendations import (
    ResponsePolicy,
    SafetyContext,
    ThreatResponseStore,
    decide_response,
)
from dashboard.runtime import Instance


class ResponsePolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime.now(timezone.utc)
        self.policy = ResponsePolicy(
            active_window_hours=24,
            stale_minutes=360,
            recommendation_ttl_hours=24,
            dismiss_hours=24,
        )

    def actor(self, **overrides):
        value = {
            "identity_key": "8.8.8.8",
            "client_ip": "8.8.8.8",
            "source_type": "ip",
            "worker_zone": None,
            "global_level": 4,
            "global_score": 70,
            "hits": 25,
            "persisted_hits": 4,
            "app_count": 2,
            "category_count": 3,
            "max_severity": 5,
            "high_severity_events": 3,
            "high_level_events": 4,
            "first_seen": (self.now - timedelta(hours=2)).isoformat(),
            "last_seen": self.now.isoformat(),
            "apps": ["One", "Two"],
            "categories": ["secret", "git", "wordpress-install"],
            "top_paths": [{"path": "/.env", "hits": 12}],
            "network": {"asn": 15169, "provider": "Google LLC", "enriched": True},
            "lifetime": {"lifetime_hits": 40, "max_global_level": 4},
        }
        value.update(overrides)
        return value

    def test_level4_recommends_temporary_block(self) -> None:
        result = decide_response(
            self.actor(), self.policy, SafetyContext(), now=self.now
        )
        self.assertEqual(result["action"], "recommend_block")
        self.assertEqual(result["confidence"], "high")
        self.assertEqual(result["target_type"], "ip")
        self.assertEqual(result["target_value"], "8.8.8.8")
        self.assertEqual(result["duration_hours"], 24)

    def test_repeated_level4_can_recommend_longer_block(self) -> None:
        result = decide_response(
            self.actor(
                hits=35,
                app_count=3,
                lifetime={"lifetime_hits": 120, "max_global_level": 4},
            ),
            self.policy,
            SafetyContext(),
            now=self.now,
        )
        self.assertEqual(result["action"], "recommend_long_block")
        self.assertEqual(result["duration_hours"], 168)

    def test_allowlisted_or_stale_actor_is_not_recommended_for_action(self) -> None:
        allowlisted = decide_response(
            self.actor(),
            self.policy,
            SafetyContext(allow_cidrs=("8.8.8.0/24",)),
            now=self.now,
        )
        self.assertEqual(allowlisted["action"], "observe")
        self.assertTrue(allowlisted["safety_excluded"])

        stale = decide_response(
            self.actor(last_seen=(self.now - timedelta(hours=8)).isoformat()),
            self.policy,
            SafetyContext(),
            now=self.now,
        )
        self.assertEqual(stale["action"], "observe")
        self.assertIn("actor is stale", stale["safety_reasons"])

    def test_shared_worker_without_zone_never_recommends_ip_block(self) -> None:
        result = decide_response(
            self.actor(
                identity_key=LEGACY_WORKER_KEY,
                client_ip=CLOUDFLARE_WORKER_SHARED_IP,
                source_type="cloudflare-worker",
                worker_zone=None,
            ),
            self.policy,
            SafetyContext(),
            now=self.now,
        )
        self.assertEqual(result["action"], "watch")
        self.assertEqual(result["target_type"], "none")
        self.assertIsNone(result["target_value"])

    def test_known_worker_zone_is_a_distinct_future_enforcement_target(self) -> None:
        result = decide_response(
            self.actor(
                identity_key="cf-worker:scanner.example",
                client_ip=CLOUDFLARE_WORKER_SHARED_IP,
                source_type="cloudflare-worker",
                worker_zone="scanner.example",
            ),
            self.policy,
            SafetyContext(),
            now=self.now,
        )
        self.assertEqual(result["action"], "recommend_block")
        self.assertEqual(result["target_type"], "cloudflare-worker-zone")
        self.assertEqual(result["target_value"], "scanner.example")


class ThreatResponseStoreTests(unittest.IsolatedAsyncioTestCase):
    async def test_recommendation_is_stable_dismissible_and_not_immediately_recreated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = ThreatResponseStore(Path(tmp), retention_days=90)
            instance = Instance("one", "One", "http://one")
            now = datetime.now(timezone.utc).isoformat()
            await store.ingest(
                instance,
                [
                    {
                        "id": 1,
                        "ts": now,
                        "client_ip": "8.8.8.8",
                        "path": "/.env",
                        "category": "secret",
                        "scanner": "scanner",
                        "action": "tarpit",
                        "severity": 5,
                        "escalation_level": 4,
                        "suppressed_before": 24,
                    }
                ],
                1,
            )
            policy = ResponsePolicy()

            first = await store.sync_response_recommendations(policy, [])
            self.assertEqual(first["summary"]["pending"], 1)
            rec = first["recommendations"][0]
            self.assertEqual(rec["action"], "recommend_block")
            recommendation_id = rec["recommendation_id"]

            second = await store.sync_response_recommendations(policy, [])
            self.assertEqual(second["recommendations"][0]["recommendation_id"], recommendation_id)

            dismissed = await store.dismiss_recommendation(
                recommendation_id, policy.dismiss_hours
            )
            self.assertIsNotNone(dismissed)
            assert dismissed is not None
            self.assertEqual(dismissed["status"], "dismissed")

            after = await store.sync_response_recommendations(policy, [])
            self.assertEqual(after["summary"]["pending"], 0)
            history = await store.recommendations(policy, status="dismissed")
            self.assertEqual(history["count"], 1)
            self.assertEqual(history["recommendations"][0]["recommendation_id"], recommendation_id)

    async def test_collected_safety_cidrs_prevent_recommendation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = ThreatResponseStore(Path(tmp), retention_days=90)
            instance = Instance("one", "One", "http://one")
            await store.ingest(
                instance,
                [
                    {
                        "id": 1,
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "client_ip": "8.8.8.8",
                        "path": "/.git/config",
                        "category": "git",
                        "severity": 5,
                        "escalation_level": 4,
                        "suppressed_before": 30,
                    }
                ],
                1,
            )
            response = await store.sync_response_recommendations(
                ResponsePolicy(),
                [
                    {
                        "allowlist_cidrs": ["8.8.8.0/24"],
                        "trusted_proxy_cidrs": ["127.0.0.1/32"],
                    }
                ],
            )
            self.assertEqual(response["summary"]["pending"], 0)


if __name__ == "__main__":
    unittest.main()
