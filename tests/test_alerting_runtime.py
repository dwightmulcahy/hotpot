from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dashboard.alerting_runtime import AlertingInvestigationStore, AlertNotificationCenter
from dashboard.notifications import NotificationConfig
from dashboard.response_enforcement_store import ApprovalResponsePolicy
from dashboard.runtime import Instance


class FakeRecommendationStore:
    async def recommendation(self, recommendation_id):
        return {
            "action": "recommend_block",
            "confidence": "high",
            "actor_key": "8.8.8.8",
            "evidence": {
                "global_level": 4,
                "global_score": 70,
                "observed_hits": 25,
                "app_count": 1,
            },
        }


class AlertRuntimeTests(unittest.IsolatedAsyncioTestCase):
    def disabled_config(self) -> NotificationConfig:
        return NotificationConfig(
            enabled=False,
            webhook_url="https://example.invalid/hook",
            webhook_bearer="secret",
            smtp_host="",
            smtp_port=587,
            smtp_starttls=True,
            smtp_ssl=False,
            smtp_username="",
            smtp_password="",
            smtp_from="",
            smtp_to=(),
            retry_seconds=300,
        )

    async def test_recommendation_change_is_alertable(self) -> None:
        center = AlertNotificationCenter(self.disabled_config(), FakeRecommendationStore())
        candidate = await center._candidate_from_audit(
            {
                "event_type": "recommendation_changed",
                "recommendation_id": "rec-1",
                "actor_key": "8.8.8.8",
                "details": {
                    "from_action": "watch",
                    "action": "recommend_block",
                },
            }
        )
        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate["severity"], "critical")
        self.assertIn("L4", candidate["subject"])

    async def test_delivery_disable_stops_existing_pending_retries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AlertingInvestigationStore(Path(tmp), retention_days=90)
            await store.queue_notification(
                event_key="pending-before-disable",
                event_type="apply_failed",
                severity="critical",
                subject="Failure",
                message="Failure",
                channels=["webhook"],
            )
            center = AlertNotificationCenter(self.disabled_config(), store)
            self.assertEqual(await center.deliver_due(object()), 0)
            row = (await store.recent_notifications(limit=1))[0]
            self.assertEqual(row["status"], "pending")
            self.assertEqual(row["attempts"], 0)

    async def test_pending_recommendation_escalation_gets_durable_audit_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = AlertingInvestigationStore(Path(tmp), retention_days=90)
            instance = Instance("one", "One", "http://one")
            now = datetime.now(timezone.utc)
            apps = [
                {
                    "id": "one",
                    "name": "One",
                    "allowlist_cidrs": [],
                    "trusted_proxy_cidrs": [],
                }
            ]
            await store.ingest(
                instance,
                [
                    {
                        "id": 1,
                        "ts": (now - timedelta(seconds=2)).isoformat(),
                        "client_ip": "8.8.8.8",
                        "attacker_key": "8.8.8.8",
                        "path": "/robots.txt",
                        "category": "generic",
                        "scanner": "scanner",
                        "action": "observe",
                        "severity": 1,
                        "escalation_level": 2,
                        "suppressed_before": 2,
                    }
                ],
                1,
            )
            first = await store.sync_response_recommendations(
                ApprovalResponsePolicy(), apps
            )
            self.assertEqual(first["recommendations"][0]["action"], "watch")

            await store.ingest(
                instance,
                [
                    {
                        "id": 2,
                        "ts": now.isoformat(),
                        "client_ip": "8.8.8.8",
                        "attacker_key": "8.8.8.8",
                        "path": "/.env",
                        "category": "secret",
                        "scanner": "scanner",
                        "action": "tarpit",
                        "severity": 5,
                        "escalation_level": 4,
                        "suppressed_before": 20,
                    }
                ],
                2,
            )
            second = await store.sync_response_recommendations(
                ApprovalResponsePolicy(), apps
            )
            self.assertIn(
                second["recommendations"][0]["action"],
                {"recommend_block", "recommend_long_block"},
            )
            audits = await store.audit_events_after(0, limit=20)
            event_types = [row["event_type"] for row in audits]
            self.assertIn("recommendation_created", event_types)
            self.assertIn("recommendation_changed", event_types)
            changed = next(
                row for row in audits if row["event_type"] == "recommendation_changed"
            )
            self.assertEqual(changed["details"]["from_action"], "watch")
            self.assertIn("block", changed["details"]["action"])

            timeline = await store.attacker_timeline("8.8.8.8")
            changed_items = [
                item
                for item in timeline
                if item.get("event_type") == "recommendation_changed"
            ]
            self.assertEqual(len(changed_items), 1)
            self.assertEqual(changed_items[0]["kind"], "recommendation")
            self.assertEqual(changed_items[0]["level"], 4)


if __name__ == "__main__":
    unittest.main()
