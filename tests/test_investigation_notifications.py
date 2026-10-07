from __future__ import annotations

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from dashboard.investigation_store import InvestigationStore
from dashboard.notifications import NotificationCenter, NotificationConfig
from dashboard.observability_production import EXTRA_JS
from dashboard.runtime import Instance


class InvestigationTimelineTests(unittest.IsolatedAsyncioTestCase):
    async def test_timeline_merges_probes_escalations_and_dashboard_audit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = InvestigationStore(Path(tmp), retention_days=90)
            instance = Instance("one", "One", "http://one")
            now = datetime.now(timezone.utc)
            await store.ingest(
                instance,
                [
                    {
                        "id": 1,
                        "ts": (now - timedelta(minutes=2)).isoformat(),
                        "client_ip": "8.8.8.8",
                        "attacker_key": "8.8.8.8",
                        "method": "GET",
                        "path": "/.env",
                        "category": "secret",
                        "scanner": "scanner-a",
                        "action": "observe",
                        "severity": 2,
                        "escalation_level": 2,
                        "attacker_score": 10,
                        "suppressed_before": 2,
                    },
                    {
                        "id": 2,
                        "ts": (now - timedelta(minutes=1)).isoformat(),
                        "client_ip": "8.8.8.8",
                        "attacker_key": "8.8.8.8",
                        "method": "GET",
                        "path": "/phpmyadmin",
                        "category": "php",
                        "scanner": "scanner-a",
                        "action": "tarpit",
                        "severity": 5,
                        "escalation_level": 4,
                        "attacker_score": 75,
                        "suppressed_before": 0,
                    },
                ],
                2,
            )
            await store.record_dashboard_action(
                event_type="dashboard_approve",
                message="Dashboard user approved Cloudflare enforcement",
                principal="dwight",
                session_id="session-1",
                actor_key="8.8.8.8",
                status="applied",
            )

            timeline = await store.attacker_timeline("8.8.8.8")
            kinds = [item["kind"] for item in timeline]
            self.assertIn("probe", kinds)
            self.assertIn("escalation", kinds)
            self.assertIn("approval", kinds)
            self.assertTrue(any(item.get("level") == 4 for item in timeline))
            approval = next(item for item in timeline if item["kind"] == "approval")
            self.assertEqual(approval["principal"], "dwight")
            self.assertEqual(approval["source"], "dashboard")
            self.assertEqual(
                timeline,
                sorted(timeline, key=lambda item: (item["ts"], item["id"])),
            )


class FakeRecommendationStore:
    def __init__(self, recommendation):
        self.value = recommendation

    async def recommendation(self, recommendation_id):
        return self.value


class NotificationPolicyTests(unittest.IsolatedAsyncioTestCase):
    def config(self) -> NotificationConfig:
        return NotificationConfig(
            enabled=False,
            webhook_url="",
            webhook_bearer="",
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

    async def candidate(self, recommendation):
        center = NotificationCenter(self.config(), FakeRecommendationStore(recommendation))
        return await center._candidate_from_audit(
            {
                "event_type": "recommendation_created",
                "recommendation_id": "rec-1",
                "actor_key": "8.8.8.8",
                "details": {},
            }
        )

    async def test_l4_and_high_confidence_l3_are_alerts_but_routine_levels_are_not(self) -> None:
        l4 = await self.candidate(
            {
                "action": "recommend_block",
                "confidence": "high",
                "actor_key": "8.8.8.8",
                "evidence": {"global_level": 4, "global_score": 70, "observed_hits": 25, "app_count": 2},
            }
        )
        self.assertIsNotNone(l4)
        self.assertEqual(l4["severity"], "critical")

        l3_high = await self.candidate(
            {
                "action": "recommend_challenge",
                "confidence": "high",
                "actor_key": "8.8.8.8",
                "evidence": {"global_level": 3, "global_score": 35, "observed_hits": 12, "app_count": 3},
            }
        )
        self.assertIsNotNone(l3_high)
        self.assertEqual(l3_high["severity"], "warning")

        l3_medium = await self.candidate(
            {
                "action": "recommend_challenge",
                "confidence": "medium",
                "actor_key": "8.8.8.8",
                "evidence": {"global_level": 3},
            }
        )
        self.assertIsNone(l3_medium)

        l2 = await self.candidate(
            {
                "action": "watch",
                "confidence": "medium",
                "actor_key": "8.8.8.8",
                "evidence": {"global_level": 2},
            }
        )
        self.assertIsNone(l2)

    async def test_notification_log_deduplicates_and_health_transitions_alert_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = InvestigationStore(Path(tmp), retention_days=90)
            config = self.config()
            center = NotificationCenter(config, store)
            first, created = await store.queue_notification(
                event_key="same-event",
                event_type="test",
                severity="warning",
                subject="One",
                message="One",
                channels=[],
            )
            self.assertTrue(created)
            _, created_again = await store.queue_notification(
                event_key="same-event",
                event_type="test",
                severity="warning",
                subject="Two",
                message="Two",
                channels=[],
            )
            self.assertFalse(created_again)
            self.assertEqual(first["status"], "recorded")

            dummy_client = object()
            healthy = [{"id": "one", "name": "One", "healthy": True, "upstream_health": {}}]
            unhealthy = [{"id": "one", "name": "One", "healthy": False, "error": "down", "upstream_health": {}}]
            self.assertEqual(await center.process_instance_health(healthy, dummy_client), 0)
            self.assertEqual(await center.process_instance_health(unhealthy, dummy_client), 1)
            self.assertEqual(await center.process_instance_health(unhealthy, dummy_client), 0)
            self.assertEqual(await center.process_instance_health(healthy, dummy_client), 1)
            recent = await store.recent_notifications(limit=10)
            event_types = [row["event_type"] for row in recent]
            self.assertIn("instance_unhealthy", event_types)
            self.assertIn("instance_recovered", event_types)

    async def test_audit_cursor_seeds_without_sending_history_then_processes_new_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = InvestigationStore(Path(tmp), retention_days=90)
            await store.record_dashboard_action(
                event_type="applied",
                message="Old enforcement",
                principal="system",
                session_id=None,
                actor_key="8.8.8.8",
                status="applied",
            )
            center = NotificationCenter(self.config(), store)
            dummy_client = object()
            seeded = await center.sync_audit_events(dummy_client)
            self.assertEqual(seeded["queued"], 0)
            self.assertEqual(await store.recent_notifications(limit=10), [])

            await store.record_dashboard_action(
                event_type="applied",
                message="New enforcement",
                principal="system",
                session_id=None,
                actor_key="1.1.1.1",
                status="applied",
            )
            result = await center.sync_audit_events(dummy_client)
            self.assertEqual(result["queued"], 1)
            recent = await store.recent_notifications(limit=10)
            self.assertEqual(len(recent), 1)
            self.assertEqual(recent[0]["event_type"], "applied")

    def test_notification_secret_files_and_public_status_do_not_expose_secret(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bearer = Path(tmp) / "bearer"
            password = Path(tmp) / "smtp"
            bearer.write_text("webhook-secret\n", encoding="utf-8")
            password.write_text("smtp-secret\n", encoding="utf-8")
            with patch.dict(
                os.environ,
                {
                    "HOTPOT_DASHBOARD_NOTIFICATIONS_ENABLED": "true",
                    "HOTPOT_DASHBOARD_NOTIFY_WEBHOOK_URL": "https://example.invalid/hook",
                    "HOTPOT_DASHBOARD_NOTIFY_WEBHOOK_BEARER_FILE": str(bearer),
                    "HOTPOT_DASHBOARD_SMTP_HOST": "smtp.example.invalid",
                    "HOTPOT_DASHBOARD_SMTP_FROM": "hotpot@example.invalid",
                    "HOTPOT_DASHBOARD_SMTP_TO": "one@example.invalid,two@example.invalid",
                    "HOTPOT_DASHBOARD_SMTP_PASSWORD_FILE": str(password),
                },
                clear=False,
            ):
                config = NotificationConfig.from_env()
            self.assertEqual(config.webhook_bearer, "webhook-secret")
            self.assertEqual(config.smtp_password, "smtp-secret")
            self.assertEqual(config.channels, ["webhook", "email"])
            public = json.dumps(config.public_status())
            self.assertNotIn("webhook-secret", public)
            self.assertNotIn("smtp-secret", public)

    def test_observability_ui_adds_timeline_and_notification_center(self) -> None:
        self.assertIn("Investigation timeline", EXTRA_JS)
        self.assertIn("Notification center", EXTRA_JS)
        self.assertIn("/api/notifications?limit=30", EXTRA_JS)
        self.assertIn("Routine L1/L2 probes are ignored", EXTRA_JS)


if __name__ == "__main__":
    unittest.main()
