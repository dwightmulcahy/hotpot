from __future__ import annotations

import unittest
from types import SimpleNamespace

from dashboard.campaign_alerts import process_campaign_notifications


class _Store:
    def __init__(self) -> None:
        self.calls = []

    async def queue_notification(self, **kwargs):
        self.calls.append(kwargs)
        return kwargs, True


class _Notifications:
    def __init__(self) -> None:
        self.deliveries = 0

    async def deliver_due(self, client):
        self.deliveries += 1
        return 1


class CampaignAlertTests(unittest.IsolatedAsyncioTestCase):
    async def test_meaningful_campaign_is_queued_without_enforcement(self) -> None:
        store = _Store()
        notifications = _Notifications()
        dashboard = SimpleNamespace(
            client=object(),
            store=store,
            notifications=notifications,
            notification_config=SimpleNamespace(channels=["email"]),
        )
        campaigns = [
            {
                "campaign_id": "campaign_deadbeef",
                "label": "nuclei · secret-discovery",
                "notification_severity": "warning",
                "actor_count": 3,
                "source_ip_count": 3,
                "hits": 12,
                "app_count": 2,
                "apps": ["One", "Two"],
                "categories": ["secret-discovery"],
                "scanners": ["nuclei"],
                "top_paths": [{"path": "/.env", "hits": 8}],
                "first_seen": "2026-10-08T12:00:00+00:00",
                "last_seen": "2026-10-08T12:10:00+00:00",
                "max_level": 3,
                "max_severity": 5,
            }
        ]
        result = await process_campaign_notifications(dashboard, campaigns)
        self.assertEqual(result, {"considered": 1, "queued": 1, "delivered": 1})
        self.assertEqual(len(store.calls), 1)
        call = store.calls[0]
        self.assertEqual(call["event_key"], "campaign:campaign_deadbeef:warning")
        self.assertEqual(call["event_type"], "attack_campaign_detected")
        self.assertEqual(call["severity"], "warning")
        self.assertFalse(call["payload"]["automatic_enforcement"])
        self.assertEqual(call["payload"]["scoring_effect"], "none")
        self.assertIn("observational", call["message"])

    async def test_low_signal_campaign_does_not_alert(self) -> None:
        store = _Store()
        notifications = _Notifications()
        dashboard = SimpleNamespace(
            client=object(),
            store=store,
            notifications=notifications,
            notification_config=SimpleNamespace(channels=["email"]),
        )
        result = await process_campaign_notifications(
            dashboard,
            [{"campaign_id": "campaign_low", "notification_severity": None}],
        )
        self.assertEqual(result["considered"], 0)
        self.assertEqual(result["queued"], 0)
        self.assertEqual(store.calls, [])
        self.assertEqual(notifications.deliveries, 1)


if __name__ == "__main__":
    unittest.main()
