from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dashboard.notification_routing import NotificationRoutingPolicy, RoutedInvestigationStore


class NotificationRoutingTests(unittest.IsolatedAsyncioTestCase):
    def test_policy_filters_to_configured_channels(self) -> None:
        with patch.dict(
            os.environ,
            {
                "HOTPOT_DASHBOARD_NOTIFY_CRITICAL_CHANNELS": "webhook,email",
                "HOTPOT_DASHBOARD_NOTIFY_WARNING_CHANNELS": "email",
                "HOTPOT_DASHBOARD_NOTIFY_INFO_CHANNELS": "",
            },
            clear=False,
        ):
            policy = NotificationRoutingPolicy.from_env()
        self.assertEqual(
            policy.configured_route(
                "critical", configured_channels=["webhook"], enabled=True
            ),
            ["webhook"],
        )
        self.assertEqual(
            policy.configured_route(
                "warning", configured_channels=["webhook"], enabled=True
            ),
            [],
        )
        self.assertEqual(
            policy.configured_route(
                "critical", configured_channels=["webhook", "email"], enabled=False
            ),
            [],
        )

    async def test_store_routes_by_severity_and_test_hits_all_channels(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            policy = NotificationRoutingPolicy(
                critical=("webhook", "email"), warning=("email",), info=()
            )
            store = RoutedInvestigationStore(
                Path(tmp),
                retention_days=90,
                routing=policy,
                configured_channels=["webhook", "email"],
                delivery_enabled=True,
            )
            critical, _ = await store.queue_notification(
                event_key="critical",
                event_type="apply_failed",
                severity="critical",
                subject="critical",
                message="critical",
                channels=[],
            )
            warning, _ = await store.queue_notification(
                event_key="warning",
                event_type="orphan_detected",
                severity="warning",
                subject="warning",
                message="warning",
                channels=[],
            )
            info, _ = await store.queue_notification(
                event_key="info",
                event_type="applied",
                severity="info",
                subject="info",
                message="info",
                channels=["webhook", "email"],
            )
            test, _ = await store.queue_notification(
                event_key="test",
                event_type="notification_test",
                severity="critical",
                subject="test",
                message="test",
                channels=[],
            )
            self.assertEqual(critical["channels"], ["email", "webhook"])
            self.assertEqual(warning["channels"], ["email"])
            self.assertEqual(info["channels"], [])
            self.assertEqual(test["channels"], ["email", "webhook"])

    def test_invalid_channel_is_rejected(self) -> None:
        with patch.dict(
            os.environ,
            {"HOTPOT_DASHBOARD_NOTIFY_CRITICAL_CHANNELS": "email,sms"},
            clear=False,
        ):
            with self.assertRaises(RuntimeError):
                NotificationRoutingPolicy.from_env()


if __name__ == "__main__":
    unittest.main()
