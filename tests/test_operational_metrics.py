from __future__ import annotations

import tempfile
import time
import unittest
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

from dashboard.metrics import DashboardMetricsCollector, MetricHistory
from hotpot.metrics import render_prometheus


class _Snapshot:
    def __init__(self, payload):
        self.payload = payload

    def snapshot(self):
        return dict(self.payload)


class _AsyncSnapshot(_Snapshot):
    async def snapshot(self):
        return dict(self.payload)


class OperationalMetricsTests(unittest.IsolatedAsyncioTestCase):
    async def test_prometheus_snapshot_exposes_core_health_and_pressure(self) -> None:
        server = SimpleNamespace(
            settings=SimpleNamespace(instance_id="test"),
            stats=Counter(
                {
                    "proxied": 12,
                    "deceptions": 5,
                    "tarpits_active": 1,
                    "tarpits_total": 3,
                    "escalation:4": 2,
                    "upstream_errors": 1,
                    "telemetry_errors": 4,
                }
            ),
            resources=_Snapshot(
                {
                    "upstream_active": 2,
                    "max_upstream_concurrent": 8,
                    "websocket_active": 1,
                    "max_websockets": 4,
                    "buffered_body_bytes": 1024,
                    "max_buffered_body_bytes": 4096,
                    "rejected_upstream": 1,
                    "rejected_websocket": 0,
                    "rejected_buffer": 2,
                }
            ),
            telemetry_queue=_Snapshot({"depth": 3, "capacity": 32, "dropped": 1}),
            notification_spool=_AsyncSnapshot({"pending": 2}),
            upstream_health={"healthy": True, "latency_ms": 17.5},
            started=time.monotonic() - 10,
        )
        body = await render_prometheus(server)
        self.assertIn('hotpot_up{instance="test"} 1', body)
        self.assertIn('hotpot_escalation_events_total{instance="test",level="4"} 2', body)
        self.assertIn('hotpot_notification_spool_pending{instance="test"} 2', body)
        self.assertIn(
            'hotpot_resource_capacity{instance="test",resource="upstream"} 8', body
        )

    async def test_history_builds_one_hour_rate_and_longer_windows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            history = MetricHistory(Path(directory))
            await history.record({"proxied_total": 10, "level4_total": 1})
            await history.record({"proxied_total": 20, "level4_total": 2})
            result = await history.trends()
            self.assertEqual(set(result["windows"]), {"1h", "24h", "7d"})
            one_hour = result["windows"]["1h"]
            self.assertGreaterEqual(one_hour["points"], 2)
            self.assertGreaterEqual(one_hour["latest"]["request_rate_per_minute"], 0)

    def test_dashboard_aggregate_reports_resource_saturation(self) -> None:
        status = {
            "healthy": True,
            "stats": {"proxied": 9, "deceptions": 2, "escalation:4": 1},
            "telemetry_queue": {"depth": 4, "dropped": 2},
            "notification_spool": {"pending": 3},
            "resource_budget": {
                "upstream_active": 8,
                "max_upstream_concurrent": 10,
                "websocket_active": 1,
                "max_websockets": 4,
                "buffered_body_bytes": 25,
                "max_buffered_body_bytes": 100,
            },
            "upstream_health": {"latency_ms": 20},
        }
        aggregate = DashboardMetricsCollector.aggregate([status])
        self.assertEqual(aggregate["healthy_instances"], 1)
        self.assertEqual(aggregate["notification_spool_pending"], 3)
        self.assertEqual(aggregate["resource_upstream_saturation"], 0.8)

    def test_container_entrypoints_use_metrics_aware_launchers(self) -> None:
        root = Path(__file__).resolve().parents[1]
        self.assertIn(
            'CMD ["python", "-m", "hotpot.main"]',
            (root / "Dockerfile").read_text(encoding="utf-8"),
        )
        self.assertIn(
            'CMD ["python", "-m", "dashboard.main"]',
            (root / "Dockerfile.dashboard").read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
