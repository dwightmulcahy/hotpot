from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dashboard.durability import DurableGlobalStore
from dashboard.production import ProductionDashboard
from dashboard.runtime import Instance
from hotpot.durable_store import SourceIdentityStore


class SourceIdentityStoreTests(unittest.TestCase):
    def test_source_id_survives_restarts_and_changes_with_fresh_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = SourceIdentityStore(root).source_id
            second = SourceIdentityStore(root).source_id
            self.assertEqual(first, second)

            for suffix in ("", "-wal", "-shm"):
                path = root / f"hotpot.sqlite3{suffix}"
                if path.exists():
                    path.unlink()

            third = SourceIdentityStore(root).source_id
            self.assertNotEqual(first, third)


class DurableGlobalStoreTests(unittest.IsolatedAsyncioTestCase):
    async def test_retention_removes_raw_events_but_preserves_lifetime_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = DurableGlobalStore(Path(tmp), retention_days=1)
            app = Instance("one", "One", "http://one")
            await store.register_source("one", "source-a")
            await store.ingest(
                app,
                [
                    {
                        "id": 1,
                        "ts": "2020-01-01T00:00:00+00:00",
                        "client_ip": "8.8.8.8",
                        "path": "/.env",
                        "category": "secret",
                        "scanner": "scanner",
                        "action": "tarpit",
                        "severity": 5,
                        "escalation_level": 3,
                        "suppressed_before": 4,
                    }
                ],
                1,
            )

            before = await store.attacker_snapshot("8.8.8.8")
            self.assertIsNotNone(before)
            self.assertEqual(before["lifetime"]["lifetime_hits"], 5)

            result = await store.housekeeping(1)
            self.assertEqual(result["events_deleted"], 1)

            after = await store.attacker_snapshot("8.8.8.8")
            self.assertIsNotNone(after)
            self.assertEqual(after["hits"], 0)
            self.assertEqual(after["lifetime"]["lifetime_hits"], 5)
            self.assertEqual(after["lifetime"]["persisted_hits"], 1)
            self.assertEqual(after["lifetime"]["app_count"], 1)
            self.assertEqual(after["lifetime"]["category_count"], 1)

            snapshot = await store.snapshot([])
            self.assertEqual(snapshot["summary"]["events"], 0)
            self.assertEqual(snapshot["summary"]["lifetime_attackers"], 1)
            self.assertEqual(snapshot["database"]["retention_days"], 1)
            self.assertEqual(snapshot["database"]["raw_events"], 0)
            self.assertEqual(snapshot["database"]["journal_mode"].lower(), "wal")
            self.assertIsNotNone(snapshot["database"]["last_housekeeping"])

    async def test_source_reset_allows_event_id_reuse_without_losing_lifetime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = DurableGlobalStore(Path(tmp), retention_days=90)
            app = Instance("one", "One", "http://one")
            await store.register_source("one", "source-a")
            await store.ingest(
                app,
                [{"id": 1, "ts": "2026-10-01T00:00:00+00:00", "client_ip": "8.8.4.4", "path": "/a", "category": "one", "severity": 2}],
                1,
            )

            reset = await store.reset_source("one", "source-b")
            self.assertEqual(reset["old_source_id"], "source-a")
            self.assertEqual(reset["events_removed"], 1)
            state = await store.cursor_state("one")
            self.assertEqual(state["cursor"], 0)
            self.assertEqual(state["source_id"], "source-b")
            self.assertEqual(state["reset_count"], 1)

            await store.ingest(
                app,
                [{"id": 1, "ts": "2026-10-02T00:00:00+00:00", "client_ip": "8.8.4.4", "path": "/b", "category": "two", "severity": 3}],
                1,
            )
            snapshot = await store.snapshot([])
            self.assertEqual(snapshot["summary"]["events"], 1)
            self.assertEqual(snapshot["summary"]["source_resets"], 1)
            attacker = await store.attacker_snapshot("8.8.4.4")
            self.assertEqual(attacker["lifetime"]["lifetime_hits"], 2)
            self.assertEqual(attacker["lifetime"]["category_count"], 2)


class DashboardSourceRecoveryTests(unittest.IsolatedAsyncioTestCase):
    def make_dashboard(self) -> ProductionDashboard:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        instances = [{"id": "one", "name": "One", "url": "http://127.0.0.1:18001"}]
        with patch.dict(
            os.environ,
            {
                "HOTPOT_DASHBOARD_INSTANCES": json.dumps(instances),
                "HOTPOT_ADMIN_TOKEN": "collector-token",
                "HOTPOT_DASHBOARD_TOKEN": "viewer-token",
                "HOTPOT_DASHBOARD_DATA_DIR": self.tmp.name,
                "HOTPOT_DASHBOARD_EVENT_RETENTION_DAYS": "90",
            },
            clear=False,
        ):
            return ProductionDashboard()

    async def test_collector_resets_cursor_when_remote_source_changes(self) -> None:
        dashboard = self.make_dashboard()
        instance = dashboard.instances[0]
        await dashboard.store.register_source("one", "source-a")
        await dashboard.store.ingest(
            instance,
            [{"id": 1, "ts": "2026-10-01T00:00:00+00:00", "client_ip": "1.1.1.1", "path": "/old", "category": "old", "severity": 2}],
            1,
        )

        async def fetch_json(url: str):
            if "cursor=1" in url:
                return {
                    "source_id": "source-b",
                    "events": [],
                    "next_cursor": 1,
                    "has_more": False,
                }
            return {
                "source_id": "source-b",
                "events": [
                    {"id": 1, "ts": "2026-10-02T00:00:00+00:00", "client_ip": "1.1.1.1", "path": "/new", "category": "new", "severity": 3}
                ],
                "next_cursor": 1,
                "has_more": False,
            }

        dashboard.fetch_json = fetch_json
        await dashboard.collect_events(instance)
        state = await dashboard.store.cursor_state("one")
        self.assertEqual(state["source_id"], "source-b")
        self.assertEqual(state["cursor"], 1)
        self.assertEqual(state["reset_count"], 1)
        snapshot = await dashboard.store.snapshot([])
        self.assertEqual(snapshot["summary"]["events"], 1)
        self.assertEqual(snapshot["recent"][0]["path"], "/new")
        attacker = await dashboard.store.attacker_snapshot("1.1.1.1")
        self.assertEqual(attacker["lifetime"]["lifetime_hits"], 2)


if __name__ == "__main__":
    unittest.main()
