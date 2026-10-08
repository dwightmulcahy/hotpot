from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from dashboard.manual_response import ManualResponseService
from dashboard.response_enforcement_store import EnforcementStore
from dashboard.runtime import Instance


class ManualResponseTests(unittest.IsolatedAsyncioTestCase):
    async def make_store(self, path: Path, **overrides):
        store = EnforcementStore(path, retention_days=90)
        instance = Instance("one", "One", "http://one")
        event = {
            "id": 1,
            "ts": datetime.now(timezone.utc).isoformat(),
            "client_ip": "8.8.8.8",
            "attacker_key": "8.8.8.8",
            "source_type": "ip",
            "worker_zone": None,
            "path": "/.env",
            "category": "secret-discovery",
            "scanner": "unknown",
            "action": "tarpit",
            "severity": 5,
            "escalation_level": 4,
        }
        event.update(overrides)
        await store.ingest(instance, [event], 1)
        return store

    async def test_prepare_and_persist_manual_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = await self.make_store(Path(tmp))
            service = ManualResponseService(store)
            rec = await service.prepare(
                actor_key="8.8.8.8",
                action_key="block_1h",
                apps=[
                    {
                        "id": "one",
                        "name": "One",
                        "allowlist_cidrs": [],
                        "trusted_proxy_cidrs": ["127.0.0.1/32"],
                    }
                ],
            )
            self.assertEqual(rec["action"], "recommend_block")
            self.assertEqual(rec["duration_hours"], 1)
            self.assertEqual(rec["target_type"], "ip")
            self.assertEqual(rec["evidence"]["instance_ids"], ["one"])
            persisted = await service.persist(rec, principal="operator")
            self.assertEqual(persisted["status"], "approved")
            self.assertTrue(persisted["recommendation_id"].startswith("manual_"))

    async def test_manual_response_refuses_allowlisted_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = await self.make_store(Path(tmp))
            service = ManualResponseService(store)
            with self.assertRaisesRegex(ValueError, "safety-excluded"):
                await service.prepare(
                    actor_key="8.8.8.8",
                    action_key="block_24h",
                    apps=[
                        {
                            "id": "one",
                            "name": "One",
                            "allowlist_cidrs": ["8.8.8.0/24"],
                            "trusted_proxy_cidrs": [],
                        }
                    ],
                )

    async def test_shared_worker_without_zone_cannot_be_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            shared = "2a06:98c0:3600::103"
            store = await self.make_store(
                Path(tmp),
                client_ip=shared,
                attacker_key="cf-worker:legacy-unknown",
                source_type="cloudflare-worker",
                worker_zone=None,
            )
            service = ManualResponseService(store)
            with self.assertRaisesRegex(ValueError, "Worker"):
                await service.prepare(
                    actor_key="cf-worker:legacy-unknown",
                    action_key="long_block",
                    apps=[
                        {
                            "id": "one",
                            "name": "One",
                            "allowlist_cidrs": [],
                            "trusted_proxy_cidrs": [],
                        }
                    ],
                )


if __name__ == "__main__":
    unittest.main()
