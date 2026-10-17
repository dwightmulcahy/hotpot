from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dashboard.policy import PolicyManager
from dashboard.runtime import Instance
from hotpot.policy import snapshot_revision

class _Response:
    def __init__(self, status: int, payload: dict):
        self.status = status
        self.payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def json(self, content_type=None):
        return self.payload


class _ScopedClient:
    def __init__(self):
        self.calls = []

    def get(self, url, *, headers):
        self.calls.append(("GET", url, headers["Authorization"]))
        return _Response(200, {"revision": "stale"})

    def put(self, url, *, headers, json):
        self.calls.append(("PUT", url, headers["Authorization"]))
        return _Response(200, {"policy": {"revision": json["revision"]}})


class DashboardPolicyManagerTests(unittest.IsolatedAsyncioTestCase):
    def manager(self, path: Path) -> PolicyManager:
        return PolicyManager(
            path,
            [
                Instance("one", "One", "http://one"),
                Instance("two", "Two", "http://two"),
            ],
        )

    async def test_policy_is_scoped_audited_and_revision_matches_core(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = self.manager(Path(tmp))
            policy = await manager.create(
                {
                    "kind": "allow_cidr",
                    "value": "192.0.2.7",
                    "app_ids": ["one"],
                    "reason": "temporary operator exception",
                    "notes": "ticket 123",
                    "expires_at": (
                        datetime.now(timezone.utc) + timedelta(hours=2)
                    ).isoformat(),
                },
                principal="operator",
            )
            one = await manager.snapshot_for("one")
            two = await manager.snapshot_for("two")
            self.assertEqual(len(one["entries"]), 1)
            self.assertEqual(two["entries"], [])
            self.assertEqual(
                one["revision"], snapshot_revision("one", one["entries"])
            )
            audit = await manager.audit()
            self.assertEqual(audit[0]["policy_id"], policy["policy_id"])
            self.assertEqual(audit[0]["event_type"], "created")

    async def test_default_routes_and_unknown_apps_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = self.manager(Path(tmp))
            with self.assertRaisesRegex(ValueError, "default-route"):
                await manager.create(
                    {
                        "kind": "allow_cidr",
                        "value": "::/0",
                        "reason": "unsafe",
                    },
                    principal="operator",
                )
            with self.assertRaisesRegex(ValueError, "unknown application"):
                await manager.create(
                    {
                        "kind": "suppress_actor",
                        "value": "8.8.8.8",
                        "app_ids": ["missing"],
                        "reason": "known scanner",
                    },
                    principal="operator",
                )

    async def test_preview_explains_allow_and_suppression_effect(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = self.manager(Path(tmp))
            await manager.create(
                {
                    "kind": "allow_cidr",
                    "value": "203.0.113.0/24",
                    "reason": "trusted tester",
                },
                principal="operator",
            )
            await manager.create(
                {
                    "kind": "suppress_actor",
                    "value": "203.0.113.25",
                    "reason": "known scanner",
                },
                principal="operator",
            )
            preview = await manager.preview(
                {
                    "app_id": "one",
                    "client_ip": "203.0.113.25",
                    "actor_key": "203.0.113.25",
                }
            )
            self.assertTrue(preview["matched"])
            self.assertIn("bypass_deception", preview["impacts"])
            self.assertIn("suppress_notifications", preview["impacts"])
            self.assertIn("suppress_response_approval", preview["impacts"])

    async def test_reconcile_uses_policy_token_for_each_instance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = self.manager(Path(tmp))
            client = _ScopedClient()
            report = await manager.reconcile(
                client,
                token_for=lambda instance_id: f"{instance_id}-policy",
                force=True,
            )
            self.assertTrue(report["in_sync"], report)
            by_app = {
                "one": "Bearer one-policy",
                "two": "Bearer two-policy",
            }
            self.assertEqual(len(client.calls), 4)
            for method, url, authorization in client.calls:
                instance_id = "one" if url.startswith("http://one/") else "two"
                self.assertIn(method, {"GET", "PUT"})
                self.assertEqual(authorization, by_app[instance_id])

    async def test_disable_preserves_audit_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = self.manager(Path(tmp))
            policy = await manager.create(
                {
                    "kind": "suppress_actor",
                    "value": "8.8.8.8",
                    "reason": "known scanner",
                },
                principal="operator",
            )
            disabled = await manager.disable(
                policy["policy_id"], principal="operator"
            )
            self.assertIsNotNone(disabled)
            assert disabled is not None
            self.assertFalse(disabled["enabled"])
            events = await manager.audit()
            self.assertEqual([events[0]["event_type"], events[1]["event_type"]], ["disabled", "created"])


if __name__ == "__main__":
    unittest.main()
