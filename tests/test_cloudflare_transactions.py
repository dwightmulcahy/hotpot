from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dashboard.cloudflare_cleanup import CloudflareCleanupQueue
from dashboard.cloudflare_enforcement import CloudflareConfig
from dashboard.cloudflare_transactional import TransactionalCloudflareEnforcer


class FakeResponse:
    def __init__(self, status, payload, headers=None):
        self.status = status
        self.payload = payload
        self.headers = headers or {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def json(self, content_type=None):
        return self.payload


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def request(self, *args, **kwargs):
        self.calls += 1
        return self.responses.pop(0)


class CloudflareTransactionTests(unittest.IsolatedAsyncioTestCase):
    async def test_retryable_server_error_is_retried(self):
        client = FakeClient(
            [
                FakeResponse(503, {"success": False}),
                FakeResponse(200, {"success": True, "result": {}}),
            ]
        )
        config = CloudflareConfig(True, "token", {}, api_base="https://example.invalid")
        with patch.dict(
            "os.environ",
            {
                "HOTPOT_CLOUDFLARE_RETRY_ATTEMPTS": "2",
                "HOTPOT_CLOUDFLARE_RETRY_BASE_SECONDS": "0.001",
            },
        ):
            enforcer = TransactionalCloudflareEnforcer(config, client)
        status, payload = await enforcer._request("GET", "/test")
        self.assertEqual(status, 200)
        self.assertTrue(payload["success"])
        self.assertEqual(client.calls, 2)

    async def test_cleanup_queue_keeps_distinct_memberships_on_shared_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            queue = CloudflareCleanupQueue(Path(tmp))
            shared = {
                "provider": "custom_waf_pool",
                "zone_id": "zone-a",
                "ruleset_id": "ruleset-a",
                "rule_id": "shared-rule",
                "ref": "hotpot_pool_block",
            }
            first = {**shared, "target_value": "1.1.1.1"}
            second = {**shared, "target_value": "2.2.2.2"}
            self.assertEqual(await queue.enqueue("rec-a", [first]), 1)
            self.assertEqual(await queue.enqueue("rec-b", [second]), 1)
            pending = await queue.pending()
            self.assertEqual(len(pending), 2)
            self.assertEqual(
                {row["rule"]["target_value"] for row in pending},
                {"1.1.1.1", "2.2.2.2"},
            )

    async def test_cleanup_jobs_are_durable_and_deduplicated(self):
        with tempfile.TemporaryDirectory() as tmp:
            queue = CloudflareCleanupQueue(Path(tmp))
            rule = {
                "zone_id": "zone-a",
                "ruleset_id": "ruleset-a",
                "rule_id": "rule-a",
                "ref": "hotpot_test",
            }
            self.assertEqual(await queue.enqueue("rec-a", [rule]), 1)
            self.assertEqual(await queue.enqueue("rec-a", [rule]), 0)
            pending = await queue.pending()
            self.assertEqual(len(pending), 1)
            self.assertEqual(pending[0]["rule"]["rule_id"], "rule-a")
            await queue.mark_removed(pending[0]["id"])
            self.assertEqual(await queue.pending(), [])


if __name__ == "__main__":
    unittest.main()
