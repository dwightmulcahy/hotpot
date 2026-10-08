from __future__ import annotations

import unittest

from hotpot.app import Hotpot
from hotpot.durable_gateway import DurableGatewayHotpot
from hotpot.gateway import GatewayHotpot
from hotpot.production import ProductionHotpot
from hotpot.runtime import HardenedHotpot
from hotpot.runtime_components import ResourceBudget
from hotpot.server import HotpotServer


class ServerArchitectureTests(unittest.IsolatedAsyncioTestCase):
    async def test_legacy_runtime_classes_are_compatibility_aliases(self) -> None:
        self.assertTrue(issubclass(HotpotServer, Hotpot))
        self.assertIs(HardenedHotpot, HotpotServer)
        self.assertIs(ProductionHotpot, HotpotServer)
        self.assertIs(GatewayHotpot, HotpotServer)
        self.assertIs(DurableGatewayHotpot, HotpotServer)

    async def test_global_buffer_budget_is_shared_and_released(self) -> None:
        budget = ResourceBudget(
            max_upstream=2,
            max_websockets=1,
            max_buffered_body_bytes=10,
            acquire_timeout=0.05,
        )
        self.assertTrue(await budget.reserve_buffer(7))
        self.assertFalse(await budget.reserve_buffer(4))
        self.assertEqual(budget.snapshot()["buffered_body_bytes"], 7)
        self.assertEqual(budget.snapshot()["rejected_buffer"], 1)
        await budget.release_buffer(7)
        self.assertEqual(budget.snapshot()["buffered_body_bytes"], 0)

    async def test_concurrency_budgets_fail_closed_without_waiting_forever(self) -> None:
        budget = ResourceBudget(
            max_upstream=1,
            max_websockets=1,
            max_buffered_body_bytes=1024,
            acquire_timeout=0.01,
        )
        self.assertTrue(await budget.acquire_upstream())
        self.assertFalse(await budget.acquire_upstream())
        budget.release_upstream()
        self.assertTrue(await budget.acquire_upstream())
        budget.release_upstream()

        self.assertTrue(await budget.acquire_websocket())
        self.assertFalse(await budget.acquire_websocket())
        budget.release_websocket()


if __name__ == "__main__":
    unittest.main()
