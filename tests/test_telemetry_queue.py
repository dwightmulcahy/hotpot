from __future__ import annotations

import asyncio
import unittest

from hotpot.telemetry import BoundedTelemetryQueue


class TelemetryQueueTests(unittest.IsolatedAsyncioTestCase):
    async def test_queue_is_bounded_nonblocking_and_preserves_order(self) -> None:
        entered = asyncio.Event()
        release = asyncio.Event()
        seen: list[int] = []

        async def processor(work):
            seen.append(int(work.event["n"]))
            if work.event["n"] == 1:
                entered.set()
                await release.wait()

        queue = BoundedTelemetryQueue(capacity=1, drain_timeout=1)
        await queue.start(processor)
        self.assertTrue(queue.submit("jsonl", {"n": 1}))
        await asyncio.wait_for(entered.wait(), timeout=1)
        self.assertTrue(queue.submit("jsonl", {"n": 2}))
        self.assertFalse(queue.submit("notify", {"n": 3}))
        self.assertEqual(queue.snapshot()["dropped"], 1)
        self.assertEqual(queue.snapshot()["dropped_by_kind"], {"notify": 1})

        release.set()
        final = await queue.stop()
        self.assertEqual(seen, [1, 2])
        self.assertEqual(final["processed"], 2)
        self.assertEqual(final["depth"], 0)
        self.assertFalse(final["running"])

    async def test_shutdown_timeout_abandons_pending_work(self) -> None:
        entered = asyncio.Event()
        never = asyncio.Event()

        async def processor(work):
            entered.set()
            await never.wait()

        queue = BoundedTelemetryQueue(capacity=2, drain_timeout=0.05)
        await queue.start(processor)
        self.assertTrue(queue.submit("jsonl", {"n": 1}))
        await entered.wait()
        self.assertTrue(queue.submit("notify", {"n": 2}))
        final = await queue.stop()
        self.assertGreaterEqual(final["abandoned"], 2)
        self.assertEqual(final["depth"], 0)
        self.assertFalse(final["running"])


if __name__ == "__main__":
    unittest.main()
