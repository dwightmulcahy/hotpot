from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Awaitable, Callable


@dataclass(frozen=True)
class TelemetryWork:
    kind: str
    event: dict


class BoundedTelemetryQueue:
    """Single-consumer bounded queue for auxiliary request-path telemetry.

    SQLite intelligence persistence remains synchronous and authoritative. This
    queue is deliberately for auxiliary work such as JSONL writes and outbound
    notifications so a slow disk/webhook/SMTP endpoint cannot indefinitely hold
    an HTTP request open. A single consumer preserves enqueue order.
    """

    def __init__(self, *, capacity: int = 2048, drain_timeout: float = 5.0) -> None:
        self.capacity = max(1, int(capacity))
        self.drain_timeout = max(0.1, float(drain_timeout))
        self.queue: asyncio.Queue[TelemetryWork] = asyncio.Queue(maxsize=self.capacity)
        self.task: asyncio.Task | None = None
        self.processor: Callable[[TelemetryWork], Awaitable[None]] | None = None
        self.accepting = False
        self.inflight = 0
        self.enqueued = 0
        self.processed = 0
        self.errors = 0
        self.dropped = 0
        self.abandoned = 0
        self.dropped_by_kind: dict[str, int] = {}

    @property
    def running(self) -> bool:
        return bool(self.task and not self.task.done() and self.accepting)

    async def start(
        self, processor: Callable[[TelemetryWork], Awaitable[None]]
    ) -> None:
        if self.task and not self.task.done():
            return
        self.processor = processor
        self.accepting = True
        self.task = asyncio.create_task(self._worker(), name="hotpot-telemetry")

    def submit(self, kind: str, event: dict) -> bool:
        if not self.running:
            return False
        work = TelemetryWork(str(kind), dict(event))
        try:
            self.queue.put_nowait(work)
        except asyncio.QueueFull:
            self.dropped += 1
            self.dropped_by_kind[work.kind] = self.dropped_by_kind.get(work.kind, 0) + 1
            return False
        self.enqueued += 1
        return True

    async def _worker(self) -> None:
        assert self.processor is not None
        while True:
            work = await self.queue.get()
            self.inflight += 1
            completed = False
            try:
                await self.processor(work)
                completed = True
            except asyncio.CancelledError:
                raise
            except Exception:
                self.errors += 1
                completed = True
            finally:
                if completed:
                    self.processed += 1
                self.inflight = max(0, self.inflight - 1)
                self.queue.task_done()

    async def stop(self) -> dict[str, object]:
        self.accepting = False
        task = self.task
        if task is None:
            return self.snapshot()

        try:
            await asyncio.wait_for(self.queue.join(), timeout=self.drain_timeout)
        except TimeoutError:
            abandoned = self.inflight
            while True:
                try:
                    self.queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                else:
                    abandoned += 1
                    self.queue.task_done()
            self.abandoned += abandoned

        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        self.task = None
        self.processor = None
        return self.snapshot()

    def snapshot(self) -> dict[str, object]:
        return {
            "running": self.running,
            "capacity": self.capacity,
            "depth": self.queue.qsize(),
            "inflight": self.inflight,
            "enqueued": self.enqueued,
            "processed": self.processed,
            "errors": self.errors,
            "dropped": self.dropped,
            "abandoned": self.abandoned,
            "dropped_by_kind": dict(self.dropped_by_kind),
            "drain_timeout_seconds": self.drain_timeout,
            "authoritative_storage": "sqlite",
            "queued_work": ["jsonl", "notifications"],
        }
