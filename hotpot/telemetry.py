from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Awaitable, Callable


@dataclass(frozen=True)
class TelemetryWork:
    kind: str
    event: dict


class BoundedTelemetryQueue:
    """Priority-aware bounded queue for auxiliary request-path telemetry.

    SQLite intelligence persistence remains synchronous and authoritative. JSONL
    traffic may use only the non-reserved portion of queue capacity, while notify
    work can consume the full queue. The worker drains notifications first so a
    JSONL burst cannot crowd out a security alert.
    """

    def __init__(
        self,
        *,
        capacity: int = 2048,
        drain_timeout: float = 5.0,
        notify_reserve: int = 128,
    ) -> None:
        self.capacity = max(1, int(capacity))
        self.drain_timeout = max(0.1, float(drain_timeout))
        self.notify_reserve = min(
            max(0, int(notify_reserve)), max(0, self.capacity - 1)
        )
        self.notify_queue: asyncio.Queue[TelemetryWork] = asyncio.Queue()
        self.normal_queue: asyncio.Queue[TelemetryWork] = asyncio.Queue()
        self._available = asyncio.Event()
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

    @property
    def depth(self) -> int:
        return self.notify_queue.qsize() + self.normal_queue.qsize()

    async def start(
        self, processor: Callable[[TelemetryWork], Awaitable[None]]
    ) -> None:
        if self.task and not self.task.done():
            return
        self.processor = processor
        self.accepting = True
        self.task = asyncio.create_task(self._worker(), name="hotpot-telemetry")

    def _drop(self, kind: str) -> bool:
        self.dropped += 1
        self.dropped_by_kind[kind] = self.dropped_by_kind.get(kind, 0) + 1
        return False

    def submit(self, kind: str, event: dict) -> bool:
        if not self.running:
            return False
        work = TelemetryWork(str(kind), dict(event))
        current = self.depth
        if work.kind == "notify":
            if current >= self.capacity:
                return self._drop(work.kind)
            self.notify_queue.put_nowait(work)
        else:
            normal_limit = self.capacity - self.notify_reserve
            if current >= normal_limit:
                return self._drop(work.kind)
            self.normal_queue.put_nowait(work)
        self.enqueued += 1
        self._available.set()
        return True

    def _next_nowait(self) -> tuple[TelemetryWork, asyncio.Queue[TelemetryWork]] | None:
        try:
            return self.notify_queue.get_nowait(), self.notify_queue
        except asyncio.QueueEmpty:
            pass
        try:
            return self.normal_queue.get_nowait(), self.normal_queue
        except asyncio.QueueEmpty:
            return None

    async def _next(self) -> tuple[TelemetryWork, asyncio.Queue[TelemetryWork]]:
        while True:
            item = self._next_nowait()
            if item is not None:
                return item
            self._available.clear()
            item = self._next_nowait()
            if item is not None:
                self._available.set()
                return item
            await self._available.wait()

    async def _worker(self) -> None:
        assert self.processor is not None
        while True:
            work, owner = await self._next()
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
                owner.task_done()

    async def stop(self) -> dict[str, object]:
        self.accepting = False
        task = self.task
        if task is None:
            return self.snapshot()

        try:
            await asyncio.wait_for(
                asyncio.gather(
                    self.notify_queue.join(), self.normal_queue.join()
                ),
                timeout=self.drain_timeout,
            )
        except TimeoutError:
            abandoned = self.inflight
            for queue in (self.notify_queue, self.normal_queue):
                while True:
                    try:
                        queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                    else:
                        abandoned += 1
                        queue.task_done()
            self.abandoned += abandoned

        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        self.task = None
        self.processor = None
        self._available.clear()
        return self.snapshot()

    def snapshot(self) -> dict[str, object]:
        return {
            "running": self.running,
            "capacity": self.capacity,
            "depth": self.depth,
            "notify_depth": self.notify_queue.qsize(),
            "jsonl_depth": self.normal_queue.qsize(),
            "notify_reserve": self.notify_reserve,
            "inflight": self.inflight,
            "enqueued": self.enqueued,
            "processed": self.processed,
            "errors": self.errors,
            "dropped": self.dropped,
            "abandoned": self.abandoned,
            "dropped_by_kind": dict(self.dropped_by_kind),
            "drain_timeout_seconds": self.drain_timeout,
            "authoritative_storage": "sqlite",
            "queued_work": ["notifications", "jsonl"],
            "priority": "notifications-first",
        }
