from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any

from .durable_store import SourceIdentityStore
from .logging import EventLogger
from .notification_digest import NotificationDigestStore
from .store import AttackerState


class ResilientEventLogger:
    """Best-effort JSONL logger that never prevents the proxy from starting."""

    def __init__(self, data_dir: Path):
        self.inner: EventLogger | None = None
        try:
            self.inner = EventLogger(data_dir)
        except Exception:
            pass

    async def write(self, event: dict[str, Any]) -> None:
        if self.inner is not None:
            await self.inner.write(event)

    async def cleanup(self, retention_days: int) -> int:
        if self.inner is None:
            return 0
        return await self.inner.cleanup(retention_days)


class ResilientSourceStore:
    """Durable SQLite store wrapper that degrades telemetry without breaking proxying."""

    def __init__(self, data_dir: Path):
        self.inner: SourceIdentityStore | None = None
        self.path: Path | None = None
        self.source_id: str | None = None
        self.notification_digest: NotificationDigestStore | None = None
        try:
            self.inner = SourceIdentityStore(data_dir)
            self.path = self.inner.path
            self.source_id = self.inner.source_id
        except Exception:
            pass
        try:
            self.notification_digest = NotificationDigestStore(data_dir)
        except Exception:
            pass

    async def state_for(self, actor_key: str) -> AttackerState:
        if self.inner is None:
            return AttackerState(actor_key, 0, 0, None, None, None, None, 1)
        return await self.inner.state_for(actor_key)

    async def record(
        self, event: dict[str, Any], *, score: int, escalation_level: int
    ) -> None:
        if self.inner is not None:
            await self.inner.record(
                event, score=score, escalation_level=escalation_level
            )

    async def claim_notification(
        self, actor_key: str, level: int, cooldown_seconds: int
    ) -> bool:
        if self.inner is None:
            return False
        claimed = await self.inner.claim_notification(actor_key, level, cooldown_seconds)
        if not claimed and self.notification_digest is not None:
            try:
                await self.notification_digest.record(actor_key, level)
            except Exception:
                pass
        return claimed

    async def cleanup(
        self, retention_days: int, attacker_retention_days: int
    ) -> dict[str, int]:
        if self.inner is None:
            return {"events_deleted": 0, "attackers_deleted": 0}
        return await self.inner.cleanup(retention_days, attacker_retention_days)

    async def attacker_history(self, actor_key: str, limit: int = 100) -> dict[str, Any]:
        if self.inner is None:
            return {"attacker": None, "events": []}
        return await self.inner.attacker_history(actor_key, limit)

    async def dashboard_snapshot(self, limit: int = 25) -> dict[str, Any]:
        if self.inner is None:
            return {
                "events": 0,
                "unique_ips": 0,
                "top_paths": [],
                "top_categories": [],
                "top_scanners": [],
                "top_offenders": [],
                "top_fingerprints": [],
                "recent": [],
            }
        return await self.inner.dashboard_snapshot(limit)


class ResourceBudget:
    """Global admission and memory budgets shared by all request handlers."""

    def __init__(
        self,
        *,
        max_upstream: int,
        max_websockets: int,
        max_buffered_body_bytes: int,
        acquire_timeout: float,
    ) -> None:
        self.max_upstream = max(1, int(max_upstream))
        self.max_websockets = max(1, int(max_websockets))
        self.max_buffered_body_bytes = max(1, int(max_buffered_body_bytes))
        self.acquire_timeout = max(0.01, float(acquire_timeout))
        self._upstream = asyncio.Semaphore(self.max_upstream)
        self._websockets = asyncio.Semaphore(self.max_websockets)
        self._buffer_lock = asyncio.Lock()
        self.upstream_active = 0
        self.upstream_peak = 0
        self.websocket_active = 0
        self.websocket_peak = 0
        self.buffered_body_bytes = 0
        self.buffered_body_peak = 0
        self.rejected_upstream = 0
        self.rejected_websocket = 0
        self.rejected_buffer = 0

    @classmethod
    def from_env(cls, *, max_request_body: int) -> "ResourceBudget":
        default_buffer = max(max_request_body, max_request_body * 4)
        return cls(
            max_upstream=max(
                1, int(os.getenv("HOTPOT_MAX_UPSTREAM_CONCURRENT", "128"))
            ),
            max_websockets=max(
                1, int(os.getenv("HOTPOT_MAX_WEBSOCKETS", "64"))
            ),
            max_buffered_body_bytes=max(
                max_request_body,
                int(
                    os.getenv(
                        "HOTPOT_MAX_BUFFERED_BODY_BYTES", str(default_buffer)
                    )
                ),
            ),
            acquire_timeout=max(
                0.01,
                float(os.getenv("HOTPOT_RESOURCE_ACQUIRE_TIMEOUT_SECONDS", "1")),
            ),
        )

    async def acquire_upstream(self) -> bool:
        try:
            await asyncio.wait_for(
                self._upstream.acquire(), timeout=self.acquire_timeout
            )
        except TimeoutError:
            self.rejected_upstream += 1
            return False
        self.upstream_active += 1
        self.upstream_peak = max(self.upstream_peak, self.upstream_active)
        return True

    def release_upstream(self) -> None:
        self.upstream_active = max(0, self.upstream_active - 1)
        self._upstream.release()

    async def acquire_websocket(self) -> bool:
        try:
            await asyncio.wait_for(
                self._websockets.acquire(), timeout=self.acquire_timeout
            )
        except TimeoutError:
            self.rejected_websocket += 1
            return False
        self.websocket_active += 1
        self.websocket_peak = max(self.websocket_peak, self.websocket_active)
        return True

    def release_websocket(self) -> None:
        self.websocket_active = max(0, self.websocket_active - 1)
        self._websockets.release()

    async def reserve_buffer(self, amount: int) -> bool:
        amount = max(0, int(amount))
        if amount == 0:
            return True
        async with self._buffer_lock:
            next_value = self.buffered_body_bytes + amount
            if next_value > self.max_buffered_body_bytes:
                self.rejected_buffer += 1
                return False
            self.buffered_body_bytes = next_value
            self.buffered_body_peak = max(
                self.buffered_body_peak, self.buffered_body_bytes
            )
            return True

    async def release_buffer(self, amount: int) -> None:
        amount = max(0, int(amount))
        if amount == 0:
            return
        async with self._buffer_lock:
            self.buffered_body_bytes = max(0, self.buffered_body_bytes - amount)

    def snapshot(self) -> dict[str, int | float]:
        return {
            "max_upstream_concurrent": self.max_upstream,
            "upstream_active": self.upstream_active,
            "upstream_peak": self.upstream_peak,
            "max_websockets": self.max_websockets,
            "websocket_active": self.websocket_active,
            "websocket_peak": self.websocket_peak,
            "max_buffered_body_bytes": self.max_buffered_body_bytes,
            "buffered_body_bytes": self.buffered_body_bytes,
            "buffered_body_peak": self.buffered_body_peak,
            "acquire_timeout_seconds": self.acquire_timeout,
            "rejected_upstream": self.rejected_upstream,
            "rejected_websocket": self.rejected_websocket,
            "rejected_buffer": self.rejected_buffer,
        }
