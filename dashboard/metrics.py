from __future__ import annotations

import asyncio
import json
import math
import os
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


WINDOWS: tuple[tuple[str, int, int], ...] = (
    ("1h", 60 * 60, 120),
    ("24h", 24 * 60 * 60, 144),
    ("7d", 7 * 24 * 60 * 60, 168),
)


class MetricHistory:
    """Durable, low-cardinality operational metric history for the dashboard."""

    def __init__(self, data_dir: Path) -> None:
        data_dir.mkdir(parents=True, exist_ok=True)
        self.path = data_dir / "metrics.sqlite3"
        self.retention_days = max(
            8, int(os.getenv("HOTPOT_DASHBOARD_METRICS_RETENTION_DAYS", "8"))
        )
        self.lock = asyncio.Lock()
        self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS metric_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_metric_samples_ts ON metric_samples(ts)"
            )

    async def record(self, payload: dict[str, Any]) -> None:
        async with self.lock:
            await asyncio.to_thread(self._record_sync, dict(payload))

    def _record_sync(self, payload: dict[str, Any]) -> None:
        now = time.time()
        cutoff = now - self.retention_days * 86400
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO metric_samples(ts, payload_json) VALUES (?, ?)",
                (now, json.dumps(payload, separators=(",", ":"), default=str)),
            )
            conn.execute("DELETE FROM metric_samples WHERE ts < ?", (cutoff,))

    async def trends(self) -> dict[str, Any]:
        async with self.lock:
            rows = await asyncio.to_thread(self._rows_sync)
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "retention_days": self.retention_days,
            "windows": {
                key: self._window(rows, seconds=seconds, max_points=max_points)
                for key, seconds, max_points in WINDOWS
            },
        }

    def _rows_sync(self) -> list[dict[str, Any]]:
        cutoff = time.time() - self.retention_days * 86400
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT ts, payload_json FROM metric_samples WHERE ts >= ? ORDER BY ts ASC",
                (cutoff,),
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(row["payload_json"])
            except (TypeError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict):
                result.append({"ts": float(row["ts"]), **payload})
        return result

    @staticmethod
    def _window(
        rows: list[dict[str, Any]], *, seconds: int, max_points: int
    ) -> dict[str, Any]:
        cutoff = time.time() - seconds
        selected = [row for row in rows if float(row.get("ts", 0)) >= cutoff]
        enriched: list[dict[str, Any]] = []
        previous: dict[str, Any] | None = None
        for row in selected:
            item = dict(row)
            rate = 0.0
            if previous is not None:
                elapsed = max(0.001, float(row["ts"]) - float(previous["ts"]))
                delta = int(row.get("proxied_total", 0) or 0) - int(
                    previous.get("proxied_total", 0) or 0
                )
                if delta >= 0:
                    rate = (delta / elapsed) * 60.0
            item["request_rate_per_minute"] = round(rate, 3)
            enriched.append(item)
            previous = row

        if len(enriched) > max_points:
            step = max(1, math.ceil(len(enriched) / max_points))
            sampled = enriched[::step]
            if sampled and enriched and sampled[-1] is not enriched[-1]:
                sampled.append(enriched[-1])
            enriched = sampled[-max_points:]

        latest = enriched[-1] if enriched else {}
        return {
            "seconds": seconds,
            "points": len(enriched),
            "latest": latest,
            "samples": enriched,
        }


class DashboardMetricsCollector:
    """Poll raw Hotpot status documents and persist aggregate operational samples."""

    def __init__(self, dashboard: Any, history: MetricHistory) -> None:
        self.dashboard = dashboard
        self.history = history
        self.task: asyncio.Task | None = None
        self.errors = 0

    async def start(self) -> None:
        await self.sample()
        if self.task is None or self.task.done():
            self.task = asyncio.create_task(self._loop(), name="hotpot-dashboard-metrics")

    async def stop(self) -> None:
        if self.task is None:
            return
        self.task.cancel()
        await asyncio.gather(self.task, return_exceptions=True)
        self.task = None

    async def _loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(max(5, int(self.dashboard.refresh_seconds)))
                await self.sample()
            except asyncio.CancelledError:
                raise
            except Exception:
                self.errors += 1

    async def _status(self, instance: Any) -> dict[str, Any]:
        try:
            return await self.dashboard.fetch_json(f"{instance.url}/_hotpot/status")
        except Exception:
            self.errors += 1
            return {}

    async def sample(self) -> dict[str, Any]:
        if self.dashboard.client is None:
            return {}
        statuses = await asyncio.gather(
            *(self._status(instance) for instance in self.dashboard.instances)
        )
        payload = self.aggregate(statuses)
        await self.history.record(payload)
        return payload

    @staticmethod
    def aggregate(statuses: list[dict[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {
            "instances": len(statuses),
            "healthy_instances": 0,
            "proxied_total": 0,
            "deceptions_total": 0,
            "tarpits_active": 0,
            "tarpits_total": 0,
            "level1_total": 0,
            "level2_total": 0,
            "level3_total": 0,
            "level4_total": 0,
            "telemetry_queue_depth": 0,
            "telemetry_queue_dropped_total": 0,
            "notification_spool_pending": 0,
            "upstream_failures": 0,
            "telemetry_errors_total": 0,
            "resource_upstream_saturation": 0.0,
            "resource_websocket_saturation": 0.0,
            "resource_buffer_saturation": 0.0,
        }
        latencies: list[float] = []

        for status in statuses:
            if not status:
                result["upstream_failures"] += 1
                continue
            if status.get("healthy"):
                result["healthy_instances"] += 1
            else:
                result["upstream_failures"] += 1
            stats = status.get("stats") or {}
            queue = status.get("telemetry_queue") or {}
            spool = status.get("notification_spool") or {}
            resources = status.get("resource_budget") or {}
            health = status.get("upstream_health") or {}

            result["proxied_total"] += int(stats.get("proxied", 0) or 0)
            result["deceptions_total"] += int(stats.get("deceptions", 0) or 0)
            result["tarpits_active"] += int(stats.get("tarpits_active", 0) or 0)
            result["tarpits_total"] += int(stats.get("tarpits_total", 0) or 0)
            result["telemetry_errors_total"] += int(
                stats.get("telemetry_errors", 0) or 0
            )
            for level in range(1, 5):
                result[f"level{level}_total"] += int(
                    stats.get(f"escalation:{level}", 0) or 0
                )
            result["telemetry_queue_depth"] += int(queue.get("depth", 0) or 0)
            result["telemetry_queue_dropped_total"] += int(
                queue.get("dropped", 0) or 0
            )
            result["notification_spool_pending"] += int(
                spool.get("pending", 0) or 0
            )
            if health.get("latency_ms") is not None:
                try:
                    latencies.append(float(health["latency_ms"]))
                except (TypeError, ValueError):
                    pass

            def saturation(active_key: str, capacity_key: str) -> float:
                active = float(resources.get(active_key, 0) or 0)
                capacity = float(resources.get(capacity_key, 0) or 0)
                return active / capacity if capacity > 0 else 0.0

            result["resource_upstream_saturation"] = max(
                float(result["resource_upstream_saturation"]),
                saturation("upstream_active", "max_upstream_concurrent"),
            )
            result["resource_websocket_saturation"] = max(
                float(result["resource_websocket_saturation"]),
                saturation("websocket_active", "max_websockets"),
            )
            result["resource_buffer_saturation"] = max(
                float(result["resource_buffer_saturation"]),
                saturation("buffered_body_bytes", "max_buffered_body_bytes"),
            )

        result["upstream_latency_ms"] = (
            round(sum(latencies) / len(latencies), 2) if latencies else 0.0
        )
        for key in (
            "resource_upstream_saturation",
            "resource_websocket_saturation",
            "resource_buffer_saturation",
        ):
            result[key] = round(float(result[key]), 4)
        return result
