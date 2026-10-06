from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class _Bucket:
    tokens: float
    updated: float
    last_seen: float
    suppressed_pending: int = 0
    suppressed_total: int = 0


class EventRateLimiter:
    """Token-bucket limiter for persistence work, not request handling.

    Every matching request is still classified and receives the normal deception
    response. This limiter only decides whether the event should be persisted to
    SQLite/JSONL and considered for notifications.
    """

    def __init__(
        self,
        rate_per_minute: int,
        burst: int,
        *,
        ttl_seconds: int = 3600,
        max_sources: int = 10000,
    ) -> None:
        self.rate_per_minute = max(0, int(rate_per_minute))
        self.rate_per_second = self.rate_per_minute / 60.0
        self.burst = max(1, int(burst))
        self.ttl_seconds = max(60, int(ttl_seconds))
        self.max_sources = max(100, int(max_sources))
        self._buckets: dict[str, _Bucket] = {}

    @property
    def enabled(self) -> bool:
        return self.rate_per_minute > 0

    def admit(self, source: str, *, now: float | None = None) -> tuple[bool, int]:
        """Return (persist, previously_suppressed_count).

        When a bucket becomes writable again, the next persisted event carries the
        number of events suppressed since the preceding persisted event. That keeps
        a useful breadcrumb in durable telemetry without writing every flood event.
        """

        if not self.enabled:
            return True, 0

        current = time.monotonic() if now is None else float(now)
        bucket = self._buckets.get(source)
        if bucket is None:
            if len(self._buckets) >= self.max_sources:
                self.prune(now=current, force=True)
            bucket = _Bucket(
                tokens=float(self.burst),
                updated=current,
                last_seen=current,
            )
            self._buckets[source] = bucket

        elapsed = max(0.0, current - bucket.updated)
        bucket.tokens = min(float(self.burst), bucket.tokens + elapsed * self.rate_per_second)
        bucket.updated = current
        bucket.last_seen = current

        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            pending = bucket.suppressed_pending
            bucket.suppressed_pending = 0
            return True, pending

        bucket.suppressed_pending += 1
        bucket.suppressed_total += 1
        return False, 0

    def pending(self, source: str) -> int:
        bucket = self._buckets.get(source)
        return bucket.suppressed_pending if bucket else 0

    def suppressed_total(self, source: str) -> int:
        bucket = self._buckets.get(source)
        return bucket.suppressed_total if bucket else 0

    def prune(self, *, now: float | None = None, force: bool = False) -> int:
        current = time.monotonic() if now is None else float(now)
        cutoff = current - self.ttl_seconds
        stale = [key for key, value in self._buckets.items() if value.last_seen < cutoff]
        for key in stale:
            self._buckets.pop(key, None)

        if force and len(self._buckets) >= self.max_sources:
            # Drop the oldest quarter rather than allowing unbounded source churn to
            # become its own memory-exhaustion vector.
            excess = max(1, self.max_sources // 4)
            oldest = sorted(self._buckets.items(), key=lambda item: item[1].last_seen)[:excess]
            for key, _ in oldest:
                self._buckets.pop(key, None)
                stale.append(key)
        return len(stale)
