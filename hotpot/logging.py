from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


class EventLogger:
    def __init__(self, data_dir: Path):
        data_dir.mkdir(parents=True, exist_ok=True)
        self.path = data_dir / "events.jsonl"
        self._lock = asyncio.Lock()

    async def write(self, event: dict[str, Any]) -> None:
        payload = {"timestamp": datetime.now(timezone.utc).isoformat(), **event}
        line = json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n"
        async with self._lock:
            await asyncio.to_thread(self._append, line)

    def _append(self, line: str) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(line)

    async def cleanup(self, retention_days: int) -> int:
        async with self._lock:
            return await asyncio.to_thread(self._cleanup_sync, retention_days)

    def _cleanup_sync(self, retention_days: int) -> int:
        if not self.path.exists():
            return 0
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
        temp = self.path.with_suffix(".jsonl.tmp")
        kept = deleted = 0
        with self.path.open("r", encoding="utf-8", errors="replace") as src, temp.open("w", encoding="utf-8") as dst:
            for line in src:
                keep = True
                try:
                    payload = json.loads(line)
                    ts = datetime.fromisoformat(str(payload.get("timestamp", "")))
                    keep = ts >= cutoff
                except (ValueError, TypeError, json.JSONDecodeError):
                    # Preserve malformed/legacy lines rather than deleting data we cannot date safely.
                    keep = True
                if keep:
                    dst.write(line)
                    kept += 1
                else:
                    deleted += 1
        temp.replace(self.path)
        return deleted
