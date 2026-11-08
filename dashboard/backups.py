from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .storage_health import _online_backup


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_backup(source: Path) -> dict[str, Any]:
    """Verify a completed backup in place without creating another full database copy."""
    connection = sqlite3.connect(f"file:{source.resolve()}?mode=ro", uri=True, timeout=30)
    try:
        quick_row = connection.execute("PRAGMA quick_check").fetchone()
        quick = str(quick_row[0] if quick_row else "unknown")
        schema_objects = int(
            connection.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type IN ('table','index','trigger','view')"
            ).fetchone()[0]
        )
    finally:
        connection.close()
    return {
        "quick_check": quick,
        "schema_objects": schema_objects,
        "ok": quick.lower() == "ok",
        "method": "direct-read-only",
    }


class DashboardBackupManager:
    """Scheduled, checksummed dashboard backups with restore verification."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.source = data_dir / "dashboard.sqlite3"
        self.backup_dir = data_dir / "backups"
        self.enabled = _env_bool("HOTPOT_DASHBOARD_BACKUPS_ENABLED", True)
        self.interval_seconds = max(
            3600,
            int(float(os.getenv("HOTPOT_DASHBOARD_BACKUP_INTERVAL_HOURS", "24")) * 3600),
        )
        self.keep = max(1, int(os.getenv("HOTPOT_DASHBOARD_BACKUP_KEEP", "7")))
        self.task: asyncio.Task | None = None
        self.last_error: str | None = None
        self.last_run: dict[str, Any] | None = None
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        if not self.enabled:
            return
        try:
            await self.maybe_backup()
        except Exception as exc:
            # A maintenance failure must not prevent the dashboard from starting.
            self.last_error = f"{type(exc).__name__}: {exc}"
        if self.task is None or self.task.done():
            self.task = asyncio.create_task(self._loop(), name="hotpot-dashboard-backups")

    async def stop(self) -> None:
        if self.task is None:
            return
        self.task.cancel()
        await asyncio.gather(self.task, return_exceptions=True)
        self.task = None

    async def _loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(min(3600, max(60, self.interval_seconds // 4)))
                await self.maybe_backup()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {exc}"

    async def maybe_backup(self) -> dict[str, Any] | None:
        if not self.enabled or not self.source.is_file():
            return None
        rows = await self.list_backups()
        newest = rows[0] if rows else None
        if newest:
            try:
                age = time.time() - float(newest.get("created_epoch", 0) or 0)
            except (TypeError, ValueError):
                age = self.interval_seconds + 1
            if age < self.interval_seconds:
                return None
        return await self.backup(label="scheduled")

    async def backup(self, *, label: str = "manual") -> dict[str, Any]:
        async with self._lock:
            try:
                result = await asyncio.to_thread(self._backup_sync, label)
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {exc}"
                raise
            self.last_error = None
            self.last_run = result
            return result

    def _backup_sync(self, label: str) -> dict[str, Any]:
        if not self.source.is_file():
            raise RuntimeError("dashboard database does not exist")
        safe_label = "".join(ch for ch in str(label).lower() if ch.isalnum() or ch in {"-", "_"})[:24] or "backup"
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        destination = self.backup_dir / f"operational-{safe_label}-{stamp}.sqlite3"
        manifest_path = destination.with_suffix(destination.suffix + ".json")
        try:
            online = _online_backup(self.source, destination)
            checksum = _sha256(destination)
            verification = _verify_backup(destination)
            if online["quick_check"].lower() != "ok" or not verification["ok"]:
                raise RuntimeError("backup failed integrity verification")
            created_epoch = destination.stat().st_mtime
            manifest = {
                "schema_version": 1,
                "backup": destination.name,
                "source": self.source.name,
                "created_at": online["created_at"],
                "created_epoch": created_epoch,
                "size_bytes": online["size_bytes"],
                "sha256": checksum,
                "quick_check": online["quick_check"],
                # Keep the existing field name for API/manifest compatibility.
                "restore_verification": verification,
                "verified": True,
            }
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            self._rotate_sync()
            return manifest
        except Exception:
            destination.unlink(missing_ok=True)
            manifest_path.unlink(missing_ok=True)
            raise

    def _rotate_sync(self) -> None:
        backups = sorted(
            self.backup_dir.glob("operational-*.sqlite3"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        for old in backups[self.keep :]:
            old.unlink(missing_ok=True)
            old.with_suffix(old.suffix + ".json").unlink(missing_ok=True)

    async def list_backups(self) -> list[dict[str, Any]]:
        return await asyncio.to_thread(self._list_sync)

    def _list_sync(self) -> list[dict[str, Any]]:
        if not self.backup_dir.exists():
            return []
        rows: list[dict[str, Any]] = []
        for manifest_path in self.backup_dir.glob("operational-*.sqlite3.json"):
            try:
                item = json.loads(manifest_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            backup = self.backup_dir / str(item.get("backup") or "")
            item["present"] = backup.is_file()
            item["manifest"] = manifest_path.name
            rows.append(item)
        rows.sort(key=lambda item: float(item.get("created_epoch", 0) or 0), reverse=True)
        return rows

    async def status(self) -> dict[str, Any]:
        rows = await self.list_backups()
        return {
            "enabled": self.enabled,
            "interval_seconds": self.interval_seconds,
            "keep": self.keep,
            "count": len(rows),
            "last_error": self.last_error,
            "latest": rows[0] if rows else None,
            "backups": rows,
            "restore_verification": "every backup is opened read-only in place and quick_check is required to pass",
        }
