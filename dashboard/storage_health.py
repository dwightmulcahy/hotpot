from __future__ import annotations

import asyncio
import os
import shutil
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _online_backup(source: Path, destination: Path) -> dict[str, Any]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    source_conn = sqlite3.connect(source, timeout=30)
    destination_conn = sqlite3.connect(destination, timeout=30)
    try:
        source_conn.backup(destination_conn)
        row = destination_conn.execute("PRAGMA quick_check").fetchone()
        quick = str(row[0] if row else "unknown")
    finally:
        destination_conn.close()
        source_conn.close()
    return {
        "path": str(destination),
        "size_bytes": destination.stat().st_size,
        "quick_check": quick,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def pre_migration_backup(data_dir: Path) -> dict[str, Any] | None:
    """Create an online backup before dashboard store constructors run migrations."""

    if not _env_bool("HOTPOT_DASHBOARD_PRE_MIGRATION_BACKUP", True):
        return None
    source = data_dir / "dashboard.sqlite3"
    if not source.is_file() or source.stat().st_size == 0:
        return None
    backup_dir = data_dir / "backups"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    destination = backup_dir / f"pre-migration-{stamp}.sqlite3"
    result = _online_backup(source, destination)
    if result["quick_check"].lower() != "ok":
        try:
            destination.unlink()
        except OSError:
            pass
        raise RuntimeError(
            "pre-migration dashboard backup failed SQLite quick_check"
        )
    keep = max(1, int(os.getenv("HOTPOT_DASHBOARD_BACKUP_KEEP", "7")))
    backups = sorted(
        backup_dir.glob("pre-migration-*.sqlite3"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for old in backups[keep:]:
        try:
            old.unlink()
        except OSError:
            pass
    return result


class DashboardStorageHealth:
    """Periodic SQLite integrity, WAL and filesystem-capacity monitoring."""

    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.path = data_dir / "dashboard.sqlite3"
        self.backup_dir = data_dir / "backups"
        self.interval_seconds = max(
            60,
            int(os.getenv("HOTPOT_DASHBOARD_STORAGE_CHECK_SECONDS", "900")),
        )
        self.warn_free_bytes = max(
            0,
            int(
                float(os.getenv("HOTPOT_DASHBOARD_DISK_WARN_FREE_GB", "2"))
                * 1024
                * 1024
                * 1024
            ),
        )
        self.critical_free_bytes = max(
            0,
            int(
                float(os.getenv("HOTPOT_DASHBOARD_DISK_CRITICAL_FREE_MB", "512"))
                * 1024
                * 1024
            ),
        )
        self.warn_db_bytes = max(
            0,
            int(
                float(os.getenv("HOTPOT_DASHBOARD_DB_WARN_MB", "1024"))
                * 1024
                * 1024
            ),
        )
        self.keep_backups = max(
            1, int(os.getenv("HOTPOT_DASHBOARD_BACKUP_KEEP", "7"))
        )
        self._last_checked_monotonic = 0.0
        self._cached: dict[str, Any] = {}

    async def maybe_snapshot(self, *, force: bool = False) -> dict[str, Any]:
        now = time.monotonic()
        if (
            not force
            and self._cached
            and now - self._last_checked_monotonic < self.interval_seconds
        ):
            return dict(self._cached)
        snapshot = await asyncio.to_thread(self._snapshot_sync)
        self._last_checked_monotonic = now
        self._cached = snapshot
        return dict(snapshot)

    def _snapshot_sync(self) -> dict[str, Any]:
        checked_at = datetime.now(timezone.utc).isoformat()
        usage = shutil.disk_usage(self.data_dir)
        db_size = self.path.stat().st_size if self.path.exists() else 0
        wal_path = Path(str(self.path) + "-wal")
        shm_path = Path(str(self.path) + "-shm")
        wal_size = wal_path.stat().st_size if wal_path.exists() else 0
        shm_size = shm_path.stat().st_size if shm_path.exists() else 0
        quick = "missing"
        checkpoint = {"busy": 0, "log_frames": 0, "checkpointed_frames": 0}
        error = None
        if self.path.exists():
            try:
                conn = sqlite3.connect(self.path, timeout=30)
                try:
                    row = conn.execute("PRAGMA quick_check").fetchone()
                    quick = str(row[0] if row else "unknown")
                    checkpoint_row = conn.execute(
                        "PRAGMA wal_checkpoint(PASSIVE)"
                    ).fetchone()
                    if checkpoint_row and len(checkpoint_row) >= 3:
                        checkpoint = {
                            "busy": int(checkpoint_row[0] or 0),
                            "log_frames": int(checkpoint_row[1] or 0),
                            "checkpointed_frames": int(checkpoint_row[2] or 0),
                        }
                finally:
                    conn.close()
            except Exception as exc:
                quick = "error"
                error = f"{type(exc).__name__}: {exc}"

        warnings: list[str] = []
        status = "healthy"
        if quick.lower() != "ok":
            status = "critical"
            warnings.append(f"SQLite quick_check={quick}")
        if usage.free <= self.critical_free_bytes:
            status = "critical"
            warnings.append("filesystem free space is below the critical threshold")
        elif usage.free <= self.warn_free_bytes:
            if status != "critical":
                status = "warning"
            warnings.append("filesystem free space is below the warning threshold")
        if self.warn_db_bytes and db_size >= self.warn_db_bytes:
            if status == "healthy":
                status = "warning"
            warnings.append("dashboard database size exceeds the warning threshold")
        if checkpoint["busy"]:
            if status == "healthy":
                status = "warning"
            warnings.append("WAL checkpoint reported a busy reader/writer")
        if error:
            warnings.append(error)

        return {
            "status": status,
            "checked_at": checked_at,
            "quick_check": quick,
            "database": {
                "path": str(self.path),
                "size_bytes": db_size,
                "wal_size_bytes": wal_size,
                "shm_size_bytes": shm_size,
            },
            "wal_checkpoint": checkpoint,
            "filesystem": {
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free,
                "free_percent": round((usage.free / usage.total) * 100, 2)
                if usage.total
                else 0.0,
                "warning_free_bytes": self.warn_free_bytes,
                "critical_free_bytes": self.critical_free_bytes,
            },
            "database_warning_bytes": self.warn_db_bytes,
            "warnings": warnings,
            "check_interval_seconds": self.interval_seconds,
            "backup_directory": str(self.backup_dir),
            "backup_keep": self.keep_backups,
        }

    async def backup(self, *, label: str = "diagnostic") -> dict[str, Any]:
        return await asyncio.to_thread(self._backup_sync, label)

    def _backup_sync(self, label: str) -> dict[str, Any]:
        if not self.path.is_file():
            raise RuntimeError("dashboard database does not exist")
        safe_label = "".join(
            char for char in str(label).lower() if char.isalnum() or char in {"-", "_"}
        )[:32] or "backup"
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        destination = self.backup_dir / f"{safe_label}-{stamp}.sqlite3"
        result = _online_backup(self.path, destination)
        backups = sorted(
            self.backup_dir.glob("*.sqlite3"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        for old in backups[self.keep_backups :]:
            try:
                old.unlink()
            except OSError:
                pass
        return result
