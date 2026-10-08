from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dashboard.storage_health import DashboardStorageHealth, pre_migration_backup


class StorageHealthTests(unittest.IsolatedAsyncioTestCase):
    def make_database(self, root: Path) -> Path:
        path = root / "dashboard.sqlite3"
        conn = sqlite3.connect(path)
        try:
            conn.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY, value TEXT)")
            conn.execute("INSERT INTO sample(value) VALUES ('ok')")
            conn.commit()
        finally:
            conn.close()
        return path

    async def test_pre_migration_backup_is_online_and_valid(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_database(root)
            with patch.dict(
                "os.environ",
                {
                    "HOTPOT_DASHBOARD_PRE_MIGRATION_BACKUP": "true",
                    "HOTPOT_DASHBOARD_BACKUP_KEEP": "3",
                },
            ):
                backup = pre_migration_backup(root)
            self.assertIsNotNone(backup)
            assert backup is not None
            self.assertEqual(backup["quick_check"].lower(), "ok")
            backup_path = Path(backup["path"])
            self.assertTrue(backup_path.is_file())
            conn = sqlite3.connect(backup_path)
            try:
                self.assertEqual(
                    conn.execute("SELECT value FROM sample").fetchone()[0], "ok"
                )
            finally:
                conn.close()

    async def test_snapshot_reports_quick_check_wal_and_capacity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.make_database(root)
            with patch.dict(
                "os.environ",
                {
                    "HOTPOT_DASHBOARD_DISK_WARN_FREE_GB": "0",
                    "HOTPOT_DASHBOARD_DISK_CRITICAL_FREE_MB": "0",
                    "HOTPOT_DASHBOARD_DB_WARN_MB": "100000",
                    "HOTPOT_DASHBOARD_STORAGE_CHECK_SECONDS": "60",
                },
            ):
                monitor = DashboardStorageHealth(root)
            snapshot = await monitor.maybe_snapshot(force=True)
            self.assertEqual(snapshot["quick_check"].lower(), "ok")
            self.assertEqual(snapshot["status"], "healthy")
            self.assertGreater(snapshot["database"]["size_bytes"], 0)
            self.assertIn("log_frames", snapshot["wal_checkpoint"])
            self.assertGreater(snapshot["filesystem"]["total_bytes"], 0)

            diagnostic = await monitor.backup(label="diagnostic")
            self.assertEqual(diagnostic["quick_check"].lower(), "ok")
            self.assertTrue(Path(diagnostic["path"]).exists())


if __name__ == "__main__":
    unittest.main()
