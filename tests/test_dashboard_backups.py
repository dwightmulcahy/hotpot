from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dashboard.backups import DashboardBackupManager


class DashboardBackupTests(unittest.IsolatedAsyncioTestCase):
    def _database(self, root: Path) -> None:
        conn = sqlite3.connect(root / "dashboard.sqlite3")
        try:
            conn.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
            conn.execute("INSERT INTO sample(value) VALUES ('hotpot')")
            conn.commit()
        finally:
            conn.close()

    async def test_backup_is_checksummed_manifested_and_restore_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            "os.environ",
            {
                "HOTPOT_DASHBOARD_BACKUPS_ENABLED": "true",
                "HOTPOT_DASHBOARD_BACKUP_KEEP": "2",
                "HOTPOT_DASHBOARD_BACKUP_INTERVAL_HOURS": "24",
            },
            clear=False,
        ):
            root = Path(directory)
            self._database(root)
            manager = DashboardBackupManager(root)
            result = await manager.backup(label="test")
            backup = root / "backups" / result["backup"]
            manifest = backup.with_suffix(backup.suffix + ".json")

            self.assertTrue(backup.is_file())
            self.assertTrue(manifest.is_file())
            self.assertTrue(result["verified"])
            self.assertEqual(result["restore_verification"]["quick_check"], "ok")
            self.assertEqual(len(result["sha256"]), 64)
            persisted = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(persisted["sha256"], result["sha256"])

    async def test_backup_rotation_keeps_configured_operational_backups(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            "os.environ",
            {
                "HOTPOT_DASHBOARD_BACKUPS_ENABLED": "true",
                "HOTPOT_DASHBOARD_BACKUP_KEEP": "2",
            },
            clear=False,
        ):
            root = Path(directory)
            self._database(root)
            manager = DashboardBackupManager(root)
            await manager.backup(label="one")
            await manager.backup(label="two")
            await manager.backup(label="three")
            rows = await manager.list_backups()
            self.assertEqual(len(rows), 2)
            self.assertTrue(all(row["verified"] for row in rows))


if __name__ == "__main__":
    unittest.main()
