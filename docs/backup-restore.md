# Dashboard backup and restore workflow

Hotpot's dashboard keeps its authoritative cross-app intelligence in `/data/dashboard.sqlite3` by default. Operational backups are enabled by default and are created with SQLite's online backup API so WAL-mode writers do not need to be stopped.

Configuration:

```dotenv
HOTPOT_DASHBOARD_BACKUPS_ENABLED=true
HOTPOT_DASHBOARD_BACKUP_INTERVAL_HOURS=24
HOTPOT_DASHBOARD_BACKUP_KEEP=7
```

Each operational backup is written under `/data/backups` with a JSON manifest containing its SHA-256 checksum, size, creation time, SQLite `quick_check` result, and restore-verification result. Before a backup is accepted, Hotpot restores it into a temporary SQLite database and requires `PRAGMA quick_check` to return `ok`.

The authenticated dashboard API exposes `GET /api/backups`. A CSRF-protected operator can request an immediate backup with `POST /api/backups/run` and `X-Hotpot-Action: backup-now`. Versioned `/api/v1/backups` equivalents are available as well.

Restore procedure: stop the dashboard container, preserve the current `/data/dashboard.sqlite3` and any `-wal`/`-shm` files, copy the selected verified `.sqlite3` backup into place as `/data/dashboard.sqlite3`, ensure the container UID/GID can read and write it, then recreate the dashboard. Do not copy an old `-wal` or `-shm` file alongside a restored backup.
