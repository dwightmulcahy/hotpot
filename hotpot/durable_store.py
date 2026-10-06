from __future__ import annotations

import uuid

from .store import IntelligenceStore


class SourceIdentityStore(IntelligenceStore):
    """Intelligence store with a persistent generation identifier.

    The source ID belongs to the SQLite event store, not the container. It survives
    restarts while the database survives and changes when a fresh database is
    created. Central collectors can therefore detect event-ID reuse safely.
    """

    def _initialize(self) -> None:
        super()._initialize()
        with self._connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS store_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            row = conn.execute(
                "SELECT value FROM store_metadata WHERE key = 'source_id'"
            ).fetchone()
            if row is None:
                source_id = str(uuid.uuid4())
                conn.execute(
                    "INSERT INTO store_metadata(key, value) VALUES ('source_id', ?)",
                    (source_id,),
                )
            else:
                source_id = str(row["value"])
        self.source_id = source_id
