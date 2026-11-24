"""Shared temp-directory teardown for runtime integration tests."""

from __future__ import annotations

import errno
import tempfile
import time


def cleanup_tempdir(
    tmp: tempfile.TemporaryDirectory, attempts: int = 20, delay: float = 0.05
) -> None:
    """Remove ``tmp``, retrying while worker threads finish their last writes.

    ``asyncio.to_thread`` work cannot be cancelled, so a SQLite call started
    just before shutdown can still create/remove journal files while the
    directory is being deleted, which fails with ENOTEMPTY.
    """
    for _ in range(attempts - 1):
        try:
            tmp.cleanup()
            return
        except OSError as exc:
            if exc.errno not in (errno.ENOTEMPTY, errno.EEXIST):
                raise
            time.sleep(delay)
    tmp.cleanup()
