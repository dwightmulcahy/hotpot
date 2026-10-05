import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from hotpot.logging import EventLogger


class EventLoggerTests(unittest.TestCase):
    def test_cleanup_prunes_old_jsonl_and_preserves_unknown_lines(self):
        with tempfile.TemporaryDirectory() as td:
            async def run():
                logger = EventLogger(Path(td))
                logger.path.write_text(
                    json.dumps({"timestamp": "2000-01-01T00:00:00+00:00", "event": "old"}) + "\n" +
                    "legacy malformed line\n",
                    encoding="utf-8",
                )
                await logger.write({"event": "new"})
                deleted = await logger.cleanup(30)
                self.assertEqual(deleted, 1)
                content = logger.path.read_text(encoding="utf-8")
                self.assertNotIn('"event": "old"', content)
                self.assertIn("legacy malformed line", content)
                self.assertIn('"event":"new"', content)
            asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
