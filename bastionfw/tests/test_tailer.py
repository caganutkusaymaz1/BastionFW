import asyncio
import logging
import tempfile
import unittest
from pathlib import Path

from ed_bt_ade.config import LogSource
from ed_bt_ade.tailer import AsyncLogTailer, MAX_BUFFER_BYTES

TAILER_LOGGER = logging.getLogger("ed_bt_ade.tailer")


class TailerTests(unittest.TestCase):
    def test_incomplete_line_and_rename_rotation(self) -> None:
        async def scenario() -> None:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "service.log"
                rotated = Path(directory) / "service.log.1"
                path.write_bytes(b"before")
                queue = asyncio.Queue()
                tailer = AsyncLogTailer(LogSource("service", path), queue)
                await tailer._read_available()
                self.assertTrue(queue.empty())
                with path.open("ab") as handle:
                    handle.write(b" rotation\n")
                await tailer._read_available()
                self.assertEqual((await queue.get()).line, "before rotation")
                path.rename(rotated)
                path.write_bytes(b"after rotation\n")
                await tailer._read_available()
                self.assertEqual((await queue.get()).line, "after rotation")
                tailer.close()

        asyncio.run(scenario())

    def test_oversized_line_is_truncated_and_logged(self) -> None:
        async def scenario() -> None:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "noisy.log"
                queue = asyncio.Queue()
                tailer = AsyncLogTailer(LogSource("noisy", path), queue)
                with self.assertLogs(TAILER_LOGGER, level="WARNING") as captured:
                    path.write_bytes(b"A" * (MAX_BUFFER_BYTES + 16)
                                     + b"B\nEND\n")
                    await tailer._read_available()
                self.assertTrue(any("buffer exceeded" in line
                                    for line in captured.output))
                lines = [event.line for event in
                         [await queue.get() for _ in range(queue.qsize())]]
                self.assertIn("END", lines)
                self.assertTrue(all(len(line) <= MAX_BUFFER_BYTES
                                    for line in lines))
                tailer.close()

        asyncio.run(scenario())


if __name__ == "__main__":
    unittest.main()