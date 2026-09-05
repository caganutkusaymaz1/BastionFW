import asyncio
import tempfile
import unittest
from pathlib import Path

from ed_bt_ade.config import LogSource
from ed_bt_ade.tailer import AsyncLogTailer


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


if __name__ == "__main__":
    unittest.main()