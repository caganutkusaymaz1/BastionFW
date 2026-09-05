import asyncio
import tempfile
import unittest
from pathlib import Path

from ed_bt_ade.config import FirewallConfig
from ed_bt_ade.firewall import FirewallDriver, FirewallOrchestrator


class RecordingDriver(FirewallDriver):
    def __init__(self) -> None:
        self.calls = []

    async def block(self, address: str) -> None:
        self.calls.append(("block", address))

    async def unblock(self, address: str) -> None:
        self.calls.append(("unblock", address))


class FirewallTests(unittest.TestCase):
    def test_private_and_whitelisted_addresses_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = FirewallConfig(state_db=Path(directory) / "state.db",
                                    whitelist=("203.0.113.0/24",))
            driver = RecordingDriver()
            firewall = FirewallOrchestrator(config, driver)
            self.assertFalse(asyncio.run(firewall.block("127.0.0.1")))
            self.assertFalse(asyncio.run(firewall.block("10.0.0.2")))
            self.assertFalse(asyncio.run(firewall.block("203.0.113.9")))
            self.assertEqual(driver.calls, [])
            self.assertTrue(asyncio.run(firewall.block("8.8.8.8", duration=1)))
            self.assertFalse(asyncio.run(firewall.block("8.8.8.8")))
            firewall.close()


if __name__ == "__main__":
    unittest.main()
