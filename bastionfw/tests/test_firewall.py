import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ed_bt_ade.config import FirewallConfig
from ed_bt_ade.firewall import (
    FirewallDriver,
    FirewallOrchestrator,
    FirewallUnavailable,
    MockFirewallDriver,
    detect_driver,
)


class RecordingDriver(FirewallDriver):
    def __init__(self) -> None:
        self.calls = []

    async def block(self, address: str) -> None:
        self.calls.append(("block", address))

    async def unblock(self, address: str) -> None:
        self.calls.append(("unblock", address))


class UnavailableDriver(FirewallDriver):
    async def block(self, address: str) -> None:
        raise FirewallUnavailable("permission denied")

    async def unblock(self, address: str) -> None:
        raise FirewallUnavailable("permission denied")


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

    def test_unavailable_driver_falls_back_without_recording_ban(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = FirewallConfig(state_db=Path(directory) / "state.db")
            firewall = FirewallOrchestrator(config, UnavailableDriver())
            self.assertFalse(asyncio.run(firewall.block("8.8.8.8")))
            self.assertIsInstance(firewall.driver, MockFirewallDriver)
            self.assertEqual(asyncio.run(firewall.unblock_expired()), 0)
            firewall.close()

    def test_missing_configured_executable_uses_mock_driver(self) -> None:
        config = FirewallConfig(backend="iptables", enabled=True)
        with patch("ed_bt_ade.firewall.shutil.which", return_value=None):
            self.assertIsInstance(detect_driver(config), MockFirewallDriver)

    def test_unblock_and_purge_all_clear_every_layer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = FirewallConfig(state_db=Path(directory) / "state.db")
            driver = RecordingDriver()
            firewall = FirewallOrchestrator(config, driver)
            self.assertTrue(asyncio.run(firewall.block("8.8.8.8", duration=3600)))
            self.assertTrue(asyncio.run(firewall.block("1.1.1.1", duration=1)))
            self.assertEqual(asyncio.run(firewall.unblock("9.9.9.9")), False)
            self.assertEqual(asyncio.run(firewall.unblock("8.8.8.8")), True)
            self.assertNotIn("8.8.8.8", firewall.active_addresses())
            purged = asyncio.run(firewall.purge_all())
            self.assertEqual(purged, 1)
            self.assertEqual(firewall.active_addresses(), [])
            self.assertEqual(asyncio.run(firewall.unblock_expired()), 0)
            firewall.close()


if __name__ == "__main__":
    unittest.main()
