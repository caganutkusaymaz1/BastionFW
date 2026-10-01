"""IPv6 policy tests (Option B: IPv4-only enforcement).

IPv6 addresses are always parsed safely, but the firewall never bans them.
The ``firewall.ipv6_enabled`` flag defaults to false and the orchestrator
rejects an IPv6 ban explicitly and logs it, rather than passing it to a
driver that only knows the IPv4 nftables set.
"""

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from ed_bt_ade.config import FirewallConfig, load_config
from ed_bt_ade.firewall import FirewallDriver, FirewallOrchestrator
from ed_bt_ade.validation import ValidationError, parse_ip, parse_network


class RecordingDriver(FirewallDriver):
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def block(self, address: str) -> None:
        self.calls.append(("block", address))

    async def unblock(self, address: str) -> None:
        self.calls.append(("unblock", address))


class ValidationIpv6Tests(unittest.TestCase):
    def test_generic_parsers_still_accept_ipv6(self) -> None:
        self.assertEqual(str(parse_ip("2001:db8::1")), "2001:db8::1")
        self.assertEqual(str(parse_network("2001:db8::/32")), "2001:db8::/32")

    def test_ipv6_disabled_rejects_address_and_network(self) -> None:
        with self.assertRaises(ValidationError):
            parse_ip("2001:db8::1", ipv6_enabled=False)
        with self.assertRaises(ValidationError):
            parse_network("2001:db8::/32", ipv6_enabled=False)
        # IPv4 is unaffected.
        self.assertEqual(str(parse_ip("8.8.8.8", ipv6_enabled=False)), "8.8.8.8")


class FirewallIpv6Tests(unittest.TestCase):
    def _orchestrator(self, directory: str, **kwargs) -> FirewallOrchestrator:
        config = FirewallConfig(state_db=Path(directory) / "state.db", **kwargs)
        return FirewallOrchestrator(config, driver=RecordingDriver())

    def test_ipv6_ban_is_rejected_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            firewall = self._orchestrator(directory)
            driver = firewall.driver
            self.assertFalse(asyncio.run(firewall.block("2001:db8::1")))
            self.assertEqual(driver.calls, [])
            self.assertEqual(asyncio.run(firewall.unblock_expired()), 0)
            firewall.close()

    def test_ipv6_ban_is_rejected_even_when_flag_enabled(self) -> None:
        # IPv6 enforcement is not implemented; the flag must not cause a
        # misfire into the IPv4 set.
        with tempfile.TemporaryDirectory() as directory:
            firewall = self._orchestrator(directory, ipv6_enabled=True)
            driver = firewall.driver
            self.assertFalse(asyncio.run(firewall.block("2001:db8::1")))
            self.assertEqual(driver.calls, [])
            firewall.close()

    def test_ipv4_ban_still_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            firewall = self._orchestrator(directory)
            self.assertTrue(asyncio.run(firewall.block("8.8.8.8")))
            firewall.close()

    def test_config_parses_ipv6_enabled_flag(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({
                "log_sources": [{"name": "t", "path": "/tmp/t.log"}],
                "firewall": {"ipv6_enabled": True},
            }), encoding="utf-8")
            config = load_config(path)
            self.assertTrue(config.firewall.ipv6_enabled)
            # Default is reject.
            self.assertFalse(FirewallConfig().ipv6_enabled)


if __name__ == "__main__":
    unittest.main()
