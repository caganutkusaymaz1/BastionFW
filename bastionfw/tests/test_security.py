import asyncio
import json
import os
import socket
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from ed_bt_ade.config import (
    ConfigError,
    FirewallConfig,
    ThreatIntelConfig,
    _validated_url,
    load_config,
)
from ed_bt_ade.detector import DetectionEngine, LogEvent, WebAttackRule
from ed_bt_ade.firewall import FirewallOrchestrator, MockFirewallDriver
from ed_bt_ade.logger import configure_logging
from ed_bt_ade.parsing import extract_remote_ip, normalize_request_data
from ed_bt_ade.threat_intel import ThreatIntelClient
from ed_bt_ade.validation import ValidationError, parse_ip, parse_network, parse_port, parse_protocol


class SecurityRegressionTests(unittest.TestCase):
    def test_multistage_html_unicode_and_case_normalization(self) -> None:
        payload = normalize_request_data(
            query="%253CScRiPt%253E",
            headers={"User-Agent": "x"},
            body="&#x3C;ScRiPt&#x3E;",
        )
        self.assertIn("<script>", payload)
        self.assertEqual(payload, payload.casefold())

    def test_untrusted_forwarded_headers_cannot_spoof_client_ip(self) -> None:
        event = json.dumps({
            "remote_addr": "198.51.100.10",
            "headers": {"X-Forwarded-For": "203.0.113.99"},
        })
        self.assertEqual(extract_remote_ip(event, ("192.0.2.0/24",)),
                         "198.51.100.10")

    def test_trusted_proxy_forwarded_ip_is_accepted(self) -> None:
        event = json.dumps({
            "remote_addr": "192.0.2.10",
            "headers": {"X-Forwarded-For": "203.0.113.99, 192.0.2.10"},
        })
        self.assertEqual(extract_remote_ip(event, ("192.0.2.0/24",)),
                         "203.0.113.99")

    def test_detection_handles_large_adversarial_input(self) -> None:
        event = LogEvent("web", "GET /?value=" + ("%" * 200_000))
        detections = DetectionEngine((WebAttackRule(),)).evaluate(event)
        self.assertEqual(detections, [])

    def test_config_validates_trusted_proxies_and_rotating_log_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({
                "log_sources": [{"name": "test", "path": "/tmp/test.log"}],
                "trusted_proxies": ["192.0.2.0/24"],
                "log_file": str(Path(directory) / "logs" / "bastionfw.log"),
            }))
            config = load_config(path)
            self.assertEqual(config.trusted_proxies, ("192.0.2.0/24",))
            configure_logging(config.log_level, config.log_file)
            self.assertTrue(config.log_file.exists())

    def test_firewall_state_db_is_owner_only(self) -> None:
        if os.name != "posix":
            self.skipTest("POSIX permission bits only")
        with tempfile.TemporaryDirectory() as directory:
            config = FirewallConfig(state_db=Path(directory) / "state.db")
            firewall = FirewallOrchestrator(config, MockFirewallDriver())
            try:
                mode = stat.S_IMODE(os.stat(config.state_db).st_mode)
                self.assertEqual(mode, 0o600)
            finally:
                firewall.close()

    def test_threat_intel_request_encodes_and_validates_ip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = ThreatIntelConfig(
                enabled=True,
                cache_db=Path(directory) / "cache.sqlite3",
                abuseipdb_url="https://api.example.com/check",
            )
            client = ThreatIntelClient(config)
            captured: dict[str, str] = {}

            class FakeResponse:
                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return False

                def read(self):
                    return b'{"data": {"abuseConfidenceScore": 42}}'

            def fake_urlopen(request, timeout=0):
                captured["url"] = request.full_url
                return FakeResponse()

            with patch("ed_bt_ade.threat_intel.urlopen", fake_urlopen):
                reputation = client._request("8.8.8.8")
            self.assertEqual(captured["url"], "https://api.example.com/check?ipAddress=8.8.8.8")
            self.assertEqual(reputation.score, 42.0)
            # Non-IP payloads must never reach the URL construction.
            with self.assertRaises(ValidationError):
                client._request("8.8.8.8; rm -rf /")

    def test_network_validation_rejects_noncanonical_or_invalid_values(self) -> None:
        self.assertEqual(str(parse_ip("2001:db8::1")), "2001:db8::1")
        self.assertEqual(str(parse_network("192.0.2.0/24")), "192.0.2.0/24")
        self.assertEqual(parse_port("443"), 443)
        self.assertEqual(parse_protocol("TCP"), "tcp")
        for value in ("192.0.2.1/24", "192.0.2.999", "0", "65536"):
            with self.assertRaises(ValidationError):
                (parse_network(value) if "/" in value else
                 parse_port(value) if value.isdigit() else parse_ip(value))
        with self.assertRaises(ValidationError):
            parse_protocol("esp")

    @staticmethod
    def _resolved(*addresses: str):
        """Build a socket.getaddrinfo stand-in returning ``addresses``."""
        def fake_getaddrinfo(host, port, *args, **kwargs):
            return [
                (socket.AF_INET6 if ":" in address else socket.AF_INET,
                 socket.SOCK_STREAM, 6, "", (address, port or 0))
                for address in addresses
            ]
        return fake_getaddrinfo

    def test_ssrf_rejects_hostname_resolving_to_loopback(self) -> None:
        with patch("ed_bt_ade.config.socket.getaddrinfo",
                   self._resolved("127.0.0.1")):
            with self.assertRaises(ConfigError):
                _validated_url("http://localhost/", "k")

    def test_ssrf_rejects_hostname_resolving_to_metadata(self) -> None:
        with patch("ed_bt_ade.config.socket.getaddrinfo",
                   self._resolved("169.254.169.254")):
            with self.assertRaises(ConfigError):
                _validated_url("http://some-internal-name/", "k")

    def test_ssrf_rejects_hostname_that_does_not_resolve(self) -> None:
        def failing_getaddrinfo(host, port, *args, **kwargs):
            raise socket.gaierror("no address associated with hostname")

        with patch("ed_bt_ade.config.socket.getaddrinfo", failing_getaddrinfo):
            with self.assertRaises(ConfigError) as ctx:
                _validated_url("http://unresolvable.invalid/", "k")
        self.assertIn("could not be resolved", str(ctx.exception))

    def test_ssrf_allowlisted_hostname_accepted_even_if_private(self) -> None:
        resolver = Mock(return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0)),
        ])
        with patch("ed_bt_ade.config.socket.getaddrinfo", resolver):
            self.assertEqual(
                _validated_url("http://waf:8080/audit", "k",
                               trusted_internal_hosts=("waf",)),
                "http://waf:8080/audit")
        # Allowlist is checked before DNS, so no lookup is performed.
        resolver.assert_not_called()

    def test_ssrf_allows_public_hostname(self) -> None:
        with patch("ed_bt_ade.config.socket.getaddrinfo",
                   self._resolved("104.26.13.38")):
            self.assertEqual(
                _validated_url("https://api.abuseipdb.com/api/v2/check", "k"),
                "https://api.abuseipdb.com/api/v2/check")


if __name__ == "__main__":
    unittest.main()
