import json
import tempfile
import unittest
from pathlib import Path

from ed_bt_ade.config import load_config
from ed_bt_ade.detector import DetectionEngine, LogEvent, WebAttackRule
from ed_bt_ade.logger import configure_logging
from ed_bt_ade.parsing import extract_remote_ip, normalize_request_data
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


if __name__ == "__main__":
    unittest.main()
