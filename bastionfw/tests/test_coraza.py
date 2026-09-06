"""Tests for the Coraza WAF audit-log parser and source wiring."""

import json
import unittest

from ed_bt_ade.config import ConfigError, load_config
from ed_bt_ade.parsing import (
    MAX_CORAZA_JSON_DEPTH,
    MAX_CORAZA_LINE_BYTES,
    parse_coraza_audit_line,
)


def _audit(ip: str = "198.51.100.23", **extra) -> str:
    payload = {
        "transaction": {"client_ip": ip, "uri": "/wp-admin?cmd=1"},
        "messages": [{"rule_ids": ["942100", "930120"]}],
        "anomaly_score": 7,
    }
    payload.update(extra)
    return json.dumps(payload)


class CorazaParserTests(unittest.TestCase):
    def test_valid_audit_line_parses(self) -> None:
        detection = parse_coraza_audit_line(_audit())
        self.assertIsNotNone(detection)
        self.assertEqual(detection.rule, "coraza_waf_match")
        self.assertEqual(detection.source, "coraza_audit")
        self.assertEqual(detection.ip, "198.51.100.23")
        self.assertEqual(detection.severity, "high")
        self.assertEqual(detection.score, 7)
        self.assertIn("942100", detection.evidence)

    def test_low_score_is_medium_or_low(self) -> None:
        detection = parse_coraza_audit_line(_audit(anomaly_score=1))
        self.assertEqual(detection.severity, "medium")

    def test_hostile_ip_is_rejected(self) -> None:
        for hostile in ("8.8.8.8; rm -rf /", "999.999.999.999",
                        "127.0.0.1\nextra", ""):
            self.assertIsNone(parse_coraza_audit_line(
                _audit(ip=hostile)), hostile)

    def test_malformed_json_never_raises(self) -> None:
        for broken in ("", "{", "not json", "[1,2,3]", "null",
                       json.dumps(["nested", {"deep": True}])):
            self.assertIsNone(parse_coraza_audit_line(broken))

    def test_deeply_nested_json_is_rejected_not_crashed(self) -> None:
        deep: dict = {"client_ip": "198.51.100.1"}
        for _ in range(MAX_CORAZA_JSON_DEPTH + 8):
            deep = {"child": deep}
        self.assertIsNone(parse_coraza_audit_line(json.dumps(deep)))

    def test_oversized_line_is_rejected(self) -> None:
        big = _audit(pad="x" * (MAX_CORAZA_LINE_BYTES + 16))
        self.assertIsNone(parse_coraza_audit_line(big))

    def test_missing_ip_yields_none(self) -> None:
        payload = {"transaction": {"uri": "/x"}, "anomaly_score": 5}
        self.assertIsNone(parse_coraza_audit_line(json.dumps(payload)))


class CorazaSourceConfigTests(unittest.TestCase):
    def test_source_type_coraza_audit_is_accepted(self) -> None:
        import tempfile
        from pathlib import Path

        document = {
            "log_sources": [{
                "name": "waf", "path": "/var/log/waf/audit.json",
                "source_type": "coraza_audit",
            }],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            config = load_config(path)
        self.assertEqual(config.log_sources[0].source_type, "coraza_audit")

    def test_unknown_source_type_is_rejected(self) -> None:
        import tempfile
        from pathlib import Path

        document = {
            "log_sources": [{
                "name": "waf", "path": "/var/log/waf/audit.json",
                "source_type": "syslog_plus_magic",
            }],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
