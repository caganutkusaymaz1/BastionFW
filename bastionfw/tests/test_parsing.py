import json
import unittest

from ed_bt_ade.parsing import (
    extract_remote_ip,
    normalize_for_detection,
    parse_coraza_audit_line,
)


CORAZA_LINE = {
    "transaction": {
        "timestamp": "2026-09-01T10:00:00Z",
        "unix_timestamp": 1785636000,
        "id": "abc123",
        "client_ip": "198.51.100.42",
        "client_port": 51234,
        "highest_severity": "CRITICAL",
        "is_interrupted": True,
        "request": {"method": "GET", "uri": "/?q=union+select",
                     "http_version": "HTTP/1.1"},
        "response": {"status": 403},
    },
    "messages": [
        {"actionset": "", "message": "SQL Injection Attack Detected",
         "data": {"id": 942100, "severity": "CRITICAL",
                   "msg": "Detects classic SQL injection",
                   "data": "union select", "tags": ["attack-sqli"]}},
        {"actionset": "", "message": "Inbound Anomaly Score Exceeded "
                                       "(Total Score: 15)",
         "data": {"id": 949110, "severity": "CRITICAL",
                   "msg": "Inbound Anomaly Score Exceeded"}},
    ],
}


class ParsingTests(unittest.TestCase):
    def test_json_and_journal_ip_extraction(self) -> None:
        self.assertEqual(extract_remote_ip('{"remote_addr":"198.51.100.7"}'),
                         "198.51.100.7")
        self.assertEqual(extract_remote_ip('{"MESSAGE":"failed from 198.51.100.8"}'),
                         "198.51.100.8")

    def test_double_encoded_payload_is_normalized(self) -> None:
        self.assertIn("union select", normalize_for_detection("union%2520select"))

    def test_coraza_audit_line_binds_score_and_rule_ids(self) -> None:
        event = parse_coraza_audit_line(json.dumps(CORAZA_LINE))
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.ip, "198.51.100.42")
        self.assertEqual(event.anomaly_score, 15)
        self.assertEqual(event.rule_ids, ("942100", "949110"))
        self.assertEqual(event.severity, "critical")
        self.assertTrue(event.interrupted)
        self.assertEqual(event.uri, "/?q=union+select")

    def test_coraza_audit_line_accepts_legacy_layout_and_ports(self) -> None:
        line = json.dumps({
            "transaction": {"time": "x", "remote_address": "203.0.113.7:4444"},
            "request": {"request_line": "POST /login HTTP/1.1"},
            "audit_data": {"anomaly_score": 8, "messages": []},
        })
        event = parse_coraza_audit_line(line)
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual(event.ip, "203.0.113.7")
        self.assertEqual(event.anomaly_score, 8)
        self.assertEqual(event.method, "POST")
        self.assertEqual(event.uri, "/login")

    def test_coraza_audit_line_rejects_noise_and_bad_ip(self) -> None:
        self.assertIsNone(parse_coraza_audit_line("not json"))
        self.assertIsNone(parse_coraza_audit_line(
            json.dumps({"transaction": {"client_ip": "999.1.1.1"}})))
        self.assertIsNone(parse_coraza_audit_line(
            json.dumps({"foo": "bar"})))


if __name__ == "__main__":
    unittest.main()