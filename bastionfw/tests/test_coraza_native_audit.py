"""Native Coraza/CRS audit parsing (real-world shape).

A real Coraza + OWASP CRS 4.25 audit record (captured from the deployed WAF
container via /var/log/waf/audit.json) carries **no structured rule
metadata**: there is no ``rule_id`` field and no ``anomaly_score`` field.
Both live inside the human-readable ``messages[].error_message`` text:

    Coraza: Warning. Inbound Anomaly Score Exceeded (Total Score: 5)
    [file "@owasp_crs/REQUEST-949-BLOCKING-EVALUATION.conf"] [id "949110"]
    ... [uri "/?id=1%27+OR+%271%27%3D%271"]

Without message-text extraction such a record parsed as ``severity='low'`` and
``rule='coraza_audit'``, which meant a genuine CRS hit never reached the ban
loop. These tests pin the native shape, and pin the security boundary that the
extraction must respect: attacker-controlled *request* content is never
scanned, so it cannot inject a rule id or inflate the anomaly score.
"""

import json
import unittest

from ed_bt_ade.parsing import parse_coraza_audit_line

# Faithful transcription of a real CRS 4.25 audit record (client IP replaced
# with a documentation address; structure and message text are unchanged).
NATIVE_AUDIT = {
    "transaction": {
        "timestamp": "2026/10/01 19:41:39",
        "unix_timestamp": 1790883699901977407,
        "id": "tLgSPvwruBCqMuZS",
        "client_ip": "203.0.113.7",
        "client_port": 0,
        "host_ip": "",
        "host_port": 0,
        "server_id": "localhost",
        "request": {
            "method": "GET",
            "http_version": 1.1,
            "uri": "/?id=1%27+OR+%271%27%3D%271",
            "headers": {"User-Agent": ["curl/8.5.0"]},
        },
        "response": {"status_code": 403, "headers": {}},
        "producer": {
            "modsecurity": "Coraza",
            "connector": "Caddy",
            "secrules_engine": "On",
            "secrules_loaded": 1,
            "secrules_matched": 2,
            "crs": {"crs_version": "4.25.0", "crs_setup_version": "4.25.0"},
        },
        "highest_severity": "CRITICAL",
        "is_interrupted": True,
    },
    "messages": [
        {
            "actionset": "",
            "message": "",
            "error_message": (
                'Coraza: Warning. Inbound Anomaly Score Exceeded (Total Score: 5) '
                '[file "@owasp_crs/REQUEST-949-BLOCKING-EVALUATION.conf"] '
                '[line "7664"] [id "949110"] [rev ""] '
                '[msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [data ""] '
                '[severity "unknown"] [ver "OWASP_CRS/4.25.0"] [maturity "0"] '
                '[accuracy "0"] [tag "anomaly-evaluation"] [tag "OWASP_CRS"] '
                '[hostname ""] [uri "/?id=1%27+OR+%271%27%3D%271"] '
                '[unique_id "tLgSPvwruBCqMuZS"]'
            ),
            "data": None,
        },
        {
            "actionset": "",
            "message": "",
            "error_message": (
                'Coraza: Warning. SQL Injection Attack Detected via libinjection '
                '[file "@owasp_crs/rules/REQUEST-942-ATTACK-SQLI.conf"] '
                '[line "29"] [id "942100"] [rev ""] '
                '[msg "SQL Injection Attack Detected via libinjection"] '
                '[data "Matched Data: 1\' OR \'1\'=\'1 found within ARGS: id"] '
                '[severity "CRITICAL"] [ver "OWASP_CRS/4.25.0"] [maturity "0"] '
                '[accuracy "0"] [tag "attack-sqli"] [tag "OWASP_CRS"] '
                '[capec/1000/152/66"] [hostname ""] '
                '[uri "/?id=1%27+OR+%271%27%3D%271"] [unique_id "tLgSPvwruBCqMuZS"]'
            ),
            "data": None,
        },
    ],
}


class NativeAuditParsingTests(unittest.TestCase):
    def test_native_audit_extracts_rule_ids_and_client_ip(self) -> None:
        detection = parse_coraza_audit_line(json.dumps(NATIVE_AUDIT))
        self.assertIsNotNone(detection)
        self.assertEqual(detection.ip, "203.0.113.7")
        self.assertEqual(detection.source, "coraza_audit")
        # A confirmed CRS match is a blocking-capable rule.
        self.assertEqual(detection.rule, "coraza_waf_match")
        self.assertIn("942100", detection.evidence)
        self.assertIn("949110", detection.evidence)

    def test_native_audit_anomaly_score_drives_severity(self) -> None:
        detection = parse_coraza_audit_line(json.dumps(NATIVE_AUDIT))
        # "Total Score: 5" is the CRS critical threshold -> high severity.
        self.assertEqual(detection.score, 5)
        self.assertEqual(detection.severity, "high")

    def test_scalar_rule_id_field_is_honored(self) -> None:
        payload = {
            "transaction": {"client_ip": "203.0.113.8"},
            "messages": [{"rule_id": "942100", "error_message": ""}],
        }
        detection = parse_coraza_audit_line(json.dumps(payload))
        self.assertEqual(detection.rule, "coraza_waf_match")
        self.assertIn("942100", detection.evidence)

    def test_request_content_cannot_inject_rule_id_or_score(self) -> None:
        """Attacker-controlled uri/headers must never influence the decision."""
        payload = {
            "transaction": {
                "client_ip": "203.0.113.9",
                "request": {
                    "uri": '/?q=%5Bid%20%221234567%22%5D%20Total%20Score%3A%2099',
                    "headers": {"User-Agent": ['x" [id "999999"] Total Score: 999']},
                },
            },
            "messages": [],
        }
        detection = parse_coraza_audit_line(json.dumps(payload))
        self.assertIsNotNone(detection)
        # No rule id and no score leak from request content -> not blockable.
        self.assertEqual(detection.rule, "coraza_audit")
        self.assertEqual(detection.score, 1)
        self.assertEqual(detection.severity, "low")
        self.assertNotIn("999999", detection.evidence)
        self.assertNotIn("1234567", detection.evidence)

    def test_low_anomaly_score_stays_below_blocking_threshold(self) -> None:
        payload = {
            "transaction": {"client_ip": "203.0.113.10"},
            "messages": [{
                "error_message": ('Coraza: Warning. Inbound Anomaly Score '
                                  'Exceeded (Total Score: 3) [id "942100"]'),
            }],
        }
        detection = parse_coraza_audit_line(json.dumps(payload))
        self.assertEqual(detection.score, 3)
        self.assertEqual(detection.severity, "medium")
        self.assertIn("942100", detection.evidence)

    def test_oversized_message_text_is_bounded_not_crashed(self) -> None:
        payload = {
            "transaction": {"client_ip": "203.0.113.11"},
            "messages": [{"error_message": '[id "942100"] ' + "x" * 200_000}],
        }
        detection = parse_coraza_audit_line(json.dumps(payload))
        self.assertIsNotNone(detection)
        self.assertIn("942100", detection.evidence)


if __name__ == "__main__":
    unittest.main()