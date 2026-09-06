import json
import unittest

from ed_bt_ade.detector import (
    CorazaAuditRule,
    DetectionEngine,
    LogEvent,
    SSHBruteForceRule,
    WebAttackRule,
)


class DetectorTests(unittest.TestCase):
    def test_ssh_threshold(self) -> None:
        engine = DetectionEngine((SSHBruteForceRule(3, 60),))
        for _ in range(2):
            self.assertFalse(engine.evaluate(LogEvent("auth", "Failed password for root from 203.0.113.4")))
        detections = engine.evaluate(LogEvent("auth", "Failed password for root from 203.0.113.4"))
        self.assertEqual(detections[0].rule, "ssh_brute_force")

    def test_combined_web_signatures(self) -> None:
        engine = DetectionEngine((WebAttackRule(2),))
        event = LogEvent("web", 'GET /?x=1%27 union select password from users <script>')
        detections = engine.evaluate(event)
        self.assertEqual(detections[0].rule, "web_attack")

    def test_coraza_audit_line_becomes_a_native_detection(self) -> None:
        line = json.dumps({
            "transaction": {
                "client_ip": "198.51.100.42",
                "is_interrupted": True,
                "request": {"uri": "/?q=union+select"},
            },
            "messages": [{"message": "SQL Injection Attack Detected",
                           "data": {"id": 942100, "severity": "CRITICAL"}}],
        })
        engine = DetectionEngine((CorazaAuditRule(),))
        detections = engine.evaluate(LogEvent("coraza_waf", line,
                                              source_type="coraza_audit"))
        self.assertEqual(len(detections), 1)
        detection = detections[0]
        self.assertEqual(detection.rule, "coraza_waf")
        self.assertEqual(detection.severity, "critical")
        self.assertEqual(detection.ip, "198.51.100.42")
        self.assertEqual(detection.rule_ids, ("942100",))
        self.assertTrue(detection.interrupted)
        self.assertEqual(engine.evaluate(LogEvent("coraza_waf", "plain text")), [])


if __name__ == "__main__":
    unittest.main()
