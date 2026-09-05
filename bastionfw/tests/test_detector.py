import unittest

from ed_bt_ade.detector import DetectionEngine, LogEvent, SSHBruteForceRule, WebAttackRule


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


if __name__ == "__main__":
    unittest.main()
