"""Task C: dashboard login rate limiting and audit logging tests."""

import json
import logging
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from ed_bt_ade.dashboard import (
    LOGIN_LOCKOUT_SECONDS,
    LOGIN_MAX_FAILURES,
    clear_login_failures,
    handle_login,
    is_login_locked_out,
    record_login_failure,
    reset_login_rate_limiter,
    start_dashboard_server,
)
from ed_bt_ade.sentinel import Sentinel
from ed_bt_ade.config import AppConfig, FirewallConfig, LogSource, ThreatIntelConfig


class RateLimiterUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_login_rate_limiter()

    def tearDown(self) -> None:
        reset_login_rate_limiter()

    def test_lockout_after_max_failures(self) -> None:
        for step in range(LOGIN_MAX_FAILURES):
            self.assertFalse(is_login_locked_out("1.2.3.4", now=step))
            record_login_failure("1.2.3.4", now=step)
        self.assertTrue(is_login_locked_out("1.2.3.4", now=LOGIN_MAX_FAILURES))

    def test_lockout_expires_after_window(self) -> None:
        base = 1000.0
        for step in range(LOGIN_MAX_FAILURES):
            record_login_failure("1.2.3.4", now=base + step)
        self.assertTrue(is_login_locked_out("1.2.3.4", now=base + 10))
        self.assertFalse(is_login_locked_out(
            "1.2.3.4", now=base + LOGIN_LOCKOUT_SECONDS + 1))

    def test_success_clears_failures(self) -> None:
        for step in range(LOGIN_MAX_FAILURES - 1):
            record_login_failure("1.2.3.4", now=step)
        clear_login_failures("1.2.3.4")
        self.assertFalse(is_login_locked_out("1.2.3.4", now=100))

    def test_memory_cap_is_bounded(self) -> None:
        from ed_bt_ade.dashboard import LOGIN_MAX_TRACKED_IPS

        now = 0.0
        for i in range(LOGIN_MAX_TRACKED_IPS + 50):
            record_login_failure(f"10.0.0.{i % 256}.{i}", now=now)
            now += 0.001
        self.assertLessEqual(len(record_login_failure.__globals__["_login_failures"]),
                             LOGIN_MAX_TRACKED_IPS)


class HandleLoginRateLimitTests(unittest.TestCase):
    def setUp(self) -> None:
        reset_login_rate_limiter()

    def tearDown(self) -> None:
        reset_login_rate_limiter()

    def test_six_wrong_attempts_yield_429_and_correct_token_blocked(self) -> None:
        alerts: list[str] = []
        # Five failures exhaust the window.
        for _ in range(LOGIN_MAX_FAILURES):
            status, _ = handle_login("Bearer wrong", "correct",
                                     client_ip="9.9.9.9", alert_hook=alerts.append)
            self.assertEqual(status, 401)
        # Sixth attempt: wrong token AND even the correct token are refused.
        self.assertEqual(handle_login("Bearer wrong", "correct",
                                      client_ip="9.9.9.9")[0], 429)
        self.assertEqual(handle_login("Bearer correct", "correct",
                                      client_ip="9.9.9.9")[0], 429)
        # Brute-force alert fired exactly once (threshold crossing).
        self.assertEqual(alerts, ["dashboard_brute_force"])

    def test_correct_token_still_works_below_threshold(self) -> None:
        status, cookie = handle_login("Bearer right", "right", client_ip="8.8.8.8")
        self.assertEqual(status, 200)
        self.assertEqual(cookie, "right")
        # A couple of failures do not lock a clean success afterwards.
        handle_login("Bearer nope", "right", client_ip="8.8.8.8")
        status, _ = handle_login("Bearer right", "right", client_ip="8.8.8.8")
        self.assertEqual(status, 200)

    def test_independent_ips_do_not_interfere(self) -> None:
        for _ in range(LOGIN_MAX_FAILURES):
            handle_login("Bearer wrong", "t", client_ip="1.1.1.1")
        self.assertEqual(handle_login("Bearer t", "t", client_ip="2.2.2.2")[0], 200)

    def test_token_never_appears_in_audit_logs(self) -> None:
        captured: list[logging.LogRecord] = []

        class Capture(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                captured.append(record)

        handler = Capture()
        logging.getLogger("bastionfw.dashboard").addHandler(handler)
        try:
            handle_login("Bearer super-secret-token-value", "super-secret-token-value",
                         client_ip="9.9.4.4")
            handle_login("Bearer super-secret-token-value", "other-token",
                         client_ip="9.9.4.4")
        finally:
            logging.getLogger("bastionfw.dashboard").removeHandler(handler)
        for record in captured:
            dumped = json.dumps(record.__dict__, default=str)
            self.assertNotIn("super-secret-token-value", dumped)


class LoginEndpointHttpTests(unittest.TestCase):
    """HTTP-level verification of the 429 path through the real server."""

    def test_http_429_after_repeated_failures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = AppConfig(
                log_sources=(LogSource(name="x", path=root / "a.log"),),
                firewall=FirewallConfig(state_db=root / "fw.db"),
                threat_intel=ThreatIntelConfig(cache_db=root / "ti.db"),
            )
            sentinel = Sentinel(config)
            server = start_dashboard_server("127.0.0.1", 0, sentinel, "correct")
            port = server.server_address[1]
            results: dict[str, object] = {}

            def run() -> None:
                codes: list[int] = []
                for _ in range(LOGIN_MAX_FAILURES + 1):
                    request = urllib.request.Request(
                        f"http://127.0.0.1:{port}/api/login", method="POST",
                        headers={"Authorization": "Bearer wrong"})
                    try:
                        with urllib.request.urlopen(request, timeout=5) as response:
                            codes.append(response.status)
                    except urllib.error.HTTPError as exc:
                        codes.append(exc.code)
                # Even the correct token is refused inside the lockout.
                request = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/login", method="POST",
                    headers={"Authorization": "Bearer correct"})
                try:
                    with urllib.request.urlopen(request, timeout=5) as response:
                        codes.append(response.status)
                except urllib.error.HTTPError as exc:
                    codes.append(exc.code)
                results["codes"] = codes

            thread = threading.Thread(target=run, daemon=True)
            thread.start()
            thread.join(timeout=15)
            server.shutdown()
            codes = results.get("codes", [])
            self.assertEqual(len(codes), LOGIN_MAX_FAILURES + 2, codes)
            self.assertTrue(all(code == 401 for code in codes[:LOGIN_MAX_FAILURES]),
                            codes)
            self.assertEqual(codes[LOGIN_MAX_FAILURES], 429)
            self.assertEqual(codes[-1], 429)  # correct token also rate-limited


if __name__ == "__main__":
    unittest.main()
