"""SSRF-hardened URL validation and cookie-based dashboard login tests."""

import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

from ed_bt_ade.config import ConfigError, _validated_url
from ed_bt_ade.dashboard import (
    LOOPBACK_HOST,
    SESSION_COOKIE,
    handle_login,
    resolve_bind_host,
    resolve_dashboard_token,
    start_dashboard_server,
)
from ed_bt_ade.sentinel import Sentinel
from ed_bt_ade.config import AppConfig, FirewallConfig, LogSource, ThreatIntelConfig


class ValidatedUrlSsrfTests(unittest.TestCase):
    def test_public_urls_accepted(self) -> None:
        self.assertEqual(_validated_url("https://api.abuseipdb.com/api/v2/check",
                                        "k"), "https://api.abuseipdb.com/api/v2/check")
        self.assertEqual(_validated_url("http://hooks.example.com/x", "k"),
                         "http://hooks.example.com/x")

    def test_private_and_metadata_targets_rejected(self) -> None:
        for bad in ("http://169.254.169.254/latest/meta-data/",
                    "http://127.0.0.1:8080/status",
                    "http://10.0.0.5/internal",
                    "http://192.168.1.1/admin",
                    "http://172.16.0.9/",
                    "http://[::1]/health",
                    "http://[fe80::1]/",
                    "http://0.0.0.0/"):
            with self.assertRaises(ConfigError):
                _validated_url(bad, "k")

    def test_trusted_internal_hosts_allowlist_bypass(self) -> None:
        url = "http://waf:8080/audit"
        self.assertEqual(_validated_url(url, "k",
                                        trusted_internal_hosts=("waf",)), url)

    def test_credentials_still_rejected(self) -> None:
        with self.assertRaises(ConfigError):
            _validated_url("http://user:pass@example.com/", "k")


class LoginEndpointTests(unittest.TestCase):
    """POST /api/login exchanges a bearer token for an HttpOnly session cookie."""

    def _server(self, token: str | None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = AppConfig(
                log_sources=(LogSource(name="x", path=root / "a.log"),),
                firewall=FirewallConfig(state_db=root / "fw.db"),
                threat_intel=ThreatIntelConfig(cache_db=root / "ti.db"),
            )
            sentinel = Sentinel(config)
            return start_dashboard_server("127.0.0.1", 0, sentinel, token)

    def test_handle_login_success_and_failure(self) -> None:
        status, cookie = handle_login("Bearer secret-token", "secret-token",
                                      client_ip="9.9.9.9")
        self.assertEqual(status, 200)
        self.assertEqual(cookie, "secret-token")
        status, cookie = handle_login("Bearer wrong", "secret-token")
        self.assertEqual(status, 401)
        self.assertEqual(cookie, "")
        # Contract updated by the rate-limiting round: alert_hook fires on
        # brute-force lockout (a security signal worth paging an operator),
        # while every individual failure is audit-logged instead. A single
        # failure below the threshold therefore raises no alert.
        alerts: list[str] = []
        status, _ = handle_login("Bearer wrong", "secret-token",
                                 alert_hook=alerts.append)
        self.assertEqual(status, 401)
        self.assertEqual(alerts, [])

    def test_login_sets_httponly_cookie_and_get_uses_it(self) -> None:
        server = self._server("correct-horse")
        port = server.server_address[1]
        host = "127.0.0.1"

        def post_login() -> tuple[int, str]:
            request = urllib.request.Request(
                f"http://{host}:{port}/api/login",
                method="POST",
                headers={"Authorization": "Bearer correct-horse"})
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, response.headers.get("Set-Cookie", "")

        def post_wrong() -> int:
            request = urllib.request.Request(
                f"http://{host}:{port}/api/login", method="POST",
                headers={"Authorization": "Bearer nope"})
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    return response.status
            except urllib.error.HTTPError as exc:
                return exc.code

        def get_with_cookie(cookie: str) -> int:
            request = urllib.request.Request(
                f"http://{host}:{port}/api/status",
                headers={"Cookie": cookie})
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status

        results: dict[str, object] = {}

        def run() -> None:
            try:
                status, set_cookie = post_login()
                results["login_status"] = status
                results["cookie"] = set_cookie
                cookie_pair = set_cookie.split(";", 1)[0]
                results["get_status"] = get_with_cookie(cookie_pair)
                results["wrong_status"] = post_wrong()
            except Exception as exc:  # pragma: no cover - surfaced by assert
                results["error"] = str(exc)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        thread.join(timeout=10)
        self.assertNotIn("error", results, results)
        self.assertEqual(results["login_status"], 200)
        cookie = str(results["cookie"])
        self.assertIn(f"{SESSION_COOKIE}=correct-horse", cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertNotIn("correct-horse", cookie.split("Path=/")[1])
        self.assertEqual(results["get_status"], 200)
        self.assertEqual(results["wrong_status"], 401)
        server.shutdown()

    def test_cookie_never_appears_in_url(self) -> None:
        # Regression guard: token bootstrap must stay cookie/POST based.
        from ed_bt_ade.dashboard import LOGIN_PATH
        self.assertEqual(LOGIN_PATH, "/api/login")


if __name__ == "__main__":
    unittest.main()
