import asyncio
import json
import os
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path
from unittest.mock import patch

from ed_bt_ade.config import load_config
from ed_bt_ade.dashboard import effective_bind_host, start_dashboard_server
from ed_bt_ade.sentinel import Sentinel

TOKEN = "test-dashboard-token-0123456789"


def request(port: int, path: str, token: str | None = None,
            cookie: str | None = None, body: str | None = None,
            method: str = "GET") -> tuple[int, str, dict[str, str]]:
    connection = HTTPConnection("127.0.0.1", port, timeout=10)
    headers: dict[str, str] = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if cookie is not None:
        headers["Cookie"] = cookie
    if body is not None:
        headers["Content-Type"] = "application/json"
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    payload = response.read().decode("utf-8", errors="replace")
    result_headers = dict(response.getheaders())
    status = response.status
    connection.close()
    return status, payload, result_headers


class DashboardAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory()
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._serve_loop, daemon=True, name="dashboard-test-loop")
        self._thread.start()
        config_path = Path(self._directory.name) / "config.json"
        config_path.write_text(json.dumps({
            "log_sources": [{"name": "auth", "path": "/tmp/auth.log"}],
            "firewall": {
                "backend": "dry-run",
                "state_db": str(Path(self._directory.name) / "firewall.sqlite3"),
            },
            "threat_intel": {
                "cache_db": str(Path(self._directory.name) / "intel.sqlite3"),
            },
        }))
        self.sentinel = Sentinel(load_config(config_path))
        self.sentinel._loop = self._loop
        self.server = start_dashboard_server("127.0.0.1", 0, self.sentinel)
        self.port = int(self.server.server_address[1])

    def _serve_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def tearDown(self) -> None:
        self.sentinel.firewall.close()
        asyncio.run_coroutine_threadsafe(
            self.sentinel.threat_intel.close(), self._loop).result(timeout=5)
        self.server.shutdown()
        self.server.server_close()
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=3)
        self._directory.cleanup()

    def test_api_requires_bearer_token(self) -> None:
        with patch.dict(os.environ, {"ED_BT_ADE_DASHBOARD_TOKEN": TOKEN}):
            status, _body, _headers = request(self.port, "/api/status")
            self.assertEqual(status, 401)
            status, _body, _headers = request(self.port, "/api/status",
                                              token="wrong-token")
            self.assertEqual(status, 401)
            status, body, _headers = request(self.port, "/api/status", token=TOKEN)
            self.assertEqual(status, 200)
            payload = json.loads(body)
            self.assertEqual(payload["mode"], "DRY-RUN")

    def test_index_cookie_bootstrap_authorizes_api(self) -> None:
        with patch.dict(os.environ, {"ED_BT_ADE_DASHBOARD_TOKEN": TOKEN}):
            status, _body, headers = request(self.port, "/?token=" + TOKEN)
            self.assertEqual(status, 200)
            set_cookie = headers.get("Set-Cookie", "")
            self.assertIn("bastionfw_token=", set_cookie)
            cookie = set_cookie.split(";", 1)[0]
            status, _body, _headers = request(self.port, "/api/status", cookie=cookie)
            self.assertEqual(status, 200)

    def test_no_token_means_no_remote_bind(self) -> None:
        self.assertEqual(effective_bind_host("0.0.0.0", ""), "127.0.0.1")
        self.assertEqual(effective_bind_host("0.0.0.0", TOKEN), "0.0.0.0")
        self.assertEqual(effective_bind_host("127.0.0.1", ""), "127.0.0.1")

    def test_ban_and_unban_roundtrip(self) -> None:
        with patch.dict(os.environ, {"ED_BT_ADE_DASHBOARD_TOKEN": TOKEN}):
            payload = json.dumps({"action": "ban", "ip": "8.8.8.8"})
            status, body, _headers = request(self.port, "/api/bans",
                                             token=TOKEN, body=payload,
                                             method="POST")
            self.assertEqual(status, 200)
            result = json.loads(body)
            self.assertTrue(result["ok"])
            self.assertEqual(result["mode"], "DRY-RUN")

            status, body, _headers = request(self.port, "/api/status", token=TOKEN)
            snapshot = json.loads(body)
            self.assertIn("8.8.8.8", snapshot["blocked_addresses"])

            payload = json.dumps({"action": "unban", "ip": "8.8.8.8"})
            status, body, _headers = request(self.port, "/api/bans",
                                             token=TOKEN, body=payload,
                                             method="POST")
            self.assertEqual(status, 200)
            self.assertTrue(json.loads(body)["ok"])

            status, body, _headers = request(self.port, "/api/status", token=TOKEN)
            snapshot = json.loads(body)
            self.assertNotIn("8.8.8.8", snapshot["blocked_addresses"])

    def test_ban_action_rejects_invalid_or_private_addresses(self) -> None:
        with patch.dict(os.environ, {"ED_BT_ADE_DASHBOARD_TOKEN": TOKEN}):
            payload = json.dumps({"action": "ban", "ip": "8.8.8.8",
                                  "duration": 60})
            status, body, _headers = request(self.port, "/api/bans",
                                             token=TOKEN, body=payload,
                                             method="POST")
            self.assertTrue(json.loads(body)["ok"])

            payload = json.dumps({"action": "ban", "ip": "127.0.0.1"})
            status, body, _headers = request(self.port, "/api/bans",
                                             token=TOKEN, body=payload,
                                             method="POST")
            self.assertEqual(status, 200)
            self.assertFalse(json.loads(body)["ok"])

            payload = json.dumps({"action": "ban", "ip": "not-an-ip"})
            status, body, _headers = request(self.port, "/api/bans",
                                             token=TOKEN, body=payload,
                                             method="POST")
            self.assertEqual(status, 400)

    def test_unauthenticated_post_is_rejected(self) -> None:
        with patch.dict(os.environ, {"ED_BT_ADE_DASHBOARD_TOKEN": TOKEN}):
            payload = json.dumps({"action": "ban", "ip": "203.0.113.55"})
            status, _body, _headers = request(self.port, "/api/bans",
                                              body=payload, method="POST")
            self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
