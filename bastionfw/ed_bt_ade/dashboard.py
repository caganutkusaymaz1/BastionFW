"""BastionFW local graphical dashboard and read/action HTTP API.

The dashboard serves a self-contained HTML application plus a small JSON
API. Every route is protected by ``ED_BT_ADE_DASHBOARD_TOKEN`` when that
environment variable is defined:

- ``/`` and ``/index.html`` accept ``Authorization: Bearer <token>``. Because
  a plain browser page cannot attach headers, the page can bootstrap an
  ``HttpOnly`` cookie by opening ``/?token=<token>`` once.
- ``/api/status`` and ``/api/metrics`` require the Bearer header or the cookie.

When the token is *not* defined the server refuses to bind anything but
loopback, even if ``0.0.0.0`` is requested (fail-safe). All token comparisons
use ``hmac.compare_digest``.
"""

from __future__ import annotations

import argparse
import asyncio
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
import logging
import os
from pathlib import Path
import signal
import threading
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .config import load_config
from .logger import configure_logging
from .sentinel import Sentinel, _install_signals
from .validation import ValidationError, parse_ip

LOGGER = logging.getLogger("bastionfw.dashboard")
WEB_ROOT = Path(__file__).parent.parent / "web"
TOKEN_COOKIE = "bastionfw_token"
MAX_REQUEST_BODY = 16 * 1024


def dashboard_token() -> str:
    """Return the configured dashboard token (empty when unset)."""
    return os.environ.get("ED_BT_ADE_DASHBOARD_TOKEN", "")


def effective_bind_host(requested: str, token: str) -> str:
    """Fail-safe loopback binding: no token means never listen beyond 127.0.0.1."""
    if not token and requested != "127.0.0.1":
        LOGGER.warning(
            "ED_BT_ADE_DASHBOARD_TOKEN is not set; binding to 127.0.0.1 only "
            "(fail-safe). Set the token to listen on other interfaces.",
            extra={"event": "dashboard_loopback_only"})
        return "127.0.0.1"
    return requested


def start_dashboard_server(host: str, port: int, sentinel: Sentinel) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, body: bytes, content_type: str,
                  extra_headers: list[tuple[str, str]] | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for key, value in extra_headers or ():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode()
            self._send(status, body, "application/json; charset=utf-8")

        def _send_unauthorized(self) -> None:
            self._send(401, b"unauthorized\n", "text/plain; charset=utf-8")

        # -- token verification ---------------------------------------------
        def _token_matches(self, candidate: str | None) -> bool:
            token = dashboard_token()
            if not token:
                return True
            if candidate is None:
                return False
            return hmac.compare_digest(candidate, token)

        def _bearer_token(self) -> str | None:
            header = self.headers.get("Authorization", "")
            if header.startswith("Bearer "):
                return header[7:].strip()
            return None

        def _cookie_token(self) -> str | None:
            raw = self.headers.get("Cookie", "")
            if not raw:
                return None
            cookies = SimpleCookie()
            try:
                cookies.load(raw)
            except Exception:
                return None
            morsel = cookies.get(TOKEN_COOKIE)
            return morsel.value if morsel is not None else None

        def _authorized(self) -> bool:
            if not dashboard_token():
                return True
            return (self._token_matches(self._bearer_token())
                    or self._token_matches(self._cookie_token()))

        def _query_token(self) -> str | None:
            query = urlsplit(self.path).query
            values = parse_qs(query).get("token", [])
            return values[0] if values else None

        # -- HTTP verbs ------------------------------------------------------
        def _serve_index(self) -> None:
            try:
                body = (WEB_ROOT / "dashboard.html").read_bytes()
            except OSError:
                self._send(500, b"dashboard asset unavailable\n", "text/plain")
                return
            headers: list[tuple[str, str]] = []
            if not self._authorized() and self._token_matches(self._query_token()):
                headers.append(("Set-Cookie",
                                f"{TOKEN_COOKIE}={self._query_token()}; "
                                "HttpOnly; SameSite=Lax; Path=/"))
            self._send(200, body, "text/html; charset=utf-8", headers)

        def do_GET(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            if path in {"/", "/index.html"}:
                if dashboard_token() and not (self._authorized()
                                              or self._token_matches(self._query_token())):
                    self._send_unauthorized()
                    return
                self._serve_index()
                return
            if not self._authorized():
                self._send_unauthorized()
                return
            if path == "/api/status":
                self._send_json(200, sentinel.dashboard_snapshot())
            elif path == "/api/metrics":
                self._send(200, sentinel.metrics.render().encode(),
                           "text/plain; version=0.0.4")
            else:
                self._send_json(404, {"error": "not found"})

        def _read_body(self) -> dict[str, Any] | None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length <= 0:
                return {}
            if length > MAX_REQUEST_BODY:
                self._send_json(413, {"error": "request body too large"})
                return None
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send_json(400, {"error": "request body must be valid JSON"})
                return None
            return payload if isinstance(payload, dict) else {}

        def do_POST(self) -> None:  # noqa: N802
            if not self._authorized():
                self._send_unauthorized()
                return
            path = urlsplit(self.path).path
            if path != "/api/bans":
                self._send_json(404, {"error": "not found"})
                return
            body = self._read_body()
            if body is None:
                return
            action = str(body.get("action", "")).strip()
            ip = str(body.get("ip", "")).strip()
            if action not in {"ban", "unban"} or not ip:
                self._send_json(400, {"error": "action ('ban'|'unban') and ip are required"})
                return
            try:
                canonical = str(parse_ip(ip))
            except ValidationError:
                self._send_json(400, {"error": "ip must be a valid IP address"})
                return
            mode = "ENFORCING" if sentinel.config.firewall.enabled else "DRY-RUN"
            try:
                if action == "ban":
                    raw_duration = body.get("duration")
                    duration: int | None = None
                    if raw_duration is not None:
                        try:
                            duration = int(raw_duration)
                        except (TypeError, ValueError):
                            self._send_json(400, {"error": "duration must be an integer"})
                            return
                        if duration <= 0:
                            self._send_json(400, {"error": "duration must be positive"})
                            return
                    added = sentinel.run_coro(sentinel.firewall.block(canonical, duration))
                    added_result = bool(added.result(timeout=15))
                    message = (f"ban staged for {canonical}" if added_result
                               else f"{canonical} is already banned or rejected by "
                                     "the safety policy")
                    self._send_json(200, {"ok": added_result, "message": message,
                                          "mode": mode})
                else:
                    removed = sentinel.run_coro(sentinel.firewall.unblock(canonical))
                    removed_result = bool(removed.result(timeout=15))
                    message = (f"unban applied for {canonical}" if removed_result
                               else f"{canonical} is not currently banned")
                    self._send_json(200, {"ok": removed_result, "message": message,
                                          "mode": mode})
            except (asyncio.TimeoutError, TimeoutError):
                self._send_json(503, {"error": "enforcement backend timed out"})
            except Exception:
                LOGGER.exception("ban action failed")
                self._send_json(500, {"error": "enforcement backend failed"})

        def log_message(self, *_args: Any) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True,
                     name="bastionfw-dashboard").start()
    return server


async def run_dashboard(config_path: Path, host: str, port: int) -> None:
    config = load_config(config_path)
    configure_logging(config.log_level, config.log_file)
    sentinel = Sentinel(config)
    effective_host = effective_bind_host(host, dashboard_token())
    server = start_dashboard_server(effective_host, port, sentinel)
    _install_signals(sentinel)
    LOGGER.info("dashboard available at http://%s:%d", effective_host, port)
    try:
        await sentinel.run()
    finally:
        server.shutdown()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-c", "--config", default="config.staging.json")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    try:
        asyncio.run(run_dashboard(Path(args.config), args.host, args.port))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
