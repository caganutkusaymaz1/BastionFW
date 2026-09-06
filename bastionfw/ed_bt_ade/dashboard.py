"""BastionFW local graphical dashboard.

The dashboard uses only Python's standard library and serves a self-contained
HTML application. It starts the same Sentinel engine used by the CLI.

Authentication model:
- When ``ED_BT_ADE_DASHBOARD_TOKEN`` is configured, every request must present
  ``Authorization: Bearer <token>``; the comparison uses ``hmac.compare_digest``
  so token checking is not timing-observable.
- When no token is configured the server is fail-safe: it binds to loopback
  only, even when the operator explicitly requested ``0.0.0.0``, and a warning
  is logged. An unauthenticated dashboard must never be network-exposed.
"""

from __future__ import annotations

import argparse
import asyncio
import hmac
import json
import logging
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import signal
import threading
from typing import Any

from .config import load_config
from .logger import configure_logging
from .sentinel import Sentinel, _install_signals

LOGGER = logging.getLogger("bastionfw.dashboard")
WEB_ROOT = Path(__file__).parent.parent / "web"

DASHBOARD_TOKEN_ENV = "ED_BT_ADE_DASHBOARD_TOKEN"
LOOPBACK_HOST = "127.0.0.1"
MAX_TOKEN_LENGTH = 512
PROTECTED_PATHS = frozenset({"/", "/index.html", "/api/status", "/api/metrics"})


def resolve_dashboard_token(environ: dict[str, str] | None = None) -> str | None:
    """Return a trimmed dashboard token, or None when unconfigured."""
    env = os.environ if environ is None else environ
    raw = env.get(DASHBOARD_TOKEN_ENV, "")
    token = raw.strip()
    if not token or len(token) > MAX_TOKEN_LENGTH:
        return None
    return token


def _constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def is_authorized(header: str | None, token: str | None) -> bool:
    """Validate an Authorization header against the configured bearer token."""
    if token is None:
        return True
    if not header:
        return False
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return False
    supplied = parts[1]
    if supplied != supplied.strip() or not supplied or len(supplied) > MAX_TOKEN_LENGTH:
        return False
    return _constant_time_equal(supplied, token)


def start_dashboard_server(host: str, port: int, sentinel: Sentinel,
                           token: str | None = None) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if status == 401:
                self.send_header("WWW-Authenticate", 'Bearer realm="bastionfw"')
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path.split("?", 1)[0] in PROTECTED_PATHS and not is_authorized(
                    self.headers.get("Authorization"), token):
                self._send(401, b"unauthorized\n", "text/plain")
                return
            if self.path.split("?", 1)[0] in {"/", "/index.html"}:
                try:
                    body = (WEB_ROOT / "dashboard.html").read_bytes()
                except OSError:
                    self._send(500, b"dashboard asset unavailable\n", "text/plain")
                    return
                self._send(200, body, "text/html; charset=utf-8")
            elif self.path.split("?", 1)[0] == "/api/status":
                snapshot = dict(sentinel.dashboard_snapshot())
                snapshot["waf"] = sentinel.waf_summary()
                body = json.dumps(snapshot, ensure_ascii=False).encode()
                self._send(200, body, "application/json; charset=utf-8")
            elif self.path.split("?", 1)[0] == "/api/metrics":
                self._send(200, sentinel.metrics.render().encode(),
                           "text/plain; version=0.0.4")
            else:
                self._send(404, b"not found\n", "text/plain")

        def log_message(self, *_args: Any) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True,
                     name="bastionfw-dashboard").start()
    return server


def resolve_bind_host(requested: str, token: str | None) -> str:
    """Fail-safe binding: unauthenticated dashboards stay on loopback."""
    if token is None and requested not in {LOOPBACK_HOST, "localhost"}:
        LOGGER.warning(
            "%s is not set; refusing to expose an unauthenticated dashboard. "
            "Binding to %s instead of %s.",
            DASHBOARD_TOKEN_ENV, LOOPBACK_HOST, requested,
            extra={"event": "dashboard_fail_safe_bind"})
        return LOOPBACK_HOST
    return requested


async def run_dashboard(config_path: Path, host: str, port: int) -> None:
    config = load_config(config_path)
    configure_logging(config.log_level, config.log_file)
    token = resolve_dashboard_token()
    host = resolve_bind_host(host, token)
    sentinel = Sentinel(config)
    server = start_dashboard_server(host, port, sentinel, token)
    _install_signals(sentinel)
    LOGGER.info("dashboard available at http://%s:%d", host, port)
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
