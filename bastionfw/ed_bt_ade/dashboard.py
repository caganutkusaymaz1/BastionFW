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
LOGIN_PATH = "/api/login"
SESSION_COOKIE = "bastionfw_session"
SESSION_MAX_AGE_SECONDS = 8 * 3600

# Login rate limiting (Task C hardening): sliding window per client IP.
LOGIN_MAX_FAILURES = 5
LOGIN_LOCKOUT_SECONDS = 60
LOGIN_WINDOW_SECONDS = 300
LOGIN_MAX_TRACKED_IPS = 10_000  # absolute memory cap (DoS-safe)

# Audit-log friendly login results (never include the token itself).
_LOGIN_EVENT = "dashboard_login"
_LOGIN_FAILURE_EVENT = "dashboard_login_failure"
_BRUTE_FORCE_EVENT = "dashboard_brute_force"


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


def is_authorized(header: str | None, token: str | None,
                  cookie_header: str | None = None) -> bool:
    """Validate bearer header or session cookie against the configured token."""
    if token is None:
        return True
    if header:
        parts = header.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            supplied = parts[1]
            if supplied == supplied.strip() and supplied and len(supplied) <= MAX_TOKEN_LENGTH:
                return _constant_time_equal(supplied, token)
    if cookie_header:
        candidate = _session_cookie_value(cookie_header)
        if candidate is not None and len(candidate) <= MAX_TOKEN_LENGTH:
            return _constant_time_equal(candidate, token)
    return False


def _session_cookie_value(cookie_header: str) -> str | None:
    """Extract the session cookie value from a Cookie header."""
    for part in cookie_header.split(";"):
        name, _, value = part.partition("=")
        if name.strip() == SESSION_COOKIE and value:
            return value.strip()
    return None


def handle_login(authorization: str | None, token: str | None,
                 client_ip: str = "unknown", now: float | None = None,
                 alert_hook: "callable[[str], None] | None" = None) -> tuple[int, str]:
    """Authenticate a bearer token and return ``(status, set_cookie_value)``.

    On success the caller receives ``200`` plus the value for a HttpOnly
    session cookie, so browsers never need the token in JavaScript or in a
    URL. On failure ``401`` is returned; after ``LOGIN_MAX_FAILURES`` failed
    attempts inside the sliding window the IP is locked out for
    ``LOGIN_LOCKOUT_SECONDS`` and receives ``429`` until it expires.

    Every attempt is audit-logged with the client IP, timestamp, and outcome
    — never the token itself. A lockout additionally fires ``alert_hook`` so
    the Sentinel alerting pipeline can notify operators (brute-force signal).
    """
    import time as _time

    current = _time.time() if now is None else now
    if is_login_locked_out(client_ip, current):
        LOGGER.warning("dashboard login locked out (brute-force guard)", extra={
            "event": _BRUTE_FORCE_EVENT, "ip": client_ip,
            "result": "rate_limited"})
        if alert_hook is not None:
            alert_hook("dashboard_brute_force")
        return 429, ""
    if not is_authorized(authorization, token):
        record_login_failure(client_ip, current)
        LOGGER.warning("dashboard login failed", extra={
            "event": _LOGIN_FAILURE_EVENT, "ip": client_ip,
            "result": "failure"})
        if alert_hook is not None and is_login_locked_out(client_ip, current):
            # The failure that crossed the threshold fires the alert exactly
            # once per lockout window.
            alert_hook("dashboard_brute_force")
        return 401, ""
    clear_login_failures(client_ip)
    LOGGER.info("dashboard login succeeded", extra={
        "event": _LOGIN_EVENT, "ip": client_ip, "result": "success"})
    if token is None:
        # Loopback-only unauthenticated dashboards have nothing to session.
        return 200, ""
    return 200, token


# --- Login rate limiter (self-contained; no firewall dependency) ------------

_login_failures: dict[str, list[float]] = {}


def is_login_locked_out(client_ip: str, now: float) -> bool:
    """True when this IP exhausted LOGIN_MAX_FAILURES inside the window."""
    window_start = now - LOGIN_WINDOW_SECONDS
    failures = [stamp for stamp in _login_failures.get(client_ip, ())
                if stamp > window_start]
    _login_failures[client_ip] = failures
    if not failures and client_ip in _login_failures and not failures:
        _login_failures.pop(client_ip, None)
    if len(failures) >= LOGIN_MAX_FAILURES:
        # Locked until the oldest failure in the window ages out.
        return (failures[0] + LOGIN_LOCKOUT_SECONDS) > now
    return False


def record_login_failure(client_ip: str, now: float) -> None:
    """Record one failed attempt; sweep stale state to stay memory-bounded."""
    if len(_login_failures) >= LOGIN_MAX_TRACKED_IPS and client_ip not in _login_failures:
        # Absolute cap: drop everything older than the window.
        window_start = now - LOGIN_WINDOW_SECONDS
        for ip in [ip for ip, stamps in _login_failures.items()
                   if not stamps or max(stamps) <= window_start]:
            _login_failures.pop(ip, None)
        if len(_login_failures) >= LOGIN_MAX_TRACKED_IPS:
            return  # still full: drop the new entry rather than grow unbounded
    _login_failures.setdefault(client_ip, []).append(now)


def clear_login_failures(client_ip: str) -> None:
    """Reset failure history after a successful authentication."""
    _login_failures.pop(client_ip, None)


def reset_login_rate_limiter() -> None:
    """Test/maintenance helper: clear all limiter state."""
    _login_failures.clear()


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

        def do_POST(self) -> None:  # noqa: N802
            if self.path.split("?", 1)[0] != LOGIN_PATH:
                self._send(404, b"not found\n", "text/plain")
                return
            status, cookie_value = handle_login(
                self.headers.get("Authorization"), token,
                client_ip=self.client_address[0] if self.client_address else "unknown",
                alert_hook=getattr(sentinel, "login_alert_hook", None))
            if status == 429:
                self._send(429, b"rate limited\n", "text/plain")
                return
            if status == 200 and cookie_value:
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Set-Cookie",
                                 f"{SESSION_COOKIE}={cookie_value}; HttpOnly; "
                                 f"Max-Age={SESSION_MAX_AGE_SECONDS}; Path=/; "
                                 "SameSite=Strict")
                body = b'{"authenticated": true}\n'
            elif status == 200:
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                body = b'{"authenticated": true}\n'
            else:
                self._send(401, b"unauthorized\n", "text/plain")
                return
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path.split("?", 1)[0] in PROTECTED_PATHS and not is_authorized(
                    self.headers.get("Authorization"), token,
                    self.headers.get("Cookie")):
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
