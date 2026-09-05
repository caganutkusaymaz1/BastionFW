"""BastionFW local graphical dashboard.

The dashboard uses only Python's standard library and serves a self-contained
HTML application. It starts the same Sentinel engine used by the CLI.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
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


def start_dashboard_server(host: str, port: int, sentinel: Sentinel) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path in {"/", "/index.html"}:
                try:
                    body = (WEB_ROOT / "dashboard.html").read_bytes()
                except OSError:
                    self._send(500, b"dashboard asset unavailable\n", "text/plain")
                    return
                self._send(200, body, "text/html; charset=utf-8")
            elif self.path == "/api/status":
                body = json.dumps(sentinel.dashboard_snapshot(),
                                  ensure_ascii=False).encode()
                self._send(200, body, "application/json; charset=utf-8")
            elif self.path == "/api/metrics":
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


async def run_dashboard(config_path: Path, host: str, port: int) -> None:
    config = load_config(config_path)
    configure_logging(config.log_level)
    sentinel = Sentinel(config)
    server = start_dashboard_server(host, port, sentinel)
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