"""Structured logging, Prometheus text exposition, and health state."""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class JsonFormatter(logging.Formatter):
    """Emit one valid JSON object per log record."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "severity": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in ("correlation_id", "source", "event", "ip", "rule"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())


class Metrics:
    """Small lock-protected Prometheus-compatible counter/gauge registry."""

    def __init__(self) -> None:
        self._values: defaultdict[tuple[str, tuple[tuple[str, str], ...]], float] = defaultdict(float)
        self._lock = threading.Lock()

    def inc(self, name: str, value: float = 1, labels: dict[str, str] | None = None) -> None:
        self._change(name, value, labels)

    def set(self, name: str, value: float, labels: dict[str, str] | None = None) -> None:
        key = (name, tuple(sorted((labels or {}).items())))
        with self._lock:
            self._values[key] = value

    def _change(self, name: str, value: float, labels: dict[str, str] | None) -> None:
        key = (name, tuple(sorted((labels or {}).items())))
        with self._lock:
            self._values[key] += value

    def render(self) -> str:
        with self._lock:
            items = list(self._values.items())
        lines: list[str] = []
        for (name, labels), value in items:
            suffix = ""
            if labels:
                suffix = "{" + ",".join(f'{k}="{v}"' for k, v in labels) + "}"
            lines.append(f"{name}{suffix} {value}")
        return "\n".join(lines) + ("\n" if lines else "")

    def value(self, name: str) -> float:
        """Return the sum of a metric across all label combinations."""
        with self._lock:
            return sum(value for (metric, _labels), value in self._values.items()
                       if metric == name)


class Health:
    def __init__(self) -> None:
        self._ready = False
        self._lock = threading.Lock()

    def set_ready(self, value: bool) -> None:
        with self._lock:
            self._ready = value

    @property
    def ready(self) -> bool:
        with self._lock:
            return self._ready


def start_metrics_server(host: str, port: int, metrics: Metrics, health: Health) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/healthz":
                body = b"ok\n" if health.ready else b"not ready\n"
                self.send_response(200 if health.ready else 503)
                self.send_header("Content-Type", "text/plain")
            elif self.path == "/metrics":
                body = metrics.render().encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4")
            else:
                body = b"not found\n"
                self.send_response(404)
                self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: Any) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True, name="metrics-http")
    thread.start()
    return server
