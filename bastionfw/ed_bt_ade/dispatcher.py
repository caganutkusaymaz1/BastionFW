"""Bounded, severity-routed webhook dispatcher.

The dispatcher is deliberately independent of any vendor SDK. It batches
alerts per endpoint and performs network I/O outside the event loop.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict
from typing import Any
from urllib.request import Request, urlopen

from .config import AlertingConfig
from .threat_intel import TokenBucket

LOGGER = logging.getLogger(__name__)


class WebhookDispatcher:
    def __init__(self, config: AlertingConfig, queue_size: int = 10_000) -> None:
        self.routes = {severity: urls for severity, urls in config.webhooks}
        self.batch_size = config.batch_size
        self.flush_interval = config.flush_interval_seconds
        self.bucket = TokenBucket(config.requests_per_second)
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=queue_size)
        self.stop = asyncio.Event()

    async def submit(self, alert: dict[str, Any]) -> None:
        """Queue an alert without performing network I/O in the detector."""
        if self.routes.get(str(alert.get("severity")), ()):
            await self.queue.put(alert)

    async def run(self) -> None:
        while not self.stop.is_set() or not self.queue.empty():
            batch: list[dict[str, Any]] = []
            try:
                batch.append(await asyncio.wait_for(self.queue.get(), timeout=self.flush_interval))
            except asyncio.TimeoutError:
                continue
            while len(batch) < self.batch_size:
                try:
                    batch.append(self.queue.get_nowait())
                except asyncio.QueueEmpty:
                    break
            by_url: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
            for alert in batch:
                for url in self.routes.get(str(alert.get("severity")), ()):
                    by_url[url].append(alert)
            await asyncio.gather(
                *(self._send(url, alerts) for url, alerts in by_url.items()),
                return_exceptions=True,
            )
            for _ in batch:
                self.queue.task_done()

    async def _send(self, url: str, alerts: list[dict[str, Any]]) -> None:
        await self.bucket.acquire()
        try:
            await asyncio.to_thread(self._post, url, alerts)
        except Exception as exc:  # webhook failures must not stop processing
            LOGGER.warning("webhook dispatch failed: %s", exc,
                           extra={"event": "webhook_failure"})

    @staticmethod
    def _post(url: str, alerts: list[dict[str, Any]]) -> None:
        payload = json.dumps({"alerts": alerts}, separators=(",", ":")).encode()
        request = Request(url, data=payload, headers={"Content-Type": "application/json"})
        # URL is operator configuration validated to http(s) in config.py
        with urlopen(request, timeout=8):  # nosec B310
            return

    def close(self) -> None:
        self.stop.set()
