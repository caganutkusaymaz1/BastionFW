"""Inode-aware asynchronous file tailing with bounded backpressure."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import logging
from pathlib import Path
from typing import BinaryIO

from .config import LogSource
from .detector import LogEvent
from .parsing import extract_remote_ip

LOGGER = logging.getLogger(__name__)

# Upper bound for the un-split byte buffer holding a partially read line. A
# pathological producer that never emits a newline (or a single record larger
# than the cap) would otherwise grow this buffer without limit and exhaust
# memory. When the cap is exceeded the buffer is truncated (the oversized,
# unparseable record is dropped) and a warning is logged.
MAX_BUFFER_BYTES = 1_048_576


@dataclass(slots=True)
class TailState:
    inode: int | None = None
    offset: int = 0


class AsyncLogTailer:
    """Polls one file without blocking the event loop.

    The file is reopened when its inode changes or when its size contracts,
    covering rename-based rotation and copytruncate-based rotation.
    """

    def __init__(self, source: LogSource, output: asyncio.Queue[LogEvent],
                 trusted_proxies: tuple[str, ...] = ()) -> None:
        self.source = source
        self.output = output
        self.state = TailState()
        self._buffer = b""
        self._handle: BinaryIO | None = None
        self.stop = asyncio.Event()
        self.trusted_proxies = trusted_proxies

    async def run(self) -> None:
        while not self.stop.is_set():
            try:
                await self._read_available()
            except OSError as exc:
                LOGGER.warning("tailer read failed: %s", exc,
                               extra={"source": self.source.name})
            try:
                await asyncio.wait_for(self.stop.wait(), timeout=self.source.poll_interval)
            except asyncio.TimeoutError:
                pass

    async def _read_available(self) -> None:
        try:
            stat = await asyncio.to_thread(self.source.path.stat)
        except FileNotFoundError:
            return
        if self._handle is None:
            self._handle = self.source.path.open("rb")
            self.state.inode = stat.st_ino
            self.state.offset = 0
        elif self.state.inode != stat.st_ino:
            # A rename-based rotation leaves the old descriptor readable.
            # Drain it before switching paths so lines written just before
            # rotation are not silently discarded.
            await self._read_handle()
            await self._flush_partial()
            self._handle.close()
            self._handle = self.source.path.open("rb")
            self.state.inode = stat.st_ino
            self.state.offset = 0
        elif stat.st_size < self.state.offset:
            # copytruncate keeps the inode but moves the write position back.
            self._handle.seek(0)
            self.state.offset = 0
        if stat.st_size == self.state.offset:
            return
        await self._read_handle()

    async def _read_handle(self) -> None:
        if self._handle is None:
            return
        self._handle.seek(self.state.offset)
        data = self._handle.read()
        self.state.offset += len(data)
        self._buffer += data
        if len(self._buffer) > MAX_BUFFER_BYTES:
            # Keep the tail so any newline that follows quickly still yields a
            # line, but never let a newline-less producer exhaust memory.
            dropped = len(self._buffer) - MAX_BUFFER_BYTES
            self._buffer = self._buffer[-MAX_BUFFER_BYTES:]
            LOGGER.warning(
                "log line exceeded %d bytes; dropped %d bytes of one record",
                MAX_BUFFER_BYTES, dropped,
                extra={"event": "tailer_buffer_overflow", "source": self.source.name})
        # splitlines() cannot preserve a final incomplete record. Keep the
        # remainder in bytes so a later read completes it without data loss.
        if b"\n" not in self._buffer:
            return
        parts = self._buffer.split(b"\n")
        self._buffer = parts.pop()
        for raw_line in parts:
            line = raw_line.rstrip(b"\r").decode(self.source.encoding, errors="replace")
            await self.output.put(LogEvent(self.source.name, line,
                                           remote_ip=extract_remote_ip(
                                               line, self.trusted_proxies)))

    async def _flush_partial(self) -> None:
        if self._buffer:
            line = self._buffer.decode(self.source.encoding, errors="replace")
            await self.output.put(LogEvent(self.source.name, line,
                                           remote_ip=extract_remote_ip(
                                               line, self.trusted_proxies)))
            self._buffer = b""

    def close(self) -> None:
        self.stop.set()
        if self._handle is not None:
            self._handle.close()
            self._handle = None
