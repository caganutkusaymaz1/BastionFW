"""Deadman switch for the Coraza WAF (fail-open safety loop).

BastionFW follows a fail-open philosophy at the L7 layer: if the WAF becomes
unhealthy for a sustained period, the deadman switch drops the Coraza engine
into ``SecRuleEngine DetectionOnly`` (detect mode) instead of letting a wedged
WAF silently take the protected application offline. The switch is *not* an
authorization system — it only degrades policy. Restoring enforcement is an
explicit operator action (reassert ``waf.mode = block`` and restart the
engine), never an automatic one.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shlex
import time
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .config import WafConfig

LOGGER = logging.getLogger(__name__)

DETECT_ENGINE_LINE = "SecRuleEngine DetectionOnly\n"
BLOCK_ENGINE_LINE = "SecRuleEngine On\n"


def engine_line_for_mode(mode: str) -> str:
    if mode == "block":
        return BLOCK_ENGINE_LINE
    if mode == "detect":
        return DETECT_ENGINE_LINE
    raise ValueError(f"invalid WAF mode: {mode!r}")


def write_engine_mode(mode: str, path: Path) -> None:
    """Persist the SecLang engine-mode file consumed by the WAF's Coraza engine."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(engine_line_for_mode(mode), encoding="utf-8")
    temporary.replace(path)


def read_engine_mode(path: Path) -> str | None:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return None
    if "DetectionOnly" in content:
        return "detect"
    if "SecRuleEngine On" in content:
        return "block"
    return None


async def caddy_admin_reload(admin_url: str, caddyfile_path: Path | None,
                             timeout: float = 5.0) -> bool:
    """Reload Caddy through its admin API using the on-disk Caddyfile.

    Caddy re-parses ``Include``/``import`` targets during the reload, so a
    freshly rewritten deny include or engine-mode file takes effect without a
    restart. A failure returns ``False`` and never raises, keeping auxiliary
    WAF management out of the critical path.
    """
    if not admin_url or caddyfile_path is None:
        return False
    try:
        text = await asyncio.to_thread(caddyfile_path.read_text, encoding="utf-8")
    except OSError as exc:
        LOGGER.warning("caddy reload skipped: cannot read %s: %s", caddyfile_path, exc)
        return False

    def _post() -> None:
        request = Request(admin_url, data=text.encode("utf-8"),
                          method="POST",
                          headers={"Content-Type": "text/caddyfile"})
        # admin_url is operator configuration validated to http(s) in config.py
        with urlopen(request, timeout=timeout):  # nosec B310
            return

    try:
        await asyncio.to_thread(_post)
        return True
    except (OSError, URLError, HTTPError) as exc:
        LOGGER.warning("caddy admin reload failed for %s: %s", admin_url, exc)
        return False


class WafDeadmanSwitch:
    """Monitors WAF health and drops the engine to detect mode on sustained loss.

    The switch also reasserts the configured engine mode once at startup so a
    fresh process restores the operator's intended policy after an earlier
    fail-open event.
    """

    def __init__(self, config: WafConfig, metrics: object,
                 notify: Callable[[dict[str, object]], None] | None = None) -> None:
        self.config = config
        self.metrics = metrics
        self.notify = notify
        self.tripped = False
        self._failures = 0
        self._started_at = time.time()
        self._lock = asyncio.Lock()

    # -- public state -------------------------------------------------------
    @property
    def engine_mode(self) -> str:
        """Engine mode in effect: detect once tripped, otherwise config.mode."""
        if self.tripped:
            return "detect"
        return self.config.mode

    def _set_metric(self, value: float) -> None:
        setter = getattr(self.metrics, "set", None)
        if setter is not None:
            setter("waf_fail_open_active", value)

    def _push_alert(self, severity: str, rule: str, message: str) -> None:
        if self.notify is None:
            return
        self.notify({
            "timestamp": time.time(),
            "rule": rule,
            "severity": severity,
            "source": "waf-health",
            "ip": None,
            "evidence": message,
        })

    # -- health probing -----------------------------------------------------
    async def _probe(self) -> bool:
        """True when the WAF answers HTTP (any status), False on connection loss."""
        url = self.config.health_url
        if not url:
            return True
        timeout = min(max(self.config.health_interval_seconds / 2.0, 1.0), 5.0)

        def _get() -> None:
            # health_url is operator configuration validated to http(s) in config.py
            with urlopen(url, timeout=timeout):  # nosec B310
                return

        try:
            await asyncio.to_thread(_get)
            return True
        except HTTPError:
            # An HTTP error response still proves the WAF is serving requests.
            return True
        except (OSError, URLError, ValueError):
            return False

    async def _write_flag(self, reason: str) -> None:
        path = self.config.fail_open_flag_path
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        payload = json.dumps({
            "tripped_at": time.time(),
            "engine_mode": "detect",
            "reason": reason,
        })
        temporary.write_text(payload, encoding="utf-8")
        temporary.replace(path)

    async def _clear_flag(self) -> None:
        try:
            self.config.fail_open_flag_path.unlink(missing_ok=True)
        except OSError:
            pass

    async def _run_rollback_command(self) -> None:
        command = self.config.rollback_command
        if not command:
            return
        try:
            argv = shlex.split(command)
        except ValueError as exc:
            LOGGER.error("invalid waf.rollback_command: %s", exc)
            return
        LOGGER.warning("executing rollback command: %s", command)
        try:
            process = await asyncio.create_subprocess_exec(
                *argv, stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL)
            await asyncio.wait_for(process.wait(), timeout=60)
        except (OSError, asyncio.TimeoutError):
            LOGGER.exception("rollback command failed")

    async def _fail_open(self) -> None:
        async with self._lock:
            if self.tripped:
                return
            LOGGER.critical(
                "WAF unhealthy for %d checks; deadman switch: fail-open to detect mode",
                self.config.failure_threshold,
                extra={"event": "waf_fail_open"})
            self.tripped = True
            self._set_metric(1.0)
            self._push_alert("critical", "waf_fail_open",
                             "WAF unhealthy; engine dropped to DetectionOnly "
                             "(fail-open). Restore with waf.mode=block and a restart.")
            try:
                await asyncio.to_thread(write_engine_mode, "detect",
                                        self.config.engine_mode_path)
            except OSError:
                LOGGER.exception("cannot write engine-mode file")
            await self._write_flag("health check threshold exceeded")
            if self.config.admin_url:
                await caddy_admin_reload(self.config.admin_url,
                                         self.config.caddyfile_path)
            await self._run_rollback_command()

    async def _startup_reassert(self) -> None:
        """Restore the operator-configured engine mode once per process start."""
        if not self.config.enabled:
            return
        try:
            await asyncio.to_thread(write_engine_mode, self.config.mode,
                                    self.config.engine_mode_path)
        except OSError:
            LOGGER.exception("cannot reassert engine-mode file at startup")
            return
        current = await asyncio.to_thread(read_engine_mode,
                                          self.config.engine_mode_path)
        if current != self.config.mode:
            LOGGER.warning("engine-mode reassert failed; active mode is %s",
                           current or "unknown")
            return
        if current == "detect":
            # Fresh starts in detect mode are the documented default; nothing
            # to reload for policy reasons.
            return
        if self.config.admin_url:
            ok = await caddy_admin_reload(self.config.admin_url,
                                          self.config.caddyfile_path)
            if ok:
                LOGGER.info("WAF engine mode reasserted to %s", self.config.mode)

    async def run(self, stop: asyncio.Event) -> None:
        if not self.config.enabled:
            return
        await self._startup_reassert()
        interval = max(self.config.health_interval_seconds, 0.05)
        # First probe immediately so a dead WAF fails open without waiting a
        # full interval.
        healthy = await self._probe()
        while not stop.is_set():
            if not healthy and not self.tripped:
                self._failures += 1
                if self._failures >= self.config.failure_threshold:
                    await self._fail_open()
            elif healthy and self.tripped:
                LOGGER.warning(
                    "WAF health recovered, but engine stays in DetectionOnly "
                    "(fail-open) until an operator reasserts block mode",
                    extra={"event": "waf_fail_open_recovery"})
                await self._clear_flag()
            else:
                self._failures = 0
            try:
                await asyncio.wait_for(stop.wait(), timeout=interval)
            except asyncio.TimeoutError:
                pass
            healthy = await self._probe()
