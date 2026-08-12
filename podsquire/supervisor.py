"""Subprocess supervisor for podsquire.

Launches the configured payload command, optionally restarts it on failure
within a configurable time window, and propagates signals from podsquire to
the running child process.
"""

import asyncio
import collections
import contextlib
import logging
import signal
import time
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


@dataclass
class RestartPolicy:
    enabled: bool = False
    max_restarts: int = 5
    window_seconds: int = 300  # restart counter resets after this many seconds of stability


@dataclass
class SupervisorConfig:
    command: str
    path: str | None = None  # working directory; None = inherit
    reload_signal: signal.Signals | None = None  # signal to send on cert renewal
    restart: RestartPolicy = field(default_factory=RestartPolicy)


class Supervisor:
    """Manages the lifecycle of the payload subprocess."""

    def __init__(self, config: SupervisorConfig) -> None:
        self._config = config
        self._proc: asyncio.subprocess.Process | None = None
        self._restart_times: collections.deque[float] = collections.deque()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send_reload_signal(self) -> None:
        """Send the configured reload signal to the running subprocess.

        No-op if no reload_signal is configured or the process is not running.
        """
        cfg = self._config
        if cfg.reload_signal is None:
            return
        if self._proc is None or self._proc.returncode is not None:
            log.debug("send_reload_signal: subprocess is not running — skipping")
            return
        try:
            self._proc.send_signal(cfg.reload_signal)
            log.info(f"Sent {cfg.reload_signal.name} to subprocess (PID {self._proc.pid})")
        except ProcessLookupError:
            log.debug("send_reload_signal: process already gone")

    async def terminate(self, timeout: float = 10.0) -> None:
        """Gracefully terminate the subprocess (SIGTERM → wait → SIGKILL)."""
        if self._proc is None or self._proc.returncode is not None:
            return
        pid = self._proc.pid
        log.info(f"Terminating subprocess (PID {pid})...")
        with contextlib.suppress(ProcessLookupError):
            self._proc.terminate()
        try:
            await asyncio.wait_for(self._proc.wait(), timeout=timeout)
            log.info(f"Subprocess (PID {pid}) terminated gracefully")
        except asyncio.TimeoutError:
            log.warning(f"Subprocess (PID {pid}) did not terminate within {timeout}s — sending SIGKILL")
            with contextlib.suppress(ProcessLookupError):
                self._proc.kill()

    async def run(self) -> int:
        """Run the subprocess, applying the restart policy.

        Returns the final exit code once the subprocess exits without being
        restarted (restart limit exceeded, or restart disabled).
        Raises asyncio.CancelledError on cancellation — call terminate() first
        if a graceful shutdown is needed.
        """
        cfg = self._config
        policy = cfg.restart

        while True:
            log.info(f"Launching subprocess: {cfg.command!r}" + (f" (cwd={cfg.path!r})" if cfg.path else ""))
            self._proc = await asyncio.create_subprocess_shell(
                cfg.command,
                cwd=cfg.path,
            )
            log.info(f"Subprocess started (PID {self._proc.pid})")

            try:
                exit_code = await self._proc.wait()
            except asyncio.CancelledError:
                await self.terminate()
                raise

            log.info(f"Subprocess exited with code {exit_code}")

            if not policy.enabled:
                return exit_code

            # Exit code 0 is a clean exit — don't treat it as a failure
            if exit_code == 0:
                log.info("Subprocess exited cleanly (code 0) — not restarting")
                return exit_code

            # ---- Restart policy check ----
            now = time.monotonic()
            self._restart_times.append(now)
            # Expire old entries outside the window
            cutoff = now - policy.window_seconds
            while self._restart_times and self._restart_times[0] < cutoff:
                self._restart_times.popleft()

            failures_in_window = len(self._restart_times)
            if failures_in_window > policy.max_restarts:
                log.error(
                    f"Subprocess has failed {failures_in_window} times in the last "
                    f"{policy.window_seconds}s (max={policy.max_restarts}) — giving up"
                )
                # Return a non-zero exit code so the container is seen as crashed
                # by Kubernetes, triggering CrashLoopBackOff rather than a clean restart
                return exit_code if exit_code != 0 else 1

            log.info(
                f"Restarting subprocess "
                f"({failures_in_window}/{policy.max_restarts} failures in last {policy.window_seconds}s)..."
            )
