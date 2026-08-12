"""Generic connectivity and vault-secrets demo application for podsquire."""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [%(name)s] %(message)s", datefmt="%Y-%m-%dT%H:%M:%SZ")
logging.Formatter.converter = time.gmtime
log = logging.getLogger("podsquire.connectivity_test")

INTERVAL = int(os.environ.get("PODSQUIRE_CHECK_INTERVAL", "60"))
_SECRETS_FILE = os.environ.get("VAULT_JSON_FILE_PATH", "/tmp/vault-secrets.json")  # nosec B108
_secrets: dict = {}


def _load_checks() -> list[dict]:
    raw = os.environ.get("PODSQUIRE_CHECKS_JSON", "[]")
    try:
        checks = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid PODSQUIRE_CHECKS_JSON: {exc}") from exc
    if not isinstance(checks, list):
        raise SystemExit("PODSQUIRE_CHECKS_JSON must be a JSON list")
    for check in checks:
        check.setdefault("ok_statuses", [200])
        check["ok_statuses"] = set(int(value) for value in check["ok_statuses"])
    return checks


def _handle_sigterm(signum: int, frame: object) -> None:  # noqa: ARG001
    log.info("Received SIGTERM - exiting cleanly for supervisor restart")
    sys.exit(0)


def _handle_sigusr1(signum: int, frame: object) -> None:  # noqa: ARG001
    global _secrets  # noqa: PLW0603
    path = Path(_SECRETS_FILE)
    if path.exists():
        try:
            with open(path, encoding="utf-8") as f:
                _secrets = json.load(f)
            log.info("SIGUSR1: reloaded %d secret key(s) from %r", len(_secrets), _SECRETS_FILE)
        except Exception as exc:  # noqa: BLE001
            log.error("SIGUSR1: failed to read %r: %s", _SECRETS_FILE, exc)
    else:
        log.warning("SIGUSR1: secrets file %r not found", _SECRETS_FILE)


def _check(url: str, ok_statuses: set[int]) -> tuple[bool, str]:
    try:
        req = urllib.request.urlopen(url, timeout=10)  # noqa: S310 B310
        status = req.status
        if status in ok_statuses:
            return True, f"HTTP {status}"
        return False, f"HTTP {status} (unexpected)"
    except urllib.error.HTTPError as exc:
        if exc.code in ok_statuses:
            return True, f"HTTP {exc.code}"
        return False, f"HTTP {exc.code}"
    except urllib.error.URLError as exc:
        return False, f"Connection error: {exc.reason}"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def run() -> None:
    signal.signal(signal.SIGTERM, _handle_sigterm)
    signal.signal(signal.SIGUSR1, _handle_sigusr1)  # type: ignore[attr-defined]
    checks = _load_checks()
    log.info("podsquire connectivity + vault-secrets test starting")
    log.info("Polling every %ds; configured checks: %s", INTERVAL, [c.get("name", c.get("url")) for c in checks])
    log.info("Secrets file: %s", _SECRETS_FILE)
    _handle_sigusr1(0, None)
    env_keys = sorted(k for k in os.environ if k.startswith("VAULT_SECRET_"))
    if env_keys:
        log.info("Env secrets present at startup: %s", env_keys)
    while True:
        now = datetime.now(tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        parts = []
        for cfg in checks:
            ok, detail = _check(cfg["url"], cfg["ok_statuses"])
            parts.append(f"[{'OK' if ok else 'FAIL'}] {cfg.get('name', cfg['url'])}: {detail}")
        file_keys = sorted(_secrets.keys()) if _secrets else []
        secret_summary = f"file-secrets keys={file_keys}" if file_keys else "file-secrets=(none loaded)"
        check_summary = "  |  ".join(parts) if parts else "no connectivity checks configured"
        log.info("[%s]  %s  |  %s", now, check_summary, secret_summary)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    run()
