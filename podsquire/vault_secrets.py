"""
Vault secrets integration for podsquire.

Fetches key-value secrets from HashiCorp Vault using Kubernetes service account
authentication and delivers them to the supervised subprocess via one of two
configurable output modes:

  env       -- inject secrets as environment variables into the podsquire
               process so that the subprocess inherits them on (re)start.

  json_file -- write secrets as a JSON file on disk so the subprocess (or any
               other process) can read them at any time without a restart.
               The file is written atomically (temp-file + rename) to avoid
               partial reads.

  env_file  -- write shell-sourceable export commands to a file. This is useful
               for CI wrappers that need to source Vault-backed variables before
               running other commands.

Change detection
----------------
On each refresh, the newly fetched secrets are compared against the previously
fetched values.  The refreshed_event is only set (and the optional reload
signal sent) when the secrets have actually changed, avoiding spurious
subprocess signals on unchanged polls.

Reload signal
-------------
An optional reload_signal can be configured directly on the vault_secrets
section.  This is independent of the cert-renewal reload_signal on the
subprocess section, allowing the two events to trigger different signals
(e.g. SIGUSR1 for vault refresh, SIGHUP for cert renewal).
"""

import asyncio
import base64
import json
import logging
import os
import shlex
import signal
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import hvac
import requests
from hvac.api.auth_methods import Kubernetes
from hvac.exceptions import Forbidden, InvalidRequest
from tenacity import retry, retry_if_exception_type, stop_after_delay, wait_fixed

log = logging.getLogger(__name__)

_K8S_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"  # nosec B105 B108


class VaultOutputMode(str, Enum):
    """Controls how fetched secrets are delivered to the subprocess."""

    ENV = "env"
    JSON_FILE = "json_file"
    ENV_FILE = "env_file"


@dataclass
class VaultSecretsConfig:
    """Configuration for Vault KV secret fetching and delivery."""

    kv_path: str
    url: str = "http://127.0.0.1:8200"
    role: str = "podsquire"
    kv_mount_point: str | None = None
    kv_version: int = 1
    # 0 = fetch once at startup only; positive = poll interval in minutes
    refresh_interval_minutes: int = 0
    output_mode: VaultOutputMode = VaultOutputMode.ENV
    # Required when output_mode == JSON_FILE
    json_file_path: str | None = None
    # Required when output_mode == ENV_FILE
    env_file_path: str | None = None
    # Optional signal to send to the subprocess when secrets change
    reload_signal: signal.Signals | None = field(default=None)


class VaultSecretsClient:
    """Fetches secrets from HashiCorp Vault and delivers them via the configured output mode."""

    def __init__(self, config: VaultSecretsConfig) -> None:
        self._cfg = config
        self._client: hvac.Client | None = None
        self._last_secrets: dict = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def fetch_and_apply(self) -> tuple[int, bool]:
        """
        Fetch secrets from Vault and apply them via the configured output mode.

        Blocking Vault I/O is offloaded to a thread executor so the asyncio
        event loop is not stalled.

        Returns (count, changed) where count is the number of secrets and
        changed is True if the secrets differ from the last fetch.
        """
        secrets = await asyncio.get_event_loop().run_in_executor(None, self._fetch_secrets_sync)

        changed = secrets != self._last_secrets
        self._last_secrets = secrets

        if self._cfg.output_mode == VaultOutputMode.ENV:
            count = self._apply_to_env(secrets)
        elif self._cfg.output_mode == VaultOutputMode.JSON_FILE:
            count = self._apply_to_json_file(secrets)
        else:
            count = self._apply_to_env_file(secrets)

        return count, changed

    # ------------------------------------------------------------------
    # Output handlers
    # ------------------------------------------------------------------

    def _process_value(self, key: str, value: object) -> str:
        """Convert a secret value to a string, applying the ToBase64 convention if needed."""
        str_value = str(value)
        if "ToBase64" in key:
            str_value = base64.b64encode(str_value.encode()).decode()
        return str_value

    def _apply_to_env(self, secrets: dict) -> int:
        """Inject secrets into os.environ so the subprocess inherits them on (re)start."""
        count = 0
        for key, value in secrets.items():
            os.environ[key] = self._process_value(key, value)
            count += 1
        log.info(f"Vault: injected {count} secret(s) from {self._cfg.kv_path!r} into process environment")
        return count

    def _apply_to_json_file(self, secrets: dict) -> int:
        """Write secrets atomically to a JSON file on disk."""
        path = self._cfg.json_file_path
        if not path:
            raise RuntimeError("vault_secrets.json_file_path must be set when output_mode is 'json_file'")

        output = {key: self._process_value(key, value) for key, value in secrets.items()}

        dest = Path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)

        # Atomic write: write to a temp file in the same directory then rename.
        # This guarantees the subprocess never reads a partially written file.
        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=dest.parent,
            suffix=".tmp",
            delete=False,
            encoding="utf-8",
        ) as tmp:
            json.dump(output, tmp, indent=2)
            tmp_path = tmp.name

        Path(tmp_path).rename(dest)
        log.info(f"Vault: wrote {len(output)} secret(s) to {path!r}")
        return len(output)

    def _apply_to_env_file(self, secrets: dict) -> int:
        """Write secrets atomically as shell-sourceable export commands."""
        path = self._cfg.env_file_path
        if not path:
            raise RuntimeError("vault_secrets.env_file_path must be set when output_mode is 'env_file'")

        output = {key: self._process_value(key, value) for key, value in secrets.items()}
        dest = Path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)

        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=dest.parent,
            suffix=".tmp",
            delete=False,
            encoding="utf-8",
        ) as tmp:
            tmp.write("# Generated by podsquire; source this file from POSIX-compatible shells.\n")
            for key, value in output.items():
                tmp.write(f"export {key}={shlex.quote(value)}\n")
            tmp_path = tmp.name

        Path(tmp_path).rename(dest)
        log.info(f"Vault: wrote {len(output)} shell export(s) to {path!r}")
        return len(output)

    # ------------------------------------------------------------------
    # Vault client internals -- blocking; must be called in an executor
    # ------------------------------------------------------------------

    def _get_k8s_token(self) -> str:
        """Read the Kubernetes service account token from the well-known path."""
        try:
            with open(_K8S_TOKEN_PATH, encoding="utf-8") as f:  # nosec B108
                return f.read().strip()
        except Exception as e:
            raise RuntimeError(f"Failed to read Kubernetes service account token: {e}") from e

    def _ensure_client(self) -> None:
        """Initialise and authenticate the Vault client (idempotent)."""
        if self._client is not None:
            return

        @retry(reraise=True, stop=stop_after_delay(120), wait=wait_fixed(2))
        def _connect_and_login() -> None:
            log.debug("Vault: initialising client and authenticating via Kubernetes...")
            token = self._get_k8s_token()
            client = hvac.Client(url=self._cfg.url)
            try:
                resp = Kubernetes(client.adapter).login(
                    role=self._cfg.role,
                    jwt=token,
                    mount_point="kubernetes",
                )
            except requests.exceptions.ConnectionError as e:
                log.error(f"Vault: connection failed: {e}")
                raise ConnectionError(f"Failed to connect to Vault at {self._cfg.url}") from e

            client_token = resp.get("auth", {}).get("client_token")
            if not client_token:
                raise RuntimeError("Vault authentication succeeded but no client token was returned")

            client.token = client_token
            self._client = client
            log.info("Vault: authenticated successfully via Kubernetes service account")

        _connect_and_login()

    def _fetch_secrets_sync(self) -> dict:
        """Blocking fetch of all secrets from the configured KV path."""
        self._ensure_client()
        if self._client is None:
            raise RuntimeError("Vault client is not initialised after _ensure_client -- this should not happen")
        client = self._client
        cfg = self._cfg

        @retry(
            reraise=True,
            retry=retry_if_exception_type(ConnectionError),
            stop=stop_after_delay(120),
            wait=wait_fixed(2),
        )
        def _read() -> dict:
            try:
                if cfg.kv_version == 2:  # noqa: PLR2004
                    secret = client.secrets.kv.v2.read_secret_version(
                        path=cfg.kv_path,
                        mount_point=cfg.kv_mount_point,
                    )
                    return secret["data"]["data"]
                secret = client.secrets.kv.v1.read_secret(
                    path=cfg.kv_path,
                    mount_point=cfg.kv_mount_point,
                )
                return secret["data"]
            except InvalidRequest as e:
                log.error(f"Vault: invalid request to {cfg.kv_path!r}: {type(e).__name__}: {e!r}")
                raise ValueError(f"Invalid request: {e}") from e
            except Forbidden as e:
                log.error(f"Vault: access forbidden to {cfg.kv_path!r}: {type(e).__name__}: {e!r}")
                raise PermissionError(f"Access forbidden: {e}") from e
            except Exception as e:
                log.error(f"Vault: unexpected error fetching secrets from {cfg.kv_path!r}: {type(e).__name__}: {e!r}")
                raise ConnectionError(f"Error fetching secrets: {e}") from e

        return _read()


async def vault_refresh_loop(client: VaultSecretsClient, refreshed_event: asyncio.Event) -> None:
    """
    Periodically refresh Vault secrets and signal via refreshed_event when they change.

    Sleeps for refresh_interval_minutes between fetches.  refreshed_event is only
    set when the fetched secrets differ from the previous fetch, so the main loop
    only reacts (and the subprocess is only signalled) on actual changes.

    This coroutine runs indefinitely until cancelled.
    """
    interval_seconds = client._cfg.refresh_interval_minutes * 60
    log.info(f"Vault: refresh loop started -- polling every {client._cfg.refresh_interval_minutes} minute(s)")

    while True:
        await asyncio.sleep(interval_seconds)
        log.info("Vault: polling for secret changes...")
        try:
            _count, changed = await client.fetch_and_apply()
            if changed:
                log.info("Vault: secrets changed -- signalling main loop")
                refreshed_event.set()
            else:
                log.debug("Vault: secrets unchanged")
        except Exception as e:
            log.error(f"Vault: secret refresh failed: {e} -- will retry at next interval")
