"""podsquire entry point.

Usage:
    python -m podsquire --config podsquire.yml
    podsquire --config podsquire.yml         # if installed via pip

    # Fetch SPIFFE certs and exit (no subprocess or proxy started):
    podsquire --pull-certs-only /path/to/output/dir

podsquire is a container init wrapper that handles any combination of:

  - SPIFFE/SPIRE cert management: fetches an X.509 SVID on startup, writes
    cert/key/CA files to a configurable path, and renews them automatically
    before expiry.

  - Subprocess supervision: launches a configured command, optionally restarts
    it on failure (with configurable retry limits), and optionally signals it
    when certs are renewed.

  - mTLS proxy: exposes local plaintext listener(s) that forward connections to
    remote services over mTLS, using the SPIFFE cert.  Listeners are restarted
    automatically when certs are renewed.

All three features are optional and independently configurable.  At least one
must be enabled for podsquire to do anything useful.
"""

import argparse
import asyncio
import contextlib
import logging
import os
import signal
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urljoin, urlparse

import yaml

from podsquire import cert_manager
from podsquire.cert_manager import SpireConfig, StaticCertConfig
from podsquire.proxy import HttpProxy, ProxyConfig, TcpProxy, create_proxy
from podsquire.supervisor import RestartPolicy, Supervisor, SupervisorConfig
from podsquire.vault_secrets import VaultOutputMode, VaultSecretsClient, VaultSecretsConfig, vault_refresh_loop

log = logging.getLogger("podsquire")


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------


def _load_spire_config(raw: dict) -> SpireConfig:
    return SpireConfig(
        cert_path=raw.get("cert_path", "/tmp/podsquire/tls.crt"),  # nosec B108
        key_path=raw.get("key_path", "/tmp/podsquire/tls.key"),  # nosec B108
        ca_path=raw.get("ca_path", "/tmp/podsquire/ca.crt"),  # nosec B108
        combined_path=raw.get("combined_path"),
        socket=raw.get("socket"),
        renewal_interval=int(raw.get("renewal_interval", 60)),
        expiry_threshold=int(raw.get("expiry_threshold", 3600)),
        retry_interval=int(raw.get("retry_interval", 5)),
    )


def _load_static_cert_config(raw: dict) -> StaticCertConfig:
    return StaticCertConfig(
        cert_path=raw["cert_path"],
        key_path=raw["key_path"],
        ca_path=raw.get("ca_path"),
    )


def _load_proxy_configs(raw: list) -> list[ProxyConfig]:
    configs = []
    for p in raw:
        configs.append(
            ProxyConfig(
                name=p["name"],
                mode=p.get("mode", "tcp"),
                local_host=p.get("local_host", "127.0.0.1"),
                local_port=int(p["local_port"]),
                remote_host=p["remote_host"],
                remote_port=int(p["remote_port"]),
                verify_remote=bool(p.get("verify_remote", True)),
            )
        )
    return configs


def _load_supervisor_config(raw: dict) -> SupervisorConfig:
    reload_signal = None
    sig_name = raw.get("reload_signal")
    if sig_name:
        # Accept signal names like "SIGHUP", "HUP", "1" or integers
        try:
            reload_signal = signal.Signals(int(sig_name))
        except (ValueError, TypeError):
            name = str(sig_name).upper().lstrip("SIG")
            reload_signal = signal.Signals[f"SIG{name}"]

    restart_raw = raw.get("restart", {})
    restart = RestartPolicy(
        enabled=bool(restart_raw.get("enabled", False)),
        max_restarts=int(restart_raw.get("max_restarts", 5)),
        window_seconds=int(restart_raw.get("window_seconds", 300)),
    )

    return SupervisorConfig(
        command=raw["command"],
        path=raw.get("path"),
        reload_signal=reload_signal,
        restart=restart,
    )


def _load_vault_config(raw: dict) -> VaultSecretsConfig | None:
    reload_signal = None
    sig_name = raw.get("reload_signal")
    if sig_name:
        try:
            reload_signal = signal.Signals(int(sig_name))
        except (ValueError, TypeError):
            name = str(sig_name).upper().lstrip("SIG")
            reload_signal = signal.Signals[f"SIG{name}"]

    output_mode = VaultOutputMode(raw.get("output_mode", "env"))
    json_file_path = raw.get("json_file_path") or os.environ.get("VAULT_JSON_FILE_PATH")
    if output_mode == VaultOutputMode.JSON_FILE and not json_file_path:
        raise ValueError("vault_secrets.json_file_path is required when output_mode is 'json_file'")

    env_file_path = raw.get("env_file_path") or os.environ.get("VAULT_ENV_FILE_PATH")
    if output_mode == VaultOutputMode.ENV_FILE and not env_file_path:
        raise ValueError("vault_secrets.env_file_path is required when output_mode is 'env_file'")

    kv_path = raw.get("kv_path") or os.environ.get("VAULT_KV_PATH")
    if not kv_path:
        log.warning(
            "Vault secrets will not be retrieved — required setting 'kv_path' is not configured "
            "in the vault_secrets config section and the VAULT_KV_PATH environment variable is not set."
        )
        return None

    return VaultSecretsConfig(
        kv_path=kv_path,
        url=raw.get("url") or os.environ.get("VAULT_URL", "http://127.0.0.1:8200"),
        role=raw.get("role") or os.environ.get("VAULT_ROLE", "podsquire"),
        kv_mount_point=raw.get("kv_mount_point") or os.environ.get("VAULT_KV_MOUNT_POINT"),
        kv_version=int(raw.get("kv_version") or os.environ.get("VAULT_KV_VERSION", "1")),
        refresh_interval_minutes=int(raw.get("refresh_interval_minutes", 0)),
        output_mode=output_mode,
        json_file_path=json_file_path,
        env_file_path=env_file_path,
        reload_signal=reload_signal,
    )


def _normalise_proxy_presets(raw_presets: object, source: str) -> dict[str, dict]:
    """Normalise a mapping/list of proxy presets into ``name -> proxy``."""
    if raw_presets is None:
        return {}
    if isinstance(raw_presets, dict):
        # Accept either {name: proxy}, {"proxies": [...]}, or {"proxy_presets": {...}}.
        if "proxy_presets" in raw_presets:
            return _normalise_proxy_presets(raw_presets["proxy_presets"], source)
        if "proxies" in raw_presets:
            return _normalise_proxy_presets(raw_presets["proxies"], source)
        if "name" in raw_presets and "remote_host" in raw_presets:
            return {str(raw_presets["name"]): dict(raw_presets)}
        return {str(name): {"name": str(name), **svc} for name, svc in raw_presets.items() if isinstance(svc, dict)}
    if isinstance(raw_presets, list):
        return {str(svc["name"]): dict(svc) for svc in raw_presets if isinstance(svc, dict) and "name" in svc}
    raise ValueError(f"Proxy preset source {source!r} must be a mapping or list of proxy definitions")


def _load_proxy_presets(config: dict, enabled_names: list[str]) -> list[dict]:
    """Load named proxy definitions from user-supplied inline config presets."""
    available = _normalise_proxy_presets(config.get("proxy_presets", {}) or {}, "proxy_presets")
    unknown = [name for name in enabled_names if name not in available]
    if unknown:
        raise ValueError(f"Unknown enabled_proxy_presets: {unknown}. Available: {sorted(available)}")
    selected = [available[name] for name in enabled_names]
    log.info("Proxy presets enabled: %s", [svc["name"] for svc in selected])
    return selected


def _is_url(path: str) -> bool:
    return urlparse(path).scheme in {"http", "https"}


def _read_text_with_retries(location: str, retries: int, retry_interval: float, timeout: float) -> str:
    """Read local or HTTP(S) text, retrying transient failures."""
    last_exc: Exception | None = None
    attempts = max(1, retries + 1)
    for attempt in range(1, attempts + 1):
        try:
            if _is_url(location):
                with urllib.request.urlopen(location, timeout=timeout) as response:  # nosec B310 - user-configured preset URL
                    return response.read().decode("utf-8")
            return Path(location).read_text(encoding="utf-8")
        except (OSError, urllib.error.URLError, TimeoutError) as exc:
            last_exc = exc
            if attempt < attempts:
                log.warning(
                    "Platform service directory: failed to load %s on attempt %s/%s: %s; retrying in %.1fs",
                    location,
                    attempt,
                    attempts,
                    exc,
                    retry_interval,
                )
                time.sleep(retry_interval)
    assert last_exc is not None
    raise last_exc


def _candidate_service_locations(base: str, service_name: str) -> list[str]:
    if _is_url(base):
        directory = base if base.endswith("/") else f"{base}/"
        return [urljoin(directory, f"{service_name}.yml"), urljoin(directory, f"{service_name}.yaml")]
    base_path = Path(base)
    return [str(base_path / f"{service_name}.yml"), str(base_path / f"{service_name}.yaml")]


def _load_platform_service_file(location: str, settings: dict) -> dict:
    raw_text = _read_text_with_retries(
        location,
        retries=int(settings.get("retries", 3)),
        retry_interval=float(settings.get("retry_interval", 2)),
        timeout=float(settings.get("timeout", 10)),
    )
    parsed = yaml.safe_load(raw_text) or {}
    if isinstance(parsed, dict) and "remote_host" in parsed:
        return dict(parsed)
    presets = _normalise_proxy_presets(parsed, location)
    if len(presets) == 1:
        return next(iter(presets.values()))
    raise ValueError(f"Platform service file {location!r} must contain exactly one proxy definition")


def _load_platform_catalogue(location: str, settings: dict) -> dict[str, dict]:
    raw_text = _read_text_with_retries(
        location,
        retries=int(settings.get("retries", 3)),
        retry_interval=float(settings.get("retry_interval", 2)),
        timeout=float(settings.get("timeout", 10)),
    )
    return _normalise_proxy_presets(yaml.safe_load(raw_text) or {}, location)


def _looks_like_catalogue_path(path: str) -> bool:
    parsed = urlparse(path)
    candidate = parsed.path if parsed.scheme else path
    return candidate.endswith((".yml", ".yaml"))


def _load_platform_service_presets(config: dict, enabled_names: list[str]) -> list[dict]:
    """Load shared platform service proxy presets from a local path or HTTP(S) URL.

    The path comes from ``platform_services.path`` or the
    ``PODSQUIRE_PLATFORM_SERVICES_PATH`` environment variable. By default,
    failures are warned and skipped so podsquire can still start with reduced
    functionality. Set ``fail_on_load_error`` or ``fail_on_missing`` to true to
    turn those warnings into startup failures.
    """
    settings = dict(config.get("platform_services", {}) or {})
    base = settings.get("path") or os.environ.get("PODSQUIRE_PLATFORM_SERVICES_PATH")
    if not base:
        message = (
            "enabled_platform_services configured but no platform service directory path was provided; "
            "set platform_services.path or PODSQUIRE_PLATFORM_SERVICES_PATH"
        )
        if settings.get("fail_on_load_error", False):
            raise RuntimeError(message)
        log.warning("Platform service directory: %s", message)
        log.warning("Platform service directory: services not loaded: %s", enabled_names)
        return []

    fail_on_load_error = bool(settings.get("fail_on_load_error", False))
    fail_on_missing = bool(settings.get("fail_on_missing", False))
    selected: list[dict] = []
    missing: list[str] = []

    if _looks_like_catalogue_path(str(base)):
        try:
            available = _load_platform_catalogue(str(base), settings)
        except Exception as exc:
            if fail_on_load_error:
                raise RuntimeError(f"Platform service directory failed to load {base!r}: {exc}") from exc
            log.warning("Platform service directory: failed to load %s: %s", base, exc)
            log.warning("Platform service directory: services not loaded: %s", enabled_names)
            return []
        for name in enabled_names:
            if name in available:
                selected.append(available[name])
            else:
                missing.append(name)
    else:
        for name in enabled_names:
            loaded = None
            errors = []
            for location in _candidate_service_locations(str(base), name):
                try:
                    loaded = _load_platform_service_file(location, settings)
                    loaded.setdefault("name", name)
                    break
                except Exception as exc:
                    errors.append(f"{location}: {exc}")
            if loaded is not None:
                selected.append(loaded)
            else:
                missing.append(name)
                log.warning("Platform service directory: service %r could not be loaded from %s", name, base)
                for error in errors:
                    log.debug("Platform service directory: %s", error)

    if missing:
        message = f"Platform service directory: services not loaded: {missing}"
        if fail_on_missing:
            raise RuntimeError(message)
        log.warning(message)
    if selected:
        log.info("Platform services enabled: %s", [svc["name"] for svc in selected])
    return selected


def _merge_enabled_proxies(config: dict, source_name: str, proxy_defs: list[dict]) -> None:
    config.setdefault("proxies", [])
    existing_names = {p["name"] for p in config["proxies"]}
    for svc in proxy_defs:
        if svc["name"] not in existing_names:
            config["proxies"].append(svc)
            existing_names.add(svc["name"])
        else:
            log.debug("%s: %r overridden by user proxies entry — skipping", source_name, svc["name"])


def _load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    # Merge any named proxy presets into the proxies list. User-defined proxies
    # take precedence when a preset and explicit proxy share a name.
    enabled = config.pop("enabled_proxy_presets", None)
    if enabled:
        _merge_enabled_proxies(config, "enabled_proxy_presets", _load_proxy_presets(config, enabled))

    enabled_platform = config.pop("enabled_platform_services", None)
    if enabled_platform:
        _merge_enabled_proxies(
            config,
            "enabled_platform_services",
            _load_platform_service_presets(config, enabled_platform),
        )

    config.pop("proxy_presets", None)
    return config


# ---------------------------------------------------------------------------
# Main async run loop
# ---------------------------------------------------------------------------


async def _run(config: dict) -> int:
    # ---- Vault secrets — configure client early, but fetch AFTER proxies are up ----
    vault_client: VaultSecretsClient | None = None
    vault_cfg: VaultSecretsConfig | None = None
    vault_refreshed_event = asyncio.Event()
    vault_refresh_task: asyncio.Task | None = None

    if "vault_secrets" in config:
        vault_cfg = _load_vault_config(config["vault_secrets"])
        if vault_cfg is not None:
            vault_client = VaultSecretsClient(vault_cfg)
            log.info("Vault secrets enabled — will fetch after proxy listeners are ready")
    else:
        log.info("No vault_secrets section in config — skipping Vault secret injection")

    # ---- Cert source --------------------------------------------------------
    spire_cfg: SpireConfig | None = None
    ssl_contexts: dict[bool, ssl.SSLContext] = {}

    if "spire" in config:
        spire_cfg = _load_spire_config(config["spire"])
        log.info("SPIRE cert management enabled — fetching initial SVID...")
        ssl_contexts = await cert_manager.initial_fetch(spire_cfg)
    elif "static" in config:
        static_cfg = _load_static_cert_config(config["static"])
        log.info("Static cert mode — loading cert files from disk (no SPIRE)")
        ssl_contexts = await cert_manager.initial_fetch_static(static_cfg)
    else:
        log.info("No cert source configured (no 'spire:' or 'static:' section)")

    # ---- Proxy listeners ----------------------------------------------------
    proxy_cfgs = _load_proxy_configs(config.get("proxies", []))
    active_proxies: list[TcpProxy | HttpProxy] = []
    for pcfg in proxy_cfgs:
        if not ssl_contexts:
            raise RuntimeError(
                f"Proxy '{pcfg.name}' requires a cert source — add a 'spire:' or 'static:' section to the config"
            )
        proxy = create_proxy(pcfg, ssl_contexts[pcfg.verify_remote])
        await proxy.start()
        active_proxies.append(proxy)

    # ---- Vault initial fetch — proxies are now listening --------------------
    if vault_client and vault_cfg:
        log.info("Vault secrets: fetching initial secrets (proxies ready)...")
        try:
            await vault_client.fetch_and_apply()
        except Exception as exc:
            log.error(f"Vault secrets: initial fetch failed — {exc}")
            log.warning("Vault secrets: continuing without secrets (check path/permissions)")
        if vault_cfg.refresh_interval_minutes > 0:
            vault_refresh_task = asyncio.create_task(
                vault_refresh_loop(vault_client, vault_refreshed_event),
                name="vault-refresh",
            )
        else:
            log.info("Vault secrets: no refresh interval configured — fetched once at startup")

    # ---- Subprocess supervisor ----------------------------------------------
    supervisor: Supervisor | None = None
    supervisor_task: asyncio.Task | None = None
    if "subprocess" in config:
        supervisor_cfg = _load_supervisor_config(config["subprocess"])
        supervisor = Supervisor(supervisor_cfg)
        supervisor_task = asyncio.create_task(supervisor.run(), name="supervisor")
        log.info(f"Subprocess supervisor started: {supervisor_cfg.command!r}")
    else:
        log.info("No subprocess configured — running in cert/proxy-only mode")

    # ---- Cert renewal task --------------------------------------------------
    renewed_event = asyncio.Event()
    renewal_task: asyncio.Task | None = None
    if spire_cfg:
        renewal_task = asyncio.create_task(
            cert_manager.renewal_loop(spire_cfg, renewed_event),
            name="cert-renewal",
        )

    if not supervisor_task and not renewal_task and not active_proxies:
        log.warning("Nothing to do — add at least one of: spire, subprocess, proxies")
        return 0

    exit_code = 0
    try:
        while True:
            # Build the set of things to wait for this iteration
            renewal_waiter = asyncio.create_task(renewed_event.wait(), name="renewal-waiter")
            vault_refresh_waiter = asyncio.create_task(vault_refreshed_event.wait(), name="vault-refresh-waiter")
            waitables: set[asyncio.Task] = {renewal_waiter, vault_refresh_waiter}
            if supervisor_task and not supervisor_task.done():
                waitables.add(supervisor_task)

            done, _ = await asyncio.wait(waitables, return_when=asyncio.FIRST_COMPLETED)

            # Cancel the renewal waiter if it wasn't the one that fired
            if renewal_waiter not in done:
                renewal_waiter.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await renewal_waiter

            # Cancel the vault refresh waiter if it wasn't the one that fired
            if vault_refresh_waiter not in done:
                vault_refresh_waiter.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await vault_refresh_waiter

            # Supervisor finished (all restarts exhausted or restart disabled)
            if supervisor_task is not None and supervisor_task in done:
                try:
                    exit_code = supervisor_task.result()
                except Exception as e:
                    log.error(f"Supervisor raised an exception: {e}")
                    exit_code = 1
                log.info(f"Subprocess supervisor finished (exit code {exit_code}) — shutting down")
                break

            # Vault secrets refreshed
            if vault_refresh_waiter in done:
                vault_refreshed_event.clear()
                log.info("Vault secrets changed — applying update")
                if supervisor and vault_cfg and vault_cfg.reload_signal:
                    proc = supervisor._proc
                    if proc and proc.returncode is None:
                        try:
                            proc.send_signal(vault_cfg.reload_signal)
                            log.info(f"Vault: sent {vault_cfg.reload_signal.name} to subprocess")
                        except ProcessLookupError:
                            log.debug("Vault: subprocess not running — reload signal skipped")

            # Cert renewed
            if renewal_waiter in done:
                renewed_event.clear()
                log.info("Cert renewed — applying update")

                # Signal subprocess if configured
                if supervisor:
                    supervisor.send_reload_signal()

                # Restart mTLS proxy listeners with the new cert
                if active_proxies and spire_cfg:
                    log.info(f"Restarting {len(active_proxies)} mTLS proxy listener(s) with renewed cert...")
                    for proxy in active_proxies:
                        await proxy.stop()
                    ssl_contexts = cert_manager.build_ssl_contexts(spire_cfg)
                    active_proxies = []
                    for pcfg in proxy_cfgs:
                        proxy = create_proxy(pcfg, ssl_contexts[pcfg.verify_remote])
                        await proxy.start()
                        active_proxies.append(proxy)
                    log.info("mTLS proxies restarted")

            # If there's no supervisor and no renewal task, nothing more to do
            if supervisor_task is None and renewal_task is None:
                break

    except asyncio.CancelledError:
        log.info("Shutdown requested")
        if supervisor_task and not supervisor_task.done():
            supervisor_task.cancel()
            if supervisor:
                await supervisor.terminate()
            with contextlib.suppress(asyncio.CancelledError):
                await supervisor_task
    finally:
        if vault_refresh_task:
            vault_refresh_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await vault_refresh_task
        if renewal_task:
            renewal_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await renewal_task
        for proxy in active_proxies:
            await proxy.stop()
        log.info("podsquire stopped")

    return exit_code


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="podsquire — container init wrapper for SPIFFE certs, subprocess supervision, and mTLS proxy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start with a config file (blocks until subprocess exits or SIGTERM)
  podsquire --config /app/config.yml

  # Fetch SPIFFE certs to a directory and exit (useful as an init container)
  podsquire --pull-certs-only /var/run/secrets/tls

  # Fetch Vault secrets and write shell exports for source-compatible CI wrappers
  podsquire --write-env-to-file /tmp/env.sh
""",
    )
    parser.add_argument("-c", "--config", help="Path to podsquire YAML config file")
    parser.add_argument(
        "--write-env-to-file",
        metavar="PATH",
        help=(
            "Fetch Vault KV secrets using VAULT_* environment variables, write shell-sourceable "
            "export commands to PATH, then exit. This is compatible with legacy /vault_env wrappers."
        ),
    )
    parser.add_argument(
        "--pull-certs-only",
        metavar="PATH",
        help=(
            "Fetch SPIFFE certs from SPIRE, write tls.crt, tls.key, ca.crt (and optionally "
            "tls.key+cert) to PATH, then exit. No subprocess or proxy is started. "
            "Honours SPIFFE_ENDPOINT_SOCKET env var for the agent socket."
        ),
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    logging.Formatter.converter = time.gmtime  # UTC timestamps

    if args.write_env_to_file:
        cfg = _build_vault_config_from_env(VaultOutputMode.ENV_FILE, args.write_env_to_file)
        if cfg is None:
            log.error("--write-env-to-file requires VAULT_KV_PATH to be set")
            sys.exit(1)
        log.info(f"--write-env-to-file: writing Vault secrets as shell exports to {args.write_env_to_file}")
        count = _fetch_vault_secrets_once(cfg)
        log.info(f"Vault env exports written — {count} variable(s); exiting")
        return

    if args.pull_certs_only:
        dest = Path(args.pull_certs_only)
        spire = SpireConfig(
            cert_path=str(dest / "tls.crt"),
            key_path=str(dest / "tls.key"),
            ca_path=str(dest / "ca.crt"),
            combined_path=str(dest / "tls.key+cert"),
        )
        log.info(f"--pull-certs-only: writing SPIFFE certs to {dest}")
        asyncio.run(cert_manager.initial_fetch(spire))
        log.info("Certs written — exiting")
        return

    if not args.config:
        parser.error("--config is required (or use --pull-certs-only or --write-env-to-file)")

    config = _load_config(args.config)

    loop = asyncio.new_event_loop()
    main_task: asyncio.Task | None = None

    def _on_shutdown(sig_name: str) -> None:
        log.info(f"Received {sig_name}")
        if main_task and not main_task.done():
            main_task.cancel()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda s=sig: _on_shutdown(signal.Signals(s).name))

    exit_code = 0
    try:
        main_task = loop.create_task(_run(config))
        loop.run_until_complete(main_task)
        exit_code = main_task.result()
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        loop.close()

    if exit_code:
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
