"""SPIFFE certificate manager for podsquire.

Fetches X.509 SVIDs from the SPIRE Workload API, writes them to disk, and
signals the main loop when a renewal is due so proxies can be restarted and
the subprocess can be signalled.

The SPIFFE Workload API calls are blocking, so they are wrapped in
asyncio.get_event_loop().run_in_executor() to avoid blocking the event loop.
"""

import asyncio
import logging
import os
import ssl
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# spiffe is imported lazily inside _fetch_and_write() so that static cert mode
# (which never calls that function) works without the spiffe package installed.

log = logging.getLogger(__name__)


@dataclass
class SpireConfig:
    cert_path: str = "/tmp/podsquire/tls.crt"  # nosec B108
    key_path: str = "/tmp/podsquire/tls.key"  # nosec B108
    ca_path: str = "/tmp/podsquire/ca.crt"  # nosec B108
    combined_path: str | None = None  # optional key+cert bundle (key PEM then cert PEM)
    socket: str | None = None  # SPIRE agent socket (see resolution order below)
    renewal_interval: int = 60  # minimum seconds between expiry checks
    expiry_threshold: int = 3600  # renew when fewer than this many seconds remain
    retry_interval: int = 5  # seconds between retries on failure


@dataclass
class StaticCertConfig:
    """Use existing cert files on disk without the SPIRE Workload API.

    Useful on developer workstations where a Vault PKI cert is present but no
    SPIRE agent is available.  Cert renewal is not performed.
    """

    cert_path: str
    key_path: str
    ca_path: str | None = None


# ---------------------------------------------------------------------------
# Blocking helpers (run in executor)
# ---------------------------------------------------------------------------


def _fetch_and_write(config: SpireConfig) -> None:
    """Fetch SPIFFE SVID from SPIRE and write cert/key/CA files to disk.

    Blocking — call via run_in_executor.

    Socket resolution order (first wins):
      1. config.socket
      2. SPIFFE_ENDPOINT_SOCKET environment variable
      3. /run/spire/sockets/agent.sock
    """
    from spiffe import WorkloadApiClient  # lazy import — not needed in static cert mode

    for path_str in (config.cert_path, config.key_path, config.ca_path):
        if path_str:
            Path(path_str).parent.mkdir(parents=True, exist_ok=True)

    _default_socket = "/run/spire/sockets/agent.sock"  # nosec B108
    socket = config.socket or os.environ.get("SPIFFE_ENDPOINT_SOCKET") or _default_socket
    if not socket.startswith("unix://"):
        socket = f"unix://{socket}"

    client = WorkloadApiClient(socket)
    try:
        svid = client.fetch_x509_svid()
        log.info(f"Fetched SPIFFE ID: {svid.spiffe_id}")

        # Write certificate chain
        with open(config.cert_path, "wb") as f:
            for cert in svid.cert_chain:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
        log.info(f"  cert  → {config.cert_path}")

        # Write private key
        key_bytes = svid.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(config.key_path, "wb") as f:
            f.write(key_bytes)
        log.info(f"  key   → {config.key_path}")

        # Write combined key+cert bundle (key first, then cert chain)
        if config.combined_path:
            Path(config.combined_path).parent.mkdir(parents=True, exist_ok=True)
            with open(config.combined_path, "wb") as f:
                f.write(key_bytes)
                for cert in svid.cert_chain:
                    f.write(cert.public_bytes(serialization.Encoding.PEM))
            log.info(f"  combined → {config.combined_path}")

        # Write CA bundle for the trust domain
        bundles = client.fetch_x509_bundles()
        ca_bundle = bundles.get_bundle_for_trust_domain(svid.spiffe_id.trust_domain)
        authorities = ca_bundle.x509_authorities if ca_bundle else []
        with open(config.ca_path, "wb") as f:
            for ca_cert in authorities:
                f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        log.info(f"  ca    → {config.ca_path}")
    finally:
        client.close()


def _get_cert_expiry(cert_path: str) -> float:
    """Return the expiry of the certificate at cert_path as a Unix timestamp."""
    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    return cert.not_valid_after_utc.timestamp()


# ---------------------------------------------------------------------------
# SSL context builder
# ---------------------------------------------------------------------------


def build_ssl_contexts(config: SpireConfig) -> dict[bool, ssl.SSLContext]:
    """Build two outbound mTLS SSL contexts from the cert files on disk.

    Returns a dict keyed by verify_remote (True/False).  Both contexts present
    the SPIFFE client certificate.  The verified context validates the remote
    server certificate against the SPIFFE CA bundle; the unverified context
    skips server cert validation.

    check_hostname is disabled on both because SPIFFE SVIDs use URI SANs
    (spiffe://...) rather than DNS names.
    """
    verified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    verified.load_cert_chain(config.cert_path, config.key_path)
    verified.load_verify_locations(config.ca_path)
    verified.check_hostname = False

    unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    unverified.load_cert_chain(config.cert_path, config.key_path)
    unverified.check_hostname = False
    unverified.verify_mode = ssl.CERT_NONE

    return {True: verified, False: unverified}


def build_ssl_contexts_static(config: StaticCertConfig) -> dict[bool, ssl.SSLContext]:
    """Build SSL contexts from static cert files (no SPIRE)."""
    unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    unverified.load_cert_chain(config.cert_path, config.key_path)
    unverified.check_hostname = False
    unverified.verify_mode = ssl.CERT_NONE

    if config.ca_path and Path(config.ca_path).exists():
        verified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        verified.load_cert_chain(config.cert_path, config.key_path)
        verified.load_verify_locations(config.ca_path)
        verified.check_hostname = False
        log.info(f"Static cert: server validation enabled via {config.ca_path}")
    else:
        log.warning("Static cert: no ca_path — server cert validation disabled for all proxies")
        verified = unverified

    return {True: verified, False: unverified}


# ---------------------------------------------------------------------------
# Async entry points
# ---------------------------------------------------------------------------


async def initial_fetch(config: SpireConfig) -> dict[bool, ssl.SSLContext]:
    """Fetch the initial SPIFFE cert and return SSL contexts.

    Blocks (in a thread pool executor) until SPIRE delivers the first valid
    SVID.  Retries indefinitely — podsquire cannot start without a valid cert.
    """
    loop = asyncio.get_event_loop()
    attempt = 0
    while True:
        try:
            attempt += 1
            log.info(f"Fetching initial SPIFFE cert (attempt {attempt})...")
            await loop.run_in_executor(None, _fetch_and_write, config)
            expiry = _get_cert_expiry(config.cert_path)
            expiry_dt = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expiry))
            log.info(f"Initial SPIFFE cert fetched (expires {expiry_dt})")
            return build_ssl_contexts(config)
        except Exception as e:
            log.error(f"Initial cert fetch failed: {e}. Retrying in {config.retry_interval}s...")
            await asyncio.sleep(config.retry_interval)


async def initial_fetch_static(config: StaticCertConfig) -> dict[bool, ssl.SSLContext]:
    """Validate static cert files exist and return SSL contexts (no SPIRE)."""
    for path, label in ((config.cert_path, "cert"), (config.key_path, "key")):
        if not Path(path).exists():
            raise FileNotFoundError(f"Static {label} file not found: {path}")

    expiry = _get_cert_expiry(config.cert_path)
    expiry_dt = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expiry))
    remaining_h = int(expiry - time.time()) // 3600
    log.info(f"Using static cert: {config.cert_path} (expires {expiry_dt}, {remaining_h}h remaining)")
    return build_ssl_contexts_static(config)


async def renewal_loop(config: SpireConfig, renewed_event: asyncio.Event) -> None:
    """Asyncio task: watch for cert expiry and renew before the threshold.

    Sets renewed_event each time a renewal is successfully written to disk.
    The main loop should clear the event, restart proxy listeners, and signal
    the subprocess.
    """
    loop = asyncio.get_event_loop()
    retry_attempt = 0

    # Sleep until the first renewal is due
    try:
        expiry = _get_cert_expiry(config.cert_path)
        sleep_secs = max(
            config.renewal_interval,
            int(expiry - time.time() - config.expiry_threshold),
        )
        log.info(f"Cert renewal: first check in {sleep_secs}s")
        await asyncio.sleep(max(sleep_secs, 10))
    except Exception:
        pass  # Fall straight into the loop if we can't read the cert

    while True:
        try:
            await loop.run_in_executor(None, _fetch_and_write, config)
            retry_attempt = 0
            log.info("Cert renewed — notifying main loop")
            renewed_event.set()

            expiry = _get_cert_expiry(config.cert_path)
            sleep_secs = max(
                config.renewal_interval,
                int(expiry - time.time() - config.expiry_threshold),
            )
            log.info(f"Cert renewal: next check in {sleep_secs}s")
            await asyncio.sleep(max(sleep_secs, 10))

        except asyncio.CancelledError:
            raise
        except Exception as e:
            retry_attempt += 1
            log.error(f"Cert renewal failed (attempt {retry_attempt}): {e}. Retrying in {config.retry_interval}s")
            await asyncio.sleep(config.retry_interval)
