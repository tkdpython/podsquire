"""TCP and HTTP mTLS proxy for podsquire.

Each proxy:
  - Listens on a local (plaintext) host:port
  - Forwards connections to a remote host:port over mTLS using the SPIFFE cert

Two modes:
  tcp  — raw asyncio byte tunnel; transparent to any TCP protocol.
  http — aiohttp-based HTTP reverse proxy; rewrites the Host header and
         maintains a shared connection pool per proxy.

Both modes expose start() / stop() coroutines.  When certs are renewed the
main loop calls stop() on all proxies, rebuilds ssl.SSLContext objects from
the freshly written cert files, then calls start() again.
"""

import asyncio
import contextlib
import logging
import ssl
from dataclasses import dataclass

import aiohttp
from aiohttp import web

log = logging.getLogger(__name__)


@dataclass
class ProxyConfig:
    name: str
    mode: str  # 'tcp' or 'http'
    local_host: str
    local_port: int
    remote_host: str
    remote_port: int
    verify_remote: bool = True


# ---------------------------------------------------------------------------
# TCP proxy
# ---------------------------------------------------------------------------


async def _pipe(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    label: str = "",
) -> None:
    """Pipe bytes from reader to writer until EOF or connection error."""
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    finally:
        with contextlib.suppress(Exception):
            writer.close()


async def _handle_tcp_connection(
    local_reader: asyncio.StreamReader,
    local_writer: asyncio.StreamWriter,
    remote_host: str,
    remote_port: int,
    ssl_ctx: ssl.SSLContext,
    proxy_name: str,
) -> None:
    """Handle one inbound TCP connection: open an mTLS tunnel and pipe both directions."""
    peer = local_writer.get_extra_info("peername")
    log.debug(f"[{proxy_name}] New connection from {peer}")
    remote_writer = None
    try:
        remote_reader, remote_writer = await asyncio.open_connection(remote_host, remote_port, ssl=ssl_ctx)
        log.debug(f"[{proxy_name}] mTLS tunnel open to {remote_host}:{remote_port}")
        await asyncio.gather(
            _pipe(local_reader, remote_writer, f"{proxy_name}→remote"),
            _pipe(remote_reader, local_writer, f"{proxy_name}←remote"),
            return_exceptions=True,
        )
    except ssl.SSLError as e:
        log.error(f"[{proxy_name}] SSL error connecting to {remote_host}:{remote_port}: {e}")
    except OSError as e:
        log.error(f"[{proxy_name}] Connection error to {remote_host}:{remote_port}: {e}")
    finally:
        with contextlib.suppress(Exception):
            local_writer.close()
        if remote_writer:
            with contextlib.suppress(Exception):
                remote_writer.close()


class TcpProxy:
    """Raw TCP tunnel with mTLS on the outbound connection."""

    def __init__(self, config: ProxyConfig, ssl_ctx: ssl.SSLContext) -> None:
        self._config = config
        self._ssl_ctx = ssl_ctx
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        cfg = self._config
        self._server = await asyncio.start_server(
            lambda r, w: _handle_tcp_connection(r, w, cfg.remote_host, cfg.remote_port, self._ssl_ctx, cfg.name),
            cfg.local_host,
            cfg.local_port,
        )
        log.info(
            f"[{cfg.name}] TCP proxy  {cfg.local_host}:{cfg.local_port}"
            f" → {cfg.remote_host}:{cfg.remote_port}"
            f"  verify_remote={cfg.verify_remote}"
        )

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            log.info(f"[{self._config.name}] TCP proxy stopped")


# ---------------------------------------------------------------------------
# HTTP proxy
# ---------------------------------------------------------------------------


def _make_http_handler(remote_base: str, session_getter, proxy_name: str, remote_host_header: str):
    """Return an aiohttp request handler that reverse-proxies to remote_base."""

    _drop_request = frozenset(("host", "content-length", "transfer-encoding", "connection", "keep-alive"))
    _drop_response = frozenset(("content-encoding", "transfer-encoding", "connection", "keep-alive"))

    async def handler(request: web.Request) -> web.Response:
        target_url = f"{remote_base}{request.path_qs}"
        fwd_headers = {k: v for k, v in request.headers.items() if k.lower() not in _drop_request}
        fwd_headers["Host"] = remote_host_header
        log.debug(f"[{proxy_name}] {request.method} {request.path_qs} → {target_url}")

        try:
            async with session_getter().request(
                method=request.method,
                url=target_url,
                headers=fwd_headers,
                data=request.content,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=60),
            ) as resp:
                body = await resp.read()
                resp_headers = {k: v for k, v in resp.headers.items() if k.lower() not in _drop_response}
                return web.Response(status=resp.status, reason=resp.reason, headers=resp_headers, body=body)

        except aiohttp.ClientSSLError as e:
            log.error(f"[{proxy_name}] SSL error: {e}")
            return web.Response(status=502, text=f"SSL error: {e}")
        except aiohttp.ClientConnectionError as e:
            log.error(f"[{proxy_name}] Connection error: {e}")
            return web.Response(status=502, text=f"Connection error: {e}")
        except Exception as e:
            log.error(f"[{proxy_name}] Proxy error: {type(e).__name__}: {e}")
            return web.Response(status=502, text=f"Proxy error: {e}")

    return handler


class HttpProxy:
    """aiohttp-based HTTP reverse proxy with mTLS on the outbound connection."""

    def __init__(self, config: ProxyConfig, ssl_ctx: ssl.SSLContext) -> None:
        self._config = config
        self._ssl_ctx = ssl_ctx
        self._runner: web.AppRunner | None = None
        self._session: aiohttp.ClientSession | None = None

    async def start(self) -> None:
        cfg = self._config
        remote_base = f"https://{cfg.remote_host}:{cfg.remote_port}"

        connector = aiohttp.TCPConnector(ssl=self._ssl_ctx)
        self._session = aiohttp.ClientSession(connector=connector)

        app = web.Application()
        app.router.add_route(
            "*",
            "/{path_info:.*}",
            _make_http_handler(remote_base, lambda: self._session, cfg.name, cfg.remote_host),
        )

        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        await web.TCPSite(self._runner, cfg.local_host, cfg.local_port).start()
        log.info(
            f"[{cfg.name}] HTTP proxy  {cfg.local_host}:{cfg.local_port}"
            f" → {remote_base}"
            f"  verify_remote={cfg.verify_remote}"
        )

    async def stop(self) -> None:
        if self._session:
            await self._session.close()
            self._session = None
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
            log.info(f"[{self._config.name}] HTTP proxy stopped")


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_proxy(config: ProxyConfig, ssl_ctx: ssl.SSLContext) -> TcpProxy | HttpProxy:
    """Instantiate the correct proxy type based on config.mode."""
    if config.mode == "http":
        return HttpProxy(config, ssl_ctx)
    if config.mode == "tcp":
        return TcpProxy(config, ssl_ctx)
    raise ValueError(f"Unknown proxy mode '{config.mode}' for proxy '{config.name}'. Use 'http' or 'tcp'.")
