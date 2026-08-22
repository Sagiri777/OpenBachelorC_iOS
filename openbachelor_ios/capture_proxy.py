from __future__ import annotations

import http.client
import http.server
import ipaddress
import secrets
import socket
import threading
from collections.abc import Callable
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit

PROXY_PATH_MARKER = "__openbachelor_proxy__"

_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def parse_http_proxy_url(value: str) -> tuple[str, int]:
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid capture proxy URL: {exc}") from exc
    if (
        parsed.scheme != "http"
        or not parsed.hostname
        or port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "capture proxy must be an HTTP proxy URL with an explicit port, "
            "for example http://127.0.0.1:8888"
        )
    return parsed.hostname, port


def discover_bridge_host(configured_host: str = "") -> str:
    """Return an IPv4 address that the iPhone can use to reach this Mac."""

    if configured_host.strip():
        try:
            results = socket.getaddrinfo(
                configured_host.strip(), None, socket.AF_INET, socket.SOCK_STREAM
            )
        except socket.gaierror as exc:
            raise RuntimeError(
                f"capture bridge host cannot be resolved: {configured_host}"
            ) from exc
        if not results:
            raise RuntimeError(f"capture bridge host has no IPv4 address: {configured_host}")
        address = results[0][4][0]
        if address == "0.0.0.0":
            raise RuntimeError("capture bridge host cannot be 0.0.0.0")
        return address

    candidates: list[str] = []
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 9))
        candidates.append(probe.getsockname()[0])
    except OSError:
        pass
    finally:
        probe.close()

    try:
        candidates.extend(
            result[4][0]
            for result in socket.getaddrinfo(
                socket.gethostname(), None, socket.AF_INET, socket.SOCK_STREAM
            )
        )
    except socket.gaierror:
        pass

    for address in candidates:
        parsed = ipaddress.ip_address(address)
        if parsed.version == 4 and not parsed.is_loopback and not parsed.is_unspecified:
            return address
    raise RuntimeError(
        "unable to detect a Mac IPv4 address reachable from the iPhone; "
        "pass --capture-host explicitly"
    )


def _connection_header_names(headers: Any) -> set[str]:
    names = set(_HOP_BY_HOP_HEADERS)
    if hasattr(headers, "get_all"):
        values = headers.get_all("Connection", [])
    else:
        values = [
            value for name, value in headers if name.casefold() == "connection"
        ]
    for value in values:
        names.update(item.strip().casefold() for item in value.split(",") if item.strip())
    return names


def _target_authority(parsed: SplitResult) -> str:
    assert parsed.hostname is not None
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    return f"{host}:{parsed.port}" if parsed.port is not None else host


class _BridgeServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address: tuple[str, int],
        bridge: "CaptureProxyBridge",
        handler: type[http.server.BaseHTTPRequestHandler],
    ) -> None:
        self.bridge = bridge
        super().__init__(address, handler)


def _decode_target_url(path: str, prefix: str) -> str:
    if not path.startswith(prefix):
        raise ValueError("invalid capture bridge path")
    encoded = path[len(prefix) :]
    scheme, separator, remainder = encoded.partition("/")
    authority, authority_separator, path_and_query = remainder.partition("/")
    if separator != "/" or scheme not in {"http", "https"} or not authority:
        raise ValueError("invalid capture bridge target")
    if authority_separator != "/":
        path_and_query = ""
    target_url = f"{scheme}://{authority}/{path_and_query}"
    parsed = urlsplit(target_url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid target port: {exc}") from exc
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("invalid capture bridge target authority")
    return target_url


class _BridgeHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: _BridgeServer

    def log_message(self, _format: str, *_args: Any) -> None:
        pass

    def _target_url(self) -> str:
        prefix = f"/{self.server.bridge.token}/{PROXY_PATH_MARKER}/"
        return _decode_target_url(self.path, prefix)

    def _read_chunked_body(self) -> bytes:
        body = bytearray()
        while True:
            line = self.rfile.readline(65537)
            if not line or len(line) > 65536:
                raise ValueError("invalid chunked request body")
            size_text = line.split(b";", 1)[0].strip()
            try:
                size = int(size_text, 16)
            except ValueError as exc:
                raise ValueError("invalid chunk size") from exc
            if size < 0:
                raise ValueError("invalid chunk size")
            if size == 0:
                while True:
                    trailer = self.rfile.readline(65537)
                    if not trailer or trailer in (b"\r\n", b"\n"):
                        return bytes(body)
                    if len(trailer) > 65536:
                        raise ValueError("invalid chunked request trailer")
            chunk = self.rfile.read(size)
            if len(chunk) != size or self.rfile.read(2) != b"\r\n":
                raise ValueError("incomplete chunked request body")
            body.extend(chunk)

    def _read_request_body(self) -> bytes:
        transfer_encoding = self.headers.get("Transfer-Encoding", "").casefold().strip()
        if transfer_encoding:
            if transfer_encoding != "chunked":
                raise ValueError(f"unsupported transfer encoding: {transfer_encoding}")
            return self._read_chunked_body()
        value = self.headers.get("Content-Length")
        if value is None:
            return b""
        try:
            size = int(value)
        except ValueError as exc:
            raise ValueError("invalid Content-Length") from exc
        if size < 0:
            raise ValueError("invalid Content-Length")
        body = self.rfile.read(size)
        if len(body) != size:
            raise ValueError("incomplete request body")
        return body

    def _forward(
        self, method: str, target_url: str, body: bytes
    ) -> tuple[int, str, list[tuple[str, str]], bytes]:
        bridge = self.server.bridge
        parsed = urlsplit(target_url)
        assert parsed.hostname is not None
        connection = http.client.HTTPConnection(
            bridge.upstream_host,
            bridge.upstream_port,
            timeout=bridge.timeout,
        )
        # The iPhone-side bridge has already exposed the request as HTTP. Forward the
        # original absolute URL to the viewer so Reqable displays the real scheme, host,
        # and path while establishing target TLS on the Mac side.
        request_target = urlunsplit(parsed._replace(fragment=""))

        skipped = _connection_header_names(self.headers) | {"host", "content-length"}
        try:
            connection.putrequest(
                method, request_target, skip_host=True, skip_accept_encoding=True
            )
            connection.putheader("Host", _target_authority(parsed))
            for name, value in self.headers.items():
                if name.casefold() not in skipped:
                    connection.putheader(name, value)
            if body:
                connection.putheader("Content-Length", str(len(body)))
            connection.endheaders(body if body else None)
            response = connection.getresponse()
            response_body = response.read()
            return response.status, response.reason, response.getheaders(), response_body
        finally:
            connection.close()

    def _send_forwarded_response(
        self,
        method: str,
        status: int,
        reason: str,
        headers: list[tuple[str, str]],
        body: bytes,
    ) -> None:
        self.send_response(status, reason)
        skipped = _connection_header_names(headers) | {"content-length"}
        for name, value in headers:
            if name.casefold() not in skipped:
                self.send_header(name, value)
        if method != "HEAD" and status not in {204, 304}:
            self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        if method != "HEAD" and body:
            self.wfile.write(body)

    def _handle(self, method: str) -> None:
        try:
            target_url = self._target_url()
            body = self._read_request_body()
        except ValueError as exc:
            self.send_error(400, str(exc))
            return

        try:
            status, reason, headers, response_body = self._forward(method, target_url, body)
        except (OSError, http.client.HTTPException) as exc:
            target = urlsplit(target_url)
            self.server.bridge.log(
                f"capture proxy upstream error for {target.scheme}://{target.netloc}: {exc}"
            )
            self.send_error(502, f"capture proxy upstream error: {exc}")
            return

        try:
            self._send_forwarded_response(method, status, reason, headers, response_body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_DELETE(self) -> None:
        self._handle("DELETE")

    def do_GET(self) -> None:
        self._handle("GET")

    def do_HEAD(self) -> None:
        self._handle("HEAD")

    def do_MERGE(self) -> None:
        self._handle("MERGE")

    def do_OPTIONS(self) -> None:
        self._handle("OPTIONS")

    def do_PATCH(self) -> None:
        self._handle("PATCH")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_PUT(self) -> None:
        self._handle("PUT")


class CaptureProxyBridge:
    def __init__(
        self,
        upstream_proxy: str,
        bridge_host: str,
        *,
        timeout: float = 30.0,
        token: str | None = None,
        log: Callable[[str], None] | None = None,
    ) -> None:
        self.upstream_host, self.upstream_port = parse_http_proxy_url(upstream_proxy)
        self.upstream_proxy = upstream_proxy
        self.bridge_host = bridge_host
        self.timeout = timeout
        self.token = token or secrets.token_urlsafe(24)
        self.log = log or (lambda _message: None)
        self._server: _BridgeServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("capture proxy bridge is not running")
        return int(self._server.server_address[1])

    @property
    def agent_proxy_url(self) -> str:
        return f"http://{self.bridge_host}:{self.port}/{self.token}"

    def start(self) -> "CaptureProxyBridge":
        if self._server is not None:
            return self
        try:
            with socket.create_connection(
                (self.upstream_host, self.upstream_port), timeout=min(self.timeout, 2.0)
            ):
                pass
        except OSError as exc:
            raise RuntimeError(
                "capture viewer proxy is not listening at "
                f"{self.upstream_host}:{self.upstream_port}"
            ) from exc

        server = _BridgeServer((self.bridge_host, 0), self, _BridgeHandler)
        thread = threading.Thread(
            target=server.serve_forever,
            name="openbachelor-ios-capture-proxy",
            daemon=True,
        )
        self._server = server
        self._thread = thread
        thread.start()
        return self

    def close(self) -> None:
        server, thread = self._server, self._thread
        self._server = None
        self._thread = None
        if server is None:
            return
        server.shutdown()
        server.server_close()
        if thread is not None:
            thread.join(timeout=2.0)

    def __enter__(self) -> "CaptureProxyBridge":
        return self.start()

    def __exit__(self, *_args: Any) -> None:
        self.close()
