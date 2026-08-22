import http.client
import http.server
import threading

import pytest

from openbachelor_ios import capture_proxy
from openbachelor_ios.capture_proxy import CaptureProxyBridge, PROXY_PATH_MARKER


class _ViewerProxy(http.server.BaseHTTPRequestHandler):
    requests = []

    def log_message(self, _format, *_args):
        pass

    def do_POST(self):
        self._handle(201)

    def do_GET(self):
        self._handle(200)

    def _handle(self, status):
        size = int(self.headers.get("Content-Length", "0"))
        type(self).requests.append((self.path, dict(self.headers), self.rfile.read(size)))
        response = b"viewer response"
        self.send_response(status)
        self.send_header("X-Viewer", "yes")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


def _start_server(handler):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_bridge_forwards_http_request_through_standard_proxy():
    _ViewerProxy.requests = []
    viewer, viewer_thread = _start_server(_ViewerProxy)
    bridge = CaptureProxyBridge(
        f"http://127.0.0.1:{viewer.server_port}",
        "127.0.0.1",
        token="test-token",
    )
    try:
        bridge.start()
        connection = http.client.HTTPConnection("127.0.0.1", bridge.port)
        path = f"/test-token/{PROXY_PATH_MARKER}/http/example.test:8080/api?q=1"
        connection.request(
            "POST",
            path,
            body=b"request body",
            headers={
                "Authorization": "Bearer secret",
                "Connection": "keep-alive, X-Remove",
                "X-Remove": "not forwarded",
            },
        )
        response = connection.getresponse()

        assert response.status == 201
        assert response.getheader("X-Viewer") == "yes"
        assert response.read() == b"viewer response"
        assert len(_ViewerProxy.requests) == 1
        target, headers, body = _ViewerProxy.requests[0]
        assert target == "http://example.test:8080/api?q=1"
        assert headers["Host"] == "example.test:8080"
        assert headers["Authorization"] == "Bearer secret"
        assert "X-Remove" not in headers
        assert body == b"request body"
    finally:
        bridge.close()
        viewer.shutdown()
        viewer.server_close()
        viewer_thread.join(timeout=2)


def test_bridge_forwards_https_post_as_visible_absolute_request():
    _ViewerProxy.requests = []
    viewer, viewer_thread = _start_server(_ViewerProxy)
    bridge = CaptureProxyBridge(
        f"http://127.0.0.1:{viewer.server_port}",
        "127.0.0.1",
        token="test-token",
    )
    try:
        bridge.start()
        connection = http.client.HTTPConnection("127.0.0.1", bridge.port)
        path = f"/test-token/{PROXY_PATH_MARKER}/https/secure.test/private?q=2"
        connection.request("POST", path, body=b"sync payload")
        response = connection.getresponse()

        assert response.status == 201
        assert response.getheader("X-Viewer") == "yes"
        assert response.read() == b"viewer response"
        assert len(_ViewerProxy.requests) == 1
        target, headers, body = _ViewerProxy.requests[0]
        assert target == "https://secure.test/private?q=2"
        assert headers["Host"] == "secure.test"
        assert body == b"sync payload"
    finally:
        bridge.close()
        viewer.shutdown()
        viewer.server_close()
        viewer_thread.join(timeout=2)
@pytest.mark.parametrize(
    "value",
    ["127.0.0.1:8888", "https://127.0.0.1:8888", "http://127.0.0.1"],
)
def test_proxy_url_requires_plain_http_and_explicit_port(value):
    with pytest.raises(ValueError, match="HTTP proxy URL"):
        capture_proxy.parse_http_proxy_url(value)


def test_bridge_fails_before_launch_when_viewer_is_not_listening():
    bridge = CaptureProxyBridge("http://127.0.0.1:1", "127.0.0.1")

    with pytest.raises(RuntimeError, match="not listening"):
        bridge.start()
