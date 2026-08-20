#!/usr/bin/env python3
"""Simple forwarding proxy that logs every request/response.

Game → Frida URL rewrite → localhost:8443 (plain HTTP) → this proxy → real HTTPS server

Usage:
    .venv/bin/python reconstructed/forward_proxy.py --port 8443
"""
from __future__ import annotations

import argparse
import gzip
import http.server
import io
import json
import ssl
import sys
import time
import urllib.request
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parent.parent / "captured"


class ForwardingHandler(http.server.BaseHTTPRequestHandler):
    def log_request(self, code="-", size="-"):
        pass  # suppress default access log, we write structured logs instead

    def _capture(self, method: str, upstream_url: str, req_headers: dict, req_body: bytes | None, resp_status: int, resp_headers: dict, resp_body: bytes | None):
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "method": method,
            "url": upstream_url,
            "request_headers": {k: v for k, v in req_headers.items()},
            "request_body": req_body.decode("utf-8", errors="replace")[:65536] if req_body else None,
            "response_status": resp_status,
            "response_headers": {k: v for k, v in resp_headers.items()},
            "response_body": None,
        }
        if resp_body:
            try:
                text = resp_body.decode("utf-8", errors="replace")
                if len(text) > 65536:
                    text = text[:65536] + "...(truncated)"
                entry["response_body"] = text
            except Exception:
                entry["response_body"] = f"<binary {len(resp_body)} bytes>"

        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_path = LOG_DIR / "capture.jsonl"
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        print(f"[{entry['timestamp']}] {method} {resp_status} {upstream_url}", flush=True)

    def _do(self, method: str):
        path = self.path.lstrip("/")
        if "/" not in path:
            self.send_error(400, f"invalid path, expected host/path, got {self.path}")
            return

        # First segment is the original host, rest is the path
        host, _, rest = path.partition("/")
        upstream_url = f"https://{host}/{rest}"
        if self.headers.get("X-Original-Scheme") == "http":
            upstream_url = f"http://{host}/{rest}"

        content_length = int(self.headers.get("Content-Length", 0))
        req_body = self.rfile.read(content_length) if content_length > 0 else None

        # Collect request headers, strip hop-by-hop and proxy-specific headers
        req_headers = {}
        skip_headers = {"host", "x-original-scheme", "x-forwarded-for", "x-forwarded-proto",
                        "connection", "proxy-connection", "transfer-encoding", "keep-alive"}
        for k, v in self.headers.items():
            if k.lower() not in skip_headers:
                req_headers[k] = v

        print(f"  -> {method} {upstream_url}", flush=True)
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            req = urllib.request.Request(upstream_url, data=req_body, method=method)
            for k, v in req_headers.items():
                req.add_header(k, v)

            with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
                resp_status = resp.status
                resp_headers = dict(resp.getheaders())
                resp_body = resp.read()

            self.send_response(resp_status)
            for k, v in resp_headers.items():
                if k.lower() not in {"transfer-encoding", "content-encoding", "content-length"}:
                    self.send_header(k, v)
            if resp_body:
                self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            if resp_body:
                self.wfile.write(resp_body)

            self._capture(method, upstream_url, req_headers, req_body, resp_status, resp_headers, resp_body)
        except Exception as exc:
            print(f"  !! upstream error: {exc}", flush=True)
            self.send_error(502, f"upstream error: {exc}")
            self._capture(method, upstream_url, req_headers, req_body, 502, {}, None)

    do_GET = lambda s: s._do("GET")
    do_POST = lambda s: s._do("POST")
    do_PUT = lambda s: s._do("PUT")
    do_DELETE = lambda s: s._do("DELETE")
    do_PATCH = lambda s: s._do("PATCH")
    do_HEAD = lambda s: s._do("HEAD")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--bind", default="127.0.0.1")
    args = ap.parse_args()

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = LOG_DIR / "capture.jsonl"
    print(f"capture log: {log_path}", flush=True)
    print(f"forwarding proxy listening on {args.bind}:{args.port}", flush=True)
    print("Game Frida script must rewrite URLs to http://127.0.0.1:8443/<original-host>/<path>", flush=True)
    print("Ctrl-C to stop", flush=True)

    server = http.server.HTTPServer((args.bind, args.port), ForwardingHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped", flush=True)
        server.server_close()


if __name__ == "__main__":
    main()
