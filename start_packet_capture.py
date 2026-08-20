#!/usr/bin/env python3
"""Capture all game traffic using launch_reconstructed's infrastructure.

Game → Frida URL rewrite (java/native scripts) → forwarding proxy → real HTTPS server → capture.jsonl

Delegates device setup, Frida server management, and game launch to launch_reconstructed.py.
Runs its own forwarding proxy server that receives URL-rewritten requests from the game's
java/native Frida hooks, forwards them to the real upstream, and logs to captured/capture.jsonl.

Usage:
    .venv/bin/python start_packet_capture.py --device 127.0.0.1:26624
    .venv/bin/python start_packet_capture.py --device 127.0.0.1:26624 --spawn
"""
from __future__ import annotations

import argparse, http.server, json, ssl, sys, threading, time, urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
LOG_DIR = ROOT / "captured"


# ---------- forwarding proxy ----------
class ForwardingHandler(http.server.BaseHTTPRequestHandler):
    """Receives URL-rewritten requests, forwards to real servers, logs to capture.jsonl.

    Expects Frida-rewritten URLs in the format:
        http://proxy:port/<original-host>/<original-path>
    e.g. http://127.0.0.1:8443/ak-gs.hypergryph.com/online/v2/config
    """
    # Shared SSL context — created once, reused across all requests.
    _ssl_context: ssl.SSLContext | None = None

    @classmethod
    def ssl_context(cls):
        if cls._ssl_context is None:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            cls._ssl_context = ctx
        return cls._ssl_context

    def log_request(self, code="-", size="-"):
        pass  # suppress default access log; structured logging below

    def _capture(self, method, upstream_url, req_headers, req_body,
                 resp_status, resp_headers, resp_body):
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "method": method,
            "url": upstream_url,
            "request_headers": {k: v for k, v in req_headers.items()},
            "request_body": (req_body.decode("utf-8", errors="replace")[:65536]
                             if req_body else None),
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

    def _do(self, method):
        path = self.path.lstrip("/")
        if "/" not in path:
            self.send_error(400, f"invalid path, expected host/path, got {self.path}")
            return

        # URL format: /<original-host>/<path>?<query>
        host, _, rest = path.partition("/")
        # Drop telemetry / analytics noise — these are not useful for capture.
        if host.endswith(".hypergryph.com"):
            rest_lower = rest.lower()
            if rest_lower.startswith("batch_event") or rest_lower.startswith("event_log"):
                self.send_response(204)
                self.end_headers()
                return
        scheme = "http" if self.headers.get("X-Original-Scheme") == "http" else "https"
        upstream_url = f"{scheme}://{host}/{rest}"

        cl = int(self.headers.get("Content-Length", 0))
        req_body = self.rfile.read(cl) if cl > 0 else None

        skip_headers = {
            "host", "x-original-scheme", "x-forwarded-for", "x-forwarded-proto",
            "connection", "proxy-connection", "transfer-encoding", "keep-alive",
            "content-length",
        }
        req_headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in skip_headers}

        print(f"  -> {method} {upstream_url}", flush=True)
        try:
            req = urllib.request.Request(upstream_url, data=req_body, method=method)
            for k, v in req_headers.items():
                req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=30, context=self.ssl_context()) as resp:
                resp_body = resp.read()

            resp_headers = dict(resp.getheaders())
            self.send_response(resp.status)
            for k, v in resp.getheaders():
                if k.lower() not in {"transfer-encoding", "content-encoding", "content-length"}:
                    self.send_header(k, v)
            self.send_header("Content-Length", str(len(resp_body)))
            self.end_headers()
            self.wfile.write(resp_body)

            self._capture(method, upstream_url, req_headers, req_body,
                          resp.status, resp_headers, resp_body)
        except Exception as exc:
            print(f"  !! upstream error: {exc}", flush=True)
            self.send_error(502, str(exc))
            self._capture(method, upstream_url, req_headers, req_body, 502, {}, None)

    do_GET = lambda s: s._do("GET")
    do_POST = lambda s: s._do("POST")
    do_PUT = lambda s: s._do("PUT")
    do_DELETE = lambda s: s._do("DELETE")
    do_PATCH = lambda s: s._do("PATCH")
    do_HEAD = lambda s: s._do("HEAD")


def run_proxy(port=8443):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), ForwardingHandler)
    print(f"forwarding proxy on 127.0.0.1:{port}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


# ---------- main ----------
def main():
    ap = argparse.ArgumentParser(
        description="Capture all game traffic via Frida URL rewrite + forwarding proxy"
    )
    ap.add_argument("--device", help="adb serial, e.g. 127.0.0.1:26624")
    ap.add_argument("--proxy-port", type=int, default=8443,
                    help="Port for the forwarding proxy (default: 8443)")
    ap.add_argument("--spawn", action="store_true",
                    help="Use Frida spawn (default in capture mode; --no-spawn for monkey+attach)")
    ap.add_argument("--no-spawn", action="store_true",
                    help="Use monkey+attach instead of Frida spawn")
    ap.add_argument("--no-trainer", action="store_true",
                    help="Disable trainer script")
    ap.add_argument("--no-extra", action="store_true",
                    help="Disable extra script")
    args = ap.parse_args()

    # Override config so traffic routes through our forwarding proxy.
    from openbachelorc.config import config
    config["host"] = "127.0.0.1"
    config["port"] = args.proxy_port
    config["no_proxy"] = False
    # Capture mode defaults to spawn for guaranteed clean hook injection.
    config["no_spawn"] = args.no_spawn
    if not args.no_trainer:
        config["enable_trainer"] = True
    else:
        config["enable_trainer"] = False
    if args.no_extra:
        config["enable_extra"] = False
    else:
        config["enable_extra"] = True

    # Import after config is patched so launch_reconstructed sees our overrides.
    import launch_reconstructed as lr

    # 1. Compile all reconstructed scripts (java, native, extra, trainer)
    lr.compile_all()

    # 2. Start the forwarding proxy in a background daemon thread
    t = threading.Thread(target=run_proxy, args=(args.proxy_port,), daemon=True)
    t.start()
    time.sleep(0.5)

    # 3. Device setup via launch_reconstructed (frida server, adb forward/reverse)
    print("info: setup device", flush=True)
    emulator_id = lr.get_emulator_id(args.device)

    try:
        # prepare_emulator handles: frida server upload/start, adb forward, adb reverse
        lr.prepare_emulator(emulator_id)

        # 4. Start or attach to game process
        device, pid, spawned = lr.start_or_attach_game(
            emulator_id,
            attach_pc=False,
            spawn=not config["no_spawn"],
        )

        proxy_url = f"http://{config['host']}:{config['port']}"
        loaded = []

        # 5. Load java/native scripts which rewrite all game URLs to our proxy
        loaded.append(lr.load_script(device, pid, "java",
                                     {"proxy_url": proxy_url, "no_proxy": False}))
        loaded.append(lr.load_script(device, pid, "native",
                                     {"proxy_url": proxy_url, "no_proxy": False}))

        # 6. Optional extra and trainer scripts
        if config["enable_extra"]:
            loaded.append(lr.load_script(device, pid, "extra", config["extra_config"]))
        if config["enable_trainer"]:
            loaded.append(lr.load_script(device, pid, "trainer", config["trainer_config"]))

        if spawned:
            device.resume(pid)
        else:
            time.sleep(2.0)  # let the attach settle

        print("----------", flush=True)
        print(f"Capture active. All game traffic -> http://127.0.0.1:{args.proxy_port}/<host>/<path> -> real server", flush=True)
        print(f"Log: {LOG_DIR / 'capture.jsonl'}", flush=True)
        print("Ctrl-C to stop", flush=True)

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\ndone")
        finally:
            for sess, script in loaded:
                try:
                    script.unload()
                except Exception:
                    pass
                try:
                    sess.detach()
                except Exception:
                    pass
    finally:
        try:
            lr.kill_frida_server(emulator_id)
        except Exception:
            pass
        try:
            lr.clear_forward_proxy(emulator_id)
        except Exception:
            pass


if __name__ == "__main__":
    main()
