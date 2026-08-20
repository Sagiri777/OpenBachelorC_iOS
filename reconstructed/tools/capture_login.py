#!/usr/bin/env python3
"""Robust capture: spawn game, hook, forward proxy, tap UI, log everything.

Designed to keep capturing even if adb or screenshots fail intermittently.
"""
from __future__ import annotations

import argparse, http.server, json, os, signal, ssl, subprocess, sys
import threading, time, urllib.request
from pathlib import Path

import frida

ROOT = Path(__file__).resolve().parents[2]
LOG_DIR = ROOT / "captured"
SCRIPT_DIR = ROOT / "tmp" / "reconstructed"
ADB_TOOL = "/Applications/MuMuPlayer Pro.app/Contents/MacOS/MuMu Android Device.app/Contents/MacOS/tools/adb"

# ---------- forwarding proxy ----------
class ForwardingHandler(http.server.BaseHTTPRequestHandler):
    _ssl_context = None
    @classmethod
    def ssl_context(cls):
        if cls._ssl_context is None:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            cls._ssl_context = ctx
        return cls._ssl_context
    def log_request(self, code="-", size="-"):
        pass
    def _capture(self, method, upstream_url, req_headers, req_body, resp_status, resp_headers, resp_body):
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "method": method, "url": upstream_url,
            "request_headers": dict(req_headers.items()) if hasattr(req_headers, "items") else dict(req_headers),
            "request_body": (req_body.decode("utf-8", errors="replace")[:65536] if req_body else None),
            "response_status": resp_status,
            "response_headers": dict(resp_headers.items()) if hasattr(resp_headers, "items") else dict(resp_headers),
            "response_body": None,
        }
        if resp_body:
            try:
                text = resp_body.decode("utf-8", errors="replace")
                if len(text) > 65536: text = text[:65536] + "...(truncated)"
                entry["response_body"] = text
            except Exception:
                entry["response_body"] = f"<binary {len(resp_body)} bytes>"
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_path = LOG_DIR / "capture.jsonl"
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        print(f"[{entry['timestamp']}] {method} {resp_status} {upstream_url}", flush=True)
    def _do(self, method):
        try:
            path = self.path.lstrip("/")
            if "/" not in path:
                self.send_error(400, f"invalid path: {self.path}")
                return
            host, _, rest = path.partition("/")
            if host.endswith(".hypergryph.com"):
                l = rest.lower()
                if l.startswith("batch_event") or l.startswith("event_log"):
                    self.send_response(204); self.end_headers(); return
            scheme = "http" if self.headers.get("X-Original-Scheme") == "http" else "https"
            upstream_url = f"{scheme}://{host}/{rest}"
            cl = int(self.headers.get("Content-Length", 0))
            req_body = self.rfile.read(cl) if cl > 0 else None
            skip = {"host","x-original-scheme","x-forwarded-for","x-forwarded-proto",
                    "connection","proxy-connection","transfer-encoding","keep-alive","content-length"}
            req_headers = {k: v for k, v in self.headers.items() if k.lower() not in skip}
            print(f"  -> {method} {upstream_url}", flush=True)
            req = urllib.request.Request(upstream_url, data=req_body, method=method)
            for k, v in req_headers.items():
                req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=30, context=self.ssl_context()) as resp:
                rb = resp.read()
                rh = dict(resp.getheaders())
                self.send_response(resp.status)
                for k, v in resp.getheaders():
                    if k.lower() not in {"transfer-encoding","content-encoding","content-length"}:
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len(rb)))
                self.end_headers()
                self.wfile.write(rb)
                self._capture(method, upstream_url, req_headers, req_body, resp.status, rh, rb)
        except Exception as exc:
            print(f"  !! upstream error: {exc}", flush=True)
            try:
                self.send_error(502, str(exc))
            except Exception:
                pass
            try:
                self._capture(method, upstream_url, {}, None, 502, {}, None)
            except Exception:
                pass
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


# ---------- adb helpers with timeout+ignore ----------
def adb_run(args, **kw):
    try:
        r = subprocess.run([ADB_TOOL, *args], capture_output=True, text=True, timeout=kw.pop("timeout", 8))
        return r
    except subprocess.TimeoutExpired:
        print(f"adb timeout: {' '.join(args[:3])}...", flush=True)
        return None
    except Exception as e:
        print(f"adb err: {e}", flush=True)
        return None


def adb_tap(adb_serial, x, y):
    r = adb_run(["-s", adb_serial, "shell", "input", "tap", str(x), str(y)])
    if r is not None:
        print(f"tap {x},{y} rc={r.returncode}", flush=True)


def adb_screencap(adb_serial, out_local="/tmp/cap.png"):
    r1 = adb_run(["-s", adb_serial, "shell", "screencap", "-p", "/sdcard/c.png"], timeout=8)
    r2 = adb_run(["-s", adb_serial, "pull", "/sdcard/c.png", out_local], timeout=8)
    return r1 is not None and r2 is not None


def adb_resume_frida(adb_serial):
    """Try to repair the adb-florida chain in case it died."""
    adb_run(["-s", adb_serial, "shell", "nohup /data/local/tmp/florida-17.9.1 -l 127.0.0.1:9443 > /data/local/tmp/florida.log 2>&1 </dev/null &"], timeout=8)


def on_message(name, errors):
    def handler(message, data):
        mt = message.get("type")
        if mt == "error":
            d = message.get("description") or message.get("stack") or str(message)
            errors.append(f"[{name}] {d}")
            print(f"ERR[{name}] {d}", flush=True)
        elif mt == "log":
            print(f"[{name}] {message.get('payload')}", flush=True)
    return handler


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--device", required=True)
    ap.add_argument("--package", default="com.hypergryph.arknights")
    ap.add_argument("--proxy-port", type=int, default=8443)
    ap.add_argument("--no-trainer", action="store_true")
    ap.add_argument("--no-extra", action="store_true")
    ap.add_argument("--max-seconds", type=int, default=900, help="max wall-clock capture window")
    args = ap.parse_args()

    # Make stdout line-buffered
    sys.stdout.reconfigure(line_buffering=True)

    t = threading.Thread(target=run_proxy, args=(args.proxy_port,), daemon=True)
    t.start()
    time.sleep(0.5)

    try:
        device = frida.get_remote_device()
    except Exception as e:
        print(f"FATAL: frida not reachable: {e}", flush=True)
        sys.exit(2)
    print(f"device: {device}", flush=True)

    try:
        pid = device.spawn([args.package])
    except Exception as e:
        print(f"FATAL: spawn failed: {e}", flush=True)
        sys.exit(3)
    print(f"spawned pid={pid}", flush=True)

    sess = device.attach(pid)
    proxy_url = f"http://127.0.0.1:{args.proxy_port}"

    loaded = []
    errors = []
    scripts = [
        ("ssl_bypass", {}),
        ("java", {"proxy_url": proxy_url, "no_proxy": False}),
        ("native", {"proxy_url": proxy_url, "no_proxy": False}),
    ]
    if not args.no_extra:
        scripts.append(("extra", {"pause_deploy": True, "3x_speed": True, "vision": True, "vision_font_size": 22}))
    if not args.no_trainer:
        scripts.append(("trainer", {"dump_json": False}))
    for name, cfg in scripts:
        try:
            src = (SCRIPT_DIR / f"{name}.js").read_text(encoding="utf-8")
            sc = sess.create_script(src)
            sc.on("message", on_message(name, errors))
            sc.load()
            for k, v in cfg.items():
                sc.post({"type": "conf", "k": k, "v": v})
            loaded.append((sess, sc))
            print(f"loaded {name} ({(SCRIPT_DIR / f'{name}.js').stat().st_size} bytes)", flush=True)
        except Exception as e:
            print(f"!! load {name} failed: {e}", flush=True)
    try:
        device.resume(pid)
    except Exception as e:
        print(f"!! resume failed: {e}", flush=True)
    print("game resumed", flush=True)

    # Interaction phase: try several tap points across multiple windows
    taps = [
        (60, "yellow diamond center-bottom", 720, 2350),
        (30, "yellow diamond alt position 1", 720, 2200),
        (30, "yellow diamond alt position 2", 720, 1900),
        (30, "yellow diamond alt position 3", 540, 2350),
        (60, "after diamond: wake button center", 720, 2350),
        (30, "after wake: confirm", 720, 2050),
        (30, "after wake: confirm alt", 720, 1700),
    ]

    deadline = time.time() + args.max_seconds
    time.sleep(45)  # initial game boot
    for delay, label, x, y in taps:
        if time.time() > deadline: break
        try:
            print(f"[tap] {label} -> ({x},{y})", flush=True)
            adb_screencap(args.device)
            adb_tap(args.device, x, y)
        except Exception as e:
            print(f"[tap] err: {e}", flush=True)
        try:
            time.sleep(delay)
        except KeyboardInterrupt:
            break

    # Continuation — keep capturing for the rest of the window
    remaining = max(0, int(deadline - time.time()))
    print(f"[hold] capturing for another {remaining}s; Ctrl-C to stop", flush=True)
    try:
        while time.time() < deadline:
            time.sleep(2)
            if remaining % 60 < 5:
                adb_screencap(args.device, "/tmp/cap.png")
    except KeyboardInterrupt:
        pass

    print("=== summary ===", flush=True)
    log = LOG_DIR / "capture.jsonl"
    if log.exists():
        n = sum(1 for _ in open(log))
        print(f"total captures: {n}", flush=True)
    print(f"errors: {len(errors)}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
