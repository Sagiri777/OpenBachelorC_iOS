#!/usr/bin/env python3
from __future__ import annotations

import argparse
import time
from pathlib import Path

import frida

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "tmp" / "reconstructed" / "unity_capture.js"


def on_message(message, data):
    if message.get("type") == "error":
        print("ERROR", message.get("description") or message.get("stack") or message, flush=True)
    elif message.get("type") == "log":
        print(message.get("payload"), flush=True)
    else:
        print(message, flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="Run Unity capture SSL-bypass script.")
    ap.add_argument("--package", default="com.hypergryph.arknights")
    ap.add_argument("--attach", action="store_true")
    ap.add_argument("--proxy-url", default="", help="Optional URL rewrite target, e.g. http://127.0.0.1:8443")
    ap.add_argument("--rewrite-unity-url", action="store_true", help="Rewrite UnityWebRequest.Get URLs to --proxy-url; default is log-only")
    args = ap.parse_args()

    device = frida.get_remote_device()
    if args.attach:
        matches = [p for p in device.enumerate_processes() if args.package in p.name or "arknights" in p.name.lower() or "明日方舟" in p.name]
        if not matches:
            raise SystemExit("target process is not running")
        target = matches[0].pid
        print(f"attaching pid={target}")
    else:
        target = device.spawn([args.package])
        print(f"spawned pid={target}")

    session = device.attach(target)
    script = session.create_script(SCRIPT_PATH.read_text(encoding="utf-8"))
    script.on("message", on_message)
    script.load()
    script.post({"type": "conf", "k": "log_unity_url", "v": True})
    script.post({"type": "conf", "k": "rewrite_unity_url", "v": bool(args.rewrite_unity_url)})
    script.post({"type": "conf", "k": "no_proxy", "v": not bool(args.rewrite_unity_url)})
    if args.proxy_url:
        script.post({"type": "conf", "k": "proxy_url", "v": args.proxy_url})

    if not args.attach:
        device.resume(target)
        print("target resumed")

    print("Unity capture active. Keep this terminal open. Ctrl-C to detach.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("detaching...")
    finally:
        try: script.unload()
        except Exception: pass
        try: session.detach()
        except Exception: pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
