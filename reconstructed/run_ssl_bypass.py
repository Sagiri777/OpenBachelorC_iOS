#!/usr/bin/env python3
from __future__ import annotations

import argparse
import time
from pathlib import Path

import frida

ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT / "tmp" / "reconstructed" / "ssl_bypass.js"


def on_message(message, data):
    if message.get("type") == "error":
        print("ERROR", message.get("description") or message.get("stack") or message, flush=True)
    elif message.get("type") == "log":
        print(message.get("payload"), flush=True)
    else:
        print(message, flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(description="Run dedicated SSL bypass Frida script for packet capture.")
    ap.add_argument("--package", default="com.hypergryph.arknights")
    ap.add_argument("--attach", action="store_true", help="attach to a running process instead of spawning")
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

    if not args.attach:
        device.resume(target)
        print("target resumed")

    print("SSL bypass active. Keep this terminal open while capturing. Ctrl-C to detach.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("detaching...")
    finally:
        try:
            script.unload()
        except Exception:
            pass
        try:
            session.detach()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
