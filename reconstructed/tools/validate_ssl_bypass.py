#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import frida

ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT / "tmp" / "reconstructed" / "ssl_bypass.js"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--package", default="com.hypergryph.arknights")
    ap.add_argument("--mode", choices=["spawn", "attach"], default="spawn")
    ap.add_argument("--wait", type=float, default=35.0)
    args = ap.parse_args()

    errors: list[str] = []

    def on_message(message, data):
        if message.get("type") == "error":
            desc = message.get("description") or message.get("stack") or str(message)
            errors.append(desc)
            print(f"ERROR {desc}", flush=True)
        elif message.get("type") == "log":
            print(message.get("payload"), flush=True)
        else:
            print(message, flush=True)

    device = frida.get_remote_device()
    print(f"device: {device}")

    spawned = False
    if args.mode == "spawn":
        target = device.spawn([args.package])
        spawned = True
        print(f"spawned: {target}")
    else:
        matches = [p for p in device.enumerate_processes() if args.package in p.name or "arknights" in p.name.lower() or "明日方舟" in p.name]
        if not matches:
            print("no matching running process", file=sys.stderr)
            return 2
        target = matches[0].pid
        print(f"attaching: {target}")

    session = device.attach(target)
    script = session.create_script(SCRIPT_PATH.read_text(encoding="utf-8"))
    script.on("message", on_message)
    script.load()
    print(f"loaded: {SCRIPT_PATH} ({SCRIPT_PATH.stat().st_size} bytes)")

    if spawned:
        device.resume(target)
        print("resumed target")

    deadline = time.time() + args.wait
    while time.time() < deadline:
        time.sleep(0.5)

    try:
        script.unload()
    except Exception:
        pass
    try:
        session.detach()
    except Exception:
        pass

    if errors:
        print("ssl bypass validation failed")
        for e in errors:
            print(" -", e)
        return 1
    print("ssl bypass validation ok: no Frida runtime errors captured")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
