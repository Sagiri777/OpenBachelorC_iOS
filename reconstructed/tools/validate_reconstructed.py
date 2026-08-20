#!/usr/bin/env python3
"""Load reconstructed Frida bundles into the target app and watch for runtime errors."""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import frida

ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = ROOT / "tmp" / "reconstructed"

SCRIPT_CONFIGS = {
    "java": {"proxy_url": "http://127.0.0.1:8443", "no_proxy": True},
    "native": {"proxy_url": "http://127.0.0.1:8443", "no_proxy": True},
    "extra": {"pause_deploy": True, "3x_speed": True, "vision": True, "vision_font_size": 22},
    "trainer": {"dump_json": False},
}


def on_message(name: str, errors: list[str]):
    def _handler(message, data):
        mtype = message.get("type")
        if mtype == "error":
            desc = message.get("description") or message.get("stack") or str(message)
            errors.append(f"[{name}] {desc}")
            print(f"ERROR [{name}] {desc}", flush=True)
        elif mtype == "log":
            print(f"LOG [{name}] {message.get('payload')}", flush=True)
        else:
            print(f"MESSAGE [{name}] {message}", flush=True)
    return _handler


def post_config(script, cfg: dict):
    for k, v in cfg.items():
        script.post({"type": "conf", "k": k, "v": v})


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--package", default="com.hypergryph.arknights")
    ap.add_argument("--attach-name", default="")
    ap.add_argument("--mode", choices=["spawn", "attach"], default="spawn")
    ap.add_argument("--scripts", nargs="+", default=["java", "native", "extra", "trainer"])
    ap.add_argument("--wait", type=float, default=35.0)
    ap.add_argument("--trainer-command", action="append", default=[])
    args = ap.parse_args()

    device = frida.get_remote_device()
    print(f"device: {device}")

    pid_or_name: int | str
    spawned = False
    if args.mode == "spawn":
        pid_or_name = device.spawn([args.package])
        spawned = True
        print(f"spawned: {pid_or_name}")
    else:
        if args.attach_name:
            pid_or_name = args.attach_name
        else:
            procs = device.enumerate_processes()
            matches = [p for p in procs if args.package in p.name or "arknights" in p.name.lower() or "明日方舟" in p.name]
            if not matches:
                print("no matching running process", file=sys.stderr)
                return 2
            pid_or_name = matches[0].pid
        print(f"attaching: {pid_or_name}")

    session = device.attach(pid_or_name)
    errors: list[str] = []
    loaded = {}
    for name in args.scripts:
        path = SCRIPT_DIR / f"{name}.js"
        source = path.read_text(encoding="utf-8")
        script = session.create_script(source)
        script.on("message", on_message(name, errors))
        script.load()
        post_config(script, SCRIPT_CONFIGS.get(name, {}))
        loaded[name] = script
        print(f"loaded: {name} ({path.stat().st_size} bytes)")

    if spawned:
        device.resume(pid_or_name)
        print("resumed target")

    deadline = time.time() + args.wait
    sent_commands = False
    while time.time() < deadline:
        remain = deadline - time.time()
        if not sent_commands and args.trainer_command and remain < args.wait - 18 and "trainer" in loaded:
            for cmd in args.trainer_command:
                print(f"trainer invoke: {cmd}")
                loaded["trainer"].post({"type": "conf", "k": "invoke", "v": cmd})
            sent_commands = True
        time.sleep(0.5)

    for script in loaded.values():
        try:
            script.unload()
        except Exception:
            pass
    try:
        session.detach()
    except Exception:
        pass

    if errors:
        print("validation failed:")
        for e in errors:
            print(" -", e)
        return 1
    print("validation ok: no Frida runtime errors captured")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
