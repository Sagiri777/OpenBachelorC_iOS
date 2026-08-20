#!/usr/bin/env python3
"""Launch OpenBachelorC with reconstructed Frida scripts.

This mirrors the project's Python launcher, but loads scripts from
    tmp/reconstructed/{java,native,extra,trainer}.js
compiled from
    reconstructed/script/*/index.ts
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

import frida
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import FileHistory

from openbachelorc.adb import (
    clear_forward_proxy,
    connect_to_emulator,
    get_running_emulators,
    kill_frida_server,
    kill_root_process,
    start_apk,
    start_forward_proxy,
    start_frida_server,
    start_reverse_proxy,
    upload_frida_server_if_necessary,
)
from openbachelorc.config import config
from openbachelorc.const import PACKAGE_NAME

ROOT = Path(__file__).resolve().parent
OUT_DIR = ROOT / "tmp" / "reconstructed"
SRC_DIR = ROOT / "reconstructed" / "script"

COMMANDS = [
    "zero_cost",
    "zero_deploy_cnt",
    "deploy_everywhere",
    "zero_cooldown",
    "unlimited_token",
    "no_sp",
    "withdraw_everything",
    "heal_everyone",
    "unlimited_ammo",
    "eat_enemy",
    "global_range",
    "anti_air",
    "true_aoe",
    "no_ban_card",
    "cloner_assist",
    "allow_dup_char",
]


def run(cmd: list[str], **kwargs):
    print("$", " ".join(cmd), flush=True)
    return subprocess.run(cmd, check=True, cwd=ROOT, **kwargs)


def compile_script(name: str):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    src = SRC_DIR / name / "index.ts"
    out = OUT_DIR / f"{name}.js"
    if out.exists() and out.stat().st_mtime >= src.stat().st_mtime:
        return out
    env = os.environ.copy()
    env.setdefault("npm_config_cache", str(ROOT / ".npm-cache"))
    run(["npx", "frida-compile", "-S", str(src), "-o", str(out)], env=env)
    return out


def compile_all():
    for name in ["java", "native", "extra", "trainer"]:
        compile_script(name)


def get_emulator_id(device: str | None):
    if device:
        return device
    running = get_running_emulators()
    if not running:
        print("info: finding emulator")
        connect_to_emulator()
        running = get_running_emulators()
    if not running:
        raise SystemExit("error: emulator not found")
    print(f"info: using emulator {running[0]}")
    return running[0]


def prepare_emulator(emulator_id: str):
    upload_frida_server_if_necessary(emulator_id)
    kill_root_process(emulator_id, "florida-")
    if not config["use_gadget"]:
        start_frida_server(emulator_id)

    if config["host"] == "127.0.0.1":
        start_reverse_proxy(emulator_id, config["port"])
    if config["multiplayer_port"] > 0:
        start_reverse_proxy(emulator_id, config["multiplayer_port"])
    if config["icebreaker_port"] > 0:
        start_reverse_proxy(emulator_id, config["icebreaker_port"])

    clear_forward_proxy(emulator_id)
    start_forward_proxy(
        emulator_id,
        config["gadget_port"] if config["use_gadget"] else config["frida_port"],
    )


def wait_remote_frida(timeout=10.0):
    deadline = time.time() + timeout
    last_exc = None
    while time.time() < deadline:
        try:
            return frida.get_remote_device()
        except Exception as exc:
            last_exc = exc
            time.sleep(0.2)
    raise RuntimeError(f"remote frida not ready: {last_exc}")


def choose_running_game_process(device):
    for proc in device.enumerate_processes():
        name = proc.name
        if "arknights" in name.lower() or "明日方舟" in name or PACKAGE_NAME in name:
            return proc.pid
    raise RuntimeError("game process not found after launch")


def start_or_attach_game(emulator_id: str | None, attach_pc: bool, spawn: bool):
    if attach_pc:
        device = wait_remote_frida()
        return device, "Gadget", False

    device = wait_remote_frida()
    if config["use_gadget"]:
        start_apk(emulator_id)
        return device, "Gadget", False

    if spawn:
        pid = device.spawn([PACKAGE_NAME])
        return device, pid, True

    start_apk(emulator_id)
    time.sleep(1.0)
    return device, choose_running_game_process(device), False


def load_script(device, pid, name: str, conf: dict):
    path = OUT_DIR / f"{name}.js"
    session = device.attach(pid)
    script = session.create_script(path.read_text(encoding="utf-8"))

    def on_message(message, data):
        if message.get("type") == "error":
            print(f"ERROR [{name}] {message.get('description') or message.get('stack') or message}", flush=True)
        elif message.get("type") == "log":
            print(message.get("payload"), flush=True)
        else:
            print(f"message [{name}]: {message}", flush=True)

    script.on("message", on_message)
    script.load()
    for k, v in conf.items():
        script.post({"type": "conf", "k": k, "v": v})
    print(f"loaded reconstructed {name}: {path}")
    return session, script


class Game:
    def __init__(self, trainer_script):
        self.trainer_script = trainer_script

    def exec_trainer_command(self, name: str):
        if not self.trainer_script:
            print("err: trainer is disabled")
            return
        self.trainer_script.post({"type": "conf", "k": "invoke", "v": name})


def cli(game: Game):
    completer = WordCompleter(["enable", "disable", *COMMANDS, "all"], match_middle=True)
    session = PromptSession(history=FileHistory("trainer.reconstructed.txt"), completer=completer)
    while True:
        try:
            text = session.prompt("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not text:
            continue
        if text.startswith("!"):
            game.exec_trainer_command(text[1:])
            continue
        arr = text.split()
        flag = True
        if arr[0] == "enable":
            arr = arr[1:]
        elif arr[0] == "disable":
            arr = arr[1:]
            flag = False
        prefix = "enable:" if flag else "disable:"
        for cmd in arr:
            if cmd == "all":
                for c in COMMANDS:
                    game.exec_trainer_command(prefix + c)
            else:
                game.exec_trainer_command(prefix + cmd)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--device", help="adb serial, e.g. 127.0.0.1:26624")
    ap.add_argument("--spawn", action="store_true", help="Frida spawn instead of monkey+attach")
    ap.add_argument("--no-trainer", action="store_true")
    ap.add_argument("--no-extra", action="store_true")
    ap.add_argument("--attach-pc", action="store_true")
    args = ap.parse_args()

    compile_all()

    emulator_id = None if args.attach_pc else get_emulator_id(args.device)
    try:
        if not args.attach_pc:
            prepare_emulator(emulator_id)
        device, pid, spawned = start_or_attach_game(emulator_id, args.attach_pc, args.spawn or not config["no_spawn"])

        proxy_url = f"http://{config['host']}:{config['port']}"
        loaded = []
        loaded.append(load_script(device, pid, "java", {"proxy_url": proxy_url, "no_proxy": config["no_proxy"]}))
        loaded.append(load_script(device, pid, "native", {"proxy_url": proxy_url, "no_proxy": config["no_proxy"]}))
        if not args.no_extra and config["enable_extra"]:
            loaded.append(load_script(device, pid, "extra", config["extra_config"]))
        trainer_script = None
        if not args.no_trainer and config["enable_trainer"]:
            sess, trainer_script = load_script(device, pid, "trainer", config["trainer_config"])
            loaded.append((sess, trainer_script))

        if spawned:
            device.resume(pid)
        print("info: reconstructed game started")
        print("----------")
        cli(Game(trainer_script))
    finally:
        if not args.attach_pc and emulator_id:
            try:
                kill_frida_server(emulator_id)
            finally:
                clear_forward_proxy(emulator_id)


if __name__ == "__main__":
    main()
