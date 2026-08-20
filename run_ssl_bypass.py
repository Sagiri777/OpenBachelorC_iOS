#!/usr/bin/env python3
"""一键启动 SSL bypass，配合抓包工具使用。

用法：
    # 先启动游戏，然后运行：
    python run_ssl_bypass.py

    # 或者自动启动游戏：
    python run_ssl_bypass.py --spawn

    # 指定设备：
    python run_ssl_bypass.py --device 127.0.0.1:26624
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

import frida

ROOT = Path(__file__).resolve().parent
SCRIPT_PATH = ROOT / "tmp" / "reconstructed" / "ssl_bypass.js"
PACKAGE = "com.hypergryph.arknights"


def find_device(device_id: str | None):
    """获取 Frida 设备"""
    if device_id:
        return frida.get_device(device_id, timeout=5)
    # 尝试获取远程设备
    try:
        return frida.get_remote_device()
    except Exception:
        pass
    # 尝试获取 USB 设备
    try:
        return frida.get_usb_device(timeout=5)
    except Exception:
        pass
    raise SystemExit("找不到设备，请确保模拟器已连接且 Frida Server 已启动")


def find_game_process(device):
    """查找游戏进程"""
    for proc in device.enumerate_processes():
        name = proc.name
        if PACKAGE in name or "arknights" in name.lower() or "明日方舟" in name:
            return proc
    return None


def on_message(message, data):
    if message.get("type") == "error":
        print(f"ERROR: {message.get('description') or message.get('stack') or message}", flush=True)
    elif message.get("type") == "log":
        print(message.get("payload"), flush=True)


def main():
    ap = argparse.ArgumentParser(description="一键启动 SSL bypass")
    ap.add_argument("--device", help="设备 ID，如 127.0.0.1:26624")
    ap.add_argument("--spawn", action="store_true", help="自动启动游戏（而不是 attach 到已运行的游戏）")
    args = ap.parse_args()

    # 检查编译产物
    if not SCRIPT_PATH.exists():
        print(f"编译产物不存在: {SCRIPT_PATH}")
        print("请先运行: npx frida-compile -S reconstructed/script/ssl_bypass/index.ts -o tmp/reconstructed/ssl_bypass.js")
        raise SystemExit(1)

    # 获取设备
    print("正在连接设备...")
    device = find_device(args.device)
    print(f"已连接: {device.name}")

    # 启动或 attach 游戏
    if args.spawn:
        print(f"正在启动游戏 {PACKAGE}...")
        pid = device.spawn([PACKAGE])
        session = device.attach(pid)
        print(f"已启动，PID={pid}")
    else:
        print("正在查找游戏进程...")
        proc = find_game_process(device)
        if not proc:
            print(f"未找到游戏进程，请先启动游戏或使用 --spawn 参数")
            raise SystemExit(1)
        print(f"找到游戏: {proc.name} (PID={proc.pid})")
        session = device.attach(proc.pid)

    # 加载脚本
    print("正在加载 SSL bypass 脚本...")
    script = session.create_script(SCRIPT_PATH.read_text(encoding="utf-8"))
    script.on("message", on_message)
    script.load()

    if args.spawn:
        device.resume(pid)
        print("游戏已恢复运行")

    print("\n" + "=" * 50)
    print("SSL bypass 已生效！")
    print("现在可以使用 Burp/Charles/mitmproxy 抓包")
    print("按 Ctrl+C 停止")
    print("=" * 50 + "\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n正在停止...")
    finally:
        try:
            script.unload()
        except Exception:
            pass
        try:
            session.detach()
        except Exception:
            pass
        print("已停止")


if __name__ == "__main__":
    main()
