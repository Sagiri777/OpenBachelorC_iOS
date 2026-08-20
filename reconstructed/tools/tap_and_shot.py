#!/usr/bin/env python3
"""Capture game traffic by running start_packet_capture.py as a subprocess, then tap UI."""
from __future__ import annotations
import os, subprocess, sys, time
from pathlib import Path

ROOT = Path('/Users/chino/Downloads/OpenBachelorC')
ADB = '/Applications/MuMuPlayer Pro.app/Contents/MacOS/MuMu Android Device.app/Contents/MacOS/tools/adb'

def adb(serial, *args, timeout=8):
    try:
        return subprocess.run([ADB, '-s', serial, *args], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f'  adb timeout: {args[:2]}', flush=True)
        return None
    except Exception as e:
        print(f'  adb err: {e}', flush=True)
        return None

def tap(serial, x, y):
    r = adb(serial, 'shell', 'input', 'tap', str(x), str(y))
    print(f'tap ({x},{y}) -> rc={r.returncode if r else "?"}', flush=True)

def screen(serial, out='/tmp/cap.png'):
    adb(serial, 'shell', 'screencap', '-p', '/sdcard/s.png', timeout=10)
    adb(serial, 'pull', '/sdcard/s.png', out)

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--device', required=True)
    ap.add_argument('--proxy-port', type=int, default=8443)
    ap.add_argument('--initial-wait', type=int, default=50)
    ap.add_argument('--capture-time', type=int, default=240)
    ap.add_argument('--no-trainer', action='store_true')
    args = ap.parse_args()

    # 1. spawn the actual capture script in a fully detached subprocess
    capture_log = open('/tmp/capture-final.log', 'wb')
    capture_cmd = [
        '.venv/bin/python',
        'start_packet_capture.py',
        '--device', args.device,
        '--proxy-port', str(args.proxy_port),
    ]
    if args.no_trainer:
        capture_cmd.append('--no-trainer')

    capture_env = os.environ.copy()
    capture_env['PYTHONUNBUFFERED'] = '1'
    print('starting capture subprocess:', ' '.join(capture_cmd), flush=True)
    cap_proc = subprocess.Popen(
        capture_cmd,
        cwd=str(ROOT),
        env=capture_env,
        stdout=capture_log,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
    )
    print(f'capture pid: {cap_proc.pid}', flush=True)

    try:
        # 2. wait for game to boot
        print(f'waiting {args.initial_wait}s for game boot…', flush=True)
        time.sleep(args.initial_wait)

        # 3. tap sequence
        sequence = [
            (0, "yellow diamond center-bottom", 720, 2350),
            (8, "yellow diamond alt", 720, 2200),
            (10, "yellow diamond lower", 720, 1900),
            (12, "yellow diamond alt-mid", 540, 2350),
            (15, "wake button center", 720, 2050),
            (20, "wake button lower", 720, 1700),
        ]
        for delay, label, x, y in sequence:
            print(f'tap[{label}] ({x},{y})', flush=True)
            tap(args.device, x, y)
            print(f'  sleep {delay}s', flush=True)
            time.sleep(delay)

        # 4. continue capture for remaining time
        elapsed = sum(d for d, *_ in sequence) + args.initial_wait
        remain = max(0, args.capture_time - elapsed)
        print(f'holding {remain}s for additional captures', flush=True)
        time.sleep(remain)
    finally:
        print('terminating capture subprocess', flush=True)
        try:
            cap_proc.terminate()
            cap_proc.wait(timeout=10)
        except Exception:
            try: cap_proc.kill()
            except: pass

    capture_log.close()
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
