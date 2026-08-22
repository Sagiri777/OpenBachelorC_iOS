from __future__ import annotations

import json
from pathlib import Path
from threading import Event
from typing import Any

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import FileHistory

from .capture import CaptureWriter
from .capture_proxy import CaptureProxyBridge, discover_bridge_host
from .compiler import BUILD_DIR, PROJECT_ROOT, compile_scripts
from .config import AppConfig
from .device import acquire_target
from .profiles import DirectProfile, select_profile

TRAINER_COMMANDS = (
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
)

_DIRECT_HOST_KEYS = {
    "capture_bridge_host",
    "capture_har",
    "capture_output_dir",
    "capture_upstream_proxy",
}


def _message_handler(name: str, capture_writer: CaptureWriter | None = None):
    def handle(message: dict[str, Any], data: bytes | None) -> None:
        if capture_writer is not None and capture_writer.handle_message(message, data):
            return
        message_type = message.get("type")
        if message_type == "error":
            detail = message.get("stack") or message.get("description") or message
            print(f"ERROR [{name}] {detail}", flush=True)
            return
        if message_type == "log":
            print(f"[{name}] {message.get('payload')}", flush=True)
            return
        if message_type == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                print(f"[{name}] {json.dumps(payload, ensure_ascii=False)}", flush=True)
            else:
                print(f"[{name}] {payload}", flush=True)
            return
        print(f"[{name}] {message}", flush=True)

    return handle


def _post_config(script: Any, values: dict[str, Any]) -> None:
    for key, value in values.items():
        if key == "startup_commands":
            continue
        script.post({"type": "conf", "k": key, "v": value})


def _post_direct_init(
    script: Any, profile: DirectProfile, values: dict[str, Any]
) -> None:
    agent_config = {
        key: value for key, value in values.items() if key not in _DIRECT_HOST_KEYS
    }
    script.post({"type": "init", "profile": profile.data, "config": agent_config})


def _enabled_scripts(
    config: AppConfig, direct_profile: DirectProfile | None = None
) -> list[str]:
    if direct_profile is not None:
        return [
            name
            for name in ("probe", "direct")
            if name == "direct" or config.scripts.probe
        ]
    return [
        name
        for name in ("probe", "core", "extra", "trainer")
        if getattr(config.scripts, name)
    ]


def _session_detached_handler(detached: Event):
    def handle(reason: Any, *_details: Any) -> None:
        print(f"session detached: {reason}", flush=True)
        detached.set()

    return handle


def _wait_for_session(detached: Event) -> None:
    while not detached.wait(1):
        pass


def _capture_writer(config: AppConfig) -> CaptureWriter:
    output_dir = Path(config.direct.get("capture_output_dir", "captured")).expanduser()
    if not output_dir.is_absolute():
        output_dir = PROJECT_ROOT / output_dir
    writer = CaptureWriter(
        output_dir,
        enabled=bool(config.direct.get("capture", False)),
        log=lambda summary: print(f"[direct] {summary}", flush=True),
    )
    # Set this after construction so integrations that provide a compatible
    # CaptureWriter wrapper do not need to know about the optional HAR switch.
    writer.har_enabled = bool(config.direct.get("capture_har", True))
    return writer


def _capture_proxy_bridge(config: AppConfig) -> CaptureProxyBridge | None:
    upstream_proxy = str(config.direct.get("capture_upstream_proxy", "")).strip()
    if not upstream_proxy:
        return None
    bridge_host = discover_bridge_host(
        str(config.direct.get("capture_bridge_host", ""))
    )
    return CaptureProxyBridge(
        upstream_proxy,
        bridge_host,
        log=lambda message: print(f"[capture-proxy] {message}", flush=True),
    )


def _trainer_cli(script: Any) -> None:
    completer = WordCompleter(
        ["enable", "disable", "all", "quit", *TRAINER_COMMANDS],
        match_middle=True,
    )
    history_path = PROJECT_ROOT / ".trainer-history"
    session = PromptSession(history=FileHistory(str(history_path)), completer=completer)

    while True:
        try:
            text = session.prompt("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not text:
            continue
        if text in {"quit", "exit"}:
            return
        if text.startswith("!"):
            script.post({"type": "conf", "k": "invoke", "v": text[1:]})
            continue

        parts = text.split()
        enabled = True
        if parts[0] == "enable":
            parts = parts[1:]
        elif parts[0] == "disable":
            enabled = False
            parts = parts[1:]
        if not parts:
            continue

        prefix = "enable:" if enabled else "disable:"
        commands = TRAINER_COMMANDS if parts == ["all"] else parts
        for command in commands:
            script.post({"type": "conf", "k": "invoke", "v": prefix + command})


def run(
    device: Any,
    config: AppConfig,
    *,
    build: bool = True,
    profile: str | Path | None = "auto",
) -> None:
    direct_profile = None if profile is None else select_profile(device, config, profile)
    names = _enabled_scripts(config, direct_profile)
    if not names:
        raise RuntimeError("no Frida scripts are enabled")
    outputs = compile_scripts(tuple(names)) if build else {
        name: BUILD_DIR / f"{name}.js" for name in names
    }
    missing = [str(path) for path in outputs.values() if not path.is_file()]
    if missing:
        raise RuntimeError(f"compiled script not found: {', '.join(missing)}")

    if direct_profile is not None:
        print(
            f"direct profile: {direct_profile.id} ({direct_profile.path})",
            flush=True,
        )

    capture_writer = _capture_writer(config) if direct_profile is not None else None
    capture_proxy_bridge = (
        _capture_proxy_bridge(config) if direct_profile is not None else None
    )
    direct_settings = dict(config.direct)
    try:
        if capture_proxy_bridge is not None:
            capture_proxy_bridge.start()
            direct_settings.update(
                capture=True,
                no_proxy=False,
                proxy_url=capture_proxy_bridge.agent_proxy_url,
                proxy_encode_scheme=True,
                proxy_include_passthrough=True,
            )
            print(
                "capture proxy active: "
                f"iPhone -> {capture_proxy_bridge.bridge_host}:"
                f"{capture_proxy_bridge.port} -> "
                f"{capture_proxy_bridge.upstream_host}:"
                f"{capture_proxy_bridge.upstream_port}",
                flush=True,
            )
        target = acquire_target(device, config)
        print(f"target: {target.name} (pid={target.pid})", flush=True)
        session = device.attach(target.pid)
    except BaseException:
        if capture_writer is not None:
            capture_writer.close()
        if capture_proxy_bridge is not None:
            capture_proxy_bridge.close()
        raise
    detached = Event()
    session.on("detached", _session_detached_handler(detached))
    loaded: dict[str, Any] = {}

    try:
        settings = {
            "probe": {},
            "core": config.core,
            "direct": direct_settings,
            "extra": config.extra,
            "trainer": config.trainer,
        }
        for name in names:
            source = outputs[name].read_text(encoding="utf-8")
            script = session.create_script(source, name=f"openbachelor-ios-{name}")
            writer = capture_writer if name == "direct" else None
            script.on("message", _message_handler(name, writer))
            script.load()
            loaded[name] = script
            if name == "direct":
                assert direct_profile is not None
                _post_direct_init(script, direct_profile, settings[name])
            else:
                _post_config(script, settings[name])
            print(f"loaded: {name}", flush=True)

        trainer = loaded.get("trainer")
        if trainer is not None:
            for command in config.trainer.get("startup_commands", []):
                trainer.post({"type": "conf", "k": "invoke", "v": command})

        if target.resume_after_load:
            try:
                device.resume(target.pid)
                print("target resumed", flush=True)
            except Exception as exc:
                if target.spawned:
                    raise
                print(f"target was already running: {exc}", flush=True)

        if trainer is not None:
            _trainer_cli(trainer)
        else:
            print("scripts active; press Ctrl-C to detach", flush=True)
            try:
                _wait_for_session(detached)
            except KeyboardInterrupt:
                print()
    finally:
        for script in reversed(list(loaded.values())):
            try:
                script.unload()
            except Exception:
                pass
        try:
            if capture_writer is not None:
                capture_writer.close()
        finally:
            try:
                if capture_proxy_bridge is not None:
                    capture_proxy_bridge.close()
            finally:
                try:
                    session.detach()
                except Exception:
                    pass
