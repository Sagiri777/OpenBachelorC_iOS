from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal

ConnectionMode = Literal["jailbreak", "gadget"]
Transport = Literal["usb", "remote"]


@dataclass(frozen=True)
class ConnectionConfig:
    mode: ConnectionMode = "jailbreak"
    transport: Transport = "usb"
    remote_address: str = "127.0.0.1:27042"
    timeout_seconds: int = 20


@dataclass(frozen=True)
class LaunchConfig:
    spawn: bool = False


@dataclass(frozen=True)
class ModuleConfig:
    probe: bool = True
    core: bool = True
    extra: bool = True
    trainer: bool = False


@dataclass(frozen=True)
class AppConfig:
    bundle_id: str
    process_name: str
    connection: ConnectionConfig
    launch: LaunchConfig
    scripts: ModuleConfig
    core: dict[str, Any]
    direct: dict[str, Any]
    extra: dict[str, Any]
    trainer: dict[str, Any]

    def with_overrides(
        self,
        *,
        bundle_id: str | None = None,
        mode: ConnectionMode | None = None,
        remote_address: str | None = None,
        spawn: bool | None = None,
        probe: bool | None = None,
        core: bool | None = None,
        extra: bool | None = None,
        trainer: bool | None = None,
    ) -> "AppConfig":
        connection = self.connection
        if mode is not None:
            connection = replace(connection, mode=mode)
        if remote_address is not None:
            connection = replace(
                connection,
                transport="remote",
                remote_address=remote_address,
            )

        launch = self.launch if spawn is None else replace(self.launch, spawn=spawn)
        scripts = self.scripts
        if probe is not None:
            scripts = replace(scripts, probe=probe)
        if core is not None:
            scripts = replace(scripts, core=core)
        if extra is not None:
            scripts = replace(scripts, extra=extra)
        if trainer is not None:
            scripts = replace(scripts, trainer=trainer)

        return replace(
            self,
            bundle_id=bundle_id or self.bundle_id,
            connection=connection,
            launch=launch,
            scripts=scripts,
        )


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a JSON object")
    return value


def load_config(path: Path) -> AppConfig:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"config file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {path}: {exc}") from exc

    raw = _mapping(raw, "config")
    connection_raw = _mapping(raw.get("connection", {}), "connection")
    launch_raw = _mapping(raw.get("launch", {}), "launch")
    scripts_raw = _mapping(raw.get("scripts", {}), "scripts")

    connection = ConnectionConfig(
        mode=connection_raw.get("mode", "jailbreak"),
        transport=connection_raw.get("transport", "usb"),
        remote_address=str(connection_raw.get("remote_address", "127.0.0.1:27042")),
        timeout_seconds=int(connection_raw.get("timeout_seconds", 20)),
    )
    if connection.mode not in ("jailbreak", "gadget"):
        raise ValueError("connection.mode must be 'jailbreak' or 'gadget'")
    if connection.transport not in ("usb", "remote"):
        raise ValueError("connection.transport must be 'usb' or 'remote'")
    if connection.timeout_seconds <= 0:
        raise ValueError("connection.timeout_seconds must be positive")

    bundle_id = str(raw.get("bundle_id", "")).strip()
    if not bundle_id:
        raise ValueError("bundle_id must not be empty")

    core = dict(_mapping(raw.get("core", {}), "core"))
    direct = {
        "capture": False,
        "bypass_ssl": True,
        "bypass_signatures": True,
        **core,
        **dict(_mapping(raw.get("direct", {}), "direct")),
    }
    capture_output_dir = direct.get("capture_output_dir", "captured")
    if not isinstance(capture_output_dir, str) or not capture_output_dir.strip():
        raise ValueError("direct.capture_output_dir must be a non-empty string")
    trainer = dict(_mapping(raw.get("trainer", {}), "trainer"))
    commands = trainer.get("startup_commands", [])
    if not isinstance(commands, list) or not all(isinstance(item, str) for item in commands):
        raise ValueError("trainer.startup_commands must be a list of strings")

    return AppConfig(
        bundle_id=bundle_id,
        process_name=str(raw.get("process_name", "")).strip(),
        connection=connection,
        launch=LaunchConfig(spawn=bool(launch_raw.get("spawn", False))),
        scripts=ModuleConfig(
            probe=bool(scripts_raw.get("probe", True)),
            core=bool(scripts_raw.get("core", True)),
            extra=bool(scripts_raw.get("extra", True)),
            trainer=bool(scripts_raw.get("trainer", False)),
        ),
        core=core,
        direct=direct,
        extra=dict(_mapping(raw.get("extra", {}), "extra")),
        trainer=trainer,
    )
