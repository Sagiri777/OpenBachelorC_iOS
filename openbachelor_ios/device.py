from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import frida

from .config import AppConfig


@dataclass(frozen=True)
class Target:
    pid: int
    name: str
    spawned: bool
    resume_after_load: bool


def connect_device(config: AppConfig):
    connection = config.connection
    if connection.transport == "remote":
        return frida.get_device_manager().add_remote_device(connection.remote_address)
    return frida.get_usb_device(timeout=connection.timeout_seconds)


def _applications(device: Any) -> list[Any]:
    enumerate_applications = getattr(device, "enumerate_applications", None)
    if not callable(enumerate_applications):
        return []

    try:
        try:
            return list(enumerate_applications(scope="full"))
        except TypeError:
            # Older Frida bindings and lightweight test fakes do not accept
            # the scope keyword.
            return list(enumerate_applications())
    except Exception:
        return []


def _processes(device: Any) -> list[Any]:
    try:
        return list(device.enumerate_processes())
    except Exception:
        return []


def _target_application(device: Any, config: AppConfig) -> Any | None:
    applications = _applications(device)
    return next(
        (candidate for candidate in applications if candidate.identifier == config.bundle_id),
        None,
    )


def _application_parameter(application: Any, name: str) -> Any:
    try:
        parameters = getattr(application, "parameters", None)
    except Exception:
        parameters = None
    if isinstance(parameters, Mapping):
        value = parameters.get(name)
        if value is not None:
            return value
    try:
        return getattr(application, name, None)
    except Exception:
        return None


def _application_info(application: Any | None, config: AppConfig) -> dict[str, Any]:
    if application is None:
        return {
            "bundle_id": config.bundle_id,
            "name": None,
            "pid": 0,
            "version": None,
            "build": None,
        }

    pid = getattr(application, "pid", 0) or 0
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        pid = 0

    return {
        "bundle_id": config.bundle_id,
        "name": getattr(application, "name", None),
        "pid": pid,
        "version": _application_parameter(application, "version"),
        "build": _application_parameter(application, "build"),
    }


def get_target_application_info(device: Any, config: AppConfig) -> dict[str, Any]:
    """Return identifying and version metadata for the configured app."""

    return _application_info(_target_application(device, config), config)


def describe_device(device: Any, config: AppConfig) -> dict[str, Any]:
    target_application = _target_application(device, config)
    app = _application_info(target_application, config)
    return {
        "device": {
            "id": getattr(device, "id", "unknown"),
            "name": getattr(device, "name", "unknown"),
            "type": getattr(device, "type", "unknown"),
        },
        "target": {
            "bundle_id": app["bundle_id"],
            "installed": target_application is not None,
            "name": app["name"],
            "pid": app["pid"],
            "version": app["version"],
            "build": app["build"],
        },
    }


def _find_running_target(device: Any, config: AppConfig) -> Target | None:
    applications = _applications(device)
    app = next(
        (candidate for candidate in applications if candidate.identifier == config.bundle_id),
        None,
    )
    if app is not None and getattr(app, "pid", 0):
        return Target(int(app.pid), str(app.name), False, False)

    processes = _processes(device)
    preferred_names = {
        name.casefold()
        for name in (config.process_name, getattr(app, "name", ""), "Gadget")
        if name
    }
    for process in processes:
        if str(process.name).casefold() in preferred_names:
            return Target(
                int(process.pid),
                str(process.name),
                False,
                config.connection.mode == "gadget" and process.name == "Gadget",
            )

    if config.connection.mode == "gadget" and len(processes) == 1:
        process = processes[0]
        return Target(int(process.pid), str(process.name), False, True)
    return None


def acquire_target(device: Any, config: AppConfig) -> Target:
    if config.connection.mode == "jailbreak" and config.launch.spawn:
        pid = int(device.spawn([config.bundle_id]))
        return Target(pid, config.bundle_id, True, True)

    target = _find_running_target(device, config)
    if target is not None:
        return target

    if config.connection.mode == "gadget":
        raise RuntimeError(
            "Gadget process not found; launch the TrollStore-installed app and retry"
        )
    raise RuntimeError(
        f"{config.bundle_id} is not running; use spawn mode or launch it manually"
    )
