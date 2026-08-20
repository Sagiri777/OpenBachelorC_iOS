from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .compiler import PROJECT_ROOT
from .config import AppConfig
from .device import get_target_application_info

PROFILES_DIR = PROJECT_ROOT / "profiles"


@dataclass(frozen=True)
class DirectProfile:
    path: Path
    data: dict[str, Any]

    @property
    def id(self) -> str:
        return self.data["id"]

    @property
    def bundle_id(self) -> str:
        return self.data["bundle_id"]

    @property
    def version(self) -> str:
        return self.data["version"]

    @property
    def build(self) -> str:
        return self.data["build"]


def _required_string(data: dict[str, Any], name: str, path: Path) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"invalid direct profile {path}: {name} must be a non-empty string")
    return value


def load_profile(path: Path) -> DirectProfile:
    path = path.expanduser().resolve()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"direct profile not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in direct profile {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"invalid direct profile {path}: root must be a JSON object")
    if data.get("schema") != 1:
        raise ValueError(f"invalid direct profile {path}: schema must be 1")
    for name in ("id", "bundle_id", "version", "build", "arch"):
        _required_string(data, name, path)

    module = data.get("module")
    if not isinstance(module, dict):
        raise ValueError(f"invalid direct profile {path}: module must be a JSON object")
    for name in ("name", "uuid"):
        _required_string(module, name, path)
    for name in ("offsets", "layout"):
        if not isinstance(data.get(name), dict):
            raise ValueError(f"invalid direct profile {path}: {name} must be a JSON object")
    return DirectProfile(path=path, data=data)


def _available_profiles(profiles_dir: Path) -> list[DirectProfile]:
    if not profiles_dir.is_dir():
        raise ValueError(f"direct profiles directory not found: {profiles_dir}")
    return [load_profile(path) for path in sorted(profiles_dir.glob("*.json"))]


def _explicit_profile(selector: str | Path, profiles_dir: Path) -> DirectProfile:
    candidate = Path(selector).expanduser()
    if candidate.is_file():
        return load_profile(candidate)

    value = str(selector)
    if candidate.is_absolute() or candidate.parent != Path(".") or value.endswith(".json"):
        raise ValueError(f"direct profile not found: {candidate.resolve()}")
    return load_profile(profiles_dir / f"{value}.json")


def select_profile(
    device: Any,
    config: AppConfig,
    selector: str | Path = "auto",
    *,
    profiles_dir: Path | None = None,
) -> DirectProfile:
    directory = PROFILES_DIR if profiles_dir is None else profiles_dir
    application = get_target_application_info(device, config)

    if str(selector) != "auto":
        profile = _explicit_profile(selector, directory)
        if profile.bundle_id != config.bundle_id:
            raise ValueError(
                f"direct profile {profile.id} targets {profile.bundle_id}, not {config.bundle_id}"
            )
        detected_version = application.get("version")
        detected_build = application.get("build")
        if detected_version is not None and str(detected_version) != profile.version:
            raise ValueError(
                f"direct profile {profile.id} is for version {profile.version}, "
                f"but the installed app is {detected_version}"
            )
        if detected_build is not None and str(detected_build) != profile.build:
            raise ValueError(
                f"direct profile {profile.id} is for build {profile.build}, "
                f"but the installed app is {detected_build}"
            )
        return profile

    profiles = [
        profile
        for profile in _available_profiles(directory)
        if profile.bundle_id == config.bundle_id
    ]
    detected_version = application.get("version")
    detected_build = application.get("build")
    matches = [
        profile
        for profile in profiles
        if (detected_version is None or profile.version == str(detected_version))
        and (detected_build is None or profile.build == str(detected_build))
    ]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        ids = ", ".join(profile.id for profile in matches)
        raise ValueError(
            "direct profile selection is ambiguous "
            f"(version={detected_version!r}, build={detected_build!r}): {ids}; "
            "use --profile PROFILE"
        )

    available = ", ".join(profile.id for profile in profiles) or "none"
    raise ValueError(
        "no direct profile matches "
        f"{config.bundle_id} version={detected_version!r} build={detected_build!r}; "
        f"available: {available}. Export the running image with "
        "`openbachelor-ios profile decrypt --device --output-dir PATH`, then "
        "generate one from the IL2CPP dump with "
        "`openbachelor-ios profile generate --dump-dir PATH`; use --probe-only "
        "to inspect compatibility, or "
        "--legacy-agents only for an unstripped compatible build."
    )
