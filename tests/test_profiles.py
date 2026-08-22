import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from openbachelor_ios.config import load_config
from openbachelor_ios.profiles import load_profile, select_profile


def _config():
    return load_config(Path("config.example.json"))


def _write_profile(
    directory: Path,
    profile_id: str,
    *,
    version: str = "2.7.61",
    build: str = "59",
    bundle_id: str = "com.hypergryph.arknights",
) -> Path:
    directory.mkdir(exist_ok=True)
    path = directory / f"{profile_id}.json"
    path.write_text(
        json.dumps(
            {
                "schema": 1,
                "id": profile_id,
                "bundle_id": bundle_id,
                "version": version,
                "build": build,
                "arch": "arm64e",
                "module": {"name": "UnityFramework", "uuid": "TEST-UUID"},
                "offsets": {"hook": "0x1000"},
                "layout": {"stringLength": 16},
            }
        ),
        encoding="utf-8",
    )
    return path


class FakeDevice:
    def __init__(self, version=None, build=None):
        parameters = {}
        if version is not None:
            parameters["version"] = version
        if build is not None:
            parameters["build"] = build
        self.application = SimpleNamespace(
            identifier="com.hypergryph.arknights",
            name="Arknights",
            pid=42,
            parameters=parameters,
        )

    def enumerate_applications(self, scope=None):
        return [self.application]


def test_auto_selects_exact_bundle_version_and_build(tmp_path):
    profiles = tmp_path / "profiles"
    _write_profile(profiles, "old", version="2.7.60", build="58")
    expected = _write_profile(profiles, "current")

    selected = select_profile(
        FakeDevice("2.7.61", 59), _config(), profiles_dir=profiles
    )

    assert selected.id == "current"
    assert selected.path == expected.resolve()


def test_auto_uses_only_bundle_candidate_when_device_hides_version(tmp_path):
    profiles = tmp_path / "profiles"
    _write_profile(profiles, "current")

    selected = select_profile(FakeDevice(), _config(), profiles_dir=profiles)

    assert selected.id == "current"


def test_auto_rejects_ambiguous_profiles(tmp_path):
    profiles = tmp_path / "profiles"
    _write_profile(profiles, "one")
    _write_profile(profiles, "two", version="2.8.0", build="60")

    with pytest.raises(ValueError, match="ambiguous.*--profile"):
        select_profile(FakeDevice(), _config(), profiles_dir=profiles)


def test_auto_missing_profile_fails_closed_with_recovery_options(tmp_path):
    profiles = tmp_path / "profiles"
    _write_profile(profiles, "old", version="2.7.60", build="58")

    with pytest.raises(
        ValueError, match=r"profile generate --dump-dir PATH.*--probe-only.*--legacy-agents"
    ):
        select_profile(
            FakeDevice("2.7.61", "59"), _config(), profiles_dir=profiles
        )


def test_explicit_profile_id_still_checks_detected_version(tmp_path):
    profiles = tmp_path / "profiles"
    _write_profile(profiles, "old", version="2.7.60", build="58")

    with pytest.raises(ValueError, match="installed app is 2.7.61"):
        select_profile(
            FakeDevice("2.7.61", "59"),
            _config(),
            "old",
            profiles_dir=profiles,
        )


def test_load_profile_rejects_unknown_schema(tmp_path):
    path = _write_profile(tmp_path, "bad")
    data = json.loads(path.read_text(encoding="utf-8"))
    data["schema"] = 2
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(ValueError, match="schema must be 1"):
        load_profile(path)
