import json
from pathlib import Path

import pytest

from openbachelor_ios.config import load_config


def test_load_example_config():
    config = load_config(Path("config.example.json"))

    assert config.bundle_id == "com.hypergryph.arknights"
    assert config.connection.mode == "jailbreak"
    assert config.connection.transport == "usb"
    assert config.launch.spawn is False
    assert config.scripts.extra is True
    assert config.scripts.trainer is False
    assert config.core["no_proxy"] is True
    assert config.direct["capture"] is False
    assert config.direct["capture_har"] is True
    assert config.direct["capture_upstream_proxy"] == ""
    assert config.direct["capture_bridge_host"] == ""
    assert config.direct["bypass_ssl"] is True
    assert config.direct["bypass_signatures"] is True
    assert config.direct["block_battle_finish_upload"] is False
    assert config.direct["floating_gui"] is True
    assert config.direct["floating_log_console"] is True
    assert config.extra["battle_timeline"] is True
    assert config.trainer["trainer_target_fps"] == 120
    assert config.trainer["trainer_battle_speed"] == 16


def test_overrides_do_not_mutate_original():
    config = load_config(Path("config.example.json"))
    changed = config.with_overrides(
        mode="gadget",
        remote_address="10.0.0.2:27042",
        spawn=False,
        trainer=True,
    )

    assert config.connection.mode == "jailbreak"
    assert changed.connection.mode == "gadget"
    assert changed.connection.transport == "remote"
    assert changed.launch.spawn is False
    assert changed.scripts.trainer is True


def test_probe_only_overrides_hook_modules():
    config = load_config(Path("config.example.json"))
    changed = config.with_overrides(core=False, extra=False, trainer=False)

    assert changed.scripts.probe is True
    assert changed.scripts.core is False
    assert changed.scripts.extra is False
    assert changed.scripts.trainer is False


def test_invalid_startup_commands_are_rejected(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps({"bundle_id": "example.app", "trainer": {"startup_commands": "all"}}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="startup_commands"):
        load_config(path)


def test_direct_defaults_reuse_core_transport_without_enabling_capture(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "bundle_id": "example.app",
                "core": {"no_proxy": False, "proxy_url": "http://10.0.0.2:8443"},
            }
        ),
        encoding="utf-8",
    )

    config = load_config(path)

    assert config.direct["no_proxy"] is False
    assert config.direct["proxy_url"] == "http://10.0.0.2:8443"
    assert config.direct["capture"] is False
    assert config.direct["floating_gui"] is True
    assert config.direct["floating_log_console"] is True


@pytest.mark.parametrize("key", ["floating_gui", "floating_log_console"])
def test_invalid_floating_overlay_flags_are_rejected(tmp_path, key):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps({"bundle_id": "example.app", "direct": {key: "false"}}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=key):
        load_config(path)


def test_invalid_capture_output_dir_is_rejected(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "bundle_id": "example.app",
                "direct": {"capture_output_dir": ""},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="capture_output_dir"):
        load_config(path)


def test_capture_proxy_override_enables_capture_without_mutating_original():
    config = load_config(Path("config.example.json"))

    changed = config.with_overrides(
        capture_proxy_port=8888, capture_host="192.168.1.20"
    )

    assert config.direct["capture"] is False
    assert config.direct["capture_upstream_proxy"] == ""
    assert changed.direct["capture"] is True
    assert changed.direct["capture_upstream_proxy"] == "http://127.0.0.1:8888"
    assert changed.direct["capture_bridge_host"] == "192.168.1.20"


def test_invalid_capture_proxy_config_is_rejected(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "bundle_id": "example.app",
                "direct": {"capture_upstream_proxy": "https://127.0.0.1:8888"},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="capture_upstream_proxy"):
        load_config(path)


def test_invalid_capture_har_config_is_rejected(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps({"bundle_id": "example.app", "direct": {"capture_har": "yes"}}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="capture_har"):
        load_config(path)


def test_invalid_battle_finish_block_config_is_rejected(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "bundle_id": "example.app",
                "direct": {"block_battle_finish_upload": "yes"},
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="block_battle_finish_upload"):
        load_config(path)


def test_battle_finish_block_config_can_be_enabled(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "bundle_id": "example.app",
                "direct": {"block_battle_finish_upload": True},
            }
        ),
        encoding="utf-8",
    )

    assert load_config(path).direct["block_battle_finish_upload"] is True
