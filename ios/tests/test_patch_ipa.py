import json
import lzma

import pytest

from openbachelor_ios.patch_ipa import (
    _copy_gadget,
    _find_app,
    _validate_gadget,
    _write_gadget_config,
    patch_ipa,
)


def test_copy_compressed_gadget(tmp_path):
    source = tmp_path / "gadget.dylib.xz"
    source.write_bytes(lzma.compress(b"gadget"))
    destination = tmp_path / "Frameworks" / "FridaGadget.dylib"

    _copy_gadget(source, destination)

    assert destination.read_bytes() == b"gadget"
    assert destination.stat().st_mode & 0o111


def test_gadget_config_waits_for_controller(tmp_path):
    path = tmp_path / "FridaGadget.config"

    _write_gadget_config(path, port=27042)

    config = json.loads(path.read_text(encoding="utf-8"))
    assert config["interaction"]["type"] == "listen"
    assert config["interaction"]["on_load"] == "wait"
    assert config["interaction"]["port"] == 27042


def test_validate_gadget_rejects_non_macho(tmp_path):
    path = tmp_path / "not-a-gadget"
    path.write_bytes(b"this is not a Mach-O dylib")

    with pytest.raises(ValueError, match="Mach-O"):
        _validate_gadget(path)


def test_find_app_requires_exactly_one_bundle(tmp_path):
    payload = tmp_path / "Payload"
    payload.mkdir()
    with pytest.raises(ValueError, match="found 0"):
        _find_app(payload)

    (payload / "One.app").mkdir()
    assert _find_app(payload).name == "One.app"
    (payload / "Two.app").mkdir()
    with pytest.raises(ValueError, match="found 2"):
        _find_app(payload)


def test_patch_refuses_to_overwrite_input(tmp_path):
    ipa = tmp_path / "input.ipa"
    gadget = tmp_path / "gadget.dylib"
    ipa.write_bytes(b"ipa")
    gadget.write_bytes(b"gadget")

    with pytest.raises(ValueError, match="different"):
        patch_ipa(ipa, ipa, gadget, sign=False)
