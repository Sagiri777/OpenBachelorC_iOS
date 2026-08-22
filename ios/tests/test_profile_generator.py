import hashlib
import json
import plistlib
import stat
from pathlib import Path

import pytest

from openbachelor_ios.profile_generator import (
    BATTLE_FINISH_METHOD_SPECS,
    EXTRA_METHOD_SPECS,
    LAYOUT_FIELDS,
    METHOD_SPECS,
    TRAINER_METHOD_SPECS,
    MachOInfo,
    ProfileGenerationError,
    _load_macho,
    _layout_from_dump,
    _resolve_methods,
    _script_methods,
    generate_profile,
    write_profile,
)
from openbachelor_ios.profiles import load_profile


class FakeMachOBinary:
    def get_content_from_virtual_address(self, _address, size):
        return [0xA5] * size


def _macho_info() -> MachOInfo:
    image_base = 0x100000000
    return MachOInfo(
        binary=FakeMachOBinary(),
        uuid="00112233-4455-6677-8899-AABBCCDDEEFF",
        arch="arm64e",
        text_vmaddr=image_base,
        text_size=0x20000,
        text_start=image_base + 0x1000,
        text_end=image_base + 0x10000,
        image_base=image_base,
        encrypted=False,
    )


def _method_entries():
    return [
        {
            "Address": 0x1000 + index * 4,
            "Name": spec.name,
            "Signature": f"void generated({spec.signature});",
        }
        for index, spec in enumerate(METHOD_SPECS)
    ]


def _write_script_json(path: Path, entries=None) -> None:
    path.write_text(
        json.dumps(
            {
                "ScriptMethod": _method_entries() if entries is None else entries,
                "IgnoredLargeSection": [],
            }
        ),
        encoding="utf-8",
    )


def _write_dump_cs(path: Path) -> None:
    fields_by_class = {}
    for index, (_key, (class_name, field)) in enumerate(LAYOUT_FIELDS.items()):
        fields_by_class.setdefault(class_name, []).append(
            f"    private object {field}; // 0x{0x18 + index * 8:X}"
        )

    blocks = []
    for class_name, fields in fields_by_class.items():
        blocks.append(
            "\n".join(
                [
                    f"public class {class_name}",
                    "{",
                    "    // Fields",
                    *fields,
                    "}",
                ]
            )
        )
    path.write_text("\n\n".join(blocks), encoding="utf-8")


@pytest.mark.skipif(
    not (Path(__file__).parents[1] / "dumps/2.7.61-59/UnityFramework").is_file(),
    reason="golden UnityFramework dump is not checked out",
)
def test_load_macho_uses_macho_parser_for_thin_framework():
    info = _load_macho(
        Path(__file__).parents[1] / "dumps/2.7.61-59/UnityFramework"
    )

    assert info.uuid == "AE59EB96-04B9-3FA5-BB0F-51353713ABA3"
    assert info.arch == "arm64"
    assert info.image_base == info.text_vmaddr == 0
    assert info.text_start == 0x4000
    assert not info.encrypted


def test_generate_profile_resolves_overloads_layout_and_identity(
    monkeypatch, tmp_path
):
    module = tmp_path / "UnityFramework"
    module.write_bytes(b"decrypted-mach-o")
    script_json = tmp_path / "script.json"
    entries = _method_entries()
    entries.insert(
        0,
        {
            "Address": 0x9000,
            "Name": "UnityEngine.Networking.UnityWebRequest$$Post",
            "Signature": "wrong overload",
        },
    )
    _write_script_json(script_json, entries)
    dump_cs = tmp_path / "dump.cs"
    _write_dump_cs(dump_cs)
    metadata = tmp_path / "global-metadata.dat"
    metadata.write_bytes(
        (0xFAB11BAF).to_bytes(4, "little") + (29).to_bytes(4, "little")
    )
    monkeypatch.setattr(
        "openbachelor_ios.profile_generator._load_macho", lambda _path: _macho_info()
    )

    generated = generate_profile(
        module,
        script_json=script_json,
        dump_cs=dump_cs,
        metadata=metadata,
        bundle_id="com.hypergryph.arknights",
        version="3.0.0",
        build="60",
        unity_version="2021.3.39f1",
        reference_profile=None,
    )

    assert generated.warnings == ()
    assert generated.data["id"] == "arknights-3.0.0-60"
    assert generated.data["arch"] == "arm64e"
    assert generated.data["module"] == {
        "name": "UnityFramework",
        "uuid": "00112233-4455-6677-8899-AABBCCDDEEFF",
        "sha256": hashlib.sha256(b"decrypted-mach-o").hexdigest(),
        "text_vmaddr": "0x100000000",
        "text_size": "0x20000",
    }
    assert generated.data["metadata"]["version"] == 29
    assert generated.data["offsets"] == {
        spec.key: hex(0x1000 + index * 4)
        for index, spec in enumerate(METHOD_SPECS)
    }
    assert set(generated.data["prologues"]) == {
        spec.key for spec in METHOD_SPECS
    }
    assert set(generated.data["prologues"].values()) == {"a5" * 8}
    assert set(LAYOUT_FIELDS).issubset(generated.data["layout"])

    output = tmp_path / "profiles" / "generated.json"
    write_profile(output, generated.data)

    loaded = load_profile(output)
    assert loaded.id == "arknights-3.0.0-60"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_generate_profile_infers_identity_from_app_info_plist(monkeypatch, tmp_path):
    app = tmp_path / "Arknights.app"
    module = app / "Frameworks" / "UnityFramework.framework" / "UnityFramework"
    module.parent.mkdir(parents=True)
    module.write_bytes(b"decrypted-mach-o")
    (app / "Info.plist").write_bytes(
        plistlib.dumps(
            {
                "CFBundleIdentifier": "com.hypergryph.arknights",
                "CFBundleShortVersionString": "3.0.0",
                "CFBundleVersion": "60",
            }
        )
    )
    script_json = tmp_path / "script.json"
    _write_script_json(script_json)
    dump_cs = tmp_path / "dump.cs"
    _write_dump_cs(dump_cs)
    monkeypatch.setattr(
        "openbachelor_ios.profile_generator._load_macho", lambda _path: _macho_info()
    )

    generated = generate_profile(
        module,
        script_json=script_json,
        dump_cs=dump_cs,
        reference_profile=None,
    )

    assert generated.data["id"] == "arknights-3.0.0-60"
    assert generated.data["bundle_id"] == "com.hypergryph.arknights"
    assert generated.data["version"] == "3.0.0"
    assert generated.data["build"] == "60"


def test_method_resolution_fails_closed_on_ambiguous_matching_overload(tmp_path):
    entries = _method_entries()
    duplicate = dict(entries[0])
    duplicate["Address"] = 0x8000
    entries.append(duplicate)
    script_json = tmp_path / "script.json"
    _write_script_json(script_json, entries)

    with pytest.raises(
        ProfileGenerationError,
        match=r"(?s)unresolved hook methods:.*unityWebRequestGet.*2 matching methods",
    ):
        _resolve_methods(script_json, _macho_info())


def test_method_resolution_does_not_accept_signature_with_extra_parameter(tmp_path):
    entries = _method_entries()
    entries[0]["Signature"] = (
        f"void generated({METHOD_SPECS[0].signature}, int32_t extra);"
    )
    script_json = tmp_path / "script.json"
    _write_script_json(script_json, entries)

    with pytest.raises(
        ProfileGenerationError,
        match=r"(?s)unresolved hook methods:.*unityWebRequestGet.*0 matching methods",
    ):
        _resolve_methods(script_json, _macho_info())


def test_method_resolution_includes_optional_extra_methods_when_unambiguous(tmp_path):
    entries = _method_entries()
    entries.extend(
        {
            "Address": 0x3000 + index * 4,
            "Name": spec.name,
            "Signature": f"void generated({spec.signature});",
        }
        for index, spec in enumerate(EXTRA_METHOD_SPECS)
    )
    script_json = tmp_path / "script.json"
    _write_script_json(script_json, entries)

    resolved = _resolve_methods(script_json, _macho_info())

    assert {
        key: value[0]
        for key, value in resolved.items()
        if key.startswith("extra")
    } == {
        spec.key: 0x3000 + index * 4
        for index, spec in enumerate(EXTRA_METHOD_SPECS)
    }


def test_method_resolution_includes_optional_battle_finish_blocker(tmp_path):
    entries = _method_entries()
    entries.extend(
        {
            "Address": 0x2800 + index * 4,
            "Name": spec.name,
            "Signature": f"bool generated({spec.signature});",
        }
        for index, spec in enumerate(BATTLE_FINISH_METHOD_SPECS)
    )
    script_json = tmp_path / "script.json"
    _write_script_json(script_json, entries)

    resolved = _resolve_methods(script_json, _macho_info())

    assert {
        spec.key: resolved[spec.key][0] for spec in BATTLE_FINISH_METHOD_SPECS
    } == {
        spec.key: 0x2800 + index * 4
        for index, spec in enumerate(BATTLE_FINISH_METHOD_SPECS)
    }


def test_method_resolution_includes_optional_trainer_methods_when_unambiguous(
    tmp_path,
):
    entries = _method_entries()
    entries.extend(
        {
            "Address": 0x4000 + index * 4,
            "Name": spec.name,
            "Signature": f"void generated({spec.signature});",
        }
        for index, spec in enumerate(TRAINER_METHOD_SPECS)
    )
    script_json = tmp_path / "script.json"
    _write_script_json(script_json, entries)

    resolved = _resolve_methods(script_json, _macho_info())

    assert {
        key: value[0]
        for key, value in resolved.items()
        if key.startswith("trainer")
    } == {
        spec.key: 0x4000 + index * 4
        for index, spec in enumerate(TRAINER_METHOD_SPECS)
    }


def test_script_methods_streams_key_and_object_across_one_mib_chunks(tmp_path):
    chunk_size = 1024 * 1024
    key = '"ScriptMethod"'
    key_start = chunk_size - 5
    prefix_start = '{"Padding":"'
    prefix_end = '",'
    padding_size = key_start - len(prefix_start) - len(prefix_end)
    prefix = prefix_start + "x" * padding_size + prefix_end
    assert len(prefix) == key_start

    entry = {
        "Address": 0x1000,
        "Name": METHOD_SPECS[0].name,
        "Signature": METHOD_SPECS[0].signature,
        "Padding": "y" * chunk_size,
    }
    script_json = tmp_path / "script.json"
    script_json.write_text(
        prefix + key + ":[" + json.dumps(entry) + "]}",
        encoding="utf-8",
    )

    methods = list(_script_methods(script_json))

    assert len(methods) == 1
    assert methods[0]["Address"] == 0x1000
    assert methods[0]["Name"] == METHOD_SPECS[0].name
    assert len(methods[0]["Padding"]) == chunk_size


def test_layout_parser_reports_missing_managed_field(tmp_path):
    dump_cs = tmp_path / "dump.cs"
    _write_dump_cs(dump_cs)
    dump_cs.write_text(
        dump_cs.read_text(encoding="utf-8").replace(
            "private object m_DownloadHandler;", "private object renamed;"
        ),
        encoding="utf-8",
    )

    layout, missing = _layout_from_dump(dump_cs)

    assert "requestDownloadHandler" in missing
    assert "requestDownloadHandler" not in layout
    assert layout["requestUploadHandler"] >= 0


@pytest.mark.skipif(
    not (Path(__file__).parents[1] / "dumps/2.7.61-59/il2cppdumper/dump.cs").is_file(),
    reason="golden IL2CPP dump is not checked out",
)
def test_layout_parser_resolves_protocol_and_streaming_fields_from_golden_dump():
    layout, missing = _layout_from_dump(
        Path(__file__).parents[1] / "dumps/2.7.61-59/il2cppdumper/dump.cs"
    )

    assert missing == []
    assert {
        key: layout[key]
        for key in (
            "byteArrayBuffer",
            "byteArrayPosition",
            "byteArraySize",
            "netMsgId",
            "bestHttpResponseBaseRequest",
            "networkerPostImplState",
            "networkerPostImplUrl",
            "networkerPostImplOutResponse",
            "webHttpResponseIsTimeout",
            "webHttpResponseIsError",
            "webHttpResponseCode",
            "webHttpResponseError",
        )
    } == {
        "byteArrayBuffer": 0x18,
        "byteArrayPosition": 0x20,
        "byteArraySize": 0x24,
        "netMsgId": 0x10,
        "bestHttpResponseBaseRequest": 0x78,
        "networkerPostImplState": 0x10,
        "networkerPostImplUrl": 0x20,
        "networkerPostImplOutResponse": 0x40,
        "webHttpResponseIsTimeout": 0x10,
        "webHttpResponseIsError": 0x11,
        "webHttpResponseCode": 0x18,
        "webHttpResponseError": 0x38,
    }


def test_missing_layout_fails_by_default_and_explicit_fallback_uses_reference(
    monkeypatch, tmp_path
):
    module = tmp_path / "UnityFramework"
    module.write_bytes(b"decrypted-mach-o")
    script_json = tmp_path / "script.json"
    _write_script_json(script_json)
    dump_cs = tmp_path / "dump.cs"
    _write_dump_cs(dump_cs)
    dump_cs.write_text(
        dump_cs.read_text(encoding="utf-8").replace(
            "private object m_DownloadHandler;", "private object renamed;"
        ),
        encoding="utf-8",
    )
    reference = tmp_path / "reference.json"
    reference.write_text(
        json.dumps({"layout": {"requestDownloadHandler": 0x88}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "openbachelor_ios.profile_generator._load_macho", lambda _path: _macho_info()
    )
    arguments = {
        "script_json": script_json,
        "dump_cs": dump_cs,
        "bundle_id": "com.hypergryph.arknights",
        "version": "3.0.0",
        "build": "60",
        "unity_version": "2021.3.39f1",
        "reference_profile": reference,
    }

    with pytest.raises(
        ProfileGenerationError,
        match=r"managed layouts.*requestDownloadHandler.*--allow-layout-fallback",
    ):
        generate_profile(module, **arguments)

    generated = generate_profile(
        module,
        **arguments,
        allow_layout_fallback=True,
    )

    assert generated.data["layout"]["requestDownloadHandler"] == 0x88
    assert (
        "layout requestDownloadHandler inherited from reference profile"
        in generated.warnings
    )


def test_write_profile_refuses_overwrite_without_force(tmp_path):
    output = tmp_path / "profile.json"
    output.write_text("original", encoding="utf-8")

    with pytest.raises(ProfileGenerationError, match="already exists.*--force"):
        write_profile(output, {"schema": 1})

    assert output.read_text(encoding="utf-8") == "original"
    write_profile(output, {"schema": 1}, force=True)
    assert json.loads(output.read_text(encoding="utf-8")) == {"schema": 1}
