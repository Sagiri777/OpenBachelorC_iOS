import json
import plistlib
import struct
import zipfile
from pathlib import Path

import pytest

from openbachelor_ios.config import load_config
from openbachelor_ios.decrypt import (
    DecryptionError,
    FRIDA_DECRYPT_AGENT,
    _DumpWriter,
    _validate_metadata_file,
    clear_cryptid,
    inspect_macho,
    inspect_macho_bytes,
    prepare_local_dump,
    dump_from_device,
)


def _macho(*, encrypted=False, uuid=b"0123456789abcdef", size=0x400):
    commands = [
        struct.pack("<II", 0x1B, 24) + uuid,
        struct.pack("<6I", 0x2C, 24, 0x100, 0x20, int(encrypted), 0),
    ]
    header = struct.pack(
        "<8I",
        0xFEEDFACF,
        0x0100000C,
        0,
        6,
        len(commands),
        sum(len(command) for command in commands),
        0,
        0,
    )
    value = bytearray(header + b"".join(commands))
    value.extend(b"\xA5" * (size - len(value)))
    return bytes(value)


def _write_app(root: Path, *, encrypted=False):
    app = root / "Payload" / "Fixture.app"
    framework = app / "Frameworks" / "UnityFramework.framework"
    framework.mkdir(parents=True)
    (app / "Info.plist").write_bytes(
        plistlib.dumps(
            {
                "CFBundleIdentifier": "example.fixture",
                "CFBundleShortVersionString": "1.2.3",
                "CFBundleVersion": "7",
                "CFBundleExecutable": "Fixture",
            }
        )
    )
    (app / "Fixture").write_bytes(_macho(encrypted=encrypted))
    (framework / "UnityFramework").write_bytes(_macho(encrypted=encrypted))
    metadata = app / "Data" / "il2cpp_data" / "Metadata"
    metadata.mkdir(parents=True)
    (metadata / "global-metadata.dat").write_bytes(
        (0xFAB11BAF).to_bytes(4, "little") + (29).to_bytes(4, "little")
    )
    return app


def test_decrypt_agent_uses_current_frida_module_api():
    assert "Process.enumerateModules()" in FRIDA_DECRYPT_AGENT
    assert "enumerateModulesSync" not in FRIDA_DECRYPT_AGENT
    assert "typeof ObjC !== 'undefined'" in FRIDA_DECRYPT_AGENT
    assert "const end = file.tell()" in FRIDA_DECRYPT_AGENT


def test_metadata_validation_rejects_an_empty_export(tmp_path):
    metadata = tmp_path / "global-metadata.dat"
    metadata.write_bytes(b"")

    with pytest.raises(DecryptionError, match="invalid global-metadata.dat header"):
        _validate_metadata_file(metadata)


def test_macho_encryption_is_detected_and_marker_can_be_cleared():
    encrypted = _macho(encrypted=True)
    report = inspect_macho_bytes(encrypted)
    assert report.encrypted is True
    assert report.slices[0].crypt_id == 1

    decrypted = clear_cryptid(encrypted, require_encrypted=True)
    report = inspect_macho_bytes(decrypted)
    assert report.encrypted is False
    assert report.slices[0].crypt_id == 0


def test_fat_macho_slices_are_parsed_and_normalised():
    thin = _macho(encrypted=True)
    slice_offset = 0x1000
    fat_header = struct.pack(
        ">II",
        0xCAFEBABE,
        1,
    ) + struct.pack(
        ">IIIII",
        0x0100000C,
        0,
        slice_offset,
        len(thin),
        2,
    )
    fat = fat_header + b"\0" * (slice_offset - len(fat_header)) + thin

    report = inspect_macho_bytes(fat)
    assert len(report.slices) == 1
    assert report.encrypted
    assert not inspect_macho_bytes(clear_cryptid(fat)).encrypted


def test_clear_cryptid_does_not_claim_to_decrypt_ciphertext():
    with pytest.raises(DecryptionError, match="not marked encrypted"):
        clear_cryptid(_macho(), require_encrypted=True)


def test_clear_cryptid_rejects_empty_encrypted_range():
    value = bytearray(_macho(encrypted=True))
    encryption_command = 32 + 24
    value[encryption_command + 12 : encryption_command + 16] = (0).to_bytes(4, "little")

    with pytest.raises(DecryptionError, match="range is empty"):
        clear_cryptid(value, require_encrypted=True)


def test_local_encrypted_app_requires_live_export(tmp_path):
    source = tmp_path / "source"
    _write_app(source, encrypted=True)

    with pytest.raises(DecryptionError, match="FairPlay-encrypted"):
        prepare_local_dump(source, tmp_path / "out")


def test_local_memory_dump_preparation_preserves_metadata_and_identity(tmp_path):
    source = tmp_path / "source"
    _write_app(source, encrypted=True)
    output = tmp_path / "out"

    prepared = prepare_local_dump(
        source,
        output,
        assume_memory_dump=True,
    )

    assert prepared.module_path.is_file()
    assert prepared.metadata_path is not None and prepared.metadata_path.is_file()
    assert inspect_macho(prepared.module_path).encrypted is False
    assert inspect_macho(output / "Payload" / "Fixture.app" / "Fixture").encrypted is False
    manifest = json.loads((output / "decryption-manifest.json").read_text())
    assert manifest["schema"] == 1


def test_local_ipa_preparation_extracts_unityframework(tmp_path):
    source_root = tmp_path / "source"
    _write_app(source_root)
    ipa = tmp_path / "fixture.ipa"
    with zipfile.ZipFile(ipa, "w") as archive:
        for path in (source_root / "Payload").rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(source_root).as_posix())

    prepared = prepare_local_dump(ipa, tmp_path / "out")
    assert prepared.module_path.name == "UnityFramework"
    assert prepared.app_path is not None
    assert prepared.app_path.name == "Fixture.app"
    assert (tmp_path / "out" / "UnityFramework").is_file()
    assert (tmp_path / "out" / "global-metadata.dat").is_file()


def test_flat_dump_directory_is_accepted(tmp_path):
    source = tmp_path / "flat"
    source.mkdir()
    (source / "UnityFramework").write_bytes(_macho())
    (source / "global-metadata.dat").write_bytes(
        (0xFAB11BAF).to_bytes(4, "little") + (29).to_bytes(4, "little")
    )

    prepared = prepare_local_dump(source, tmp_path / "out")

    assert prepared.module_path == tmp_path / "out" / "UnityFramework"
    assert prepared.metadata_path == tmp_path / "out" / "global-metadata.dat"


def test_force_refresh_keeps_existing_il2cpp_artifacts(tmp_path):
    source = tmp_path / "source"
    _write_app(source)
    output = tmp_path / "out"
    output.mkdir()
    (output / "script.json").write_text("keep", encoding="ascii")
    il2cpp = output / "il2cppdumper"
    il2cpp.mkdir()
    (il2cpp / "dump.cs").write_text("keep dump", encoding="ascii")
    (output / "notes.txt").write_text("keep notes", encoding="ascii")
    stale_app = output / "Payload" / "Stale.app"
    stale_app.mkdir(parents=True)
    (stale_app / "stale").write_text("old", encoding="ascii")
    stale_modules = output / "modules"
    stale_modules.mkdir()
    (stale_modules / "OldFramework").write_bytes(_macho())

    prepare_local_dump(source, output, force=True)

    assert (output / "script.json").read_text(encoding="ascii") == "keep"
    assert (output / "il2cppdumper" / "dump.cs").read_text(encoding="ascii") == "keep dump"
    assert (output / "notes.txt").read_text(encoding="ascii") == "keep notes"
    assert not (output / "Payload" / "Stale.app").exists()
    assert not (output / "modules").exists()


def test_in_place_module_refresh_preserves_matching_metadata(tmp_path):
    output = tmp_path / "dump"
    output.mkdir()
    module = output / "UnityFramework"
    module.write_bytes(_macho())
    metadata = output / "global-metadata.dat"
    metadata_bytes = (0xFAB11BAF).to_bytes(4, "little") + (29).to_bytes(4, "little")
    metadata.write_bytes(metadata_bytes)
    il2cpp = output / "il2cppdumper"
    il2cpp.mkdir()
    (il2cpp / "script.json").write_text("keep", encoding="ascii")

    prepared = prepare_local_dump(module, output, force=True)

    assert prepared.module_path == module
    assert prepared.metadata_path == metadata
    assert metadata.read_bytes() == metadata_bytes
    assert (il2cpp / "script.json").read_text(encoding="ascii") == "keep"


def test_dump_writer_rejects_out_of_order_chunks(tmp_path):
    writer = _DumpWriter(tmp_path)
    writer.start({"kind": "module", "id": "one", "name": "UnityFramework", "size": 4})
    with pytest.raises(DecryptionError, match="out-of-order"):
        writer.chunk({"id": "one", "offset": 2}, b"xx")
    writer.close()


def test_dump_writer_rejects_done_with_an_open_stream(tmp_path):
    writer = _DumpWriter(tmp_path)
    writer.start({"kind": "module", "id": "one", "name": "UnityFramework", "size": 4})

    with pytest.raises(DecryptionError, match="open dump streams"):
        writer.assert_complete()

    writer.close()


def test_dump_writer_rejects_reusing_a_completed_stream_id(tmp_path):
    writer = _DumpWriter(tmp_path)
    payload = {"kind": "module", "id": "one", "name": "UnityFramework", "size": 1}
    writer.start(payload)
    writer.chunk({"id": "one", "offset": 0}, b"x")
    writer.finish({"id": "one"})

    with pytest.raises(DecryptionError, match="duplicate dump stream"):
        writer.start(payload)


def test_device_export_writes_chunks_and_normalises_runtime_image(tmp_path):
    class Script:
        def __init__(self):
            self.handler = None

        def on(self, event, handler):
            assert event == "message"
            self.handler = handler

        def load(self):
            pass

        def post(self, _message):
            data = _macho(encrypted=True)
            self.handler(
                {
                    "type": "send",
                    "payload": {
                        "event": "start",
                        "kind": "module",
                        "id": "module",
                        "name": "UnityFramework",
                        "path": "/var/mobile/Fixture.app/Frameworks/UnityFramework.framework/UnityFramework",
                        "size": len(data),
                    },
                },
                None,
            )
            for offset in range(0, len(data), 127):
                chunk = data[offset : offset + 127]
                self.handler(
                    {
                        "type": "send",
                        "payload": {
                            "event": "chunk",
                            "kind": "module",
                            "id": "module",
                            "offset": offset,
                        },
                    },
                    chunk,
                )
            self.handler(
                {
                    "type": "send",
                    "payload": {"event": "end", "kind": "module", "id": "module"},
                },
                None,
            )
            self.handler(
                {"type": "send", "payload": {"event": "done"}},
                None,
            )

        def unload(self):
            pass

    class Session:
        def __init__(self):
            self.detached = None

        def on(self, event, handler):
            assert event == "detached"
            self.detached = handler

        def create_script(self, _source, name):
            assert name == "openbachelor-ios-decrypt"
            return Script()

        def detach(self):
            pass

    class Device:
        id = "usb-test"

        def enumerate_applications(self, scope=None):
            return []

        def enumerate_processes(self):
            return []

        def spawn(self, _argv):
            return 42

        def attach(self, pid):
            assert pid == 42
            return Session()

        def resume(self, pid):
            assert pid == 42

    config = load_config(Path("config.example.json")).with_overrides(spawn=True)
    prepared = dump_from_device(Device(), config, tmp_path / "out", metadata=False)

    assert prepared.module_path.name == "UnityFramework"
    assert not inspect_macho(prepared.module_path).encrypted
    assert any("cryptid" in warning for warning in prepared.warnings)
    assert not any("metadata" in warning for warning in prepared.warnings)
