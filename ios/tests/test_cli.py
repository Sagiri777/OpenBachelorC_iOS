import json

import frida
import pytest

from openbachelor_ios import cli
from openbachelor_ios.decrypt import PreparedDump
from openbachelor_ios.profile_generator import GeneratedProfile


def test_run_uses_auto_profile_by_default():
    args = cli.build_parser().parse_args(["run", "--attach"])

    assert cli._run_profile_selector(args) == "auto"


def test_run_accepts_explicit_profile_or_legacy_agents():
    parser = cli.build_parser()
    explicit = parser.parse_args(["run", "--profile", "arknights-2.7.61-59"])
    legacy = parser.parse_args(["run", "--legacy-agents", "--trainer"])

    assert cli._run_profile_selector(explicit) == "arknights-2.7.61-59"
    assert cli._run_profile_selector(legacy) is None


def test_trainer_is_rejected_in_direct_profile_mode():
    args = cli.build_parser().parse_args(["run", "--trainer"])

    with pytest.raises(ValueError, match="incompatible with direct profile mode"):
        cli._run_profile_selector(args)


def test_run_reports_locked_iphone_without_traceback(monkeypatch, capsys):
    error = frida.NotSupportedError(
        "unable to launch iOS app via FBS: The operation couldn't be completed. "
        "Unable to launch com.example.app because the device was not, or could not, be unlocked."
    )
    monkeypatch.setattr(cli, "connect_device", lambda _config: (_ for _ in ()).throw(error))

    result = cli.main(
        [
            "run",
            "--mode",
            "jailbreak",
            "--spawn",
            "--probe-only",
            "--no-build",
        ]
    )

    captured = capsys.readouterr()
    assert result == 1
    assert "iPhone is locked" in captured.err
    assert "--attach" in captured.err
    assert "Traceback" not in captured.err


def test_frida_server_error_includes_recovery_hint():
    message = cli._frida_error_message(
        frida.ServerNotRunningError("unable to connect to remote frida-server")
    )

    assert "frida-server 17.9.1" in message
    assert "USB" in message


def test_profile_generate_is_local_and_forwards_generator_options(
    monkeypatch, tmp_path, capsys
):
    module = tmp_path / "UnityFramework"
    script_json = tmp_path / "script.json"
    dump_cs = tmp_path / "dump.cs"
    output = tmp_path / "generated.json"
    calls = {}
    generated = GeneratedProfile(
        data={
            "id": "arknights-3.0.0-60",
            "bundle_id": "com.hypergryph.arknights",
            "version": "3.0.0",
            "build": "60",
            "module": {"uuid": "TEST-UUID"},
            "offsets": {spec.key: "0x1000" for spec in cli.METHOD_SPECS},
        },
        warnings=("metadata identity is omitted",),
    )

    def fake_generate(path, **kwargs):
        calls["generate"] = (path, kwargs)
        return generated

    def fake_write(path, data, *, force):
        calls["write"] = (path, data, force)

    monkeypatch.setattr(cli, "generate_profile", fake_generate)
    monkeypatch.setattr(cli, "write_profile", fake_write)
    monkeypatch.setattr(
        cli,
        "connect_device",
        lambda _config: pytest.fail("profile generation must not connect to a device"),
    )

    result = cli.main(
        [
            "profile",
            "generate",
            "--module",
            str(module),
            "--script-json",
            str(script_json),
            "--dump-cs",
            str(dump_cs),
            "--bundle-id",
            "com.hypergryph.arknights",
            "--version",
            "3.0.0",
            "--build",
            "60",
            "--id",
            "arknights-3.0.0-60",
            "--unity-version",
            "2021.3.39f1",
            "--allow-layout-fallback",
            "--output",
            str(output),
            "--force",
        ]
    )

    captured = capsys.readouterr()
    assert result == 0
    assert calls["generate"][0] == module
    assert calls["generate"][1]["script_json"] == script_json
    assert calls["generate"][1]["dump_cs"] == dump_cs
    assert calls["generate"][1]["bundle_id"] == "com.hypergryph.arknights"
    assert calls["generate"][1]["profile_id"] == "arknights-3.0.0-60"
    assert calls["generate"][1]["allow_layout_fallback"] is True
    assert calls["write"] == (output, generated.data, True)
    assert "generated profile:" in captured.out
    assert f"hooks: {len(cli.METHOD_SPECS)}/{len(cli.METHOD_SPECS)}" in captured.out
    assert "warning: metadata identity is omitted" in captured.err


def test_profile_generate_without_source_reports_usage_error(capsys):
    result = cli.main(["profile", "generate"])

    captured = capsys.readouterr()
    assert result == 1
    assert "requires --dump-dir or --module" in captured.err
    assert "Traceback" not in captured.err


def test_profile_decrypt_local_source_does_not_connect(monkeypatch, tmp_path, capsys):
    source = tmp_path / "input.ipa"
    output = tmp_path / "dump"
    source.write_bytes(b"fixture")
    prepared = PreparedDump(
        output,
        output / "UnityFramework",
        output / "global-metadata.dat",
        None,
        (output / "UnityFramework",),
        ("cleared runtime cryptid: UnityFramework",),
    )
    calls = {}

    def fake_prepare(path, destination, **kwargs):
        calls["prepare"] = (path, destination, kwargs)
        return prepared

    monkeypatch.setattr(cli, "prepare_local_dump", fake_prepare)
    monkeypatch.setattr(
        cli,
        "connect_device",
        lambda _config: pytest.fail("local decrypt must not connect to a device"),
    )

    result = cli.main(
        [
            "profile",
            "decrypt",
            str(source),
            "--output-dir",
            str(output),
            "--force",
            "--assume-memory-dump",
        ]
    )

    assert result == 0
    assert calls["prepare"] == (
        source,
        output,
        {"force": True, "assume_memory_dump": True},
    )
    assert json.loads(capsys.readouterr().out)["module"].endswith("UnityFramework")


def test_profile_generate_auto_decrypt_uses_prepared_paths(monkeypatch, tmp_path):
    source = tmp_path / "input.app"
    output = tmp_path / "dump"
    module = output / "UnityFramework"
    metadata = output / "global-metadata.dat"
    source.mkdir()
    output.mkdir()
    module.write_bytes(b"module")
    metadata.write_bytes(b"metadata")
    prepared = PreparedDump(output, module, metadata, None, (module,), ())
    calls = {}
    generated = GeneratedProfile(
        data={
            "id": "fixture-1-1",
            "bundle_id": "example.fixture",
            "version": "1",
            "build": "1",
            "module": {"uuid": "TEST"},
            "offsets": {},
        },
        warnings=(),
    )

    def fake_prepare(path, destination, **kwargs):
        calls["prepare"] = (path, destination, kwargs)
        return prepared

    def fake_generate(path, **kwargs):
        calls["generate"] = (path, kwargs)
        return generated

    monkeypatch.setattr(cli, "prepare_local_dump", fake_prepare)
    monkeypatch.setattr(cli, "generate_profile", fake_generate)
    monkeypatch.setattr(cli, "write_profile", lambda *args, **kwargs: None)

    result = cli.main(
        [
            "profile",
            "generate",
            "--source",
            str(source),
            "--auto-decrypt",
            "--decrypt-output",
            str(output),
            "--bundle-id",
            "example.fixture",
            "--version",
            "1",
            "--build",
            "1",
        ]
    )

    assert result == 0
    assert calls["prepare"][0] == source
    assert calls["generate"][0] == module
    assert calls["generate"][1]["dump_dir"] == output
    assert calls["generate"][1]["metadata"] == metadata


def test_profile_generate_auto_decrypt_accepts_module_as_source(monkeypatch, tmp_path):
    module = tmp_path / "UnityFramework"
    module.write_bytes(b"module")
    output = tmp_path / "dump"
    prepared = PreparedDump(output, output / "UnityFramework", None, None, (), ())
    calls = {}

    def fake_prepare(path, destination, **kwargs):
        calls["prepare"] = (path, destination, kwargs)
        return prepared

    def fake_generate(path, **kwargs):
        calls["generate"] = (path, kwargs)
        return GeneratedProfile(
            data={
                "id": "fixture-1-1",
                "bundle_id": "example.fixture",
                "version": "1",
                "build": "1",
                "module": {"uuid": "TEST"},
                "offsets": {},
            },
            warnings=(),
        )

    monkeypatch.setattr(cli, "prepare_local_dump", fake_prepare)
    monkeypatch.setattr(cli, "generate_profile", fake_generate)
    monkeypatch.setattr(cli, "write_profile", lambda *args, **kwargs: None)

    assert (
        cli.main(
            [
                "profile",
                "generate",
                "--module",
                str(module),
                "--auto-decrypt",
                "--decrypt-output",
                str(output),
                "--bundle-id",
                "example.fixture",
                "--version",
                "1",
                "--build",
                "1",
            ]
        )
        == 0
    )
    assert calls["prepare"][0] == module


def test_profile_generate_source_implies_auto_decrypt(monkeypatch, tmp_path):
    source = tmp_path / "source.ipa"
    source.write_bytes(b"fixture")
    output = tmp_path / "dump"
    prepared = PreparedDump(output, output / "UnityFramework", None, None, (), ())
    calls = []

    monkeypatch.setattr(
        cli,
        "prepare_local_dump",
        lambda path, destination, **kwargs: (calls.append((path, destination)), prepared)[1],
    )
    monkeypatch.setattr(
        cli,
        "generate_profile",
        lambda path, **kwargs: GeneratedProfile(
            data={
                "id": "fixture-1-1",
                "bundle_id": "example.fixture",
                "version": "1",
                "build": "1",
                "module": {"uuid": "TEST"},
                "offsets": {},
            },
            warnings=(),
        ),
    )
    monkeypatch.setattr(cli, "write_profile", lambda *args, **kwargs: None)

    assert (
        cli.main(
            [
                "profile",
                "generate",
                "--source",
                str(source),
                "--decrypt-output",
                str(output),
                "--bundle-id",
                "example.fixture",
                "--version",
                "1",
                "--build",
                "1",
            ]
        )
        == 0
    )
    assert calls == [(source, output)]
