from __future__ import annotations

import json
import lzma
import os
import plistlib
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import lief

GADGET_BASENAME = "FridaGadget.dylib"
GADGET_LOAD_PATH = f"@executable_path/Frameworks/{GADGET_BASENAME}"


def _run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(command, check=True, **kwargs)


def _find_app(payload: Path) -> Path:
    apps = sorted(path for path in payload.glob("*.app") if path.is_dir())
    if len(apps) != 1:
        raise ValueError(f"expected one app in Payload, found {len(apps)}")
    return apps[0]


def _copy_gadget(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.suffix == ".xz":
        with lzma.open(source, "rb") as compressed, destination.open("wb") as output:
            shutil.copyfileobj(compressed, output)
    else:
        shutil.copy2(source, destination)
    destination.chmod(0o755)


def _validate_gadget(path: Path) -> None:
    parsed = lief.MachO.parse(str(path))
    if parsed is None or parsed.size == 0:
        raise ValueError(
            "Frida Gadget must be an iOS Mach-O dylib (use the iOS arm64/universal release)"
        )


def _is_encrypted(binary: Any) -> bool:
    info = binary.encryption_info if binary.has_encryption_info else None
    return info is not None and info.crypt_id != 0


def _inject_load_command(executable: Path) -> None:
    fat = lief.MachO.parse(str(executable))
    if fat is None or fat.size == 0:
        raise ValueError(f"not a Mach-O executable: {executable}")

    for binary in fat:
        if _is_encrypted(binary):
            raise ValueError(
                "the IPA executable is encrypted; supply a decrypted IPA from a device you own"
            )
        dependencies = {library.name for library in binary.libraries}
        if GADGET_LOAD_PATH not in dependencies:
            binary.add_library(GADGET_LOAD_PATH)

    rebuilt = executable.with_name(executable.name + ".patched")
    fat.write(str(rebuilt))
    rebuilt.chmod(executable.stat().st_mode)
    os.replace(rebuilt, executable)


def _extract_entitlements(ldid: str, executable: Path, output: Path) -> Path | None:
    try:
        result = _run([ldid, "-e", str(executable)], capture_output=True)
    except subprocess.CalledProcessError:
        return None
    data = result.stdout.strip()
    if not data:
        return None
    try:
        plistlib.loads(data)
    except plistlib.InvalidFileException:
        return None
    output.write_bytes(data)
    return output


def _sign(ldid: str, executable: Path, gadget: Path, entitlements: Path | None) -> None:
    _run([ldid, "-S", str(gadget)])
    sign_flag = f"-S{entitlements}" if entitlements is not None else "-S"
    _run([ldid, sign_flag, str(executable)])


def _write_gadget_config(path: Path, *, port: int) -> None:
    config = {
        "interaction": {
            "type": "listen",
            "address": "127.0.0.1",
            "port": port,
            "on_load": "wait",
        },
        "teardown": "full",
    }
    path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")


def patch_ipa(
    input_ipa: Path,
    output_ipa: Path,
    gadget_source: Path,
    *,
    gadget_port: int = 27042,
    allow_http: bool = False,
    sign: bool = True,
) -> dict[str, Any]:
    input_ipa = input_ipa.resolve()
    output_ipa = output_ipa.resolve()
    gadget_source = gadget_source.resolve()

    if not input_ipa.is_file():
        raise ValueError(f"input IPA not found: {input_ipa}")
    if not gadget_source.is_file():
        raise ValueError(f"Frida Gadget not found: {gadget_source}")
    if input_ipa == output_ipa:
        raise ValueError("output IPA must be different from input IPA")
    if output_ipa.exists():
        raise ValueError(f"output already exists: {output_ipa}")
    if not 1 <= gadget_port <= 65535:
        raise ValueError("gadget port must be between 1 and 65535")

    ditto = shutil.which("ditto")
    if ditto is None:
        raise RuntimeError("ditto is required; run this command on macOS")
    ldid = shutil.which("ldid") if sign else None
    if sign and ldid is None:
        raise RuntimeError("ldid is required for signing; install it or pass --no-sign")

    output_ipa.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="openbachelor-ios-") as temp_name:
        temp = Path(temp_name)
        extracted = temp / "extracted"
        extracted.mkdir()
        _run([ditto, "-x", "-k", str(input_ipa), str(extracted)])

        app = _find_app(extracted / "Payload")
        info_path = app / "Info.plist"
        with info_path.open("rb") as stream:
            info = plistlib.load(stream)
        executable_name = info.get("CFBundleExecutable")
        bundle_id = info.get("CFBundleIdentifier")
        if not isinstance(executable_name, str) or not executable_name:
            raise ValueError("Info.plist has no CFBundleExecutable")
        if not isinstance(bundle_id, str) or not bundle_id:
            raise ValueError("Info.plist has no CFBundleIdentifier")

        executable = app / executable_name
        if not executable.is_file():
            raise ValueError(f"app executable not found: {executable}")

        entitlements = None
        if ldid is not None:
            entitlements = _extract_entitlements(
                ldid, executable, temp / "entitlements.plist"
            )

        gadget = app / "Frameworks" / GADGET_BASENAME
        _copy_gadget(gadget_source, gadget)
        _validate_gadget(gadget)
        _write_gadget_config(
            gadget.with_name("FridaGadget.config"), port=gadget_port
        )
        _inject_load_command(executable)

        if allow_http:
            transport = info.setdefault("NSAppTransportSecurity", {})
            if not isinstance(transport, dict):
                transport = {}
                info["NSAppTransportSecurity"] = transport
            transport["NSAllowsArbitraryLoads"] = True
            with info_path.open("wb") as stream:
                plistlib.dump(info, stream, sort_keys=False)

        signature = app / "_CodeSignature"
        if signature.exists():
            if signature.is_dir():
                shutil.rmtree(signature)
            else:
                signature.unlink()
        if ldid is not None:
            _sign(ldid, executable, gadget, entitlements)

        staged_output = temp / output_ipa.name
        _run(
            [
                ditto,
                "-c",
                "-k",
                "--sequesterRsrc",
                "--keepParent",
                "Payload",
                str(staged_output),
            ],
            cwd=extracted,
        )
        shutil.move(staged_output, output_ipa)

    return {
        "bundle_id": bundle_id,
        "executable": executable_name,
        "output": str(output_ipa),
        "gadget_port": gadget_port,
        "signed": sign,
    }
