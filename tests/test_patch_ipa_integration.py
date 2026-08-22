import json
import plistlib
import shutil
import subprocess
import sys

import lief
import pytest

from openbachelor_ios.patch_ipa import GADGET_LOAD_PATH, patch_ipa


pytestmark = pytest.mark.skipif(
    sys.platform != "darwin"
    or shutil.which("clang") is None
    or shutil.which("xcrun") is None
    or shutil.which("ditto") is None,
    reason="requires the macOS iPhoneOS toolchain",
)


def _compile_ios_binary(source, output, *, dylib=False):
    sdk = subprocess.check_output(
        ["xcrun", "--sdk", "iphoneos", "--show-sdk-path"],
        text=True,
    ).strip()
    command = [
        "clang",
        "-target",
        "arm64-apple-ios15.0",
        "-isysroot",
        sdk,
    ]
    if dylib:
        command.extend(
            ["-dynamiclib", "-Wl,-install_name,@rpath/FridaGadget.dylib"]
        )
    else:
        command.append("-Wl,-e,_main")
    command.extend([str(source), "-o", str(output)])
    subprocess.run(command, check=True, capture_output=True)


def test_patch_minimal_ios_ipa(tmp_path):
    source_root = tmp_path / "source"
    app = source_root / "Payload" / "Fixture.app"
    app.mkdir(parents=True)
    executable = app / "Fixture"
    main_source = tmp_path / "main.c"
    main_source.write_text("int main(void) { return 0; }\n", encoding="ascii")
    _compile_ios_binary(main_source, executable)
    executable.chmod(0o755)

    with (app / "Info.plist").open("wb") as stream:
        plistlib.dump(
            {
                "CFBundleExecutable": "Fixture",
                "CFBundleIdentifier": "example.openbachelor.fixture",
                "CFBundleName": "Fixture",
                "CFBundlePackageType": "APPL",
            },
            stream,
        )

    gadget_source = tmp_path / "gadget.c"
    gadget_source.write_text("void gadget_entry(void) {}\n", encoding="ascii")
    gadget = tmp_path / "FridaGadget.dylib"
    _compile_ios_binary(gadget_source, gadget, dylib=True)

    input_ipa = tmp_path / "input.ipa"
    output_ipa = tmp_path / "output.ipa"
    subprocess.run(
        ["ditto", "-c", "-k", "--keepParent", "Payload", str(input_ipa)],
        cwd=source_root,
        check=True,
    )

    result = patch_ipa(input_ipa, output_ipa, gadget, sign=False)

    assert result["bundle_id"] == "example.openbachelor.fixture"
    assert output_ipa.is_file()

    extracted = tmp_path / "result"
    extracted.mkdir()
    subprocess.run(
        ["ditto", "-x", "-k", str(output_ipa), str(extracted)],
        check=True,
    )
    patched_app = extracted / "Payload" / "Fixture.app"
    assert (patched_app / "Frameworks" / "FridaGadget.dylib").is_file()
    gadget_config = json.loads(
        (patched_app / "Frameworks" / "FridaGadget.config").read_text(
            encoding="utf-8"
        )
    )
    assert gadget_config["interaction"]["on_load"] == "wait"

    fat = lief.MachO.parse(str(patched_app / "Fixture"))
    assert fat is not None
    for binary in fat:
        assert GADGET_LOAD_PATH in {library.name for library in binary.libraries}
