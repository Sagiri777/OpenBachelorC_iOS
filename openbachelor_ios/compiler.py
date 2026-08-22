from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIR = PROJECT_ROOT / "frida"
BUILD_DIR = PROJECT_ROOT / "build"
SCRIPT_NAMES = ("probe", "core", "direct", "extra", "trainer")


def _compiler_command() -> str:
    candidates = (
        PROJECT_ROOT / "node_modules" / ".bin" / "frida-compile",
        PROJECT_ROOT.parent / "node_modules" / ".bin" / "frida-compile",
    )
    for candidate in candidates:
        if candidate.is_file() and _compiler_works(str(candidate)):
            return str(candidate)
    command = shutil.which("frida-compile")
    if command and _compiler_works(command):
        return command
    raise RuntimeError("frida-compile not found; run 'npm install' in the ios directory")


def _compiler_works(command: str) -> bool:
    try:
        result = subprocess.run(
            [command, "--help"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def compile_scripts(names: tuple[str, ...] = SCRIPT_NAMES) -> dict[str, Path]:
    unknown = sorted(set(names) - set(SCRIPT_NAMES))
    if unknown:
        raise ValueError(f"unknown Frida script(s): {', '.join(unknown)}")

    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    compiler = _compiler_command()
    env = os.environ.copy()
    env.setdefault("npm_config_cache", str(PROJECT_ROOT / ".npm-cache"))

    outputs: dict[str, Path] = {}
    for name in names:
        source = SOURCE_DIR / f"{name}.ts"
        output = BUILD_DIR / f"{name}.js"
        subprocess.run(
            [compiler, "-S", str(source), "-o", str(output)],
            cwd=PROJECT_ROOT,
            env=env,
            check=True,
        )
        outputs[name] = output
    return outputs
