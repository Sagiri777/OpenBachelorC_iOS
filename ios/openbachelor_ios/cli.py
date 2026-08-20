from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

import frida

from .compiler import SCRIPT_NAMES, compile_scripts
from .config import AppConfig, load_config
from .decrypt import dump_from_device, prepare_local_dump
from .device import connect_device, describe_device, get_target_application_info
from .patch_ipa import patch_ipa
from .profile_generator import (
    DEFAULT_REFERENCE_PROFILE,
    METHOD_SPECS,
    PROFILES_DIR,
    generate_profile,
    write_profile,
)
from .runner import run

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = PROJECT_ROOT / "config.json"
EXAMPLE_CONFIG = PROJECT_ROOT / "config.example.json"

# Frida's Python bindings expose concrete exception classes rather than one
# public common base class. Keep the tuple explicit so connection, spawn,
# attach, and script-load failures are all handled without a traceback.
_FRIDA_ERROR_NAMES = (
    "AddressInUseError",
    "ExecutableNotFoundError",
    "ExecutableNotSupportedError",
    "InvalidArgumentError",
    "InvalidOperationError",
    "NotSupportedError",
    "OperationCancelledError",
    "PermissionDeniedError",
    "ProcessNotFoundError",
    "ProcessNotRespondingError",
    "ProtocolError",
    "ServerNotRunningError",
    "TimedOutError",
    "TransportError",
)
_FRIDA_ERRORS = tuple(
    getattr(frida, name) for name in _FRIDA_ERROR_NAMES if hasattr(frida, name)
)


def _frida_error_message(exc: Exception) -> str:
    """Turn common iOS Frida failures into a short actionable message."""

    detail = str(exc).strip() or exc.__class__.__name__
    lowered = detail.casefold()
    if "not, or could not, be unlocked" in lowered or "could not be unlocked" in lowered:
        return (
            "Frida could not launch the iOS app because the iPhone is locked; "
            "unlock it and keep it unlocked, then retry (or launch the app manually "
            "and use --attach)."
        )
    if "server not running" in lowered or "unable to connect" in lowered:
        return (
            "Frida server is not reachable; verify the jailbroken iPhone is trusted, "
            "frida-server 17.9.1 is running, and the USB connection is active. "
            f"Details: {detail}"
        )
    if "permission denied" in lowered or "not permitted" in lowered:
        return (
            "Frida was denied permission on the iPhone; unlock/trust the device and "
            "check the jailbreak Frida server entitlement. "
            f"Details: {detail}"
        )
    if "transport" in lowered or "usb" in lowered or "connection" in lowered:
        return (
            "Frida lost the iPhone connection; reconnect the trusted USB device and "
            f"retry. Details: {detail}"
        )
    return f"Frida error ({exc.__class__.__name__}): {detail}"


def _config_path(value: str | None) -> Path:
    if value:
        return Path(value).expanduser().resolve()
    if DEFAULT_CONFIG.is_file():
        return DEFAULT_CONFIG
    return EXAMPLE_CONFIG


def _load_with_overrides(args: argparse.Namespace) -> AppConfig:
    config = load_config(_config_path(args.config))
    spawn = None
    if getattr(args, "spawn", False):
        spawn = True
    elif getattr(args, "attach", False):
        spawn = False
    return config.with_overrides(
        bundle_id=getattr(args, "bundle_id", None),
        mode=getattr(args, "mode", None),
        remote_address=getattr(args, "remote", None),
        spawn=spawn,
        core=False if getattr(args, "probe_only", False) else None,
        extra=False
        if getattr(args, "probe_only", False) or getattr(args, "no_extra", False)
        else None,
        trainer=False
        if getattr(args, "probe_only", False)
        else (True if getattr(args, "trainer", False) else None),
    )


def _add_connection_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", help="JSON config path")
    parser.add_argument("--bundle-id", help="override target bundle identifier")
    parser.add_argument("--mode", choices=("jailbreak", "gadget"))
    parser.add_argument(
        "--remote",
        metavar="HOST:PORT",
        help="use a remote Frida endpoint instead of USB",
    )


def _run_profile_selector(args: argparse.Namespace) -> str | None:
    if args.trainer and not args.legacy_agents:
        raise ValueError(
            "--trainer is incompatible with direct profile mode; "
            "use --legacy-agents only for an unstripped compatible build"
        )
    if args.probe_only and args.profile is not None:
        raise ValueError("--profile cannot be used with --probe-only")
    if args.probe_only or args.legacy_agents:
        return None
    return args.profile or "auto"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="openbachelor-ios")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build", help="compile iOS Frida agents")
    build.add_argument("scripts", nargs="*", choices=SCRIPT_NAMES)

    profile = subparsers.add_parser(
        "profile", help="generate and inspect direct-agent profiles"
    )
    profile_commands = profile.add_subparsers(dest="profile_command", required=True)
    generate = profile_commands.add_parser(
        "generate",
        help="generate a fail-closed profile from an IL2CPP dump",
    )
    generate.add_argument(
        "--dump-dir",
        type=Path,
        help="directory containing UnityFramework, global-metadata.dat and il2cppdumper/",
    )
    generate.add_argument("--module", type=Path, help="decrypted UnityFramework path")
    generate.add_argument(
        "--source",
        "--ipa",
        "--app",
        dest="source",
        type=Path,
        help="IPA/.app, flat dump, or UnityFramework source to prepare automatically",
    )
    generate.add_argument("--script-json", type=Path, help="Il2CppDumper script.json path")
    generate.add_argument("--dump-cs", type=Path, help="Il2CppDumper dump.cs path")
    generate.add_argument("--metadata", type=Path, help="global-metadata.dat path")
    generate.add_argument("--bundle-id", help="application bundle identifier")
    generate.add_argument("--version", help="CFBundleShortVersionString")
    generate.add_argument("--build", help="CFBundleVersion")
    generate.add_argument("--id", dest="profile_id", help="profile id override")
    generate.add_argument("--unity-version", help="Unity editor/runtime version")
    generate.add_argument(
        "--reference-profile",
        type=Path,
        default=DEFAULT_REFERENCE_PROFILE,
        help="profile used only for explicitly allowed layout fallback",
    )
    generate.add_argument(
        "--allow-layout-fallback",
        action="store_true",
        help="inherit unresolved managed layouts from the reference profile",
    )
    generate.add_argument("--output", type=Path, help="output JSON path")
    generate.add_argument("--force", action="store_true", help="replace an existing output")
    generate.add_argument(
        "--auto-decrypt",
        "--decrypt",
        dest="auto_decrypt",
        action="store_true",
        help="export/prepare the source before generating the profile",
    )
    generate.add_argument(
        "--device",
        "--live",
        "--from-device",
        dest="device_dump",
        action="store_true",
        help="read decrypted images from the running iOS app via Frida",
    )
    generate.add_argument(
        "--decrypt-output",
        type=Path,
        help="directory for an automatic device/local dump (defaults to --dump-dir)",
    )
    generate.add_argument(
        "--assume-memory-dump",
        action="store_true",
        help="clear cryptid only for a verified plaintext memory dump",
    )
    generate.add_argument(
        "--no-metadata",
        action="store_true",
        help="do not attempt to export global-metadata.dat in device mode",
    )
    generate.add_argument("--config", help="JSON config path for --device")
    generate.add_argument("--mode", choices=("jailbreak", "gadget"))
    generate.add_argument("--remote", metavar="HOST:PORT", help="remote Frida endpoint")
    generate.add_argument(
        "--timeout",
        type=float,
        default=180.0,
        help="device export timeout in seconds",
    )
    generate_mode = generate.add_mutually_exclusive_group()
    generate_mode.add_argument("--spawn", action="store_true")
    generate_mode.add_argument("--attach", action="store_true")

    decrypt = profile_commands.add_parser(
        "decrypt",
        help="export decrypted app images or prepare an already-decrypted IPA",
    )
    decrypt.add_argument(
        "source",
        nargs="?",
        type=Path,
        help="IPA/.app, flat dump, or UnityFramework path; omit with --device",
    )
    decrypt.add_argument(
        "--source",
        "--ipa",
        "--app",
        dest="source_option",
        type=Path,
        help="local source path (optional named form)",
    )
    decrypt.add_argument("--output-dir", "--output", dest="output_dir", type=Path, required=True)
    decrypt.add_argument("--bundle-id", help="target bundle identifier for --device")
    decrypt.add_argument(
        "--device",
        "--live",
        "--from-device",
        dest="device_dump",
        action="store_true",
    )
    decrypt.add_argument("--mode", choices=("jailbreak", "gadget"))
    decrypt.add_argument("--remote", metavar="HOST:PORT", help="remote Frida endpoint")
    decrypt.add_argument("--config", help="JSON config path for --device")
    decrypt.add_argument(
        "--timeout",
        type=float,
        default=180.0,
        help="device export timeout in seconds",
    )
    decrypt_mode = decrypt.add_mutually_exclusive_group()
    decrypt_mode.add_argument("--spawn", action="store_true")
    decrypt_mode.add_argument("--attach", action="store_true")
    decrypt.add_argument("--force", action="store_true", help="replace files in an existing output")
    decrypt.add_argument(
        "--assume-memory-dump",
        action="store_true",
        help="clear cryptid only for a verified plaintext memory dump",
    )
    decrypt.add_argument(
        "--module",
        action="append",
        default=[],
        help="limit device export to a module name/path (repeatable)",
    )
    decrypt.add_argument(
        "--no-metadata",
        action="store_true",
        help="do not attempt to export global-metadata.dat",
    )

    doctor = subparsers.add_parser("doctor", help="check device and target app")
    _add_connection_options(doctor)

    launch = subparsers.add_parser("run", help="attach and load iOS agents")
    _add_connection_options(launch)
    mode = launch.add_mutually_exclusive_group()
    mode.add_argument("--spawn", action="store_true")
    mode.add_argument("--attach", action="store_true")
    agents = launch.add_mutually_exclusive_group()
    agents.add_argument(
        "--profile",
        metavar="PROFILE",
        help="direct profile id or JSON path (default: auto-detect version/build)",
    )
    agents.add_argument(
        "--legacy-agents",
        action="store_true",
        help="load configured core/extra/trainer agents instead of the direct agent",
    )
    launch.add_argument("--no-extra", action="store_true")
    launch.add_argument("--trainer", action="store_true")
    launch.add_argument(
        "--probe-only",
        action="store_true",
        help="load only the compatibility probe; do not install gameplay hooks",
    )
    launch.add_argument("--no-build", action="store_true")

    patch = subparsers.add_parser(
        "patch-ipa", help="embed Frida Gadget into a decrypted IPA"
    )
    patch.add_argument("input", type=Path)
    patch.add_argument("output", type=Path)
    patch.add_argument("--gadget", type=Path, required=True)
    patch.add_argument("--port", type=int, default=27042)
    patch.add_argument("--allow-http", action="store_true")
    patch.add_argument("--no-sign", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            names = tuple(args.scripts) if args.scripts else SCRIPT_NAMES
            outputs = compile_scripts(names)
            for name, path in outputs.items():
                print(f"{name}: {path}")
            return 0

        if args.command == "profile" and args.profile_command == "decrypt":
            if args.source is not None and args.source_option is not None:
                raise ValueError("profile decrypt accepts only one SOURCE")
            source = args.source_option or args.source
            if args.device_dump:
                if source is not None:
                    raise ValueError("profile decrypt --device does not accept a local source")
                config = _load_with_overrides(args)
                device = connect_device(config)
                prepared = dump_from_device(
                    device,
                    config,
                    args.output_dir,
                    modules=args.module,
                    metadata=not args.no_metadata,
                    timeout_seconds=args.timeout,
                    force=args.force,
                )
            else:
                if source is None:
                    raise ValueError("profile decrypt requires SOURCE or --device")
                prepared = prepare_local_dump(
                    source,
                    args.output_dir,
                    force=args.force,
                    assume_memory_dump=args.assume_memory_dump,
                )
            print(
                json.dumps(
                    {
                        "output_dir": str(prepared.output_dir),
                        "module": str(prepared.module_path),
                        "metadata": str(prepared.metadata_path)
                        if prepared.metadata_path
                        else None,
                        "modules": [str(path) for path in prepared.modules],
                        "warnings": list(prepared.warnings),
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0

        if args.command == "profile" and args.profile_command == "generate":
            dump_dir = args.dump_dir.expanduser().resolve() if args.dump_dir else None
            module = args.module
            # A source/device is an unambiguous request for the preparation
            # phase; keep --auto-decrypt as a readable explicit alias.
            if args.source is not None or args.device_dump:
                args.auto_decrypt = True
            if args.auto_decrypt:
                if args.device_dump and (args.source is not None or args.module is not None):
                    raise ValueError("profile generate --device does not accept a local source")
                local_source = args.source or args.module
                if local_source is None and dump_dir is not None:
                    candidate = dump_dir / "UnityFramework"
                    if candidate.is_file():
                        local_source = candidate
                decrypt_output = (
                    args.decrypt_output.expanduser().resolve()
                    if args.decrypt_output
                    else dump_dir
                )
                if decrypt_output is None:
                    if local_source is not None:
                        source_path = local_source.expanduser().resolve()
                        decrypt_output = source_path.with_name(
                            f"{source_path.stem}.decrypted-dump"
                        )
                    else:
                        decrypt_output = PROJECT_ROOT / "dumps" / "device-export"
                if args.device_dump:
                    config = _load_with_overrides(args)
                    device = connect_device(config)
                    prepared = dump_from_device(
                        device,
                        config,
                        decrypt_output,
                        metadata=not args.no_metadata,
                        timeout_seconds=args.timeout,
                        force=args.force,
                    )
                    detected = get_target_application_info(device, config)
                    args.bundle_id = args.bundle_id or detected.get("bundle_id")
                    args.version = args.version or detected.get("version")
                    args.build = args.build or detected.get("build")
                else:
                    if local_source is None:
                        raise ValueError(
                            "--auto-decrypt requires --source/--ipa/--app, --module, "
                            "--dump-dir with UnityFramework, or --device"
                        )
                    prepared = prepare_local_dump(
                        local_source,
                        decrypt_output,
                        force=args.force
                        or local_source.expanduser().resolve().parent == decrypt_output,
                        assume_memory_dump=args.assume_memory_dump,
                    )
                module = prepared.module_path
                dump_dir = prepared.output_dir
                if args.metadata is None:
                    args.metadata = prepared.metadata_path
                print(f"decrypted dump: {prepared.output_dir}")
                for warning in prepared.warnings:
                    print(f"warning: {warning}", file=sys.stderr)
            if module is None and dump_dir is not None:
                module = dump_dir / "UnityFramework"
            if module is None:
                raise ValueError("profile generate requires --dump-dir or --module")
            generated = generate_profile(
                module,
                script_json=args.script_json,
                dump_cs=args.dump_cs,
                metadata=args.metadata,
                dump_dir=dump_dir,
                bundle_id=args.bundle_id,
                version=args.version,
                build=args.build,
                profile_id=args.profile_id,
                unity_version=args.unity_version,
                reference_profile=args.reference_profile,
                allow_layout_fallback=args.allow_layout_fallback,
            )
            output = args.output or PROFILES_DIR / f"{generated.data['id']}.json"
            write_profile(output, generated.data, force=args.force)
            output = output.expanduser().resolve()
            print(f"generated profile: {output}")
            print(
                f"target: {generated.data['bundle_id']} "
                f"{generated.data['version']} ({generated.data['build']})"
            )
            print(f"module UUID: {generated.data['module']['uuid']}")
            print(f"hooks: {len(generated.data['offsets'])}/{len(METHOD_SPECS)}")
            for warning in generated.warnings:
                print(f"warning: {warning}", file=sys.stderr)
            return 0

        if args.command == "patch-ipa":
            result = patch_ipa(
                args.input,
                args.output,
                args.gadget,
                gadget_port=args.port,
                allow_http=args.allow_http,
                sign=not args.no_sign,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0

        config = _load_with_overrides(args)
        profile = _run_profile_selector(args) if args.command == "run" else None
        device = connect_device(config)
        if args.command == "doctor":
            report = describe_device(device, config)
            report["host_tools"] = {
                "ldid": shutil.which("ldid"),
                "frida_version": __import__("frida").__version__,
            }
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 0 if report["target"]["installed"] else 2

        if args.command == "run":
            run(device, config, build=not args.no_build, profile=profile)
            return 0
    except _FRIDA_ERRORS as exc:
        print(f"error: {_frida_error_message(exc)}", file=sys.stderr)
        return 1
    except (RuntimeError, ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    parser.error("unknown command")
    return 2
