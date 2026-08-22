"""Export decrypted iOS application images from an authorised device.

FairPlay does not expose a useful offline decryption operation.  An IPA that
still has a non-zero ``cryptid`` can only be recovered after the app has been
loaded by iOS; this module therefore has two deliberately separate paths:

* local preparation, which copies already-decrypted app bundles and validates
  every Mach-O image; and
* a Frida exporter, which reads the loaded images from a running process.

The exporter writes process images, not a re-signed IPA.  They are sufficient
for profile generation because the Mach-O headers, UUID and executable text
are present.  No local operation silently pretends to decrypt FairPlay data.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import threading
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from .device import Target, acquire_target


class DecryptionError(ValueError):
    """Raised when an image cannot be safely exported or prepared."""


# Mach-O and FAT magic values.  The parser accepts both byte orders so a
# malformed/unexpected input is reported rather than accidentally rewritten.
_MACHO_MAGICS = {
    0xFEEDFACE: (False, "<"),
    0xFEEDFACF: (True, "<"),
    0xCEFAEDFE: (False, ">"),
    0xCFFAEDFE: (True, ">"),
}
_FAT_MAGICS = {
    0xCAFEBABE: (False, ">"),
    0xBEBAFECA: (False, "<"),
    0xCAFEBABF: (True, ">"),
    0xBFBAFECA: (True, "<"),
}
_LC_UUID = 0x1B
_LC_ENCRYPTION_INFO = 0x21
_LC_ENCRYPTION_INFO_64 = 0x2C
_CPU_TYPE_ARM64 = 0x0100000C
_HEADER_32_SIZE = 28
_HEADER_64_SIZE = 32
_FAT_ARCH_32_SIZE = 20
_FAT_ARCH_64_SIZE = 32
_EXPORT_ROOT_NAMES = frozenset(
    {
        "Payload",
        "modules",
        "resources",
        "UnityFramework",
        "global-metadata.dat",
        "decryption-manifest.json",
    }
)


@dataclass(frozen=True)
class MachOSlice:
    """The relevant load-command information for one Mach-O slice."""

    offset: int
    size: int
    magic: int
    is_64: bool
    endian: str
    cpu_type: int
    cpu_subtype: int
    uuid: str | None
    crypt_command_offset: int | None
    crypt_offset: int
    crypt_size: int
    crypt_id: int

    @property
    def encrypted(self) -> bool:
        return self.crypt_command_offset is not None and self.crypt_id != 0


@dataclass(frozen=True)
class MachOReport:
    path: Path | None
    slices: tuple[MachOSlice, ...]

    @property
    def encrypted(self) -> bool:
        return any(item.encrypted for item in self.slices)

    @property
    def uuids(self) -> tuple[str, ...]:
        return tuple(item.uuid for item in self.slices if item.uuid is not None)


@dataclass(frozen=True)
class PreparedDump:
    """Paths produced by either local preparation or a device export."""

    output_dir: Path
    module_path: Path
    metadata_path: Path | None
    app_path: Path | None
    modules: tuple[Path, ...] = ()
    warnings: tuple[str, ...] = ()


@dataclass
class _DumpWriter:
    root: Path
    module_path: Path | None = None
    metadata_path: Path | None = None
    app_path: Path | None = None
    modules: list[Path] = field(default_factory=list)
    _handles: dict[str, Any] = field(default_factory=dict)
    _expected: dict[str, int] = field(default_factory=dict)
    _received: dict[str, int] = field(default_factory=dict)
    _names: dict[str, Path] = field(default_factory=dict)
    _started: set[str] = field(default_factory=set)

    def _safe_relative(self, value: str, *, default: str) -> Path:
        # The device supplies an absolute path.  Never allow it to become a
        # path traversal on the host; only a stable basename is retained.
        name = Path(value).name or default
        if name in {".", ".."} or any(char in name for char in ("/", "\\", "\x00")):
            name = default
        return Path(name)

    def _module_destination(self, name: str, source_path: str) -> Path:
        candidate = self._safe_relative(name or source_path, default="module")
        if candidate.name == "UnityFramework":
            destination = self.root / "UnityFramework"
        else:
            modules_dir = self.root / "modules"
            modules_dir.mkdir(parents=True, exist_ok=True)
            destination = modules_dir / candidate.name
        # Multiple loaded images can share a basename.  Keep each image and
        # make the UnityFramework path deterministic.
        original = destination
        index = 1
        while destination in self._names.values():
            destination = original.with_name(f"{original.name}.{index}")
            index += 1
        return destination

    def _file_destination(self, path: str, name: str) -> Path:
        lower = path.casefold()
        if lower.endswith("global-metadata.dat") or name == "global-metadata.dat":
            return self.root / "global-metadata.dat"
        resources = self.root / "resources"
        resources.mkdir(parents=True, exist_ok=True)
        return resources / self._safe_relative(name or path, default="resource.bin").name

    def start(self, payload: Mapping[str, Any]) -> None:
        kind = str(payload.get("kind", "module"))
        identifier = str(payload.get("id") or payload.get("name") or kind)
        if identifier in self._started:
            raise DecryptionError(f"duplicate dump stream: {identifier}")
        size = payload.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise DecryptionError(f"invalid dump size for {identifier}: {size!r}")
        if kind == "module":
            destination = self._module_destination(
                str(payload.get("name", "")), str(payload.get("path", ""))
            )
            if destination.name == "UnityFramework":
                self.module_path = destination
            self.modules.append(destination)
            self._names[identifier] = destination
        else:
            destination = self._file_destination(
                str(payload.get("path", "")), str(payload.get("name", ""))
            )
            if destination.name == "global-metadata.dat":
                self.metadata_path = destination
            self._names[identifier] = destination
        destination.parent.mkdir(parents=True, exist_ok=True)
        stream = destination.open("wb")
        stream.truncate(size)
        self._handles[identifier] = stream
        self._expected[identifier] = size
        self._received[identifier] = 0
        self._started.add(identifier)

    def chunk(self, payload: Mapping[str, Any], data: bytes | bytearray | memoryview | None) -> None:
        identifier = str(payload.get("id") or payload.get("name") or "")
        stream = self._handles.get(identifier)
        if stream is None:
            raise DecryptionError(f"dump chunk arrived before start: {identifier}")
        if data is None:
            raise DecryptionError(f"empty dump chunk for {identifier}")
        offset = payload.get("offset")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise DecryptionError(f"invalid dump offset for {identifier}: {offset!r}")
        value = bytes(data)
        expected_offset = self._received[identifier]
        if offset != expected_offset:
            raise DecryptionError(
                f"out-of-order dump chunk for {identifier}: {offset}, expected {expected_offset}"
            )
        if offset + len(value) > self._expected[identifier]:
            raise DecryptionError(f"dump chunk exceeds declared size for {identifier}")
        stream.seek(offset)
        stream.write(value)
        self._received[identifier] = offset + len(value)

    def finish(self, payload: Mapping[str, Any]) -> None:
        identifier = str(payload.get("id") or payload.get("name") or "")
        stream = self._handles.pop(identifier, None)
        if stream is None:
            raise DecryptionError(f"dump end arrived before start: {identifier}")
        received = self._received.pop(identifier)
        expected = self._expected.pop(identifier)
        try:
            stream.flush()
            os.fsync(stream.fileno())
        finally:
            stream.close()
        if received != expected:
            raise DecryptionError(
                f"short dump for {identifier}: received {received}, expected {expected}"
            )
        destination = self._names[identifier]
        try:
            destination.chmod(0o600)
        except OSError:
            pass

    def close(self) -> None:
        for stream in self._handles.values():
            try:
                stream.close()
            except OSError:
                pass
        self._handles.clear()

    def assert_complete(self) -> None:
        """Ensure the agent did not signal completion with an open stream."""

        if self._handles:
            pending = ", ".join(sorted(self._handles))
            raise DecryptionError(f"device export ended with open dump streams: {pending}")
        if self._expected or self._received:
            pending = ", ".join(sorted(set(self._expected) | set(self._received)))
            raise DecryptionError(f"device export has incomplete dump streams: {pending}")


def _u32(data: bytes | bytearray, offset: int, endian: str) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise DecryptionError(f"Mach-O field at 0x{offset:x} is outside the file")
    return int.from_bytes(data[offset : offset + 4], "little" if endian == "<" else "big")


def _u64(data: bytes | bytearray, offset: int, endian: str) -> int:
    if offset < 0 or offset + 8 > len(data):
        raise DecryptionError(f"Mach-O field at 0x{offset:x} is outside the file")
    return int.from_bytes(data[offset : offset + 8], "little" if endian == "<" else "big")


def _uuid_text(raw: bytes) -> str:
    if len(raw) != 16:
        raise DecryptionError("LC_UUID must contain 16 bytes")
    value = raw.hex().upper()
    return f"{value[:8]}-{value[8:12]}-{value[12:16]}-{value[16:20]}-{value[20:]}"


def _parse_thin(data: bytes, offset: int, size: int) -> MachOSlice:
    if offset < 0 or size < _HEADER_32_SIZE or offset + size > len(data):
        raise DecryptionError("Mach-O slice is truncated")
    magic = int.from_bytes(data[offset : offset + 4], "little")
    if magic not in _MACHO_MAGICS:
        magic = int.from_bytes(data[offset : offset + 4], "big")
    details = _MACHO_MAGICS.get(magic)
    if details is None:
        raise DecryptionError(f"unsupported Mach-O magic at 0x{offset:x}")
    is_64, endian = details
    header_size = _HEADER_64_SIZE if is_64 else _HEADER_32_SIZE
    ncmds = _u32(data, offset + 16, endian)
    sizeofcmds = _u32(data, offset + 20, endian)
    commands_start = offset + header_size
    commands_end = commands_start + sizeofcmds
    if commands_end > offset + size or commands_end > len(data):
        raise DecryptionError("Mach-O load commands are truncated")
    cpu_type = _u32(data, offset + 4, endian)
    cpu_subtype = _u32(data, offset + 8, endian)
    command_offset = commands_start
    uuid: str | None = None
    crypt_command_offset: int | None = None
    crypt_offset = crypt_size = crypt_id = 0
    for _ in range(ncmds):
        if command_offset + 8 > commands_end:
            raise DecryptionError("Mach-O load command header is truncated")
        command = _u32(data, command_offset, endian)
        command_size = _u32(data, command_offset + 4, endian)
        if command_size < 8 or command_offset + command_size > commands_end:
            raise DecryptionError("invalid Mach-O load command size")
        if command == _LC_UUID:
            if command_size < 24:
                raise DecryptionError("truncated LC_UUID")
            uuid = _uuid_text(data[command_offset + 8 : command_offset + 24])
        elif command in (_LC_ENCRYPTION_INFO, _LC_ENCRYPTION_INFO_64):
            if command_size < 20:
                raise DecryptionError("truncated LC_ENCRYPTION_INFO")
            if crypt_command_offset is not None:
                raise DecryptionError("multiple Mach-O encryption commands")
            crypt_command_offset = command_offset
            crypt_offset = _u32(data, command_offset + 8, endian)
            crypt_size = _u32(data, command_offset + 12, endian)
            crypt_id = _u32(data, command_offset + 16, endian)
        command_offset += command_size
    if command_offset != commands_end:
        raise DecryptionError("Mach-O load command sizes are inconsistent")
    return MachOSlice(
        offset=offset,
        size=size,
        magic=magic,
        is_64=is_64,
        endian=endian,
        cpu_type=cpu_type,
        cpu_subtype=cpu_subtype,
        uuid=uuid,
        crypt_command_offset=crypt_command_offset,
        crypt_offset=crypt_offset,
        crypt_size=crypt_size,
        crypt_id=crypt_id,
    )


def inspect_macho_bytes(data: bytes | bytearray, *, path: Path | None = None) -> MachOReport:
    """Parse Mach-O headers and return encryption state without changing data."""

    raw = bytes(data)
    if len(raw) < 4:
        raise DecryptionError("file is too small to be a Mach-O image")
    magic_little = int.from_bytes(raw[:4], "little")
    magic_big = int.from_bytes(raw[:4], "big")
    if magic_little in _MACHO_MAGICS or magic_big in _MACHO_MAGICS:
        return MachOReport(path, (_parse_thin(raw, 0, len(raw)),))
    fat_details = _FAT_MAGICS.get(magic_big) or _FAT_MAGICS.get(magic_little)
    if fat_details is None:
        raise DecryptionError("file is not a Mach-O image")
    is_fat64, endian = fat_details
    nfat_arch = _u32(raw, 4, endian)
    entry_size = _FAT_ARCH_64_SIZE if is_fat64 else _FAT_ARCH_32_SIZE
    table_end = 8 + nfat_arch * entry_size
    if nfat_arch <= 0 or table_end > len(raw):
        raise DecryptionError("invalid FAT Mach-O architecture table")
    slices: list[MachOSlice] = []
    for index in range(nfat_arch):
        entry = 8 + index * entry_size
        slice_offset = _u64(raw, entry + 8, endian) if is_fat64 else _u32(raw, entry + 8, endian)
        slice_size = _u64(raw, entry + 16, endian) if is_fat64 else _u32(raw, entry + 12, endian)
        if slice_offset + slice_size > len(raw) or slice_size == 0:
            raise DecryptionError("FAT Mach-O slice is outside the file")
        slices.append(_parse_thin(raw, slice_offset, slice_size))
    return MachOReport(path, tuple(slices))


def inspect_macho(path: Path) -> MachOReport:
    path = Path(path).expanduser().resolve()
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise DecryptionError(f"unable to read Mach-O {path}: {exc}") from exc
    return inspect_macho_bytes(data, path=path)


def _cryptid_offset(slice_info: MachOSlice) -> int | None:
    if slice_info.crypt_command_offset is None:
        return None
    return slice_info.crypt_command_offset + 16


def clear_cryptid(data: bytes | bytearray, *, require_encrypted: bool = False) -> bytes:
    """Clear FairPlay markers in an image that is already decrypted in memory.

    This function does *not* decrypt ciphertext.  Callers must only pass a
    process/memory dump or another independently verified plaintext image.
    """

    output = bytearray(data)
    report = inspect_macho_bytes(output)
    encrypted = False
    for slice_info in report.slices:
        if not slice_info.encrypted:
            continue
        encrypted = True
        if slice_info.crypt_size <= 0:
            raise DecryptionError("encrypted Mach-O range is empty")
        if slice_info.crypt_offset + slice_info.crypt_size > slice_info.size:
            raise DecryptionError("encrypted range exceeds Mach-O slice")
        location = _cryptid_offset(slice_info)
        if location is None:
            raise DecryptionError("encrypted Mach-O slice has no cryptid field")
        output[location : location + 4] = (0).to_bytes(4, "little" if slice_info.endian == "<" else "big")
    if require_encrypted and not encrypted:
        raise DecryptionError("Mach-O is not marked encrypted")
    return bytes(output)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_macho_file(path: Path) -> bool:
    try:
        with path.open("rb") as stream:
            prefix = stream.read(4)
    except OSError:
        return False
    if len(prefix) != 4:
        return False
    little = int.from_bytes(prefix, "little")
    big = int.from_bytes(prefix, "big")
    return little in _MACHO_MAGICS or big in _MACHO_MAGICS or little in _FAT_MAGICS or big in _FAT_MAGICS


def _find_app(root: Path) -> Path:
    payload = root / "Payload"
    apps = sorted(path for path in payload.glob("*.app") if path.is_dir())
    if len(apps) != 1:
        raise DecryptionError(f"expected one app in Payload, found {len(apps)}")
    return apps[0]


def _safe_extract_ipa(source: Path, destination: Path) -> Path:
    try:
        with zipfile.ZipFile(source) as archive:
            for member in archive.infolist():
                target = (destination / member.filename).resolve()
                if destination.resolve() not in target.parents and target != destination.resolve():
                    raise DecryptionError(f"IPA contains an unsafe path: {member.filename}")
                archive.extract(member, destination)
    except zipfile.BadZipFile as exc:
        raise DecryptionError(f"invalid IPA/ZIP archive: {source}") from exc
    return _find_app(destination)


def _find_unityframework(app: Path) -> Path:
    candidates = [
        app / "Frameworks" / "UnityFramework.framework" / "UnityFramework",
        app / "Frameworks" / "UnityFramework",
    ]
    candidates.extend(
        path
        for path in sorted(app.rglob("UnityFramework"))
        if path not in candidates
    )
    for candidate in candidates:
        if candidate.is_file() and _is_macho_file(candidate):
            return candidate
    raise DecryptionError(f"UnityFramework was not found under {app}")


def _find_metadata(app: Path) -> Path | None:
    candidates = sorted(app.rglob("global-metadata.dat"))
    if not candidates:
        return None
    candidates.sort(key=lambda path: ("il2cpp_data/Metadata" not in str(path), len(path.parts)))
    return candidates[0]


def _validate_metadata_file(path: Path) -> None:
    try:
        with path.open("rb") as stream:
            header = stream.read(8)
    except OSError as exc:
        raise DecryptionError(f"unable to read global-metadata.dat {path}: {exc}") from exc
    if len(header) != 8 or int.from_bytes(header[:4], "little") != 0xFAB11BAF:
        raise DecryptionError(f"invalid global-metadata.dat header: {path}")
    version = int.from_bytes(header[4:8], "little")
    if version <= 0:
        raise DecryptionError(f"invalid global-metadata.dat version: {version}")


def _iter_regular_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            yield path


def _copy_tree(source: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for path in _iter_regular_files(source):
        relative = path.relative_to(source)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)


def _stage_existing_output(
    output_dir: Path,
    staging: Path,
    *,
    force: bool,
    preserve_export_names: Iterable[str] = (),
) -> None:
    """Preserve user dump artifacts while dropping the previous export."""

    if not force or not output_dir.is_dir() or not any(output_dir.iterdir()):
        return
    preserved = frozenset(preserve_export_names)
    for path in _iter_regular_files(output_dir):
        relative = path.relative_to(output_dir)
        if (
            relative.parts[0] in _EXPORT_ROOT_NAMES
            and relative.parts[0] not in preserved
        ):
            continue
        target = staging / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)


def _install_staging(staging: Path, output_dir: Path, *, force: bool) -> None:
    """Install a complete staging tree after rechecking the target."""

    if output_dir.exists():
        if not output_dir.is_dir():
            raise DecryptionError(f"output path is not a directory: {output_dir}")
        if any(output_dir.iterdir()) and not force:
            raise DecryptionError(f"output directory is not empty: {output_dir}")
        if force:
            shutil.rmtree(output_dir)
        else:
            output_dir.rmdir()
    os.replace(staging, output_dir)


def _materialise_alias(source: Path | None, destination: Path) -> None:
    """Expose convenient dump-dir names without changing the app tree."""

    if source is None or not source.is_file() or source == destination:
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        if destination.is_dir() and not destination.is_symlink():
            raise DecryptionError(f"dump alias is a directory: {destination}")
        destination.unlink()
    try:
        os.link(source, destination)
    except OSError:
        shutil.copy2(source, destination)


def _write_manifest(root: Path, *, source: Path, modules: list[Path], warnings: list[str]) -> None:
    manifest = {
        "schema": 1,
        "source": str(source),
        "modules": [
            {"path": str(path.relative_to(root)), "sha256": _sha256(path)}
            for path in modules
            if path.is_file()
        ],
        "warnings": list(dict.fromkeys(warnings)),
    }
    manifest_path = root / "decryption-manifest.json"
    temporary = manifest_path.with_name(f".{manifest_path.name}.tmp")
    temporary.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, manifest_path)
    try:
        manifest_path.chmod(0o600)
    except OSError:
        pass


def _validate_output_dir(output_dir: Path, source: Path | None = None) -> None:
    """Reject ambiguous or dangerously broad destructive targets."""

    resolved = output_dir.expanduser().resolve()
    project_root = Path(__file__).resolve().parent.parent
    current_dir = Path.cwd().resolve()
    protected = {Path("/"), Path.home().resolve(), Path(tempfile.gettempdir()).resolve()}
    if (
        resolved in protected
        or resolved == project_root
        or resolved in project_root.parents
        or resolved == current_dir
        or resolved in current_dir.parents
    ):
        raise DecryptionError(f"refusing to use broad output directory: {resolved}")
    if resolved.exists() and not resolved.is_dir():
        raise DecryptionError(f"output path is not a directory: {resolved}")
    if source is not None and source.is_dir() and (
        resolved == source or source in resolved.parents
    ):
        raise DecryptionError("output directory must be outside the source app")


def _normalise_exported_modules(modules: Iterable[Path], warnings: list[str]) -> None:
    """Mark runtime images as decrypted after their plaintext pages were read."""

    for path in modules:
        try:
            raw = path.read_bytes()
            report = inspect_macho_bytes(raw, path=path)
        except OSError as exc:
            raise DecryptionError(f"unable to read exported module {path}: {exc}") from exc
        if not report.encrypted:
            continue
        try:
            normalised = clear_cryptid(raw, require_encrypted=True)
        except DecryptionError as exc:
            raise DecryptionError(
                f"exported module {path} still has an invalid encrypted range: {exc}"
            ) from exc
        temporary = path.with_name(f".{path.name}.decrypted.tmp")
        try:
            temporary.write_bytes(normalised)
            os.replace(temporary, path)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        warnings.append(f"cleared runtime cryptid: {path.name}")


def prepare_local_dump(
    source: Path,
    output_dir: Path,
    *,
    force: bool = False,
    assume_memory_dump: bool = False,
) -> PreparedDump:
    """Prepare an app/IPA or a dumped module for profile generation.

    ``assume_memory_dump`` is intentionally explicit.  It is useful when a
    third-party dumper already read plaintext pages but left ``cryptid`` set;
    it must never be inferred from a filename.
    """

    source = Path(source).expanduser().resolve()
    output_dir = Path(output_dir).expanduser().resolve()
    if not source.exists():
        raise DecryptionError(f"decryption source not found: {source}")
    _validate_output_dir(output_dir, source)
    if output_dir.exists() and any(output_dir.iterdir()) and not force:
        raise DecryptionError(f"output directory is not empty: {output_dir} (use --force to replace files)")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    warnings: list[str] = []
    modules: list[Path] = []

    staging = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.", dir=output_dir.parent))
    try:
        # A forced refresh replaces only the exported app artifacts while
        # retaining an existing script.json/dump.cs in the dump directory.
        preserve_export_names = (
            ("global-metadata.dat",)
            if source.is_file() and source.suffix.casefold() not in {".ipa", ".zip"}
            else ()
        )
        _stage_existing_output(
            output_dir,
            staging,
            force=force,
            preserve_export_names=preserve_export_names,
        )
        app: Path | None = None
        if source.is_file() and source.suffix.casefold() in {".ipa", ".zip"}:
            app = _safe_extract_ipa(source, staging)
        elif source.is_dir() and source.suffix.casefold() == ".app":
            app_root = staging / "Payload" / source.name
            _copy_tree(source, app_root)
            app = app_root
        elif source.is_dir() and (source / "UnityFramework").is_file():
            # Accept the conventional flat dump layout as an input too.  It
            # is common for an external dumper to have already copied the
            # framework and metadata out of the app bundle.
            _copy_tree(source, staging)
            module = staging / "UnityFramework"
            metadata = staging / "global-metadata.dat"
            if not metadata.is_file():
                metadata = None
            else:
                _validate_metadata_file(metadata)
            for path in _iter_regular_files(staging):
                if not _is_macho_file(path):
                    continue
                report = inspect_macho(path)
                if report.encrypted:
                    if not assume_memory_dump:
                        raise DecryptionError(
                            f"{path} is FairPlay-encrypted; use the device exporter to obtain plaintext"
                        )
                    path.write_bytes(clear_cryptid(path.read_bytes(), require_encrypted=True))
                    warnings.append(f"cleared cryptid on assumed memory dump: {path.name}")
                modules.append(path)
            _install_staging(staging, output_dir, force=force)
            module = output_dir / "UnityFramework"
            metadata = output_dir / "global-metadata.dat" if metadata is not None else None
            _materialise_alias(module, output_dir / "UnityFramework")
            _materialise_alias(metadata, output_dir / "global-metadata.dat")
            modules = [output_dir / path.relative_to(staging) for path in modules]
            _write_manifest(output_dir, source=source, modules=modules, warnings=warnings)
            return PreparedDump(output_dir, module, metadata, None, tuple(modules), tuple(warnings))
        elif source.is_dir():
            candidate = source / "Payload"
            if candidate.is_dir():
                app = _find_app(source)
                _copy_tree(source, staging)
                app = staging / "Payload" / app.name
            else:
                raise DecryptionError("directory source must be an .app bundle or an IPA extraction")
        elif source.is_file():
            target = staging / "UnityFramework"
            shutil.copy2(source, target)
            module = target
            modules.append(module)
            try:
                report = inspect_macho(module)
            except DecryptionError:
                raise DecryptionError(f"source is not a Mach-O image: {source}")
            if report.encrypted:
                if not assume_memory_dump:
                    raise DecryptionError(
                        f"{source} is FairPlay-encrypted; attach to the running app or pass "
                        "--assume-memory-dump only for a verified plaintext memory dump"
                    )
                module.write_bytes(clear_cryptid(module.read_bytes(), require_encrypted=True))
                warnings.append(f"cleared cryptid on assumed memory dump: {module.name}")
            destination = staging / module.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            if module != destination:
                shutil.copy2(module, destination)
            staged_metadata = staging / "global-metadata.dat"
            if staged_metadata.is_file():
                _validate_metadata_file(staged_metadata)
            _install_staging(staging, output_dir, force=force)
            output_module = output_dir / module.name
            output_metadata = output_dir / "global-metadata.dat"
            if not output_metadata.is_file():
                output_metadata = None
            _write_manifest(output_dir, source=source, modules=[output_module], warnings=warnings)
            return PreparedDump(
                output_dir,
                output_module,
                output_metadata,
                None,
                (output_module,),
                tuple(warnings),
            )

        if app is None:
            raise DecryptionError("unable to locate an application bundle in source")
        for path in _iter_regular_files(app):
            if not _is_macho_file(path):
                continue
            report = inspect_macho(path)
            if report.encrypted:
                if not assume_memory_dump:
                    raise DecryptionError(
                        f"{path} is FairPlay-encrypted; use the device exporter to obtain plaintext"
                    )
                path.write_bytes(clear_cryptid(path.read_bytes(), require_encrypted=True))
                warnings.append(f"cleared cryptid on assumed memory dump: {path.name}")
            modules.append(path)
        module = _find_unityframework(app)
        metadata = _find_metadata(app)
        if metadata is not None:
            _validate_metadata_file(metadata)
        # Preserve any existing dump artifacts only when force is requested;
        # the source app itself is always copied into the fresh staging tree.
        _install_staging(staging, output_dir, force=force)
        app = output_dir / "Payload" / app.name
        module = output_dir / module.relative_to(staging)
        modules = [output_dir / path.relative_to(staging) for path in modules]
        metadata = output_dir / metadata.relative_to(staging) if metadata is not None else None
        _materialise_alias(module, output_dir / "UnityFramework")
        _materialise_alias(metadata, output_dir / "global-metadata.dat")
        _write_manifest(output_dir, source=source, modules=modules, warnings=warnings)
        return PreparedDump(output_dir, module, metadata, app, tuple(modules), tuple(warnings))
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


# Kept as a constant so the host never needs to compile a helper before a
# profile can be exported.  The agent reads loaded modules and sends bounded
# binary chunks; it does not expose arbitrary host commands or file paths.
FRIDA_DECRYPT_AGENT = r"""
'use strict';

const CHUNK_SIZE = 1024 * 1024;
const APP_SUFFIX = '.app/';

function emitError(error) {
    send({ event: 'error', error: String(error && error.stack || error) });
}

function moduleId(module, index) {
    return `${index}:${module.name}:${module.base}`;
}

function sendBytes(kind, id, name, path, bytes, size, offset) {
    if (bytes === null) throw new Error(`unable to read ${name} at 0x${offset.toString(16)}`);
    send({ event: 'chunk', kind, id, name, path, size, offset }, bytes);
}

function byteOrder(bytes) {
    if (bytes.length < 4) return null;
    const key = `${bytes[0].toString(16).padStart(2, '0')}${bytes[1].toString(16).padStart(2, '0')}${bytes[2].toString(16).padStart(2, '0')}${bytes[3].toString(16).padStart(2, '0')}`;
    return {
        'cffaedfe': { macho: true, is64: true, little: true },
        'feedfacf': { macho: true, is64: true, little: false },
        'cefaedfe': { macho: true, is64: false, little: true },
        'feedface': { macho: true, is64: false, little: false },
        'cafebabe': { fat: true, is64: false, little: false },
        'bebafeca': { fat: true, is64: false, little: true },
        'cafebabf': { fat: true, is64: true, little: false },
        'bfbafeca': { fat: true, is64: true, little: true },
    }[key] || null;
}

function read32(bytes, offset, little) {
    if (offset < 0 || offset + 4 > bytes.length) throw new Error('truncated Mach-O field');
    if (little) return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;
    return ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
}

function read64Number(bytes, offset, little) {
    const low = read32(bytes, little ? offset : offset + 4, little);
    const high = read32(bytes, little ? offset + 4 : offset, little);
    const value = high * 0x100000000 + low;
    if (!Number.isSafeInteger(value)) throw new Error('Mach-O offset is too large');
    return value;
}

function readAt(file, offset, length) {
    if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0) {
        throw new Error(`invalid file range: offset=${offset}, length=${length}`);
    }
    file.seek(offset, File.SEEK_SET);
    const value = file.readBytes(length);
    if (value === null || value.byteLength !== length) throw new Error(`short read at 0x${offset.toString(16)}`);
    return new Uint8Array(value);
}

function checkRange(offset, size, total, label) {
    if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(size) || offset < 0 || size < 0 || offset > total || size > total - offset) {
        throw new Error(`${label} is outside the Mach-O slice`);
    }
}

function sourceSlice(file, module, fileSize) {
    const prefix = readAt(file, 0, Math.min(fileSize, 4096));
    const info = byteOrder(prefix);
    if (info === null) throw new Error(`unrecognised Mach-O at ${module.path}`);
    const memoryBytes = module.base.readByteArray(32);
    if (memoryBytes === null) throw new Error(`unable to read loaded Mach-O header for ${module.name}`);
    const memoryHeader = new Uint8Array(memoryBytes);
    const memoryInfo = byteOrder(memoryHeader);
    if (memoryInfo === null || !memoryInfo.macho) throw new Error(`invalid loaded Mach-O ${module.name}`);
    const cpuType = read32(memoryHeader, 4, memoryInfo.little);
    const cpuSubtype = read32(memoryHeader, 8, memoryInfo.little);
    if (!info.fat) {
        if (!info.macho || prefix.length < 12) throw new Error(`invalid thin Mach-O at ${module.path}`);
        const fileCpuType = read32(prefix, 4, info.little);
        const fileCpuSubtype = read32(prefix, 8, info.little);
        if (fileCpuType !== cpuType || (fileCpuSubtype & 0x00ffffff) !== (cpuSubtype & 0x00ffffff)) {
            throw new Error(`loaded architecture for ${module.name} does not match its file`);
        }
        return { offset: 0, size: fileSize };
    }
    const count = read32(prefix, 4, info.little);
    if (count <= 0 || count > 128) throw new Error(`invalid FAT architecture count: ${count}`);
    const entrySize = info.is64 ? 32 : 20;
    const tableSize = 8 + count * entrySize;
    checkRange(0, tableSize, fileSize, 'FAT architecture table');
    const table = readAt(file, 0, tableSize);
    const candidates = [];
    for (let index = 0; index < count; index += 1) {
        const entry = 8 + index * entrySize;
        const candidateCpuType = read32(table, entry, info.little);
        const candidateCpuSubtype = read32(table, entry + 4, info.little);
        if (candidateCpuType !== cpuType) continue;
        const offset = info.is64 ? read64Number(table, entry + 8, info.little) : read32(table, entry + 8, info.little);
        const size = info.is64 ? read64Number(table, entry + 16, info.little) : read32(table, entry + 12, info.little);
        checkRange(offset, size, fileSize, 'FAT Mach-O slice');
        if (size === 0) throw new Error('FAT Mach-O slice is empty');
        candidates.push({ offset, size, cpuSubtype: candidateCpuSubtype });
    }
    const exact = candidates.filter(candidate => candidate.cpuSubtype === cpuSubtype);
    if (exact.length === 1) return exact[0];
    const compatible = candidates.filter(candidate =>
        (candidate.cpuSubtype & 0x00ffffff) === (cpuSubtype & 0x00ffffff));
    if (compatible.length === 1) return compatible[0];
    if (exact.length > 1 || compatible.length > 1) {
        throw new Error(`loaded architecture for ${module.name} is ambiguous in the file`);
    }
    throw new Error(`loaded architecture for ${module.name} is absent from the file`);
}

function parseThinLayout(file, slice) {
    const prefix = readAt(file, slice.offset, Math.min(slice.size, 32));
    const info = byteOrder(prefix);
    if (info === null || !info.macho) throw new Error('selected FAT entry is not a thin Mach-O');
    const headerSize = info.is64 ? 32 : 28;
    if (slice.size < headerSize) throw new Error('thin Mach-O header is truncated');
    const ncmds = read32(prefix, 16, info.little);
    const sizeofcmds = read32(prefix, 20, info.little);
    if (ncmds > 4096) throw new Error(`invalid Mach-O load command count: ${ncmds}`);
    if (sizeofcmds > 16 * 1024 * 1024) throw new Error(`Mach-O load commands are too large: ${sizeofcmds}`);
    checkRange(headerSize, sizeofcmds, slice.size, 'Mach-O load commands');
    const commandsEnd = headerSize + sizeofcmds;
    const bytes = readAt(file, slice.offset, commandsEnd);
    const segments = [];
    let encryption = null;
    let command = headerSize;
    for (let index = 0; index < ncmds; index += 1) {
        if (command + 8 > commandsEnd) throw new Error('Mach-O load command header is truncated');
        const kind = read32(bytes, command, info.little);
        const size = read32(bytes, command + 4, info.little);
        if (size < 8 || command + size > commandsEnd) throw new Error(`invalid load command size: ${size}`);
        if (kind === 0x21 || kind === 0x2c) {
            if (size < 20) throw new Error('truncated LC_ENCRYPTION_INFO');
            if (encryption !== null) throw new Error('multiple encryption commands in one Mach-O slice');
            encryption = {
                commandOffset: command,
                cryptOffset: read32(bytes, command + 8, info.little),
                cryptSize: read32(bytes, command + 12, info.little),
                cryptId: read32(bytes, command + 16, info.little),
            };
        } else if (kind === 0x1 || kind === 0x19) {
            const is64 = kind === 0x19;
            const minimumSize = is64 ? 72 : 56;
            if (size < minimumSize) throw new Error('truncated LC_SEGMENT command');
            const vmAddress = is64
                ? read64Number(bytes, command + 24, info.little)
                : read32(bytes, command + 24, info.little);
            const vmSize = is64
                ? read64Number(bytes, command + 32, info.little)
                : read32(bytes, command + 28, info.little);
            const fileOffset = is64
                ? read64Number(bytes, command + 40, info.little)
                : read32(bytes, command + 32, info.little);
            const fileSize = is64
                ? read64Number(bytes, command + 48, info.little)
                : read32(bytes, command + 36, info.little);
            checkRange(fileOffset, fileSize, slice.size, 'Mach-O segment');
            if (fileSize > vmSize) throw new Error('Mach-O segment file size exceeds VM size');
            segments.push({ vmAddress, vmSize, fileOffset, fileSize });
        }
        command += size;
    }
    if (command !== commandsEnd) throw new Error('Mach-O load command sizes are inconsistent');
    const headerSegments = segments.filter(segment =>
        segment.fileOffset === 0 && segment.fileSize >= commandsEnd);
    if (headerSegments.length !== 1) throw new Error('Mach-O header does not have one file-backed segment');
    if (encryption !== null && encryption.cryptId !== 0) {
        if (encryption.cryptSize === 0) throw new Error('encrypted Mach-O range is empty');
        checkRange(encryption.cryptOffset, encryption.cryptSize, slice.size, 'encrypted Mach-O range');
    }
    return { info, segments, headerVmAddress: headerSegments[0].vmAddress, encryption };
}

function mappedSegment(layout, fileOffset) {
    return layout.segments.find(segment =>
        segment.fileSize > 0 && fileOffset >= segment.fileOffset && fileOffset < segment.fileOffset + segment.fileSize);
}

function validateMappedRange(module, layout, start, size) {
    const moduleSize = Number(module.size);
    if (!Number.isSafeInteger(moduleSize) || moduleSize <= 0) throw new Error(`invalid module size for ${module.name}`);
    let cursor = start;
    const end = start + size;
    while (cursor < end) {
        const segment = mappedSegment(layout, cursor);
        if (segment === undefined) throw new Error(`encrypted file offset 0x${cursor.toString(16)} is not mapped`);
        const pieceEnd = Math.min(end, segment.fileOffset + segment.fileSize);
        const runtimeOffset = segment.vmAddress - layout.headerVmAddress + cursor - segment.fileOffset;
        const length = pieceEnd - cursor;
        if (!Number.isSafeInteger(runtimeOffset) || runtimeOffset < 0 || runtimeOffset > moduleSize || length > moduleSize - runtimeOffset) {
            throw new Error(`encrypted range for ${module.name} is outside the loaded module`);
        }
        cursor = pieceEnd;
    }
}

function copyMappedPlaintext(module, layout, bytes, outputOffset, start, end) {
    let cursor = start;
    while (cursor < end) {
        const segment = mappedSegment(layout, cursor);
        if (segment === undefined) throw new Error(`encrypted file offset 0x${cursor.toString(16)} is not mapped`);
        const pieceEnd = Math.min(end, segment.fileOffset + segment.fileSize);
        const runtimeOffset = segment.vmAddress - layout.headerVmAddress + cursor - segment.fileOffset;
        const plaintext = module.base.add(runtimeOffset).readByteArray(pieceEnd - cursor);
        if (plaintext === null) throw new Error(`unable to read decrypted pages for ${module.name}`);
        bytes.set(new Uint8Array(plaintext), cursor - outputOffset);
        cursor = pieceEnd;
    }
}

function dumpMemoryModule(module, index) {
    const id = moduleId(module, index);
    const size = Number(module.size);
    if (!Number.isSafeInteger(size) || size <= 0) throw new Error(`invalid module size for ${module.name}`);
    send({ event: 'start', kind: 'module', id, name: module.name, path: module.path, size });
    for (let offset = 0; offset < size; offset += CHUNK_SIZE) {
        const length = Math.min(CHUNK_SIZE, size - offset);
        sendBytes('module', id, module.name, module.path, module.base.add(offset).readByteArray(length), size, offset);
    }
    send({ event: 'end', kind: 'module', id, name: module.name, path: module.path, size });
}

function dumpFileBackedModule(module, index, state) {
    const file = new File(module.path, 'rb');
    try {
        const fileSize = fileLength(file);
        const slice = sourceSlice(file, module, fileSize);
        const layout = parseThinLayout(file, slice);
        const encryption = layout.encryption;
        if (encryption !== null && encryption.cryptId !== 0) {
            validateMappedRange(module, layout, encryption.cryptOffset, encryption.cryptSize);
        }
        const id = moduleId(module, index);
        state.started = true;
        send({ event: 'start', kind: 'module', id, name: module.name, path: module.path, size: slice.size, format: 'file-slice' });
        for (let offset = 0; offset < slice.size; offset += CHUNK_SIZE) {
            const length = Math.min(CHUNK_SIZE, slice.size - offset);
            const bytes = readAt(file, slice.offset + offset, length);
            if (encryption !== null && encryption.cryptId !== 0) {
                const overlapStart = Math.max(offset, encryption.cryptOffset);
                const overlapEnd = Math.min(offset + length, encryption.cryptOffset + encryption.cryptSize);
                if (overlapEnd > overlapStart) {
                    copyMappedPlaintext(module, layout, bytes, offset, overlapStart, overlapEnd);
                }
                const cryptidOffset = encryption.commandOffset + 16;
                const markerStart = Math.max(offset, cryptidOffset);
                const markerEnd = Math.min(offset + length, cryptidOffset + 4);
                if (markerEnd > markerStart) {
                    bytes.fill(0, markerStart - offset, markerEnd - offset);
                }
            }
            sendBytes('module', id, module.name, module.path, bytes.buffer, slice.size, offset);
        }
        send({ event: 'end', kind: 'module', id, name: module.name, path: module.path, size: slice.size, format: 'file-slice' });
    } finally {
        file.close();
    }
}

function dumpModule(module, index) {
    const state = { started: false };
    try {
        dumpFileBackedModule(module, index, state);
    } catch (error) {
        if (state.started) throw error;
        send({ event: 'warning', name: module.name, warning: `file-backed export unavailable: ${String(error)}` });
        dumpMemoryModule(module, index);
    }
}

function fileLength(file) {
    const current = file.tell();
    file.seek(0, File.SEEK_END);
    const end = file.tell();
    file.seek(current, File.SEEK_SET);
    if (!Number.isSafeInteger(end) || end < 0) throw new Error(`invalid file size: ${end}`);
    return end;
}

function dumpFile(path, name, index, state) {
    const file = new File(path, 'rb');
    try {
        const size = fileLength(file);
        const id = `file:${index}:${name}`;
        state.started = true;
        send({ event: 'start', kind: 'file', id, name, path, size });
        for (let offset = 0; offset < size; offset += CHUNK_SIZE) {
            const length = Math.min(CHUNK_SIZE, size - offset);
            const bytes = file.readBytes(length);
            sendBytes('file', id, name, path, bytes, size, offset);
        }
        send({ event: 'end', kind: 'file', id, name, path, size });
    } finally {
        file.close();
    }
}

function metadataCandidates(appPath) {
    return [
        `${appPath}/Data/Managed/Metadata/global-metadata.dat`,
        `${appPath}/Data/il2cpp_data/Metadata/global-metadata.dat`,
        `${appPath}/Frameworks/UnityFramework.framework/Data/Managed/Metadata/global-metadata.dat`,
        `${appPath}/Frameworks/UnityFramework.framework/Data/il2cpp_data/Metadata/global-metadata.dat`,
    ];
}

function applicationPath(modules) {
    for (const module of modules) {
        const marker = module.path.indexOf(APP_SUFFIX);
        if (marker !== -1) return module.path.slice(0, marker + APP_SUFFIX.length - 1);
    }
    if (typeof ObjC !== 'undefined' && ObjC.available && ObjC.classes.NSBundle) {
        return ObjC.classes.NSBundle.mainBundle().bundlePath().toString();
    }
    return null;
}

function loadedModules(request) {
    const wanted = new Set((request && request.modules) || []);
    const all = Process.enumerateModules();
    return all.filter(module => module.path.indexOf(APP_SUFFIX) !== -1)
        .filter(module => module.name === 'UnityFramework' || wanted.size === 0 || wanted.has(module.name) || wanted.has(module.path));
}

function dump(request) {
    const modules = loadedModules(request);
    if (modules.length === 0) throw new Error('no app modules are loaded');
    modules.forEach((module, index) => dumpModule(module, index));

    if (request && request.metadata !== false) {
        const appPath = applicationPath(modules);
        if (appPath !== null) {
            for (const candidate of metadataCandidates(appPath)) {
                const state = { started: false };
                try {
                    dumpFile(candidate, 'global-metadata.dat', 10000, state);
                    break;
                } catch (error) {
                    if (state.started) throw error;
                    // Try the next Unity layout.
                }
            }
        }
    }
    send({ event: 'done', modules: modules.map(module => module.name) });
}

recv('dump', request => {
    const value = request || {};
    const retry = (attempt) => {
        try {
            const modules = loadedModules(value);
            const hasUnity = modules.some(module => module.name === 'UnityFramework');
            const requested = (value.modules || []).length > 0;
            const hasRequested = !requested || (value.modules || []).every(name =>
                modules.some(module => module.name === name || module.path === name));
            if ((!hasUnity || !hasRequested) && attempt < 120) {
                setTimeout(() => retry(attempt + 1), 500);
                return;
            }
            if (!hasUnity) throw new Error('UnityFramework did not load before export timeout');
            if (!hasRequested) throw new Error('one or more requested modules did not load before export timeout');
            dump(value);
        } catch (error) {
            emitError(error);
        }
    };
    retry(0);
});
"""


def _message_payload(message: Mapping[str, Any]) -> Mapping[str, Any] | None:
    payload = message.get("payload")
    return payload if isinstance(payload, Mapping) else None


def dump_from_device(
    device: Any,
    config: Any,
    output_dir: Path,
    *,
    modules: Iterable[str] = (),
    metadata: bool = True,
    timeout_seconds: float = 180.0,
    force: bool = False,
    agent_source: str = FRIDA_DECRYPT_AGENT,
) -> PreparedDump:
    """Dump loaded app images from a Frida device into ``output_dir``."""

    output_dir = Path(output_dir).expanduser().resolve()
    if timeout_seconds <= 0:
        raise DecryptionError("device export timeout must be positive")
    _validate_output_dir(output_dir)
    if output_dir.exists() and any(output_dir.iterdir()) and not force:
        raise DecryptionError(f"output directory is not empty: {output_dir} (use --force to replace files)")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.", dir=output_dir.parent))
    _stage_existing_output(output_dir, staging, force=force)
    writer = _DumpWriter(staging)
    completed = threading.Event()
    detached = threading.Event()
    failure: list[BaseException] = []
    agent_warnings: list[str] = []
    session: Any = None
    script: Any = None
    target: Target | None = None

    def on_message(message: Mapping[str, Any], data: bytes | None) -> None:
        payload = _message_payload(message)
        if payload is None:
            if message.get("type") == "error":
                failure.append(DecryptionError(str(message.get("stack") or message)))
                completed.set()
            return
        try:
            event = payload.get("event")
            if event == "start":
                writer.start(payload)
            elif event == "chunk":
                writer.chunk(payload, data)
            elif event == "end":
                writer.finish(payload)
            elif event == "error":
                failure.append(DecryptionError(str(payload.get("error", "device exporter failed"))))
                completed.set()
            elif event == "warning":
                warning = str(payload.get("warning", "device exporter fallback used"))
                agent_warnings.append(warning)
            elif event == "done":
                completed.set()
        except BaseException as exc:
            failure.append(exc)
            completed.set()

    def on_detached(reason: Any, *_details: Any) -> None:
        detached.set()
        if not completed.is_set():
            failure.append(DecryptionError(f"Frida session detached during export: {reason}"))
            completed.set()

    try:
        target = acquire_target(device, config)
        session = device.attach(target.pid)
        session.on("detached", on_detached)
        script = session.create_script(agent_source, name="openbachelor-ios-decrypt")
        script.on("message", on_message)
        script.load()
        if target.resume_after_load:
            device.resume(target.pid)
        script.post({"type": "dump", "modules": list(modules), "metadata": metadata})
        if not completed.wait(timeout_seconds):
            raise DecryptionError(f"timed out waiting for device export after {timeout_seconds:.0f}s")
        if failure:
            raise failure[0]
        writer.assert_complete()
        if writer.module_path is None:
            raise DecryptionError("device export did not include UnityFramework")
        if writer.metadata_path is not None:
            _validate_metadata_file(writer.metadata_path)
        export_warnings: list[str] = []
        _normalise_exported_modules(writer.modules, export_warnings)
        _install_staging(staging, output_dir, force=force)
        module_path = output_dir / writer.module_path.relative_to(staging)
        metadata_path = (
            output_dir / writer.metadata_path.relative_to(staging)
            if writer.metadata_path is not None
            else None
        )
        modules_out = tuple(output_dir / path.relative_to(staging) for path in writer.modules)
        warnings: list[str] = [*agent_warnings, *export_warnings]
        if metadata and metadata_path is None:
            warnings.append("global-metadata.dat was not found in the running app bundle")
        _write_manifest(output_dir, source=Path("device:" + str(getattr(device, "id", "unknown"))), modules=list(modules_out), warnings=warnings)
        return PreparedDump(output_dir, module_path, metadata_path, None, modules_out, tuple(warnings))
    except Exception:
        writer.close()
        shutil.rmtree(staging, ignore_errors=True)
        raise
    finally:
        if script is not None:
            try:
                script.unload()
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
