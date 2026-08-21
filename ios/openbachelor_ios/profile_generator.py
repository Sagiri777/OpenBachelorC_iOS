"""Generate a direct-agent profile from an IL2CPP dump and Mach-O image.

The direct agent uses RVAs into ``UnityFramework``.  Those RVAs cannot be
recovered safely from an app version string alone, so this module deliberately
requires a decrypted Mach-O and an IL2CPP ``script.json``.  The CLI can prepare
that Mach-O with the device exporter in :mod:`openbachelor_ios.decrypt`; this
module itself remains fail-closed and never treats an encrypted image as
plaintext.  Every required method must resolve to exactly one address and
every generated address is validated against the executable ``__text`` section
before a profile is written.
"""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

import lief

from .compiler import PROJECT_ROOT

PROFILES_DIR = PROJECT_ROOT / "profiles"
DEFAULT_REFERENCE_PROFILE = PROFILES_DIR / "arknights-2.7.61-59.json"
PROLOGUE_BYTES = 8


class ProfileGenerationError(ValueError):
    """Raised when a profile cannot be generated with sufficient confidence."""


@dataclass(frozen=True)
class MethodSpec:
    key: str
    name: str
    signature: str


# These names are emitted by Il2CppDumper.  The signature predicate is
# intentional: several Unity/BestHTTP methods are overloaded in the dump.
METHOD_SPECS: tuple[MethodSpec, ...] = (
    MethodSpec(
        "unityWebRequestGet",
        "UnityEngine.Networking.UnityWebRequest$$Get",
        "System_String_o* uri, const MethodInfo* method",
    ),
    MethodSpec(
        "unityWebRequestPostString",
        "UnityEngine.Networking.UnityWebRequest$$Post",
        "System_String_o* uri, System_String_o* postData, const MethodInfo* method",
    ),
    MethodSpec(
        "unityWebRequestCtor",
        "UnityEngine.Networking.UnityWebRequest$$.ctor",
        "System_String_o* url, System_String_o* method, const MethodInfo* method",
    ),
    MethodSpec(
        "unityWebRequestSetUrl",
        "UnityEngine.Networking.UnityWebRequest$$set_url",
        "System_String_o* value, const MethodInfo* method",
    ),
    MethodSpec(
        "unityWebRequestSetMethod",
        "UnityEngine.Networking.UnityWebRequest$$set_method",
        "System_String_o* value, const MethodInfo* method",
    ),
    MethodSpec(
        "unityWebRequestSend",
        "UnityEngine.Networking.UnityWebRequest$$SendWebRequest",
        "UnityEngine_Networking_UnityWebRequest_o* __this, const MethodInfo* method",
    ),
    MethodSpec(
        "unityWebRequestGetResponseCode",
        "UnityEngine.Networking.UnityWebRequest$$get_responseCode",
        "UnityEngine_Networking_UnityWebRequest_o* __this, const MethodInfo* method",
    ),
    MethodSpec(
        "unityWebRequestGetUrl",
        "UnityEngine.Networking.UnityWebRequest$$get_url",
        "UnityEngine_Networking_UnityWebRequest_o* __this, const MethodInfo* method",
    ),
    MethodSpec(
        "unityWebRequestSetRequestHeader",
        "UnityEngine.Networking.UnityWebRequest$$SetRequestHeader",
        "System_String_o* name, System_String_o* value, const MethodInfo* method",
    ),
    MethodSpec(
        "uploadHandlerRawCtorBytes",
        "UnityEngine.Networking.UploadHandlerRaw$$.ctor",
        "System_Byte_array* data, const MethodInfo* method",
    ),
    MethodSpec(
        "downloadHandlerGetData",
        "UnityEngine.Networking.DownloadHandler$$get_data",
        "UnityEngine_Networking_DownloadHandler_o* __this, const MethodInfo* method",
    ),
    MethodSpec(
        "downloadHandlerGetText",
        "UnityEngine.Networking.DownloadHandler$$get_text",
        "UnityEngine_Networking_DownloadHandler_o* __this, const MethodInfo* method",
    ),
    MethodSpec(
        "asyncOperationInvokeCompletionEvent",
        "UnityEngine.AsyncOperation$$InvokeCompletionEvent",
        "UnityEngine_AsyncOperation_o* __this, const MethodInfo* method",
    ),
    MethodSpec(
        "certificateHandlerValidate",
        "UnityEngine.Networking.CertificateHandler$$ValidateCertificate",
        "System_Byte_array* certificateData, const MethodInfo* method",
    ),
    MethodSpec(
        "certificateHandlerValidateNative",
        "UnityEngine.Networking.CertificateHandler$$ValidateCertificateNative",
        "System_Byte_array* certificateData, const MethodInfo* method",
    ),
    MethodSpec(
        "bouncyCastleIsValid",
        "Torappu.Network.Certificate.CertificateHandlerFactory.BouncyCastleCertVerifyer$$IsValid",
        "System_Uri_o* targetUri, Org_BouncyCastle_Asn1_X509_X509CertificateStructure_array* certs, const MethodInfo* method",
    ),
    MethodSpec(
        "cryptUtilsVerifySignMd5RsaString",
        "Torappu.CryptUtils$$VerifySignMD5RSA",
        "System_String_o* content, System_String_o* sign, System_String_o* publicKey, const MethodInfo* method",
    ),
    MethodSpec(
        "rsaCryptoServiceProviderVerifyHashLegacy",
        "System.Security.Cryptography.RSACryptoServiceProvider$$VerifyHash",
        "System_Byte_array* rgbHash, System_String_o* str, System_Byte_array* rgbSignature, const MethodInfo* method",
    ),
    MethodSpec(
        "stringFastAllocate",
        "System.String$$FastAllocateString",
        "int32_t length, const MethodInfo* method",
    ),
    MethodSpec(
        "networkerPostWithBestHttp",
        "Torappu.Network.Networker$$_PostWithBestHttp",
        "System_String_o* url, System_String_o* text, System_Collections_Generic_Dictionary_string__string__o* header, Torappu_Network_WebHttpResponse_o* outResponse, System_Func_bool__o* checkIfCancelled, Torappu_Network_BinaryData_array* binaryDatas, Torappu_Network_Networker_PostRetryContext_o* retryContext, const MethodInfo* method",
    ),
    MethodSpec(
        "networkerGenerateHttpPostRequest",
        "Torappu.Network.Networker$$_GenerateHttpPostRequest",
        "System_String_o* url, System_String_o* text, System_Collections_Generic_Dictionary_string__string__o* header, Torappu_Network_BinaryData_array* binaryDatas, BestHTTP_HTTPResponse_o* response, BestHTTP_HTTPRequest_o** request, const MethodInfo* method",
    ),
    MethodSpec(
        "networkerProcessBestHttpResponse",
        "Torappu.Network.Networker$$_ProcessHttpWebResponse",
        "BestHTTP_HTTPRequest_o* request, BestHTTP_HTTPResponse_o* response, Torappu_Network_WebHttpResponse_o* outResponse, const MethodInfo* method",
    ),
    MethodSpec(
        "bestHttpRequestSend",
        "BestHTTP.HTTPRequest$$Send",
        "BestHTTP_HTTPRequest_o* __this, const MethodInfo* method",
    ),
    MethodSpec(
        "bestHttpRequestDumpHeaders",
        "BestHTTP.HTTPRequest$$DumpHeaders",
        "BestHTTP_HTTPRequest_o* __this, const MethodInfo* method",
    ),
    MethodSpec(
        "bestHttpManagerSendRequest",
        "BestHTTP.HTTPManager$$SendRequest",
        "BestHTTP_HTTPRequest_o* request, const MethodInfo* method",
    ),
    MethodSpec(
        "systemUriCtorString",
        "System.Uri$$.ctor",
        "System_String_o* uriString, const MethodInfo* method",
    ),
    MethodSpec(
        "systemUriGetAbsoluteUri",
        "System.Uri$$get_AbsoluteUri",
        "System_Uri_o* __this, const MethodInfo* method",
    ),
)

DEFAULT_LAYOUT: dict[str, int] = {
    "stringLength": 16,
    "stringChars": 20,
    "arrayLength": 24,
    "arrayData": 32,
    "requestDownloadHandler": 24,
    "requestUploadHandler": 32,
    "asyncOperationWebRequest": 32,
    "bestRequestUri": 16,
    "bestRequestMethod": 24,
    "bestRequestRawData": 32,
    "bestHttpResponseCode": 24,
    "bestHttpResponseData": 72,
    "webHttpResponseText": 40,
    "webHttpResponseData": 48,
}

# dump.cs class/field pairs used to derive the managed object layouts.
LAYOUT_FIELDS: dict[str, tuple[str, str]] = {
    "requestDownloadHandler": ("UnityWebRequest", "m_DownloadHandler"),
    "requestUploadHandler": ("UnityWebRequest", "m_UploadHandler"),
    "asyncOperationWebRequest": ("UnityWebRequestAsyncOperation", "<webRequest>k__BackingField"),
    "bestRequestUri": ("HTTPRequest", "<Uri>k__BackingField"),
    "bestRequestMethod": ("HTTPRequest", "<MethodType>k__BackingField"),
    "bestRequestRawData": ("HTTPRequest", "<RawData>k__BackingField"),
    "bestHttpResponseCode": ("HTTPResponse", "<StatusCode>k__BackingField"),
    "bestHttpResponseData": ("HTTPResponse", "<Data>k__BackingField"),
    "webHttpResponseText": ("WebHttpResponse", "text"),
    "webHttpResponseData": ("WebHttpResponse", "data"),
}


@dataclass(frozen=True)
class MachOInfo:
    binary: Any
    uuid: str
    arch: str
    text_vmaddr: int
    text_size: int
    text_start: int
    text_end: int
    image_base: int
    encrypted: bool
    module_path: Path | None = None
    text_file_offset: int | None = None
    container: Any = None


@dataclass(frozen=True)
class GeneratedProfile:
    data: dict[str, Any]
    warnings: tuple[str, ...]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_uuid(raw: Iterable[int]) -> str:
    values = bytes(int(item) & 0xFF for item in raw)
    if len(values) != 16:
        raise ProfileGenerationError(f"Mach-O UUID has {len(values)} bytes; expected 16")
    hex_value = values.hex().upper()
    return f"{hex_value[:8]}-{hex_value[8:12]}-{hex_value[12:16]}-{hex_value[16:20]}-{hex_value[20:]}"


def _cpu_arch(binary: Any) -> str:
    cpu_type = binary.header.cpu_type
    if cpu_type != lief.MachO.Header.CPU_TYPE.ARM64:
        raise ProfileGenerationError(f"unsupported UnityFramework architecture: {cpu_type}")
    subtype = int(binary.header.cpu_subtype)
    # CPU_SUBTYPE_ARM64E is 2.  LIEF reports some arm64e images as ARM64 with
    # the subtype preserved; keep the distinction when it is available.
    return "arm64e" if (subtype & 0xFF) == 2 else "arm64"


def _select_binary(parsed: Any) -> Any:
    if isinstance(parsed, lief.MachO.Binary):
        return parsed
    if isinstance(parsed, lief.MachO.FatBinary):
        candidates = [
            item
            for item in parsed
            if item.header.cpu_type == lief.MachO.Header.CPU_TYPE.ARM64
        ]
        if len(candidates) != 1:
            raise ProfileGenerationError(
                f"fat Mach-O must contain exactly one arm64 slice; found {len(candidates)}"
            )
        return candidates[0]
    raise ProfileGenerationError("module is not a Mach-O binary")


def _load_macho(path: Path) -> MachOInfo:
    path = Path(path).expanduser().resolve()
    try:
        # MachO.parse preserves a fat container even when the host platform
        # has already selected one native slice.  That lets us reject an
        # ambiguous universal image instead of silently profiling the wrong
        # architecture.
        parsed = lief.MachO.parse(str(path))
    except Exception as exc:  # LIEF exposes several version-specific exception types.
        raise ProfileGenerationError(f"unable to parse Mach-O {path}: {exc}") from exc
    if parsed is None:
        raise ProfileGenerationError(f"unable to parse Mach-O {path}")
    binary = _select_binary(parsed)
    try:
        uuid = _canonical_uuid(binary.uuid.uuid)
    except Exception as exc:
        raise ProfileGenerationError(f"Mach-O UUID is missing or invalid: {exc}") from exc

    segments = list(binary.segments)
    text_segment = next((item for item in segments if item.name == "__TEXT"), None)
    text_section = next(
        (item for item in binary.sections if item.name == "__text" and item.segment_name == "__TEXT"),
        None,
    )
    if text_segment is None or int(text_segment.virtual_size) <= 0:
        raise ProfileGenerationError("Mach-O has no usable __TEXT segment")
    if text_section is None or int(text_section.size) <= 0:
        raise ProfileGenerationError("Mach-O has no usable __TEXT,__text section")

    # Frida's Module.base is the address of __TEXT for a loaded framework.
    # Selecting this segment explicitly avoids treating an optional
    # __PAGEZERO segment as the image base for an executable-shaped input.
    image_base = int(text_segment.virtual_address)
    text_segment_end = image_base + int(text_segment.virtual_size)
    text_start = int(text_section.virtual_address)
    text_end = text_start + int(text_section.size)
    if not (image_base <= text_start < text_end <= text_segment_end):
        raise ProfileGenerationError("__TEXT,__text is outside the __TEXT segment")
    if (int(text_segment.init_protection) & 0x4) == 0:
        raise ProfileGenerationError("__TEXT segment is not executable")
    encryption = getattr(binary, "encryption_info", None)
    encrypted = bool(encryption is not None and int(getattr(encryption, "crypt_id", 0)) != 0)
    if encrypted:
        raise ProfileGenerationError("UnityFramework is encrypted; use a decrypted image")

    return MachOInfo(
        binary=binary,
        uuid=uuid,
        arch=_cpu_arch(binary),
        text_vmaddr=int(text_segment.virtual_address),
        text_size=int(text_segment.virtual_size),
        text_start=text_start,
        text_end=text_end,
        image_base=image_base,
        encrypted=encrypted,
        module_path=path,
        text_file_offset=int(getattr(binary, "fat_offset", 0)) + int(text_section.offset),
        container=parsed,
    )


def _normalise_method_address(raw: Any, info: MachOInfo, key: str) -> tuple[int, int]:
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 0:
        raise ProfileGenerationError(f"method {key} has invalid Address: {raw!r}")

    # Il2CppDumper normally emits a VA relative to the Mach-O image base.  A
    # few dumpers emit an absolute preferred VA, so accept that form only when
    # it is the unique value that lands in __TEXT,__text.
    candidates: list[tuple[int, int]] = []
    for va in (raw, raw + info.image_base, raw - info.image_base):
        if va < info.text_start or va >= info.text_end or va % 4:
            continue
        rva = va - info.image_base
        if rva < 0:
            continue
        candidates.append((va, rva))
    unique = {(va, rva) for va, rva in candidates}
    if len(unique) != 1:
        raise ProfileGenerationError(
            f"method {key} address 0x{raw:x} does not resolve uniquely inside __TEXT,__text"
        )
    return next(iter(unique))


def _read_prologue(info: MachOInfo, va: int, key: str, length: int = PROLOGUE_BYTES) -> str:
    if va < info.text_start or va + length > info.text_end:
        raise ProfileGenerationError(
            f"prologue for {key} at 0x{va:x} crosses __TEXT,__text"
        )
    if info.module_path is not None and info.text_file_offset is not None:
        offset = info.text_file_offset + (va - info.text_start)
        try:
            with info.module_path.open("rb") as stream:
                stream.seek(offset)
                value = stream.read(length)
        except OSError as exc:
            raise ProfileGenerationError(
                f"unable to read prologue for {key} at file offset 0x{offset:x}: {exc}"
            ) from exc
        if len(value) != length:
            raise ProfileGenerationError(f"short prologue for {key}: {len(value)} bytes")
        return value.hex()
    try:
        raw = info.binary.get_content_from_virtual_address(va, length)
        value = bytes(raw)
    except Exception as exc:
        raise ProfileGenerationError(f"unable to read prologue for {key} at 0x{va:x}: {exc}") from exc
    if len(value) != length:
        raise ProfileGenerationError(f"short prologue for {key}: {len(value)} bytes")
    return value.hex()


def _load_reference(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    path = Path(path).expanduser().resolve()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ProfileGenerationError(f"reference profile not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ProfileGenerationError(f"invalid reference profile {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ProfileGenerationError("reference profile root must be an object")
    return value


def _script_methods(path: Path) -> Iterator[dict[str, Any]]:
    """Yield only ScriptMethod entries without materialising other dump arrays."""

    # The dump is large (the current script.json is over 200 MiB).  Locate the
    # top-level ScriptMethod array first, then decode its objects one at a time.
    path = Path(path).expanduser().resolve()
    decoder = json.JSONDecoder()
    with path.open("r", encoding="utf-8") as stream:
        buffer = ""
        found = False
        while not found:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            buffer += chunk
            match = re.search(r'"ScriptMethod"\s*:\s*', buffer)
            if match:
                buffer = buffer[match.end() :]
                found = True
                break
            # Keep enough tail for a key split across chunk boundaries.
            buffer = buffer[-64:]
        if not found:
            raise ProfileGenerationError(f"script dump has no ScriptMethod array: {path}")

        def fill() -> bool:
            nonlocal buffer
            chunk = stream.read(1024 * 1024)
            if chunk:
                buffer += chunk
                return True
            return False

        while True:
            buffer = buffer.lstrip()
            if not buffer:
                if not fill():
                    raise ProfileGenerationError("unexpected EOF in ScriptMethod array")
                continue
            if buffer[0] != "[":
                raise ProfileGenerationError("ScriptMethod is not a JSON array")
            buffer = buffer[1:]
            break

        while True:
            buffer = buffer.lstrip()
            if not buffer:
                if not fill():
                    raise ProfileGenerationError("unexpected EOF in ScriptMethod array")
                continue
            if buffer[0] == "]":
                return
            try:
                value, consumed = decoder.raw_decode(buffer)
            except json.JSONDecodeError:
                if not fill():
                    raise ProfileGenerationError("invalid JSON in ScriptMethod array")
                continue
            if not isinstance(value, dict):
                raise ProfileGenerationError("ScriptMethod entry is not an object")
            yield value
            buffer = buffer[consumed:]
            while True:
                buffer = buffer.lstrip()
                if buffer:
                    break
                if not fill():
                    raise ProfileGenerationError("unexpected EOF after ScriptMethod entry")
            if buffer[0] == ",":
                buffer = buffer[1:]
                continue
            if buffer[0] == "]":
                return
            raise ProfileGenerationError("invalid separator in ScriptMethod array")


def _resolve_methods(path: Path, info: MachOInfo) -> dict[str, tuple[int, str, str]]:
    wanted = {spec.name: spec for spec in METHOD_SPECS}
    matches: dict[str, list[dict[str, Any]]] = {spec.key: [] for spec in METHOD_SPECS}
    for method in _script_methods(path):
        name = method.get("Name")
        if not isinstance(name, str) or name not in wanted:
            continue
        spec = wanted[name]
        signature = method.get("Signature")
        if not isinstance(signature, str):
            continue
        # Compare the complete parameter list, rather than a loose substring,
        # so a future overload with an additional trailing argument cannot be
        # mistaken for the hook we intend to install.
        opening = signature.find("(")
        closing = signature.rfind(")")
        if opening < 0 or closing < opening:
            continue
        parameters = " ".join(signature[opening + 1 : closing].split())
        expected = " ".join(spec.signature.split())
        # Il2CppDumper includes the implicit object pointer for instance
        # methods, while the profile specification intentionally describes
        # only the explicit managed arguments.  Accept that one well-defined
        # prefix, but keep the remaining parameter list exact.
        implicit_this = re.match(r"[^,]+\* __this, (.+)$", parameters)
        if parameters != expected and (
            implicit_this is None or implicit_this.group(1) != expected
        ):
            continue
        matches[spec.key].append(method)

    unresolved: list[str] = []
    resolved: dict[str, tuple[int, str, str]] = {}
    for spec in METHOD_SPECS:
        candidates = matches[spec.key]
        if len(candidates) != 1:
            unresolved.append(
                f"{spec.key} ({spec.name}): {len(candidates)} matching methods"
            )
            continue
        raw_address = candidates[0].get("Address")
        va, rva = _normalise_method_address(raw_address, info, spec.key)
        resolved[spec.key] = (rva, spec.name, str(candidates[0].get("Signature", "")))
        # Force a read now so a bad VA cannot make it into a profile.
        _read_prologue(info, va, spec.key)
    if unresolved:
        raise ProfileGenerationError("unresolved hook methods:\n- " + "\n- ".join(unresolved))
    return resolved


def _class_blocks(text: str, class_name: str) -> Iterator[str]:
    pattern = re.compile(rf"\bclass\s+{re.escape(class_name)}(?=\s|:|\{{)")
    cursor = 0
    while True:
        match = pattern.search(text, cursor)
        if match is None:
            return
        opening = text.find("{", match.end())
        if opening < 0:
            return
        depth = 0
        in_string = False
        escaped = False
        for index in range(opening, len(text)):
            char = text[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    yield text[opening + 1 : index]
                    cursor = index + 1
                    break
        else:
            return


def _class_block(text: str, class_name: str) -> str | None:
    """Return the first class block for compatibility with older callers."""

    return next(_class_blocks(text, class_name), None)


def _field_offset(block: str, field: str) -> int | None:
    pattern = re.compile(
        rf"^\s*(?:[^\n;]+\s+)?{re.escape(field)}\s*;\s*//\s*0x([0-9A-Fa-f]+)\s*$",
        re.MULTILINE,
    )
    match = pattern.search(block)
    return int(match.group(1), 16) if match else None


def _layout_from_dump(path: Path) -> tuple[dict[str, int], list[str]]:
    path = Path(path).expanduser().resolve()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ProfileGenerationError(f"unable to read dump.cs {path}: {exc}") from exc
    layout: dict[str, int] = {
        "stringLength": 16,
        "stringChars": 20,
        "arrayLength": 24,
        "arrayData": 32,
    }
    missing: list[str] = []
    for key, (class_name, field) in LAYOUT_FIELDS.items():
        values = {
            value
            for block in _class_blocks(text, class_name)
            if (value := _field_offset(block, field)) is not None
        }
        if not values:
            missing.append(key)
        elif len(values) > 1:
            rendered = ", ".join(f"0x{value:x}" for value in sorted(values))
            raise ProfileGenerationError(
                f"ambiguous layout for {class_name}.{field}: {rendered}"
            )
        else:
            layout[key] = values.pop()
    return layout, missing


def _find_info_plists(module: Path) -> list[Path]:
    module = Path(module).expanduser().resolve()
    result: list[Path] = []
    for parent in (module.parent, *module.parents):
        if parent.name.endswith(".app"):
            candidate = parent / "Info.plist"
            if candidate.is_file():
                result.append(candidate)
            break
    return result


def _identity_from_plist(module: Path) -> dict[str, str]:
    # Prefer the application plist over the framework plist.  Framework
    # plists often carry a different CFBundleIdentifier.
    candidates = _find_info_plists(module)
    candidates.sort(key=lambda item: (0 if item.parent.name.endswith(".app") else 1, len(item.parts)))
    for path in candidates:
        try:
            raw = plistlib.loads(path.read_bytes())
        except Exception:
            continue
        if not isinstance(raw, dict):
            continue
        result: dict[str, str] = {}
        for out, key in (
            ("bundle_id", "CFBundleIdentifier"),
            ("version", "CFBundleShortVersionString"),
            ("build", "CFBundleVersion"),
            ("unity_version", "Unity-Version"),
        ):
            value = raw.get(key)
            if value is not None and str(value).strip():
                result[out] = str(value).strip()
        if result:
            return result
    return {}


def _metadata_info(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    path = Path(path).expanduser().resolve()
    try:
        with path.open("rb") as stream:
            header = stream.read(8)
    except OSError as exc:
        raise ProfileGenerationError(f"unable to read metadata {path}: {exc}") from exc
    if len(header) < 8 or int.from_bytes(header[:4], "little") != 0xFAB11BAF:
        raise ProfileGenerationError(f"invalid global-metadata.dat header: {path}")
    return {
        "version": int.from_bytes(header[4:8], "little"),
        "sha256": _sha256(path),
    }


def _safe_identifier(value: str, name: str) -> str:
    value = value.strip()
    if not value or "/" in value or "\\" in value or "\n" in value or "\r" in value:
        raise ProfileGenerationError(f"{name} must be a non-empty path-safe string")
    return value


def _infer_dump_path(module: Path, dump_dir: Path | None, name: str) -> Path | None:
    roots = [dump_dir] if dump_dir is not None else []
    roots.extend([module.parent, module.parent / "il2cppdumper", module.parent.parent / "il2cppdumper"])
    for root in roots:
        if root is None:
            continue
        candidate = root / name
        if candidate.is_file():
            return candidate
    return None


def generate_profile(
    module_path: Path,
    *,
    script_json: Path | None = None,
    dump_cs: Path | None = None,
    metadata: Path | None = None,
    dump_dir: Path | None = None,
    bundle_id: str | None = None,
    version: str | None = None,
    build: str | None = None,
    profile_id: str | None = None,
    unity_version: str | None = None,
    reference_profile: Path | None = DEFAULT_REFERENCE_PROFILE,
    allow_layout_fallback: bool = False,
) -> GeneratedProfile:
    module_path = Path(module_path).expanduser().resolve()
    if dump_dir is not None:
        dump_dir = Path(dump_dir).expanduser().resolve()
    if not module_path.is_file():
        raise ProfileGenerationError(f"UnityFramework file not found: {module_path}")
    info = _load_macho(module_path)

    if script_json is not None:
        script_path = Path(script_json).expanduser().resolve()
        if not script_path.is_file():
            raise ProfileGenerationError(f"script.json not found: {script_path}")
    else:
        script_path = _infer_dump_path(module_path, dump_dir, "script.json")
    if script_path is None:
        raise ProfileGenerationError(
            "script.json is required; pass --script-json or --dump-dir pointing to an IL2CPP dump"
        )
    script_path = Path(script_path).expanduser().resolve()
    resolved = _resolve_methods(script_path, info)

    if dump_cs is not None:
        dump_path = Path(dump_cs).expanduser().resolve()
        if not dump_path.is_file():
            raise ProfileGenerationError(f"dump.cs not found: {dump_path}")
    else:
        dump_path = _infer_dump_path(module_path, dump_dir, "dump.cs")
    warnings: list[str] = []
    if dump_path is not None and dump_path.is_file():
        layout, missing_layout = _layout_from_dump(Path(dump_path).expanduser().resolve())
    else:
        layout, missing_layout = {}, list(LAYOUT_FIELDS)
    if missing_layout and not allow_layout_fallback:
        source = str(dump_path) if dump_path is not None else "not found"
        raise ProfileGenerationError(
            "dump.cs did not provide all required managed layouts "
            f"({source}); missing: {', '.join(missing_layout)}. "
            "Pass --allow-layout-fallback only after verifying the new build uses the old layouts."
        )
    if missing_layout:
        if reference_profile is None:
            raise ProfileGenerationError(
                "layout fallback requires --reference-profile with a verified layout"
            )
        reference = _load_reference(Path(reference_profile))
        reference_layout = reference.get("layout")
        if not isinstance(reference_layout, dict):
            raise ProfileGenerationError(
                "reference profile has no usable layout for fallback"
            )
        invalid = [
            key
            for key in missing_layout
            if (
                key not in reference_layout
                or isinstance(reference_layout[key], bool)
                or not isinstance(reference_layout[key], int)
                or reference_layout[key] < 0
            )
        ]
        if invalid:
            raise ProfileGenerationError(
                "reference profile is missing verified layouts: "
                + ", ".join(invalid)
            )
        for key in missing_layout:
            layout[key] = reference_layout[key]
            warnings.append(f"layout {key} inherited from reference profile")
    # Ensure the fixed managed object header fields are always present.
    for key in ("stringLength", "stringChars", "arrayLength", "arrayData"):
        layout[key] = int(layout.get(key, DEFAULT_LAYOUT[key]))

    identity = _identity_from_plist(module_path)
    values = {
        "bundle_id": bundle_id or identity.get("bundle_id"),
        "version": version or identity.get("version"),
        "build": build or identity.get("build"),
    }
    missing_identity = [key for key, value in values.items() if not value]
    if missing_identity:
        raise ProfileGenerationError(
            "missing app identity (pass --bundle-id, --version and --build; "
            f"missing: {', '.join(missing_identity)})"
        )
    for key in values:
        values[key] = _safe_identifier(str(values[key]), key)
    generated_id = profile_id
    if not generated_id:
        suffix = values["bundle_id"].rsplit(".", 1)[-1]
        generated_id = f"{suffix}-{values['version']}-{values['build']}"
    generated_id = _safe_identifier(str(generated_id), "id")

    if metadata is not None:
        metadata_path = Path(metadata).expanduser().resolve()
    else:
        metadata_path = _infer_dump_path(module_path, dump_dir, "global-metadata.dat")
    metadata_data = _metadata_info(metadata_path)
    if not metadata_data:
        warnings.append("global-metadata.dat was not supplied; metadata identity is omitted")

    offsets = {key: hex(value[0]) for key, value in resolved.items()}
    prologues = {
        key: _read_prologue(info, value[0] + info.image_base, key)
        for key, value in resolved.items()
    }
    method_names = {key: value[1] for key, value in resolved.items()}
    resolved_unity_version = unity_version or identity.get("unity_version")
    if not resolved_unity_version:
        resolved_unity_version = "unknown"
        warnings.append("Unity version was not supplied; unity_version is set to unknown")
    data: dict[str, Any] = {
        "schema": 1,
        "id": generated_id,
        "bundle_id": values["bundle_id"],
        "version": values["version"],
        "build": values["build"],
        "arch": info.arch,
        "unity_version": resolved_unity_version,
        "module": {
            "name": "UnityFramework",
            "uuid": info.uuid,
            "sha256": _sha256(module_path),
            "text_vmaddr": hex(info.text_vmaddr),
            "text_size": hex(info.text_size),
        },
        "metadata": metadata_data,
        "offsets": offsets,
        "prologues": prologues,
        "layout": {key: int(value) for key, value in sorted(layout.items())},
        "generator": {
            "method_names": method_names,
            "script_json_sha256": _sha256(script_path),
            "prologue_bytes": PROLOGUE_BYTES,
        },
    }
    return GeneratedProfile(data=data, warnings=tuple(dict.fromkeys(warnings)))


def write_profile(path: Path, data: dict[str, Any], *, force: bool = False) -> None:
    path = Path(path).expanduser().resolve()
    if path.exists() and not force:
        raise ProfileGenerationError(f"profile already exists: {path} (use --force to replace it)")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary_path: Path | None = Path(temporary)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fchmod(stream.fileno(), 0o600)
        if force:
            os.replace(temporary, path)
        else:
            # A hard-link create is the POSIX no-clobber primitive.  The
            # initial exists() check is only a fast path; this closes the
            # race where another process creates the destination meanwhile.
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise ProfileGenerationError(
                    f"profile already exists: {path} (use --force to replace it)"
                ) from exc
            os.unlink(temporary)
        temporary_path = None
    except Exception:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
        raise
