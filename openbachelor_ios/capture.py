from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from types import TracebackType
from typing import Any, TextIO
from urllib.parse import parse_qsl, quote, urlsplit

_INLINE_BODY_KEYS = frozenset(
    {
        "body",
        "body_base64",
        "body_text",
        "request_body",
        "response_body",
    }
)
_MISSING_BODY = object()


def _har_headers(value: Any) -> list[dict[str, str]]:
    """Convert a captured header mapping to the HAR header list shape."""

    if isinstance(value, dict):
        items = value.items()
    elif isinstance(value, list):
        items = (
            (item.get("name"), item.get("value"))
            for item in value
            if isinstance(item, dict)
        )
    else:
        return []

    headers: list[dict[str, str]] = []
    for name, header_value in items:
        if not isinstance(name, str) or not name:
            continue
        if header_value is None:
            header_value = ""
        elif not isinstance(header_value, str):
            header_value = str(header_value)
        headers.append({"name": name, "value": header_value})
    return headers


def _header_value(headers: Any, name: str) -> str | None:
    wanted = name.casefold()
    for header in _har_headers(headers):
        if header["name"].casefold() == wanted:
            return header["value"]
    return None


def _mime_type(record: dict[str, Any], headers_key: str) -> str:
    value = _header_value(record.get(headers_key), "content-type")
    if value:
        return value.split(";", 1)[0].strip() or "application/octet-stream"
    return "application/octet-stream"


def _body_path(record: dict[str, Any], output_dir: Path) -> Path | None:
    value = record.get("body_file")
    if not isinstance(value, str) or not value:
        return None
    base = output_dir.resolve()
    root = base.parent if base.name == "bodies" else base
    relative = Path(value)
    # Body paths written by CaptureWriter are relative to output_dir.  Reject
    # absolute and escaping paths even when the JSONL was edited externally.
    if relative.is_absolute():
        return None
    body_root = base if base.name == "bodies" else root / "bodies"
    candidate = (
        (base / relative).resolve()
        if base.name == "bodies" and relative.parts[:1] != (base.name,)
        else (root / relative).resolve()
    )
    try:
        candidate.relative_to(body_root)
    except ValueError:
        return None
    return candidate


def _read_body(record: dict[str, Any], output_dir: Path) -> bytes | None:
    path = _body_path(record, output_dir)
    if path is None or not path.is_file():
        return None
    try:
        return path.read_bytes()
    except OSError:
        return None


def _body_size(record: dict[str, Any], data: bytes | None) -> int:
    value = record.get("body_size")
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    captured = record.get("body_captured_bytes")
    if isinstance(captured, int) and not isinstance(captured, bool) and captured >= 0:
        return captured
    return len(data) if data is not None else 0


def _content_from_bytes(data: bytes | None, size: int, mime_type: str) -> dict[str, Any]:
    content: dict[str, Any] = {"size": size, "mimeType": mime_type}
    if data is None:
        return content
    try:
        text = data.decode("utf-8")
        if any(
            (ord(character) < 32 and character not in "\t\r\n")
            or ord(character) == 127
            for character in text
        ):
            raise UnicodeDecodeError("utf-8", data, 0, 1, "binary control byte")
        content["text"] = text
    except UnicodeDecodeError:
        content["text"] = base64.b64encode(data).decode("ascii")
        content["encoding"] = "base64"
    return content


def _har_content(
    record: dict[str, Any], output_dir: Path, *, mime_type: str | None = None
) -> dict[str, Any]:
    """Build HAR content from a record and its body sidecar."""

    data = _read_body(record, output_dir)
    return _content_from_bytes(
        data,
        _body_size(record, data),
        mime_type or _mime_type(record, "response_headers"),
    )


def _timestamp(record: dict[str, Any], fallback_index: int) -> str:
    value = record.get("timestamp")
    if isinstance(value, str) and value:
        return value
    # Keep generated values deterministic within one export while still being
    # valid HAR startedDateTime values for records without timestamps.
    return datetime.fromtimestamp(
        fallback_index, tz=timezone.utc
    ).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _status(value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        try:
            parsed = int(value)
        except ValueError:
            return 0
        return parsed
    return 0


def _har_request(
    record: dict[str, Any], output_dir: Path, *, method: str, url: str
) -> dict[str, Any]:
    headers = _har_headers(record.get("request_headers"))
    try:
        parsed = urlsplit(url)
        query_string = [
            {"name": name, "value": value}
            for name, value in parse_qsl(parsed.query, keep_blank_values=True)
        ]
    except ValueError:
        query_string = []
    request: dict[str, Any] = {
        "method": method,
        "url": url,
        "httpVersion": "HTTP/1.1",
        "headers": headers,
        "queryString": query_string,
        "cookies": [],
        "headersSize": -1,
        "bodySize": _body_size(record, _read_body(record, output_dir)),
    }
    data = _read_body(record, output_dir)
    if data is not None:
        request["postData"] = {
            "mimeType": _mime_type(record, "request_headers"),
            **_content_from_bytes(
                data,
                _body_size(record, data),
                _mime_type(record, "request_headers"),
            ),
        }
    return request


def _har_response(
    record: dict[str, Any] | None,
    output_dir: Path,
    *,
    data: bytes | None | object = _MISSING_BODY,
    size: int | None = None,
) -> dict[str, Any]:
    record = record or {}
    if data is _MISSING_BODY:
        data = _read_body(record, output_dir)
    content = _content_from_bytes(
        data,
        _body_size(record, data) if size is None else size,
        _mime_type(record, "response_headers"),
    )
    return {
        "status": _status(record.get("response_status")),
        "statusText": "",
        "httpVersion": "HTTP/1.1",
        "headers": _har_headers(record.get("response_headers")),
        "cookies": [],
        "content": content,
        "redirectURL": "",
        "headersSize": -1,
        "bodySize": content["size"],
    }


def _entry_shell(record: dict[str, Any], index: int) -> dict[str, Any]:
    return {
        "startedDateTime": _timestamp(record, index),
        "time": 0,
        "request": {},
        "response": {},
        "cache": {},
        "timings": {"send": 0, "wait": 0, "receive": 0},
    }


def _is_proprietary(record: dict[str, Any]) -> bool:
    protocol = record.get("protocol")
    return record.get("transport") == "TorappuSocketNetwork" or (
        isinstance(protocol, str) and protocol in {"ServerNet", "LongService"}
    )


def _proprietary_entry(record: dict[str, Any], output_dir: Path, index: int) -> dict[str, Any]:
    protocol = str(record.get("protocol") or "Unknown")
    direction = str(record.get("direction") or record.get("phase") or "unknown")
    main_value = record.get("protocol_main_id")
    sub_value = record.get("protocol_sub_id")
    main_id = str(main_value if main_value is not None else "unknown")
    sub_id = str(sub_value if sub_value is not None else "0")
    url = (
        "https://torappu.invalid/socket/"
        f"{quote(protocol, safe='')}/{quote(direction, safe='')}/"
        f"{quote(main_id, safe='')}/{quote(sub_id, safe='')}"
    )
    entry = _entry_shell(record, index)
    entry["request"] = _har_request(
        record if direction == "outbound" else {},
        output_dir,
        method="CUSTOM",
        url=url,
    )
    entry["response"] = _har_response(
        record if direction != "outbound" else {}, output_dir
    )
    if direction == "outbound":
        entry["request"]["postData"] = {
            "mimeType": "application/octet-stream",
            **_har_content(record, output_dir, mime_type="application/octet-stream"),
        }
        entry["request"]["bodySize"] = _body_size(record, _read_body(record, output_dir))
    else:
        entry["response"] = _har_response(
            record, output_dir, data=_read_body(record, output_dir)
        )
    entry["response"]["status"] = _status(record.get("response_status")) or 200
    entry["response"]["statusText"] = "Captured frame"
    entry["_openbachelor"] = {
        "transport": record.get("transport", "TorappuSocketNetwork"),
        "phase": record.get("phase"),
        "direction": record.get("direction"),
        "protocol": record.get("protocol"),
        "protocol_main_id": record.get("protocol_main_id"),
        "protocol_sub_id": record.get("protocol_sub_id"),
        "frame_header_size": record.get("frame_header_size"),
        "frame_size": record.get("frame_size"),
        "payload_size": record.get("payload_size"),
    }
    if record.get("body_truncated") is True:
        entry["_openbachelor_body_truncated"] = True
    return entry


def _http_entry(
    records: list[dict[str, Any]], output_dir: Path, index: int
) -> dict[str, Any]:
    request = next((item for item in records if item.get("phase") == "request"), records[0])
    response = next((item for item in records if item.get("phase") == "response"), None)
    streams = [item for item in records if item.get("phase") == "stream"]
    url = request.get("url") or (response or {}).get("url") or "https://openbachelor.invalid/capture"
    if not isinstance(url, str) or not url:
        url = "https://openbachelor.invalid/capture"
    method = request.get("method", "UNKNOWN")
    if not isinstance(method, str) or not method:
        method = "UNKNOWN"
    entry = _entry_shell(request, index)
    entry["request"] = _har_request(request, output_dir, method=method, url=url)

    if response is None and streams:
        fragment_data = [_read_body(item, output_dir) for item in streams]
        if all(data is not None for data in fragment_data):
            combined = b"".join(data for data in fragment_data if data is not None)
        else:
            combined = None
        declared_size = sum(_body_size(item, data) for item, data in zip(streams, fragment_data))
        response = streams[-1]
        entry["response"] = _har_response(
            response, output_dir, data=combined, size=declared_size
        )
    else:
        entry["response"] = _har_response(response, output_dir)

    entry["_openbachelor"] = {
        "transport": request.get("transport") or (response or {}).get("transport"),
        "request_id": request.get("request_id") or (response or {}).get("request_id"),
        "sources": sorted(
            {
                str(item["source"])
                for item in records
                if isinstance(item.get("source"), str) and item.get("source")
            }
        ),
    }
    if streams:
        entry["_openbachelor_stream_fragments"] = [
            {
                "fragment_index": item.get("fragment_index"),
                "stream_id": item.get("stream_id"),
                "body_size": item.get("body_size"),
                "body_captured_bytes": item.get("body_captured_bytes"),
                "body_sha256": item.get("body_sha256"),
            }
            for item in sorted(
                streams,
                key=lambda value: (
                    value.get("fragment_index")
                    if isinstance(value.get("fragment_index"), int)
                    else 0
                ),
            )
        ]
    if any(item.get("body_truncated") is True for item in records):
        entry["_openbachelor_body_truncated"] = True
    return entry


def export_har(
    records: list[dict[str, Any]], output_dir: Path, path: Path | None = None
) -> Path:
    """Export capture records as a HAR 1.2 file using an atomic replace."""

    output_dir = Path(output_dir)
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    output_dir.chmod(0o700)
    target = Path(path) if path is not None else output_dir / "capture.har"
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    target.parent.chmod(0o700)

    ordered_entries: list[tuple[int, dict[str, Any]]] = []
    groups: dict[tuple[str, str | int], list[dict[str, Any]]] = {}
    group_indexes: dict[tuple[str, str | int], int] = {}
    group_order: list[tuple[str, str | int]] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        if _is_proprietary(record):
            ordered_entries.append((index, _proprietary_entry(record, output_dir, index)))
            continue
        request_id = record.get("request_id")
        if isinstance(request_id, (str, int)) and not isinstance(request_id, bool):
            key = ("request", request_id)
        else:
            key = ("record", index)
        if key not in groups:
            groups[key] = []
            group_indexes[key] = index
            group_order.append(key)
        groups[key].append(record)
    for key in group_order:
        ordered_entries.append(
            (group_indexes[key], _http_entry(groups[key], output_dir, group_indexes[key]))
        )
    entries = [entry for _, entry in sorted(ordered_entries, key=lambda item: item[0])]

    document = {
        "log": {
            "version": "1.2",
            "creator": {"name": "OpenBachelor iOS", "version": "0.1.0"},
            "entries": entries,
        }
    }
    fd, temporary_name = tempfile.mkstemp(
        prefix=".capture-", suffix=".har", dir=target.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(document, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        target.chmod(0o600)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise
    return target


def _display_url(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        if not parsed.scheme or hostname is None:
            return "<url omitted>"
        host = f"[{hostname}]" if ":" in hostname else hostname
        try:
            port = f":{parsed.port}" if parsed.port is not None else ""
        except ValueError:
            return "<url omitted>"
        path = parsed.path or "/"
        if any(ord(character) < 32 or ord(character) == 127 for character in path):
            path = "/<path omitted>"
        elif len(path) > 256:
            path = f"{path[:253]}..."
        return f"{parsed.scheme}://{host}{port}{path}"
    except (TypeError, ValueError):
        return "<url omitted>"


def format_capture_summary(payload: dict[str, Any]) -> str:
    """Return a bounded summary that never includes headers or body contents."""

    parts = ["capture", str(payload.get("phase", "event"))]
    method = payload.get("method")
    if isinstance(method, str) and method:
        parts.append(method)
    display_url = _display_url(payload.get("url"))
    if display_url is not None:
        parts.append(display_url)
    status = payload.get("response_status")
    if isinstance(status, (int, str)) and not isinstance(status, bool):
        parts.append(f"status={status}")
    captured = payload.get("body_captured_bytes")
    size = payload.get("body_size")
    if isinstance(captured, int) and isinstance(size, int):
        parts.append(f"body={captured}/{size}B")
    elif isinstance(size, int):
        parts.append(f"body={size}B")
    if payload.get("body_truncated") is True:
        parts.append("truncated")
    return " ".join(parts)


class CaptureWriter:
    """Persist Frida capture messages without sending raw payloads to stdout."""

    def __init__(
        self,
        output_dir: Path,
        *,
        enabled: bool = True,
        jsonl_name: str = "capture.jsonl",
        har_name: str = "capture.har",
        har_enabled: bool = True,
        log: Callable[[str], None] | None = None,
    ) -> None:
        if Path(jsonl_name).name != jsonl_name:
            raise ValueError("jsonl_name must be a file name, not a path")
        if Path(har_name).name != har_name:
            raise ValueError("har_name must be a file name, not a path")
        self.output_dir = Path(output_dir)
        self.jsonl_path = self.output_dir / jsonl_name
        self.har_path = self.output_dir / har_name
        self.body_dir = self.output_dir / "bodies"
        self.enabled = enabled
        self.har_enabled = har_enabled
        self._log = log
        self._stream: TextIO | None = None
        self._lock = threading.Lock()

    def handle_message(self, message: dict[str, Any], data: bytes | None) -> bool:
        """Handle a capture message and return whether generic logging must skip it.

        Disabled writers still consume capture messages. This is intentional: a
        caller can safely put this check before its generic Frida message logger
        without exposing request headers when capture persistence is turned off.
        """

        payload = message.get("payload")
        if (
            message.get("type") != "send"
            or not isinstance(payload, dict)
            or payload.get("event") != "capture"
        ):
            return False
        if not self.enabled:
            return True

        body = bytes(data) if data is not None else None
        with self._lock:
            record = self._make_record(payload, body)
            stream = self._open_stream()
            stream.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
            stream.write("\n")
            stream.flush()

        if self._log is not None:
            self._log(format_capture_summary(record))
        return True

    def _make_record(
        self, payload: dict[str, Any], body: bytes | None
    ) -> dict[str, Any]:
        record = {
            key: value for key, value in payload.items() if key not in _INLINE_BODY_KEYS
        }
        record["capture_schema"] = 1
        if any(key in payload for key in _INLINE_BODY_KEYS):
            record["inline_body_omitted"] = True
        if body is not None:
            digest = hashlib.sha256(body).hexdigest()
            path = self._write_body(digest, body)
            record["body_file"] = path.relative_to(self.output_dir).as_posix()
            record["body_sha256"] = digest
            record["body_captured_bytes"] = len(body)
        return record

    def _open_stream(self) -> TextIO:
        if self._stream is not None:
            return self._stream
        self.output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.output_dir.chmod(0o700)
        fd = os.open(
            self.jsonl_path,
            os.O_APPEND | os.O_CREAT | os.O_WRONLY,
            0o600,
        )
        os.fchmod(fd, 0o600)
        self._stream = os.fdopen(fd, "a", encoding="utf-8", buffering=1)
        return self._stream

    def _write_body(self, digest: str, body: bytes) -> Path:
        self.body_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.body_dir.chmod(0o700)
        target = self.body_dir / f"{digest}.bin"
        if target.exists():
            if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                raise OSError(f"capture body sidecar is corrupt: {target}")
            target.chmod(0o600)
            return target

        fd, temporary_name = tempfile.mkstemp(prefix=".body-", dir=self.body_dir)
        temporary = Path(temporary_name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(body)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            temporary.unlink(missing_ok=True)
            raise
        return target

    def close(self) -> None:
        with self._lock:
            if self._stream is not None:
                self._stream.close()
                self._stream = None
            if not self.enabled or not self.har_enabled or not self.jsonl_path.exists():
                return
            try:
                records: list[dict[str, Any]] = []
                with self.jsonl_path.open("r", encoding="utf-8") as stream:
                    for line_number, line in enumerate(stream, start=1):
                        if not line.strip():
                            continue
                        try:
                            record = json.loads(line)
                        except json.JSONDecodeError as exc:
                            raise ValueError(
                                f"invalid capture JSONL at line {line_number}: {exc}"
                            ) from exc
                        if isinstance(record, dict):
                            records.append(record)
                export_har(records, self.output_dir, self.har_path)
            except Exception as exc:
                # JSONL and sidecars are the source of truth.  HAR is a
                # convenience export and must not make a capture session lose
                # its primary artifacts.
                if self._log is not None:
                    self._log(f"capture HAR export failed: {exc}")

    def __enter__(self) -> "CaptureWriter":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
