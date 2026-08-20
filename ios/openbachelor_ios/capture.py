from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path
from types import TracebackType
from typing import Any, TextIO
from urllib.parse import urlsplit

_INLINE_BODY_KEYS = frozenset(
    {
        "body",
        "body_base64",
        "body_text",
        "request_body",
        "response_body",
    }
)


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
        log: Callable[[str], None] | None = None,
    ) -> None:
        if Path(jsonl_name).name != jsonl_name:
            raise ValueError("jsonl_name must be a file name, not a path")
        self.output_dir = Path(output_dir)
        self.jsonl_path = self.output_dir / jsonl_name
        self.body_dir = self.output_dir / "bodies"
        self.enabled = enabled
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

    def __enter__(self) -> "CaptureWriter":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
