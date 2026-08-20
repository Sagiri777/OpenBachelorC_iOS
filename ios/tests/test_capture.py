import hashlib
import json
import stat

from openbachelor_ios.capture import CaptureWriter, format_capture_summary


def test_capture_message_writes_jsonl_and_body_sidecar_without_logging_secrets(
    tmp_path,
):
    messages: list[str] = []
    body = b"response secret that must not reach the terminal"
    payload = {
        "event": "capture",
        "phase": "request",
        "request_id": "ios-1",
        "timestamp": "2026-08-19T10:00:00.000Z",
        "method": "POST",
        "url": "https://user:password@example.test/online/v2/syncData?token=query-secret",
        "request_headers": {
            "Authorization": "Bearer header-secret",
            "Cookie": "session=cookie-secret",
        },
        "body_size": len(body),
        "body_truncated": False,
    }
    writer = CaptureWriter(tmp_path / "custom-output", log=messages.append)

    assert writer.handle_message({"type": "send", "payload": payload}, body) is True
    writer.close()

    record = json.loads(writer.jsonl_path.read_text(encoding="utf-8"))
    digest = hashlib.sha256(body).hexdigest()
    assert record["request_headers"] == payload["request_headers"]
    assert record["body_file"] == f"bodies/{digest}.bin"
    assert record["body_sha256"] == digest
    assert record["body_captured_bytes"] == len(body)
    assert (writer.output_dir / record["body_file"]).read_bytes() == body
    assert stat.S_IMODE(writer.jsonl_path.stat().st_mode) == 0o600
    assert stat.S_IMODE((writer.output_dir / record["body_file"]).stat().st_mode) == 0o600

    terminal_output = "\n".join(messages)
    assert "https://example.test/online/v2/syncData" in terminal_output
    for secret in ("password", "query-secret", "header-secret", "cookie-secret"):
        assert secret not in terminal_output
    assert body.decode() not in terminal_output


def test_disabled_writer_consumes_capture_without_creating_output(tmp_path):
    output_dir = tmp_path / "disabled"
    writer = CaptureWriter(output_dir, enabled=False)

    handled = writer.handle_message(
        {
            "type": "send",
            "payload": {
                "event": "capture",
                "request_headers": {"Authorization": "Bearer secret"},
            },
        },
        b"large-or-sensitive-body",
    )

    assert handled is True
    assert not output_dir.exists()


def test_non_capture_message_is_left_for_the_generic_handler(tmp_path):
    writer = CaptureWriter(tmp_path)

    assert (
        writer.handle_message(
            {"type": "send", "payload": {"event": "direct-ready"}}, None
        )
        is False
    )
    assert not tmp_path.joinpath("capture.jsonl").exists()


def test_inline_body_fields_are_never_written_to_jsonl(tmp_path):
    writer = CaptureWriter(tmp_path)
    secret = "x" * 100_000

    assert writer.handle_message(
        {
            "type": "send",
            "payload": {
                "event": "capture",
                "phase": "response",
                "response_body": secret,
            },
        },
        None,
    )
    writer.close()

    record = json.loads(writer.jsonl_path.read_text(encoding="utf-8"))
    assert "response_body" not in record
    assert record["inline_body_omitted"] is True
    assert secret not in writer.jsonl_path.read_text(encoding="utf-8")


def test_summary_omits_malformed_or_credential_bearing_url_parts():
    summary = format_capture_summary(
        {
            "phase": "response",
            "url": "https://name:secret@example.test/path?api_key=hidden#fragment",
            "response_status": 200,
            "body_size": 10,
            "body_captured_bytes": 4,
            "body_truncated": True,
        }
    )

    assert summary == (
        "capture response https://example.test/path status=200 body=4/10B truncated"
    )
    assert "secret" not in summary
    assert "hidden" not in summary


def test_summary_bounds_untrusted_url_path():
    summary = format_capture_summary(
        {"phase": "request", "url": f"https://example.test/{'x' * 10_000}"}
    )

    assert len(summary) < 320
    assert summary.endswith("...")


def test_writer_tightens_existing_output_permissions(tmp_path):
    output_dir = tmp_path / "capture"
    body_dir = output_dir / "bodies"
    body_dir.mkdir(parents=True)
    output_dir.chmod(0o755)
    body_dir.chmod(0o755)

    writer = CaptureWriter(output_dir)
    writer.handle_message(
        {"type": "send", "payload": {"event": "capture", "phase": "request"}},
        b"body",
    )
    writer.close()

    body_path = next(body_dir.iterdir())
    assert stat.S_IMODE(output_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(body_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(body_path.stat().st_mode) == 0o600
