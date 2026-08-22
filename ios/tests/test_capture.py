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
    assert writer.har_path.exists()
    assert stat.S_IMODE(writer.har_path.stat().st_mode) == 0o600

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


def test_summary_handles_protocol_frame_without_url_or_body_contents():
    secret = "protocol-payload-secret"
    summary = format_capture_summary(
        {
            "phase": "receive",
            "transport": "TorappuSocketNetwork",
            "protocol": "LongService",
            "protocol_main_id": 7,
            "protocol_sub_id": "18446744073709551615",
            "body_size": len(secret),
            "body_captured_bytes": len(secret),
            "body": secret,
        }
    )

    assert summary == f"capture receive body={len(secret)}/{len(secret)}B"
    assert secret not in summary


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


def test_close_automatically_exports_http_request_and_response_to_har(tmp_path):
    output_dir = tmp_path / "capture"
    writer = CaptureWriter(output_dir)
    writer.handle_message(
        {
            "type": "send",
            "payload": {
                "event": "capture",
                "phase": "request",
                "request_id": "req-1",
                "timestamp": "2026-08-22T00:00:00.000Z",
                "transport": "BestHTTP",
                "method": "POST",
                "url": "https://example.test/api?a=1",
                "request_headers": {"Content-Type": "application/json"},
                "body_size": 7,
            },
        },
        b'{"x":1}',
    )
    writer.handle_message(
        {
            "type": "send",
            "payload": {
                "event": "capture",
                "phase": "response",
                "request_id": "req-1",
                "timestamp": "2026-08-22T00:00:01.000Z",
                "transport": "BestHTTP",
                "url": "https://example.test/api?a=1",
                "response_status": 201,
                "response_headers": {"Content-Type": "application/octet-stream"},
                "body_size": 2,
            },
        },
        b"\x00\xff",
    )
    writer.close()

    document = json.loads(writer.har_path.read_text(encoding="utf-8"))
    assert document["log"]["version"] == "1.2"
    assert len(document["log"]["entries"]) == 1
    entry = document["log"]["entries"][0]
    assert entry["request"]["method"] == "POST"
    assert entry["request"]["queryString"] == [{"name": "a", "value": "1"}]
    assert entry["request"]["postData"]["text"] == '{"x":1}'
    assert entry["response"]["status"] == 201
    assert entry["response"]["content"]["encoding"] == "base64"
    assert entry["response"]["content"]["text"] == "AP8="


def test_har_preserves_stream_fragments_and_synthesizes_proprietary_frames(tmp_path):
    output_dir = tmp_path / "capture"
    writer = CaptureWriter(output_dir)
    for index, fragment in enumerate((b"part-1", b"part-2")):
        writer.handle_message(
            {
                "type": "send",
                "payload": {
                    "event": "capture",
                    "phase": "stream",
                    "request_id": "stream-1",
                    "stream_id": "stream-1:response",
                    "fragment_index": index,
                    "transport": "BestHTTP",
                    "url": "https://example.test/stream",
                    "body_size": len(fragment),
                },
            },
            fragment,
        )
    writer.handle_message(
        {
            "type": "send",
            "payload": {
                "event": "capture",
                "phase": "receive",
                "direction": "inbound",
                "transport": "TorappuSocketNetwork",
                "protocol": "LongService",
                "protocol_main_id": 8,
                "protocol_sub_id": "783518950194493",
                "frame_header_size": 16,
                "frame_size": 20,
                "payload_size": 4,
                "body_size": 4,
            },
        },
        b"\x01\x02\x03\x04",
    )
    writer.close()

    entries = json.loads(writer.har_path.read_text(encoding="utf-8"))["log"]["entries"]
    assert len(entries) == 2
    stream_entry = entries[0]
    assert stream_entry["response"]["content"]["text"] == "part-1part-2"
    assert [
        item["fragment_index"] for item in stream_entry["_openbachelor_stream_fragments"]
    ] == [0, 1]
    protocol_entry = entries[1]
    assert protocol_entry["request"]["url"] == (
        "https://torappu.invalid/socket/LongService/inbound/8/783518950194493"
    )
    assert protocol_entry["_openbachelor"]["protocol"] == "LongService"
    assert protocol_entry["response"]["content"]["encoding"] == "base64"


def test_har_export_can_be_disabled_without_affecting_jsonl(tmp_path):
    writer = CaptureWriter(tmp_path / "capture", har_enabled=False)
    writer.handle_message(
        {"type": "send", "payload": {"event": "capture", "phase": "request"}},
        b"body",
    )
    writer.close()

    assert writer.jsonl_path.exists()
    assert not writer.har_path.exists()
