from pathlib import Path
from threading import Event
from types import SimpleNamespace

from openbachelor_ios import runner
from openbachelor_ios.config import load_config
from openbachelor_ios.profiles import DirectProfile


class FakeScript:
    def __init__(self, name, events):
        self.name = name
        self.events = events
        self.messages = []
        self.message_handler = None

    def on(self, event, handler):
        assert event == "message"
        self.message_handler = handler

    def load(self):
        self.events.append((self.name, "load"))

    def post(self, message):
        self.events.append((self.name, "post"))
        self.messages.append(message)

    def unload(self):
        self.events.append((self.name, "unload"))


class FakeSession:
    def __init__(self):
        self.events = []
        self.scripts = {}
        self.detached_handler = None

    def on(self, event, handler):
        assert event == "detached"
        self.detached_handler = handler

    def create_script(self, source, name):
        script_name = name.removeprefix("openbachelor-ios-")
        script = FakeScript(script_name, self.events)
        self.scripts[script_name] = script
        return script

    def detach(self):
        self.events.append(("session", "detach"))


class FakeDevice:
    def __init__(self):
        self.application = SimpleNamespace(
            identifier="com.hypergryph.arknights",
            name="Arknights",
            pid=42,
            parameters={"version": "2.7.61", "build": "59"},
        )
        self.session = FakeSession()

    def enumerate_applications(self, scope=None):
        return [self.application]

    def enumerate_processes(self):
        return []

    def attach(self, pid):
        assert pid == 42
        return self.session


def test_direct_run_loads_only_probe_and_direct_and_posts_init(monkeypatch, tmp_path):
    config = load_config(Path("config.example.json"))
    profile_data = {
        "schema": 1,
        "id": "arknights-2.7.61-59",
        "bundle_id": config.bundle_id,
        "version": "2.7.61",
        "build": "59",
    }
    profile = DirectProfile(tmp_path / "profile.json", profile_data)
    outputs = {}
    for name in ("probe", "direct"):
        path = tmp_path / f"{name}.js"
        path.write_text(f"// {name}", encoding="utf-8")
        outputs[name] = path

    compiled = []

    class SpyCaptureWriter:
        instances = []

        def __init__(self, output_dir, *, enabled, log):
            self.output_dir = output_dir
            self.enabled = enabled
            self.log = log
            self.closed = False
            self.instances.append(self)

        def handle_message(self, message, data):
            return False

        def close(self):
            self.closed = True

    def fake_compile(names):
        compiled.append(names)
        return {name: outputs[name] for name in names}

    monkeypatch.setattr(runner, "select_profile", lambda *_args, **_kwargs: profile)
    monkeypatch.setattr(runner, "compile_scripts", fake_compile)
    monkeypatch.setattr(runner, "CaptureWriter", SpyCaptureWriter)
    monkeypatch.setattr(runner, "_wait_for_session", lambda _event: None)
    device = FakeDevice()

    runner.run(device, config, profile="auto")

    assert compiled == [("probe", "direct")]
    assert set(device.session.scripts) == {"probe", "direct"}
    direct = device.session.scripts["direct"]
    agent_config = {
        key: value
        for key, value in config.direct.items()
        if key != "capture_output_dir"
    }
    assert direct.messages == [
        {"type": "init", "profile": profile_data, "config": agent_config}
    ]
    assert "capture_output_dir" not in direct.messages[0]["config"]
    assert config.direct["capture"] is False
    assert device.session.events.index(("direct", "load")) < device.session.events.index(
        ("direct", "post")
    )
    assert device.session.detached_handler is not None
    writer = SpyCaptureWriter.instances[0]
    assert writer.output_dir == runner.PROJECT_ROOT / "captured"
    assert writer.enabled is False
    assert writer.closed is True


def test_session_detached_handler_releases_wait(capsys):
    detached = Event()

    runner._session_detached_handler(detached)("process-terminated")

    assert detached.is_set()
    assert "session detached: process-terminated" in capsys.readouterr().out


def test_message_handler_lets_capture_writer_consume_sensitive_payload(capsys):
    calls = []

    class ConsumingWriter:
        def handle_message(self, message, data):
            calls.append((message, data))
            return True

    message = {
        "type": "send",
        "payload": {
            "event": "capture",
            "request_headers": {"Authorization": "secret"},
        },
    }

    runner._message_handler("direct", ConsumingWriter())(message, b"secret-body")

    assert calls == [(message, b"secret-body")]
    assert capsys.readouterr().out == ""
