from dataclasses import dataclass
from pathlib import Path

from openbachelor_ios.config import load_config
from openbachelor_ios.device import acquire_target, describe_device


@dataclass
class FakeApplication:
    identifier: str
    name: str
    pid: int
    parameters: dict[str, str] | None = None


@dataclass
class FakeProcess:
    name: str
    pid: int


class FakeDevice:
    id = "usb-1"
    name = "Test iPhone"
    type = "usb"

    def __init__(self, applications=(), processes=()):
        self.applications = list(applications)
        self.processes = list(processes)
        self.spawned = []
        self.application_scopes = []

    def enumerate_applications(self, scope=None):
        self.application_scopes.append(scope)
        return self.applications

    def enumerate_processes(self):
        return self.processes

    def spawn(self, argv):
        self.spawned.append(argv)
        return 1234


def config():
    return load_config(Path("config.example.json"))


def test_jailbreak_spawn_uses_bundle_id():
    device = FakeDevice()
    target = acquire_target(device, config().with_overrides(spawn=True))

    assert target.pid == 1234
    assert target.spawned is True
    assert target.resume_after_load is True
    assert device.spawned == [["com.hypergryph.arknights"]]


def test_gadget_attach_selects_gadget_process():
    gadget_config = config().with_overrides(mode="gadget", spawn=False)
    device = FakeDevice(processes=[FakeProcess("Gadget", 55)])

    target = acquire_target(device, gadget_config)

    assert target.pid == 55
    assert target.resume_after_load is True


def test_doctor_reports_installed_app():
    device = FakeDevice(
        applications=[
            FakeApplication(
                "com.hypergryph.arknights",
                "Arknights",
                99,
                {"version": "2.7.61", "build": "59"},
            )
        ]
    )

    report = describe_device(device, config())

    assert report["device"]["name"] == "Test iPhone"
    assert report["target"]["installed"] is True
    assert report["target"]["pid"] == 99
    assert report["target"]["version"] == "2.7.61"
    assert report["target"]["build"] == "59"
    assert device.application_scopes == ["full"]


def test_legacy_application_enumerator_without_scope_is_supported():
    class LegacyFakeDevice(FakeDevice):
        def enumerate_applications(self):
            return self.applications

    device = LegacyFakeDevice(
        applications=[
            FakeApplication("com.hypergryph.arknights", "Arknights", 99)
        ]
    )

    report = describe_device(device, config())

    assert report["target"]["installed"] is True
    assert report["target"]["version"] is None
    assert report["target"]["build"] is None
