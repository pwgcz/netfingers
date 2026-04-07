import pytest
from netfingerprinter.core import registry as reg
from netfingerprinter.probers.base import BaseProber
from netfingerprinter.core.result import FingerprintResult


# --- helpers ---

def _make_prober(name: str, ports: list[int]) -> type[BaseProber]:
    """Dynamically create and register a dummy prober for test isolation."""

    class DummyProber(BaseProber):
        NAME = name
        DEFAULT_PORTS = ports

        def probe(self) -> FingerprintResult:
            return FingerprintResult(host="", port=0, protocol=name)

    reg.register(name, ports)(DummyProber)
    return DummyProber


# --- tests ---

def test_register_and_get_by_name():
    cls = _make_prober("test_proto_a", [19999])
    assert reg.get_prober_by_name("test_proto_a") is cls


def test_get_prober_for_port():
    cls = _make_prober("test_proto_b", [29999])
    assert reg.get_prober_for_port(29999) is cls


def test_get_prober_by_name_unknown_returns_none():
    assert reg.get_prober_by_name("does_not_exist") is None


def test_get_prober_for_port_unknown_returns_none():
    assert reg.get_prober_for_port(65000) is None


def test_all_probers_contains_registered():
    cls = _make_prober("test_proto_c", [39999])
    assert cls in reg.all_probers()
