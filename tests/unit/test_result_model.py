import json
import pytest
from netfingerprinter.core.result import FingerprintResult, Confidence


def test_defaults():
    r = FingerprintResult(host="127.0.0.1", port=22, protocol="ssh")
    assert r.software is None
    assert r.version is None
    assert r.confidence == Confidence.LOW
    assert r.ssh_kex_algorithms == []
    assert r.ssh_ciphers == []
    assert r.ssh_macs == []
    assert r.ssh_host_key_algorithms == []
    assert r.http_headers == {}
    assert r.error is None


def test_to_dict_basic():
    r = FingerprintResult(
        host="10.0.0.1",
        port=22,
        protocol="ssh",
        software="OpenSSH",
        version="8.9p1",
        confidence=Confidence.CONFIRMED,
    )
    d = r.to_dict()
    assert d["host"] == "10.0.0.1"
    assert d["port"] == 22
    assert d["protocol"] == "ssh"
    assert d["software"] == "OpenSSH"
    assert d["version"] == "8.9p1"
    assert d["confidence"] == "confirmed"


def test_to_dict_excludes_none_lists_are_present():
    r = FingerprintResult(host="h", port=80, protocol="http")
    d = r.to_dict()
    assert "ssh_kex_algorithms" in d
    assert d["ssh_kex_algorithms"] == []


def test_to_json_is_valid():
    r = FingerprintResult(host="h", port=22, protocol="ssh", software="OpenSSH")
    raw = r.to_json()
    parsed = json.loads(raw)
    assert parsed["software"] == "OpenSSH"


def test_confidence_values():
    assert Confidence.CONFIRMED == "confirmed"
    assert Confidence.HIGH == "high"
    assert Confidence.LOW == "low"


def test_to_dict_with_error():
    r = FingerprintResult(host="h", port=9999, protocol="unknown", error="Connection refused")
    d = r.to_dict()
    assert d["error"] == "Connection refused"
