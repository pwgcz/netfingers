import pytest
from unittest.mock import patch, MagicMock
from netfingerprinter.core.scanner import Scanner
from netfingerprinter.core.result import FingerprintResult, Confidence

_SSH_RESULT = FingerprintResult(
    host="10.0.0.1", port=22, protocol="ssh",
    software="OpenSSH", version="8.9p1", confidence=Confidence.CONFIRMED,
)
_HTTP_RESULT = FingerprintResult(
    host="10.0.0.1", port=80, protocol="http",
    software="nginx", version="1.24.0", confidence=Confidence.CONFIRMED,
)


@pytest.mark.integration
def test_scanner_selects_ssh_for_port_22(fake_conn):
    with patch("netfingerprinter.core.scanner.Connection") as MockConn:
        MockConn.return_value = fake_conn([])
        with patch("netfingerprinter.probers.ssh.SSHProber.probe", return_value=_SSH_RESULT):
            result = Scanner("10.0.0.1", 22).run()
    assert result.protocol == "ssh"
    assert result.software == "OpenSSH"


@pytest.mark.integration
def test_scanner_selects_http_for_port_80(fake_conn):
    with patch("netfingerprinter.core.scanner.Connection") as MockConn:
        MockConn.return_value = fake_conn([])
        with patch("netfingerprinter.probers.http.HTTPProber.probe", return_value=_HTTP_RESULT):
            result = Scanner("10.0.0.1", 80).run()
    assert result.protocol == "http"


@pytest.mark.integration
def test_scanner_force_protocol(fake_conn):
    with patch("netfingerprinter.core.scanner.Connection") as MockConn:
        MockConn.return_value = fake_conn([])
        with patch("netfingerprinter.probers.ssh.SSHProber.probe", return_value=_SSH_RESULT):
            result = Scanner("10.0.0.1", 9999, force_protocol="ssh").run()
    assert result.protocol == "ssh"


@pytest.mark.integration
def test_scanner_unknown_port_returns_error():
    with patch("netfingerprinter.core.scanner.Connection") as MockConn:
        MockConn.return_value.__enter__ = lambda s: s
        MockConn.return_value.__exit__ = MagicMock(return_value=False)
        result = Scanner("10.0.0.1", 65001).run()
    assert result.error is not None


@pytest.mark.integration
def test_scanner_connection_error_returns_error():
    with patch("netfingerprinter.core.scanner.Connection") as MockConn:
        instance = MockConn.return_value
        instance.connect.side_effect = ConnectionRefusedError("refused")
        # Also need probe to call connect
        with patch("netfingerprinter.probers.ssh.SSHProber.probe", side_effect=ConnectionRefusedError("refused")):
            result = Scanner("10.0.0.1", 22).run()
    assert result.error is not None
    assert result.software is None
