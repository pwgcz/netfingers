import json
import pytest
from unittest.mock import patch
from click.testing import CliRunner
from netfingerprinter.cli import cli
from netfingerprinter.core.result import FingerprintResult, Confidence

_SSH_RESULT = FingerprintResult(
    host="10.0.0.1", port=22, protocol="ssh",
    software="OpenSSH", version="8.9p1",
    confidence=Confidence.CONFIRMED,
    ssh_kex_algorithms=["curve25519-sha256"],
    ssh_ciphers=["chacha20-poly1305@openssh.com"],
    ssh_macs=["umac-64-etm@openssh.com"],
    ssh_host_key_algorithms=["ssh-ed25519"],
)

_HTTP_RESULT = FingerprintResult(
    host="example.com", port=80, protocol="http",
    software="nginx", version="1.24.0",
    confidence=Confidence.CONFIRMED,
    http_status=200,
)

_ERROR_RESULT = FingerprintResult(
    host="10.0.0.1", port=22, protocol="ssh",
    error="Connection refused",
)


@pytest.fixture
def runner():
    return CliRunner()


# ── scan command ────────────────────────────────────────────────────────────

@pytest.mark.e2e
def test_scan_json_output(runner):
    with patch("netfingerprinter.core.scanner.Scanner.run", return_value=_SSH_RESULT):
        result = runner.invoke(cli, ["scan", "10.0.0.1", "--port", "22", "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["software"] == "OpenSSH"
    assert data["version"] == "8.9p1"
    assert data["protocol"] == "ssh"


@pytest.mark.e2e
def test_scan_jsonl_output(runner):
    with patch("netfingerprinter.core.scanner.Scanner.run", return_value=_HTTP_RESULT):
        result = runner.invoke(cli, ["scan", "example.com", "--port", "80", "--format", "jsonl"])
    assert result.exit_code == 0
    data = json.loads(result.output.strip())
    assert data["software"] == "nginx"


@pytest.mark.e2e
def test_scan_human_output(runner):
    with patch("netfingerprinter.core.scanner.Scanner.run", return_value=_SSH_RESULT):
        result = runner.invoke(cli, ["scan", "10.0.0.1", "--port", "22", "--no-color"])
    assert result.exit_code == 0
    assert "OpenSSH" in result.output


@pytest.mark.e2e
def test_scan_error_exits_nonzero(runner):
    with patch("netfingerprinter.core.scanner.Scanner.run", return_value=_ERROR_RESULT):
        result = runner.invoke(cli, ["scan", "10.0.0.1", "--port", "22", "--format", "json"])
    assert result.exit_code != 0


@pytest.mark.e2e
def test_scan_force_protocol(runner):
    with patch("netfingerprinter.core.scanner.Scanner.run", return_value=_SSH_RESULT) as mock_run:
        with patch("netfingerprinter.core.scanner.Scanner.__init__", return_value=None) as mock_init:
            mock_init.return_value = None
            # Just verify the flag is accepted
            result = runner.invoke(
                cli, ["scan", "10.0.0.1", "--port", "9999", "--protocol", "ssh",
                      "--format", "json"]
            )
    # Exit code 0 or non-zero is fine; what matters is no parse error
    assert "Error: No such option" not in (result.output or "")


@pytest.mark.e2e
def test_scan_missing_port(runner):
    result = runner.invoke(cli, ["scan", "10.0.0.1"])
    assert result.exit_code != 0
    assert "port" in result.output.lower() or "missing" in result.output.lower()


# ── list-protocols command ───────────────────────────────────────────────────

@pytest.mark.e2e
def test_list_protocols(runner):
    result = runner.invoke(cli, ["list-protocols"])
    assert result.exit_code == 0
    assert "ssh" in result.output.lower()
    assert "http" in result.output.lower()


@pytest.mark.e2e
def test_list_protocols_shows_ports(runner):
    result = runner.invoke(cli, ["list-protocols"])
    assert "22" in result.output
    assert "80" in result.output
