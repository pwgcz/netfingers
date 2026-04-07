import pytest
from netfingerprinter.parsers.ssh_banner import parse_ssh_banner
from netfingerprinter.core.result import Confidence


@pytest.mark.unit
@pytest.mark.parametrize("raw, expected_software, expected_version", [
    (b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n", "OpenSSH", "8.9p1"),
    (b"SSH-2.0-OpenSSH_9.3\r\n", "OpenSSH", "9.3"),
    (b"SSH-2.0-dropbear_2022.83\r\n", "Dropbear", "2022.83"),
    (b"SSH-1.99-Cisco-1.25\r\n", "Cisco", "1.25"),
    (b"SSH-2.0-libssh_0.9.6\r\n", "libssh", "0.9.6"),
    (b"SSH-2.0-ROSSSH\r\n", "RouterOS", None),
    (b"SSH-2.0-AsyncSSH_2.14.2\r\n", "AsyncSSH", "2.14.2"),
    (b"SSH-2.0-Bitvise-8.49\r\n", "Bitvise", "8.49"),
])
def test_ssh_banner_parsing(raw, expected_software, expected_version):
    result = parse_ssh_banner(raw)
    assert result.software == expected_software
    assert result.version == expected_version
    assert result.confidence == Confidence.CONFIRMED
    assert result.protocol == "ssh"


@pytest.mark.unit
def test_invalid_banner_returns_low_confidence():
    result = parse_ssh_banner(b"not an ssh banner\r\n")
    assert result.confidence == Confidence.LOW
    assert result.software is None


@pytest.mark.unit
def test_banner_stored_raw():
    raw = b"SSH-2.0-OpenSSH_8.9p1\r\n"
    result = parse_ssh_banner(raw)
    assert "OpenSSH" in result.banner
