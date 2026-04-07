import struct
import pytest
from netfingerprinter.probers.ssh import SSHProber
from netfingerprinter.core.result import Confidence


def _name_list(names: list[str]) -> bytes:
    encoded = ",".join(names).encode("ascii")
    return struct.pack(">I", len(encoded)) + encoded


def build_kex_packet(kex=None, hk=None, ciphers=None, macs=None) -> bytes:
    kex = kex or ["curve25519-sha256", "diffie-hellman-group14-sha256"]
    hk = hk or ["ecdsa-sha2-nistp256", "ssh-ed25519"]
    ciphers = ciphers or ["chacha20-poly1305@openssh.com", "aes128-ctr"]
    macs = macs or ["umac-64-etm@openssh.com", "hmac-sha2-256"]

    payload = (
        bytes([20]) + b"\x00" * 16
        + _name_list(kex)
        + _name_list(hk)
        + _name_list(ciphers)
        + _name_list(ciphers)
        + _name_list(macs)
        + _name_list(macs)
        + _name_list(["none"])
        + _name_list(["none"])
        + _name_list([]) + _name_list([])
        + b"\x00" + b"\x00\x00\x00\x00"
    )
    pl = 8 - ((len(payload) + 1) % 8)
    if pl < 4:
        pl += 8
    pkt_len = 1 + len(payload) + pl
    return struct.pack(">I", pkt_len) + bytes([pl]) + payload + b"\x00" * pl


BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
KEX_PACKET = build_kex_packet()


@pytest.mark.integration
def test_ssh_prober_software_and_version(fake_conn):
    conn = fake_conn([BANNER, KEX_PACKET])
    result = SSHProber(conn).probe()
    assert result.software == "OpenSSH"
    assert result.version == "8.9p1"
    assert result.confidence == Confidence.CONFIRMED


@pytest.mark.integration
def test_ssh_prober_kex_algorithms(fake_conn):
    conn = fake_conn([BANNER, KEX_PACKET])
    result = SSHProber(conn).probe()
    assert "curve25519-sha256" in result.ssh_kex_algorithms


@pytest.mark.integration
def test_ssh_prober_ciphers(fake_conn):
    conn = fake_conn([BANNER, KEX_PACKET])
    result = SSHProber(conn).probe()
    assert "chacha20-poly1305@openssh.com" in result.ssh_ciphers


@pytest.mark.integration
def test_ssh_prober_macs(fake_conn):
    conn = fake_conn([BANNER, KEX_PACKET])
    result = SSHProber(conn).probe()
    assert "umac-64-etm@openssh.com" in result.ssh_macs


@pytest.mark.integration
def test_ssh_prober_host_key_algorithms(fake_conn):
    conn = fake_conn([BANNER, KEX_PACKET])
    result = SSHProber(conn).probe()
    assert "ssh-ed25519" in result.ssh_host_key_algorithms


@pytest.mark.integration
def test_ssh_prober_sends_our_banner(fake_conn):
    conn = fake_conn([BANNER, KEX_PACKET])
    SSHProber(conn).probe()
    assert any(b"SSH-2.0-NetFingerprinter" in sent for sent in conn.sent)


@pytest.mark.integration
def test_ssh_prober_dropbear(fake_conn):
    banner = b"SSH-2.0-dropbear_2022.83\r\n"
    conn = fake_conn([banner, KEX_PACKET])
    result = SSHProber(conn).probe()
    assert result.software == "Dropbear"
    assert result.version == "2022.83"


@pytest.mark.integration
def test_ssh_prober_host_and_port_set(fake_conn):
    conn = fake_conn([BANNER, KEX_PACKET])
    conn.host = "192.168.1.1"
    conn.port = 22
    result = SSHProber(conn).probe()
    assert result.host == "192.168.1.1"
    assert result.port == 22


@pytest.mark.integration
def test_ssh_prober_can_handle():
    assert SSHProber.can_handle_banner(b"SSH-2.0-OpenSSH") is True
    assert SSHProber.can_handle_banner(b"220 ESMTP") is False
