import struct
import pytest
from netfingerprinter.parsers.ssh_kex import parse_ssh_kex_init, SSHKexInfo


def _name_list(names: list[str]) -> bytes:
    encoded = ",".join(names).encode("ascii")
    return struct.pack(">I", len(encoded)) + encoded


def build_kex_init_packet(
    kex_algorithms: list[str],
    host_key_algorithms: list[str],
    ciphers_c2s: list[str],
    ciphers_s2c: list[str],
    macs_c2s: list[str],
    macs_s2c: list[str],
    compression_c2s: list[str] | None = None,
    compression_s2c: list[str] | None = None,
) -> bytes:
    """Build a minimal SSH_MSG_KEXINIT binary packet for testing."""
    if compression_c2s is None:
        compression_c2s = ["none"]
    if compression_s2c is None:
        compression_s2c = ["none"]

    payload = (
        bytes([20])            # SSH_MSG_KEXINIT
        + b"\x00" * 16        # cookie
        + _name_list(kex_algorithms)
        + _name_list(host_key_algorithms)
        + _name_list(ciphers_c2s)
        + _name_list(ciphers_s2c)
        + _name_list(macs_c2s)
        + _name_list(macs_s2c)
        + _name_list(compression_c2s)
        + _name_list(compression_s2c)
        + _name_list([])       # languages_c2s
        + _name_list([])       # languages_s2c
        + b"\x00"              # first_kex_packet_follows
        + b"\x00\x00\x00\x00" # reserved
    )
    padding_length = 8 - ((len(payload) + 1) % 8)
    if padding_length < 4:
        padding_length += 8
    packet_length = 1 + len(payload) + padding_length
    return (
        struct.pack(">I", packet_length)
        + bytes([padding_length])
        + payload
        + b"\x00" * padding_length
    )


KEX_ALGOS = ["curve25519-sha256", "diffie-hellman-group14-sha256"]
HOST_KEY_ALGOS = ["ecdsa-sha2-nistp256", "ssh-ed25519"]
CIPHERS = ["chacha20-poly1305@openssh.com", "aes128-ctr"]
MACS = ["umac-64-etm@openssh.com", "hmac-sha2-256"]

SAMPLE_PACKET = build_kex_init_packet(
    kex_algorithms=KEX_ALGOS,
    host_key_algorithms=HOST_KEY_ALGOS,
    ciphers_c2s=CIPHERS,
    ciphers_s2c=CIPHERS,
    macs_c2s=MACS,
    macs_s2c=MACS,
)


@pytest.mark.unit
def test_kex_algorithms_parsed():
    info = parse_ssh_kex_init(SAMPLE_PACKET)
    assert info.kex_algorithms == KEX_ALGOS


@pytest.mark.unit
def test_host_key_algorithms_parsed():
    info = parse_ssh_kex_init(SAMPLE_PACKET)
    assert info.host_key_algorithms == HOST_KEY_ALGOS


@pytest.mark.unit
def test_ciphers_parsed():
    info = parse_ssh_kex_init(SAMPLE_PACKET)
    assert info.ciphers_c2s == CIPHERS
    assert info.ciphers_s2c == CIPHERS


@pytest.mark.unit
def test_macs_parsed():
    info = parse_ssh_kex_init(SAMPLE_PACKET)
    assert info.macs_c2s == MACS
    assert info.macs_s2c == MACS


@pytest.mark.unit
def test_empty_bytes_returns_empty_info():
    info = parse_ssh_kex_init(b"")
    assert isinstance(info, SSHKexInfo)
    assert info.kex_algorithms == []


@pytest.mark.unit
def test_wrong_message_type_returns_empty():
    # Build packet with msg type 21 instead of 20
    bad = SAMPLE_PACKET[:5] + bytes([21]) + SAMPLE_PACKET[6:]
    info = parse_ssh_kex_init(bad)
    assert info.kex_algorithms == []
