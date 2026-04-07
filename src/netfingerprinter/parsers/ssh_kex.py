"""Parse SSH_MSG_KEXINIT packets (RFC 4253 §7.1)."""

import struct
from dataclasses import dataclass, field

MSG_KEXINIT = 20


@dataclass
class SSHKexInfo:
    kex_algorithms: list[str] = field(default_factory=list)
    host_key_algorithms: list[str] = field(default_factory=list)
    ciphers_c2s: list[str] = field(default_factory=list)
    ciphers_s2c: list[str] = field(default_factory=list)
    macs_c2s: list[str] = field(default_factory=list)
    macs_s2c: list[str] = field(default_factory=list)
    compression_c2s: list[str] = field(default_factory=list)
    compression_s2c: list[str] = field(default_factory=list)


def _read_name_list(data: bytes, offset: int) -> tuple[list[str], int]:
    """Read a uint32-prefixed comma-separated name-list at *offset*."""
    if offset + 4 > len(data):
        return [], offset
    (length,) = struct.unpack_from(">I", data, offset)
    offset += 4
    if offset + length > len(data):
        return [], offset
    raw = data[offset : offset + length]
    offset += length
    names = raw.decode("ascii", errors="replace").split(",") if raw else []
    return names, offset


def parse_ssh_kex_init(raw: bytes) -> SSHKexInfo:
    """
    Parse the SSH binary packet carrying SSH_MSG_KEXINIT.

    The packet format (RFC 4253 §6):
      4 bytes  packet_length
      1 byte   padding_length
      payload  (packet_length - padding_length - 1 bytes)
      padding

    KEXINIT payload (RFC 4253 §7.1):
      1 byte   msg type (20)
      16 bytes cookie
      10 × name-list fields
      1 byte   first_kex_packet_follows
      4 bytes  reserved (0)
    """
    info = SSHKexInfo()
    if len(raw) < 6:
        return info

    # Skip the binary-packet framing
    (packet_length,) = struct.unpack_from(">I", raw, 0)
    padding_length = raw[4]
    payload_start = 5
    payload_end = 4 + packet_length - padding_length
    payload = raw[payload_start:payload_end]

    if not payload or payload[0] != MSG_KEXINIT:
        return info

    # Skip msg type (1) + cookie (16)
    offset = 17

    info.kex_algorithms, offset = _read_name_list(payload, offset)
    info.host_key_algorithms, offset = _read_name_list(payload, offset)
    info.ciphers_c2s, offset = _read_name_list(payload, offset)
    info.ciphers_s2c, offset = _read_name_list(payload, offset)
    info.macs_c2s, offset = _read_name_list(payload, offset)
    info.macs_s2c, offset = _read_name_list(payload, offset)
    info.compression_c2s, offset = _read_name_list(payload, offset)
    info.compression_s2c, offset = _read_name_list(payload, offset)

    return info
