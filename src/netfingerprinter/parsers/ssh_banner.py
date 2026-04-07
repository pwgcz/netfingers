"""Parse SSH version strings (RFC 4253 §4.2)."""

import re
from netfingerprinter.core.result import FingerprintResult, Confidence

_BANNER_RE = re.compile(
    rb"SSH-(?P<proto>[\d.]+)-(?P<software>[^\s\r\n-]+)(?:[-_](?P<version>[^\s\r\n]+))?"
)

# Map software identifiers found in banners to canonical names.
_SOFTWARE_MAP: dict[str, str] = {
    "openssh": "OpenSSH",
    "dropbear": "Dropbear",
    "libssh": "libssh",
    "libssh2": "libssh2",
    "cisco": "Cisco",
    "routeros": "RouterOS",
    "rosssh": "RouterOS",
    "bitvise": "Bitvise",
    "paramiko": "Paramiko",
    "jsch": "JSch",
    "putty": "PuTTY",
    "asyncssh": "AsyncSSH",
    "mobassh": "MobaSSH",
}


def parse_ssh_banner(raw: bytes) -> FingerprintResult:
    """
    Parse a raw SSH banner line into a FingerprintResult.

    Example input:  b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\\r\\n"
    """
    line = raw.strip()
    m = _BANNER_RE.match(line)
    if not m:
        return FingerprintResult(
            host="",
            port=0,
            protocol="ssh",
            banner=line.decode(errors="replace"),
            confidence=Confidence.LOW,
        )

    software_raw = m.group("software").decode(errors="replace")
    version_raw = m.group("version")
    version = version_raw.decode(errors="replace") if version_raw else None

    # Normalise: "OpenSSH_8.9p1" → software="OpenSSH", version="8.9p1"
    if "_" in software_raw and version is None:
        parts = software_raw.split("_", 1)
        software_raw, version = parts[0], parts[1]

    canonical = _SOFTWARE_MAP.get(software_raw.lower(), software_raw)

    banner_str = line.decode(errors="replace")
    return FingerprintResult(
        host="",
        port=0,
        protocol="ssh",
        software=canonical,
        version=version,
        banner=banner_str,
        confidence=Confidence.CONFIRMED,
    )
