"""Parse HTTP/1.x response headers."""

import re
from dataclasses import dataclass, field

_STATUS_RE = re.compile(r"HTTP/[\d.]+ (\d{3})")

# Maps header names (lower-case) to (software_hint, version_regex) for
# extracting software identity from header values.
_SOFTWARE_HEADERS: list[tuple[str, re.Pattern]] = [
    ("server", re.compile(r"^(?P<sw>[^/\s(]+)(?:/(?P<ver>[^\s(]+))?")),
    ("x-powered-by", re.compile(r"^(?P<sw>[^/\s(]+)(?:/(?P<ver>[^\s(]+))?")),
    ("x-aspnet-version", re.compile(r"^(?P<ver>.+)$")),
    ("x-aspnetmvc-version", re.compile(r"^(?P<ver>.+)$")),
]


@dataclass
class HTTPResponseInfo:
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    software: str | None = None
    version: str | None = None


def parse_http_response(raw: bytes) -> HTTPResponseInfo:
    """
    Parse a raw HTTP response (status line + headers).

    Accepts both \\r\\n and \\n line endings.
    """
    info = HTTPResponseInfo()

    try:
        text = raw.decode("latin-1")
    except Exception:
        return info

    lines = text.replace("\r\n", "\n").split("\n")
    if not lines:
        return info

    # Status line
    m = _STATUS_RE.match(lines[0])
    if m:
        info.status = int(m.group(1))

    # Headers
    for line in lines[1:]:
        if not line.strip():
            break  # end of headers
        if ":" in line:
            name, _, value = line.partition(":")
            info.headers[name.strip().lower()] = value.strip()

    # Software detection
    for header_name, pattern in _SOFTWARE_HEADERS:
        value = info.headers.get(header_name)
        if not value:
            continue
        m = pattern.match(value)
        if not m:
            continue
        groups = m.groupdict()
        if "sw" in groups and groups["sw"] and info.software is None:
            info.software = groups["sw"]
        if "ver" in groups and groups["ver"] and info.version is None:
            info.version = groups["ver"]
        # x-aspnet-version has no sw group — label it explicitly
        if header_name == "x-aspnet-version" and info.software is None:
            info.software = "ASP.NET"

    return info
