# netfingerprinter

> Actively fingerprint network services by performing minimal protocol handshakes and extracting structured identity information - software name, version, supported algorithms, and server configuration.

Think of it as what Wireshark does **passively** in a capture, but done **actively and programmatically** against a target host, with clean structured output you can pipe into other tools.

---

## What it does

Connect to a host on a specific port → send the smallest possible valid protocol message → parse the response → emit a structured fingerprint.

```
$ netfingerprinter scan 192.168.1.1 --port 22

╭─ 192.168.1.1:22 ─────────────────────────────────────────────────────╮
│  Protocol    SSH                                                     │
│  Software    OpenSSH  8.9p1                                          │
│  Confidence  confirmed                                               │
│  Banner      SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6                 │
│  KEX         curve25519-sha256, diffie-hellman-group14-sha256        │
│  Ciphers     chacha20-poly1305@openssh.com, aes128-ctr               │
│  MACs        umac-64-etm@openssh.com, hmac-sha2-256                  │
│  Host Keys   ecdsa-sha2-nistp256, ssh-ed25519                        │
╰──────────────────────────────────────────────────────────────────────╯
```

```
$ netfingerprinter scan example.com --port 443 --protocol https --format json

{
  "host": "example.com",
  "port": 443,
  "protocol": "https",
  "software": "nginx",
  "version": "1.24.0",
  "confidence": "confirmed",
  "tls_version": "TLSv1.3",
  "tls_cipher": "TLS_AES_256_GCM_SHA384",
  "http_status": 200,
  "http_headers": { "server": "nginx/1.24.0", ... }
}
```

---

## Supported protocols

| Protocol | Default Ports | Method | What you get |
|----------|--------------|--------|-------------|
| **SSH** | 22 | RFC 4253 banner + `SSH_MSG_KEXINIT` | Software, version, KEX algorithms, ciphers, MACs, host-key types |
| **HTTP** | 80, 8080, 8000 | `HEAD /` request | Software, version, response headers |
| **HTTPS** | 443, 8443 | TLS handshake + `HEAD /` | All of HTTP + TLS version, cipher suite |

---

## Installation

Requires Python ≥ 3.12 and [uv](https://github.com/astral-sh/uv).

```shell
# Clone and install in a virtual environment
git clone https://github.com/pwgcz/netfingerprinter
cd netfingerprinter
uv sync

# Or install as a global tool
uv tool install .
```

---

## Usage

### Fingerprint a single host

```shell
# SSH on default port
netfingerprinter scan 192.168.1.1 --port 22

# HTTP server
netfingerprinter scan example.com --port 80

# HTTPS - performs TLS handshake first
netfingerprinter scan example.com --port 443 --protocol https

# Force a specific prober even on a non-standard port
netfingerprinter scan 10.0.0.5 --port 2222 --protocol ssh
```

### Output formats

```shell
# Human-readable (default) - uses Rich for colour, degrades gracefully when piped
netfingerprinter scan host --port 22

# JSON - pretty-printed, suitable for scripting
netfingerprinter scan host --port 22 --format json

# JSON Lines - one object per line, ideal for streaming pipelines
netfingerprinter scan host --port 22 --format jsonl | jq '.ssh_kex_algorithms[]'
```

### All options

```
netfingerprinter scan HOST --port PORT
  --protocol, -P    Force a specific prober: ssh | http | https
  --format,   -f    Output format: human | json | jsonl  [default: human]
  --timeout,  -t    Connection timeout in seconds        [default: 5.0]
  --no-color        Disable colour output
  --help

netfingerprinter list-protocols   List all registered probers and their ports
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Connection error / refused |
| `2` | Timeout |
| `3` | Unknown or unsupported protocol |

---

## Architecture

The project is split into four layers, each with a single responsibility:

```
src/netfingerprinter/
├── core/
│   ├── connection.py   # Raw TCP socket + optional TLS upgrade (stdlib ssl)
│   ├── registry.py     # @register decorator - maps ports/names → prober classes
│   ├── result.py       # FingerprintResult dataclass + Confidence enum
│   └── scanner.py      # Orchestrates prober selection and error handling
├── parsers/            # Pure functions - no I/O, fully unit-testable
│   ├── ssh_banner.py   # Regex parser for RFC 4253 §4.2 version strings
│   ├── ssh_kex.py      # Binary parser for SSH_MSG_KEXINIT (struct.unpack)
│   └── http_response.py
├── probers/            # Protocol-specific handshake logic
│   ├── base.py         # BaseProber ABC
│   ├── ssh.py          # SSHProber - banner + KEX_INIT exchange
│   └── http.py         # HTTPProber / HTTPSProber
└── output/
    └── formatter.py    # Rich human output + JSON/JSONL rendering
```

### Adding a new protocol

1. Create `src/netfingerprinter/parsers/myproto.py` with pure parsing functions.
2. Write unit tests for the parser against real captured bytes.
3. Create `src/netfingerprinter/probers/myproto.py`:

```python
from netfingerprinter.core import registry
from netfingerprinter.probers.base import BaseProber

@registry.register("myproto", [1234])
class MyProtoProber(BaseProber):
    NAME = "myproto"
    DEFAULT_PORTS = [1234]

    def probe(self) -> FingerprintResult:
        with self.conn:
            self.conn.connect()
            self.conn.send(b"HELLO\r\n")
            raw = self.conn.recv()
        return parse_myproto_response(raw)
```

4. Import the prober in `core/scanner.py` so the decorator fires.

---

## Technical notes

- **SSH KEX_INIT parsing** is implemented with `struct.unpack` directly against RFC 4253 §7.1 - no `paramiko` or `cryptography` dependency. The tool only needs to read the public handshake, not establish a full session.
- **TLS** uses the Python stdlib `ssl` module - sufficient to extract protocol version, cipher suite, and certificate chain without pulling in `pyopenssl`.
- **Zero mandatory external runtime dependencies** beyond `click` (CLI) and `rich` (output). All protocol parsing uses the standard library.
- **Extensible by design** - new protocols self-register via a decorator; the scanner needs no modification.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `click` | CLI framework |
| `rich` | Coloured terminal output, degrades gracefully when piped |

