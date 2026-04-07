import socket
import ssl
from typing import Self


class Connection:
    def __init__(self, host: str, port: int, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: socket.socket | ssl.SSLSocket | None = None

    def connect(self) -> None:
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        raw.settimeout(self.timeout)
        self._sock = raw

    def send(self, data: bytes) -> None:
        assert self._sock is not None, "Not connected"
        self._sock.sendall(data)

    def recv(self, n: int = 4096) -> bytes:
        assert self._sock is not None, "Not connected"
        return self._sock.recv(n)

    def recv_until(self, sentinel: bytes, max_bytes: int = 65536) -> bytes:
        """Read until sentinel bytes are found or max_bytes is reached."""
        assert self._sock is not None, "Not connected"
        buf = b""
        while len(buf) < max_bytes:
            chunk = self._sock.recv(1)
            if not chunk:
                break
            buf += chunk
            if sentinel in buf:
                break
        return buf

    def upgrade_tls(self, server_hostname: str | None = None) -> None:
        """Wrap the existing socket with TLS."""
        assert self._sock is not None, "Not connected"
        ctx = ssl.create_default_context()
        self._sock = ctx.wrap_socket(
            self._sock,
            server_hostname=server_hostname or self.host,
        )

    def tls_info(self) -> dict:
        """Return TLS version and cipher if TLS is active, else empty dict."""
        if not isinstance(self._sock, ssl.SSLSocket):
            return {}
        cipher = self._sock.cipher()
        return {
            "tls_version": self._sock.version(),
            "tls_cipher": cipher[0] if cipher else None,
        }

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args) -> None:
        self.close()
