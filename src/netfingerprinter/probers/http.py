from netfingerprinter.core import registry
from netfingerprinter.core.result import FingerprintResult, Confidence
from netfingerprinter.parsers.http_response import parse_http_response
from netfingerprinter.probers.base import BaseProber

_HEAD_REQUEST = b"HEAD / HTTP/1.0\r\nConnection: close\r\n\r\n"


@registry.register("http", [80, 8080, 8000])
class HTTPProber(BaseProber):
    NAME = "http"
    DEFAULT_PORTS = [80, 8080, 8000]

    def __init__(self, connection, tls: bool = False):
        super().__init__(connection)
        self.tls = tls

    def probe(self) -> FingerprintResult:
        protocol = "https" if self.tls else "http"

        with self.conn:
            self.conn.connect()

            if self.tls:
                self.conn.upgrade_tls()

            self.conn.send(_HEAD_REQUEST)

            # Read up to 8 KB — enough for headers
            raw = self.conn.recv(8192)

        info = parse_http_response(raw)
        tls_meta = self.conn.tls_info()

        confidence = Confidence.CONFIRMED if info.software else Confidence.LOW

        result = FingerprintResult(
            host=self.conn.host,
            port=self.conn.port,
            protocol=protocol,
            software=info.software,
            version=info.version,
            confidence=confidence,
            http_status=info.status,
            http_headers=info.headers,
            tls_version=tls_meta.get("tls_version"),
            tls_cipher=tls_meta.get("tls_cipher"),
        )
        return result

    @staticmethod
    def can_handle_banner(banner: bytes) -> bool:
        return banner.startswith(b"HTTP/")


@registry.register("https", [443, 8443])
class HTTPSProber(HTTPProber):
    NAME = "https"
    DEFAULT_PORTS = [443, 8443]

    def __init__(self, connection):
        super().__init__(connection, tls=True)
