import socket
from netfingerprinter.core.connection import Connection
from netfingerprinter.core.result import FingerprintResult
from netfingerprinter.core import registry

# Import probers so their @register decorators fire on import
import netfingerprinter.probers.ssh  # noqa: F401
import netfingerprinter.probers.http  # noqa: F401


class Scanner:
    def __init__(
        self,
        host: str,
        port: int,
        timeout: float = 5.0,
        force_protocol: str | None = None,
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.force_protocol = force_protocol

    def run(self) -> FingerprintResult:
        # Resolve the prober class
        if self.force_protocol:
            prober_cls = registry.get_prober_by_name(self.force_protocol)
            if prober_cls is None:
                return FingerprintResult(
                    host=self.host,
                    port=self.port,
                    protocol=self.force_protocol,
                    error=f"Unknown protocol: {self.force_protocol}",
                )
        else:
            prober_cls = registry.get_prober_for_port(self.port)
            if prober_cls is None:
                return FingerprintResult(
                    host=self.host,
                    port=self.port,
                    protocol="unknown",
                    error=f"No prober registered for port {self.port}",
                )

        conn = Connection(self.host, self.port, self.timeout)
        prober = prober_cls(conn)

        try:
            return prober.probe()
        except ConnectionRefusedError as e:
            return FingerprintResult(
                host=self.host,
                port=self.port,
                protocol=prober_cls.NAME,
                error=f"Connection refused: {e}",
            )
        except TimeoutError as e:
            return FingerprintResult(
                host=self.host,
                port=self.port,
                protocol=prober_cls.NAME,
                error=f"Timeout: {e}",
            )
        except OSError as e:
            return FingerprintResult(
                host=self.host,
                port=self.port,
                protocol=prober_cls.NAME,
                error=str(e),
            )
