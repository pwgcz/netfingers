from abc import ABC, abstractmethod
from netfingerprinter.core.result import FingerprintResult


class BaseProber(ABC):
    NAME: str = ""
    DEFAULT_PORTS: list[int] = []

    def __init__(self, connection):
        self.conn = connection

    @abstractmethod
    def probe(self) -> FingerprintResult:
        """Perform the protocol handshake and return a structured result."""
        ...

    def can_handle(self, banner: bytes) -> bool:
        """Fast-path check: can this prober handle the given opening bytes?"""
        return False
