import json
from dataclasses import dataclass, field
from enum import Enum


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    LOW = "low"


@dataclass
class FingerprintResult:
    host: str
    port: int
    protocol: str
    software: str | None = None
    version: str | None = None
    banner: str | None = None
    confidence: Confidence = Confidence.LOW
    # SSH-specific
    ssh_kex_algorithms: list[str] = field(default_factory=list)
    ssh_host_key_algorithms: list[str] = field(default_factory=list)
    ssh_ciphers: list[str] = field(default_factory=list)
    ssh_macs: list[str] = field(default_factory=list)
    # HTTP-specific
    http_headers: dict[str, str] = field(default_factory=dict)
    http_status: int | None = None
    tls_version: str | None = None
    tls_cipher: str | None = None
    # Generic
    metadata: dict = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "software": self.software,
            "version": self.version,
            "banner": self.banner,
            "confidence": self.confidence.value,
            "ssh_kex_algorithms": self.ssh_kex_algorithms,
            "ssh_host_key_algorithms": self.ssh_host_key_algorithms,
            "ssh_ciphers": self.ssh_ciphers,
            "ssh_macs": self.ssh_macs,
            "http_headers": self.http_headers,
            "http_status": self.http_status,
            "tls_version": self.tls_version,
            "tls_cipher": self.tls_cipher,
            "metadata": self.metadata,
            "error": self.error,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
