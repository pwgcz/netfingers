from netfingerprinter.core import registry
from netfingerprinter.core.result import FingerprintResult
from netfingerprinter.parsers.ssh_banner import parse_ssh_banner
from netfingerprinter.parsers.ssh_kex import parse_ssh_kex_init
from netfingerprinter.probers.base import BaseProber

_OUR_BANNER = b"SSH-2.0-NetFingerprinter_1.0\r\n"


@registry.register("ssh", [22])
class SSHProber(BaseProber):
    NAME = "ssh"
    DEFAULT_PORTS = [22]

    def probe(self) -> FingerprintResult:
        with self.conn:
            self.conn.connect()

            # 1. Read the server's version banner
            raw_banner = self.conn.recv_until(b"\n", max_bytes=256)

            # 2. Parse banner
            result = parse_ssh_banner(raw_banner)
            result.host = self.conn.host
            result.port = self.conn.port

            # 3. Send our banner to trigger KEX_INIT
            self.conn.send(_OUR_BANNER)

            # 4. Read KEX_INIT packet
            kex_raw = self.conn.recv(4096)
            kex_info = parse_ssh_kex_init(kex_raw)

            result.ssh_kex_algorithms = kex_info.kex_algorithms
            result.ssh_host_key_algorithms = kex_info.host_key_algorithms
            result.ssh_ciphers = kex_info.ciphers_c2s
            result.ssh_macs = kex_info.macs_c2s

        return result

    @staticmethod
    def can_handle_banner(banner: bytes) -> bool:
        return banner.startswith(b"SSH-")
