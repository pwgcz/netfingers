import pytest


class FakeConnection:
    """
    Simulates a Connection by replaying pre-recorded byte sequences.

    Pass a list of bytes objects; each recv() / recv_until() call consumes
    the next item. Calls to send() are recorded in `.sent`.
    """

    def __init__(self, responses: list[bytes]):
        self._responses = list(responses)
        self._index = 0
        self.sent: list[bytes] = []
        self.host = "fake-host"
        self.port = 0
        self._tls_info: dict = {}

    def connect(self) -> None:
        pass

    def send(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, n: int = 4096) -> bytes:
        if self._index >= len(self._responses):
            return b""
        data = self._responses[self._index]
        self._index += 1
        return data

    def recv_until(self, sentinel: bytes, max_bytes: int = 65536) -> bytes:
        return self.recv()

    def upgrade_tls(self, server_hostname: str | None = None) -> None:
        self._tls_info = {
            "tls_version": "TLSv1.3",
            "tls_cipher": "TLS_AES_256_GCM_SHA384",
        }

    def tls_info(self) -> dict:
        return self._tls_info

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args) -> None:
        self.close()


@pytest.fixture
def fake_conn():
    """Factory fixture: fake_conn([bytes, bytes, ...]) → FakeConnection."""
    def _factory(responses: list[bytes]) -> FakeConnection:
        return FakeConnection(responses)
    return _factory
