import pytest
from netfingerprinter.probers.http import HTTPProber
from netfingerprinter.core.result import Confidence

NGINX_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: nginx/1.24.0\r\n"
    b"Content-Type: text/html\r\n"
    b"\r\n"
)

APACHE_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: Apache/2.4.54 (Ubuntu)\r\n"
    b"\r\n"
)

IIS_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: Microsoft-IIS/10.0\r\n"
    b"X-Powered-By: ASP.NET\r\n"
    b"X-AspNet-Version: 4.0.30319\r\n"
    b"\r\n"
)

PLAIN_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html\r\n"
    b"\r\n"
)


@pytest.mark.integration
def test_http_prober_nginx(fake_conn):
    conn = fake_conn([NGINX_RESPONSE])
    result = HTTPProber(conn).probe()
    assert result.software == "nginx"
    assert result.version == "1.24.0"
    assert result.confidence == Confidence.CONFIRMED
    assert result.protocol == "http"


@pytest.mark.integration
def test_http_prober_apache(fake_conn):
    conn = fake_conn([APACHE_RESPONSE])
    result = HTTPProber(conn).probe()
    assert result.software == "Apache"
    assert result.version == "2.4.54"


@pytest.mark.integration
def test_http_prober_iis(fake_conn):
    conn = fake_conn([IIS_RESPONSE])
    result = HTTPProber(conn).probe()
    assert result.software == "Microsoft-IIS"
    assert result.version == "10.0"
    assert result.http_headers.get("x-aspnet-version") == "4.0.30319"


@pytest.mark.integration
def test_http_prober_sends_head_request(fake_conn):
    conn = fake_conn([NGINX_RESPONSE])
    HTTPProber(conn).probe()
    assert any(b"HEAD" in sent for sent in conn.sent)


@pytest.mark.integration
def test_http_prober_status_code(fake_conn):
    conn = fake_conn([NGINX_RESPONSE])
    result = HTTPProber(conn).probe()
    assert result.http_status == 200


@pytest.mark.integration
def test_http_prober_no_server_header_low_confidence(fake_conn):
    conn = fake_conn([PLAIN_RESPONSE])
    result = HTTPProber(conn).probe()
    assert result.software is None
    assert result.confidence == Confidence.LOW


@pytest.mark.integration
def test_http_prober_host_and_port_set(fake_conn):
    conn = fake_conn([NGINX_RESPONSE])
    conn.host = "10.0.0.1"
    conn.port = 80
    result = HTTPProber(conn).probe()
    assert result.host == "10.0.0.1"
    assert result.port == 80


@pytest.mark.integration
def test_https_prober_upgrades_tls(fake_conn):
    conn = fake_conn([NGINX_RESPONSE])
    result = HTTPProber(conn, tls=True).probe()
    assert result.protocol == "https"
    assert result.tls_version == "TLSv1.3"
    assert result.tls_cipher is not None


@pytest.mark.integration
def test_http_prober_headers_captured(fake_conn):
    conn = fake_conn([NGINX_RESPONSE])
    result = HTTPProber(conn).probe()
    assert "content-type" in result.http_headers
