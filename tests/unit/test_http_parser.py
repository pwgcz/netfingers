import pytest
from netfingerprinter.parsers.http_response import parse_http_response


@pytest.mark.unit
def test_status_parsed():
    raw = b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n"
    info = parse_http_response(raw)
    assert info.status == 200


@pytest.mark.unit
def test_nginx_server_header():
    raw = b"HTTP/1.0 200 OK\r\nServer: nginx/1.24.0\r\n\r\n"
    info = parse_http_response(raw)
    assert info.software == "nginx"
    assert info.version == "1.24.0"


@pytest.mark.unit
def test_apache_server_header():
    raw = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.54 (Ubuntu)\r\n\r\n"
    info = parse_http_response(raw)
    assert info.software == "Apache"
    assert info.version == "2.4.54"


@pytest.mark.unit
def test_iis_with_aspnet():
    raw = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Microsoft-IIS/10.0\r\n"
        b"X-Powered-By: ASP.NET\r\n"
        b"X-AspNet-Version: 4.0.30319\r\n"
        b"\r\n"
    )
    info = parse_http_response(raw)
    assert info.software == "Microsoft-IIS"
    assert info.version == "10.0"
    assert info.headers.get("x-aspnet-version") == "4.0.30319"


@pytest.mark.unit
def test_x_powered_by_fallback():
    raw = b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.2.1\r\n\r\n"
    info = parse_http_response(raw)
    assert info.software == "PHP"
    assert info.version == "8.2.1"


@pytest.mark.unit
def test_server_without_version():
    raw = b"HTTP/1.1 200 OK\r\nServer: cloudflare\r\n\r\n"
    info = parse_http_response(raw)
    assert info.software == "cloudflare"
    assert info.version is None


@pytest.mark.unit
def test_empty_response():
    info = parse_http_response(b"")
    assert info.status is None
    assert info.software is None


@pytest.mark.unit
def test_headers_are_lowercased():
    raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Custom: val\r\n\r\n"
    info = parse_http_response(raw)
    assert "content-type" in info.headers
    assert "x-custom" in info.headers


@pytest.mark.unit
def test_lf_only_line_endings():
    raw = b"HTTP/1.1 301 Moved\nServer: nginx/1.18.0\n\n"
    info = parse_http_response(raw)
    assert info.status == 301
    assert info.software == "nginx"
