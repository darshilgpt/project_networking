"""Unit tests for HTTP Inspector."""

from dpi.http_inspector import HTTPInspector


def test_http_get_request():
    """Tests parsing a standard HTTP GET request."""
    raw = (
        b"GET /admin/dashboard HTTP/1.1\r\n"
        b"Host: 192.168.1.1\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        b"Accept: */*\r\n\r\n"
    )
    meta = HTTPInspector.inspect(raw)

    assert meta is not None
    assert meta.is_request is True
    assert meta.method == "GET"
    assert meta.uri == "/admin/dashboard"
    assert meta.version == "HTTP/1.1"
    assert meta.host == "192.168.1.1"
    assert "Mozilla" in meta.user_agent


def test_http_post_request():
    """Tests parsing an HTTP POST request with body."""
    body = b'{"username": "admin", "password": "password123"}'
    header_str = (
        "POST /api/login HTTP/1.1\r\n"
        "Host: auth.example.com\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    )
    raw = header_str.encode("ascii") + body
    meta = HTTPInspector.inspect(raw)

    assert meta is not None
    assert meta.is_request is True
    assert meta.method == "POST"
    assert meta.uri == "/api/login"
    assert meta.content_type == "application/json"
    assert meta.content_length == len(body)
    assert "password123" in meta.body_preview


def test_http_response():
    """Tests parsing an HTTP 200 OK response."""
    raw = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: nginx/1.18.0\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b"<html><body>Welcome</body></html>"
    )
    meta = HTTPInspector.inspect(raw)

    assert meta is not None
    assert meta.is_request is False
    assert meta.status_code == 200
    assert meta.reason_phrase == "OK"
    assert meta.content_type == "text/html"
    assert "Welcome" in meta.body_preview


def test_non_http_payload():
    """Tests rejection of non-HTTP random bytes."""
    raw = b"\x00\x01\x02\x03\x04\x05\x06\x07"
    assert HTTPInspector.is_http(raw) is False
    assert HTTPInspector.inspect(raw) is None
