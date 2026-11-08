"""Unit tests for TLS Inspector and SNI extraction."""

import struct
from dpi.tls_inspector import TLSInspector


def build_client_hello(sni_host: str) -> bytes:
    """Constructs a binary TLS 1.2 ClientHello record with SNI extension."""
    host_bytes = sni_host.encode("ascii")
    # SNI extension: type 0 (2 bytes), len (2 bytes), list_len (2 bytes), type 0 (1 byte), name_len (2 bytes), name
    sni_ext_data = struct.pack("!HBH", len(host_bytes) + 3, 0, len(host_bytes)) + host_bytes
    sni_ext = struct.pack("!HH", 0x0000, len(sni_ext_data)) + sni_ext_data

    # Extensions block
    ext_block = struct.pack("!H", len(sni_ext)) + sni_ext

    # ClientHello body:
    # 2 bytes ver (0x0303 = TLS 1.2)
    # 32 bytes random
    # 1 byte session ID len (0)
    # 2 bytes cipher len + 2 ciphers (4 bytes)
    # 1 byte comp len + 1 comp (0x00)
    # extensions
    random_bytes = b"\xAA" * 32
    ciphers = struct.pack("!HHH", 4, 0x1301, 0xC02F)  # len 4, 2 ciphers
    compression = b"\x01\x00"  # len 1, method null

    ch_body = struct.pack("!H", 0x0303) + random_bytes + b"\x00" + ciphers + compression + ext_block

    # Handshake header: type 1 (ClientHello), 3 bytes length
    ch_len = len(ch_body)
    hs_header = struct.pack("!B", 1) + bytes([(ch_len >> 16) & 0xFF, (ch_len >> 8) & 0xFF, ch_len & 0xFF])
    handshake_msg = hs_header + ch_body

    # TLS Record Header: ContentType 22 (Handshake), Version 0x0301, 2 bytes length
    rec_len = len(handshake_msg)
    rec_header = struct.pack("!BHH", 22, 0x0301, rec_len)

    return rec_header + handshake_msg


def test_tls_client_hello_sni_extraction():
    """Tests extracting the SNI hostname from an unencrypted ClientHello."""
    raw_tls = build_client_hello("www.example.com")

    meta = TLSInspector.inspect(raw_tls)

    assert meta is not None
    assert meta.is_handshake is True
    assert meta.handshake_type == "ClientHello"
    assert meta.client_version_name == "TLS 1.2"
    assert meta.sni == "www.example.com"
    assert meta.cipher_suite_count == 2
    assert meta.is_encrypted_application_data is False


def test_tls_encrypted_application_data():
    """Tests that encrypted ApplicationData (ContentType 23) is flagged as encrypted."""
    # Record header for ApplicationData: ContentType 23, Version TLS 1.2, length 100
    encrypted_record = struct.pack("!BHH", 23, 0x0303, 100) + (b"\xFF" * 100)

    meta = TLSInspector.inspect(encrypted_record)

    assert meta is not None
    assert meta.content_type_code == 23
    assert meta.is_encrypted_application_data is True
    assert meta.sni is None  # Cannot and does not attempt to decrypt


def test_non_tls_bytes():
    """Tests rejection of arbitrary non-TLS data."""
    raw = b"\x01\x02\x03\x04\x05\x06"
    assert TLSInspector.is_tls(raw) is False
    assert TLSInspector.inspect(raw) is None

