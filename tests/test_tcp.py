"""Unit tests for TCP segment parser."""

import pytest
from scapy.layers.inet import TCP

from parser.tcp_parser import TCPParser


def test_valid_tcp_segment():
    """Tests parsing a standard 20-byte TCP segment header with flags."""
    pkt = TCP(
        sport=54321,
        dport=443,
        seq=100000,
        ack=200000,
        flags="SA",  # SYN-ACK
        window=65535,
        urgptr=0,
    ) / b"Secure TLS handshake initial payload"
    raw_bytes = bytes(pkt)

    header, payload = TCPParser.parse(raw_bytes)

    assert header.src_port == 54321
    assert header.dst_port == 443
    assert header.seq_num == 100000
    assert header.ack_num == 200000
    assert header.data_offset == 5
    assert header.header_length == 20
    assert header.flags.syn is True
    assert header.flags.ack is True
    assert header.flags.fin is False
    assert header.flags.rst is False
    assert header.flags.psh is False
    assert header.window_size == 65535
    assert header.payload_length == len(b"Secure TLS handshake initial payload")
    assert payload == b"Secure TLS handshake initial payload"


def test_tcp_flags_breakdown():
    """Tests individual flag decoding for all 8 standard control flags."""
    # Test PSH + ACK
    p1 = bytes(TCP(flags="PA"))
    h1, _ = TCPParser.parse(p1)
    assert h1.flags.psh is True
    assert h1.flags.ack is True
    assert "PSH" in h1.flags.summary()
    assert "ACK" in h1.flags.summary()

    # Test RST
    p2 = bytes(TCP(flags="R"))
    h2, _ = TCPParser.parse(p2)
    assert h2.flags.rst is True
    assert h2.flags.summary() == "RST"

    # Test FIN + ACK
    p3 = bytes(TCP(flags="FA"))
    h3, _ = TCPParser.parse(p3)
    assert h3.flags.fin is True
    assert h3.flags.ack is True

    # Test CWR + ECE (Congestion)
    p4 = bytes(TCP(flags="CE"))
    h4, _ = TCPParser.parse(p4)
    assert h4.flags.cwr is True
    assert h4.flags.ece is True


def test_tcp_options_parsing():
    """Tests parsing TCP options such as MSS, Window Scale, SACK, and Timestamps."""
    options = [
        ("MSS", 1460),
        ("WScale", 7),
        ("SAckOK", b""),
        ("Timestamp", (12345, 67890)),
        ("EOL", None),
    ]
    pkt = TCP(sport=8080, dport=80, flags="S", options=options) / b"Syn Payload"
    raw_bytes = bytes(pkt)

    header, payload = TCPParser.parse(raw_bytes)

    assert header.data_offset > 5
    assert header.header_length == header.data_offset * 4
    assert len(header.options) >= 4

    opt_names = [o.name for o in header.options]
    assert any("MSS" in name for name in opt_names)
    assert any("Window Scale" in name for name in opt_names)
    assert any("SACK Permitted" in name for name in opt_names)
    assert any("Timestamp" in name for name in opt_names)

    # Check decoded MSS value
    mss_opt = next(o for o in header.options if "MSS" in o.name)
    assert mss_opt.decoded == 1460

    # Check decoded Window Scale
    ws_opt = next(o for o in header.options if "Window Scale" in o.name)
    assert ws_opt.decoded == 7

    assert payload == b"Syn Payload"


def test_truncated_tcp_header():
    """Tests that a buffer smaller than 20 bytes raises a ValueError."""
    short = b"\x00\x50\x01\xBB\x00\x00\x00\x01"  # 8 bytes
    with pytest.raises(ValueError, match="TCP segment truncated"):
        TCPParser.parse(short)


def test_invalid_tcp_data_offset():
    """Tests that data offset < 5 raises a ValueError."""
    # Build 20 bytes where offset nibble is 4
    bad_offset_hdr = bytearray(b"\x00" * 20)
    bad_offset_hdr[12] = 0x40  # offset = 4 (16 bytes, invalid)
    with pytest.raises(ValueError, match="Invalid TCP data offset"):
        TCPParser.parse(bytes(bad_offset_hdr))

