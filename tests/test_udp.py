"""Unit tests for UDP datagram parser."""

import pytest
from scapy.layers.inet import UDP

from parser.udp_parser import UDPParser


def test_valid_udp_datagram():
    """Tests parsing a standard 8-byte UDP header with DNS payload."""
    payload_data = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    pkt = UDP(sport=5353, dport=53) / payload_data
    raw_bytes = bytes(pkt)

    header, payload = UDPParser.parse(raw_bytes)

    assert header.src_port == 5353
    assert header.dst_port == 53
    assert header.length == 8 + len(payload_data)
    assert header.payload_length == len(payload_data)
    assert payload == payload_data


def test_udp_with_padding():
    """Tests that payload is correctly sliced when Ethernet padding exceeds UDP length."""
    pkt = UDP(sport=1234, dport=5678) / b"ShortData"
    raw_bytes = bytes(pkt) + (b"\x00" * 20)  # Append 20 bytes of trailing ethernet padding

    header, payload = UDPParser.parse(raw_bytes)

    assert header.length == 8 + len(b"ShortData")
    assert header.payload_length == len(b"ShortData")
    assert payload == b"ShortData"


def test_truncated_udp_header():
    """Tests that a buffer shorter than 8 bytes raises a ValueError."""
    short_data = b"\x04\xd2\x11\x5c\x00\x09"  # 6 bytes
    with pytest.raises(ValueError, match="UDP packet truncated"):
        UDPParser.parse(short_data)


def test_invalid_udp_length():
    """Tests that a length field less than 8 raises a ValueError."""
    # 8-byte header with length field set to 4
    bad_length_hdr = b"\x04\xd2\x11\x5c\x00\x04\x00\x00"
    with pytest.raises(ValueError, match="Invalid UDP length field"):
        UDPParser.parse(bad_length_hdr)

