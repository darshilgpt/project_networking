"""Unit tests for IPv4 packet parser."""

import pytest
from scapy.layers.inet import IP, IPOption_RR, TCP

from parser.ipv4_parser import IPv4Parser, calculate_checksum


def test_valid_ipv4_packet():
    """Tests parsing a standard 20-byte IPv4 packet header."""
    pkt = IP(src="192.168.1.50", dst="10.0.0.1", ttl=64, id=12345, proto=6) / b"Payload data"
    raw_bytes = bytes(pkt)

    header, payload = IPv4Parser.parse(raw_bytes)

    assert header.version == 4
    assert header.ihl == 5
    assert header.header_length == 20
    assert header.src_ip == "192.168.1.50"
    assert header.dst_ip == "10.0.0.1"
    assert header.ttl == 64
    assert header.identification == 12345
    assert header.protocol_code == 6
    assert header.protocol_name == "TCP"
    assert header.flag_df is False
    assert header.flag_mf is False
    assert header.fragment_offset == 0
    assert header.is_fragmented is False
    assert header.checksum_valid is True
    assert payload == b"Payload data"


def test_ipv4_with_options():
    """Tests parsing an IPv4 header containing options (IHL > 5)."""
    # Record Route option in IPv4
    opt = IPOption_RR()
    pkt = IP(src="172.16.0.1", dst="172.16.0.2", options=[opt]) / b"Data with options"
    raw_bytes = bytes(pkt)

    header, payload = IPv4Parser.parse(raw_bytes)

    assert header.version == 4
    assert header.ihl > 5
    assert header.header_length == header.ihl * 4
    assert len(header.options) > 0
    assert payload == b"Data with options"


def test_ipv4_fragmentation():
    """Tests handling of fragmented IPv4 packets."""
    # Packet with More Fragments flag
    mf_pkt = IP(src="1.1.1.1", dst="2.2.2.2", flags="MF", frag=0) / b"First Fragment"
    h_mf, p_mf = IPv4Parser.parse(bytes(mf_pkt))
    assert h_mf.flag_mf is True
    assert h_mf.fragment_offset == 0
    assert h_mf.is_fragmented is True
    assert p_mf == b"First Fragment"

    # Subsequent fragment with offset
    sub_pkt = IP(src="1.1.1.1", dst="2.2.2.2", flags=0, frag=16) / b"Second Fragment"
    h_sub, p_sub = IPv4Parser.parse(bytes(sub_pkt))
    assert h_sub.flag_mf is False
    assert h_sub.fragment_offset == 16 * 8
    assert h_sub.is_fragmented is True


def test_truncated_ipv4_packet():
    """Tests that IPv4 data shorter than 20 bytes raises a ValueError."""
    short_data = b"\x45\x00\x00\x28\x00\x01\x00\x00\x40\x06"  # 10 bytes
    with pytest.raises(ValueError, match="IPv4 packet truncated"):
        IPv4Parser.parse(short_data)


def test_invalid_ipv4_version():
    """Tests rejection of non-IPv4 version field."""
    # Version 6 in IPv4 layout
    invalid_data = b"\x65" + b"\x00" * 19
    with pytest.raises(ValueError, match="Invalid IPv4 version"):
        IPv4Parser.parse(invalid_data)


def test_invalid_ihl():
    """Tests rejection of IHL < 5."""
    # Version 4, IHL 4 (16 bytes, invalid)
    invalid_data = b"\x44" + b"\x00" * 19
    with pytest.raises(ValueError, match="Invalid IPv4 header length"):
        IPv4Parser.parse(invalid_data)


def test_checksum_calculation():
    """Tests checksum validator on valid and corrupted header bytes."""
    pkt = IP(src="10.1.1.1", dst="10.2.2.2", ttl=128)
    raw = bytes(pkt)[:20]

    # Valid checksum
    assert calculate_checksum(raw) is True

    # Corrupt a byte in the header
    corrupted = bytearray(raw)
    corrupted[10] ^= 0xFF
    assert calculate_checksum(bytes(corrupted)) is False

