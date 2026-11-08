"""Unit tests for IPv6 parser and extension header traversal."""

import pytest
from scapy.layers.inet6 import (
    IPv6,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrRouting,
    IPv6ExtHdrFragment,
    HBHOptUnknown,
)
from scapy.layers.inet import TCP, UDP

from parser.ipv6_parser import IPv6Parser


def test_valid_ipv6_packet():
    """Tests parsing a standard 40-byte IPv6 header."""
    pkt = IPv6(
        src="2001:db8:85a3::8a2e:370:7334",
        dst="2001:db8::1",
        tc=0x20,
        fl=0x12345,
        hlim=64,
        nh=6,
    ) / b"IPv6 Raw Payload"
    raw_bytes = bytes(pkt)

    header, payload = IPv6Parser.parse(raw_bytes)

    assert header.version == 6
    assert header.traffic_class == 0x20
    assert header.flow_label == 0x12345
    assert header.hop_limit == 64
    assert header.src_ip.lower() == "2001:db8:85a3::8a2e:370:7334"
    assert header.dst_ip.lower() == "2001:db8::1"
    assert header.upper_protocol_code == 6
    assert header.upper_protocol_name == "TCP"
    assert len(header.extension_headers) == 0
    assert payload == b"IPv6 Raw Payload"


def test_ipv6_with_extension_headers():
    """Tests traversing IPv6 extension headers to locate upper layer protocol."""
    pkt = (
        IPv6(src="fe80::1", dst="fe80::2")
        / IPv6ExtHdrHopByHop(options=[HBHOptUnknown(otype=1, optlen=4, optdata=b"\x00" * 4)])
        / UDP(sport=5000, dport=5001)
        / b"Inner UDP"
    )
    raw_bytes = bytes(pkt)

    header, payload = IPv6Parser.parse(raw_bytes)

    assert header.version == 6
    assert len(header.extension_headers) >= 1
    assert header.extension_headers[0].next_header_name == "Hop-by-Hop Options"
    assert header.upper_protocol_code == 17  # UDP
    assert header.upper_protocol_name == "UDP"
    assert len(payload) > 0


def test_ipv6_fragment_header():
    """Tests handling IPv6 Fragment Header."""
    pkt = (
        IPv6(src="2001:db8::10", dst="2001:db8::20")
        / IPv6ExtHdrFragment(id=0xCAFE, offset=0, m=1)
        / b"Fragmented Part"
    )
    raw_bytes = bytes(pkt)

    header, payload = IPv6Parser.parse(raw_bytes)

    assert header.version == 6
    assert len(header.extension_headers) == 1
    assert header.extension_headers[0].next_header_name == "Fragment Header"
    assert payload == b"Fragmented Part"


def test_truncated_ipv6_header():
    """Tests that a buffer shorter than 40 bytes raises a ValueError."""
    short = b"\x60\x00\x00\x00\x00\x14\x06\x40"  # 8 bytes
    with pytest.raises(ValueError, match="IPv6 packet truncated"):
        IPv6Parser.parse(short)


def test_invalid_ipv6_version():
    """Tests rejection when IPv6 version field is not 6."""
    bad_ver = b"\x40" + b"\x00" * 39  # Version 4 in IPv6 layout
    with pytest.raises(ValueError, match="Invalid IPv6 version"):
        IPv6Parser.parse(bad_ver)

