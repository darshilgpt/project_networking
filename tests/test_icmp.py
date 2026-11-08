"""Unit tests for ICMP and ICMPv6 parser."""

import pytest
from scapy.layers.inet import ICMP
from scapy.layers.inet6 import ICMPv6EchoRequest

from parser.icmp_parser import ICMPParser


def test_icmp_echo_request():
    """Tests parsing an IPv4 ICMP Echo Request."""
    pkt = ICMP(type=8, code=0, id=10, seq=1) / b"abcdefghijklmnopqrstuvw"
    raw_bytes = bytes(pkt)

    header, payload = ICMPParser.parse(raw_bytes, is_ipv6=False)

    assert header.icmp_type == 8
    assert header.type_name == "Echo Request"
    assert header.code == 0
    assert header.code_name == "Code 0"
    assert header.is_ipv6 is False
    assert payload == b"abcdefghijklmnopqrstuvw"


def test_icmp_destination_unreachable():
    """Tests parsing an ICMP Destination Unreachable message."""
    pkt = ICMP(type=3, code=3)  # Port unreachable
    raw_bytes = bytes(pkt)

    header, payload = ICMPParser.parse(raw_bytes, is_ipv6=False)

    assert header.icmp_type == 3
    assert header.type_name == "Destination Unreachable"
    assert header.code == 3
    assert header.code_name == "Port Unreachable"


def test_icmpv6_echo_request():
    """Tests parsing an ICMPv6 Echo Request."""
    pkt = ICMPv6EchoRequest(id=0x1234, seq=1, data=b"pingv6")
    raw_bytes = bytes(pkt)

    header, payload = ICMPParser.parse(raw_bytes, is_ipv6=True)

    assert header.icmp_type == 128
    assert header.type_name == "Echo Request"
    assert header.code == 0
    assert header.is_ipv6 is True


def test_truncated_icmp_header():
    """Tests that ICMP data shorter than 4 bytes raises a ValueError."""
    short = b"\x08\x00\x00"  # 3 bytes
    with pytest.raises(ValueError, match="ICMP packet truncated"):
        ICMPParser.parse(short)

