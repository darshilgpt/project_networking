"""Unit tests for Ethernet II parser."""

import pytest
from scapy.layers.l2 import Dot1Q, Ether
from scapy.layers.inet import IP

from parser.ethernet_parser import EthernetParser, format_mac


def test_valid_ethernet_frame():
    """Tests parsing a standard Ethernet II frame constructed with Scapy."""
    src = "00:11:22:33:44:55"
    dst = "66:77:88:99:aa:bb"
    pkt = Ether(src=src, dst=dst, type=0x0800) / b"Hello Ethernet"
    raw_bytes = bytes(pkt)

    header, payload = EthernetParser.parse(raw_bytes)

    assert header.src_mac.upper() == src.upper()
    assert header.dst_mac.upper() == dst.upper()
    assert header.ethertype_code == 0x0800
    assert header.ethertype_name == "IPv4"
    assert header.vlan_id is None
    assert payload == b"Hello Ethernet"


def test_vlan_tagged_frame():
    """Tests parsing an 802.1Q VLAN tagged frame."""
    src = "00:aa:bb:cc:dd:ee"
    dst = "ff:ee:dd:cc:bb:aa"
    pkt = Ether(src=src, dst=dst) / Dot1Q(vlan=100, prio=5) / IP(src="1.2.3.4", dst="5.6.7.8")
    raw_bytes = bytes(pkt)

    header, payload = EthernetParser.parse(raw_bytes)

    assert header.src_mac.upper() == src.upper()
    assert header.dst_mac.upper() == dst.upper()
    assert header.vlan_id == 100
    assert header.vlan_pcp == 5
    assert header.ethertype_code == 0x0800
    assert header.ethertype_name == "IPv4"
    assert len(payload) > 0


def test_truncated_ethernet_frame():
    """Tests that a frame shorter than 14 bytes raises a ValueError."""
    short_data = b"\x00\x11\x22\x33\x44"  # Only 5 bytes
    with pytest.raises(ValueError, match="Ethernet frame truncated"):
        EthernetParser.parse(short_data)


def test_truncated_vlan_frame():
    """Tests that a VLAN frame shorter than 18 bytes raises a ValueError."""
    # 14 bytes with EtherType 0x8100, but only 2 bytes of VLAN header (missing remaining 2)
    truncated_vlan = b"\x00" * 12 + b"\x81\x00" + b"\x00\x01"
    with pytest.raises(ValueError, match="VLAN tagged Ethernet frame truncated"):
        EthernetParser.parse(truncated_vlan)


def test_unknown_ethertype():
    """Tests handling of unmapped EtherTypes."""
    raw = b"\x11" * 6 + b"\x22" * 6 + b"\x99\x99" + b"custom payload"
    header, payload = EthernetParser.parse(raw)

    assert header.ethertype_code == 0x9999
    assert "Unknown" in header.ethertype_name
    assert payload == b"custom payload"


def test_format_mac():
    """Tests MAC address byte formatting helper."""
    raw = bytes([0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03])
    assert format_mac(raw) == "AA:BB:CC:01:02:03"

