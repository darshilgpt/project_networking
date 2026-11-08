"""Unit tests for WireGuard adapter detection and Raw IP packet dissection."""

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

from capture.interface_manager import InterfaceManager
from models.packet_models import InterfaceInfo
from parser.packet_dispatcher import PacketDispatcher


def test_interface_manager_wireguard_detection():
    """Verifies that InterfaceManager correctly identifies WireGuard and Wintun tunnel adapters."""
    is_wg, kind = InterfaceManager._is_wireguard("wg0", "WireGuard Tunnel")
    assert is_wg is True
    assert kind == "WireGuard"

    is_wg, kind = InterfaceManager._is_wireguard("wintun0", "Wintun Userspace Tunnel")
    assert is_wg is True
    assert kind == "Wintun"

    is_wg, kind = InterfaceManager._is_wireguard("Wi-Fi", "Intel(R) Wi-Fi 6 AX201")
    assert is_wg is False
    assert kind is None


def test_find_tunnel_interface():
    """Verifies InterfaceManager.find_tunnel_interface."""
    ifaces = [
        InterfaceInfo(index=1, name="Ethernet", description="Realtek PCIe", guid="g1", mac="m1"),
        InterfaceInfo(index=2, name="wg0", description="WireGuard Tunnel", guid="g2", mac="m2", is_tunnel=True, tunnel_type="WireGuard"),
    ]
    tunnel = InterfaceManager.find_tunnel_interface(ifaces)
    assert tunnel is not None
    assert tunnel.name == "wg0"
    assert tunnel.is_tunnel is True


def test_raw_ipv4_packet_dissection_without_ethernet():
    """Verifies that PacketDispatcher handles raw L3 IPv4 packets (WireGuard tunnel traffic)."""
    # Create raw IP packet (NO Ether layer)
    pkt = IP(src="10.8.0.2", dst="1.1.1.1") / UDP(sport=53000, dport=53) / b"DNS Query"
    raw_ip_bytes = bytes(pkt)

    dispatcher = PacketDispatcher()

    # Test with AUTO detection
    parsed = dispatcher.dispatch(raw_ip_bytes, link_type="AUTO")
    assert parsed.is_malformed is False
    assert parsed.ethernet is None
    assert parsed.network_type == "IPv4"
    assert parsed.ipv4 is not None
    assert parsed.ipv4.src_ip == "10.8.0.2"
    assert parsed.ipv4.dst_ip == "1.1.1.1"
    assert parsed.transport_type == "UDP"
    assert parsed.udp is not None
    assert parsed.udp.src_port == 53000
    assert parsed.udp.dst_port == 53
    assert parsed.payload == b"DNS Query"

    # Test with explicit RAW_IP link_type
    parsed_explicit = dispatcher.dispatch(raw_ip_bytes, link_type="RAW_IP")
    assert parsed_explicit.is_malformed is False
    assert parsed_explicit.ipv4.src_ip == "10.8.0.2"


def test_raw_ipv6_packet_dissection_without_ethernet():
    """Verifies that PacketDispatcher handles raw L3 IPv6 packets without Ethernet framing."""
    pkt = IPv6(src="fd00::2", dst="fd00::1") / TCP(sport=8080, dport=80, flags="S", seq=100)
    raw_ip6_bytes = bytes(pkt)

    dispatcher = PacketDispatcher()
    parsed = dispatcher.dispatch(raw_ip6_bytes, link_type="RAW_IP")
    assert parsed.is_malformed is False
    assert parsed.ethernet is None
    assert parsed.network_type == "IPv6"
    assert parsed.ipv6 is not None
    assert parsed.ipv6.src_ip == "fd00::2"
    assert parsed.ipv6.dst_ip == "fd00::1"
    assert parsed.transport_type == "TCP"
    assert parsed.tcp.src_port == 8080
    assert parsed.tcp.dst_port == 80

