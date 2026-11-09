"""Unit tests for the end-to-end PacketDispatcher pipeline."""

from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6

from parser.packet_dispatcher import PacketDispatcher


def test_dispatch_full_tcp_packet():
    """Tests full stack dissection: Ether -> IPv4 -> TCP -> Payload."""
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="192.168.1.100", dst="142.250.190.46", ttl=64)
        / TCP(sport=51520, dport=443, flags="A", seq=1000, ack=2000)
        / (b"X" * 1200)
    )
    raw = bytes(pkt)

    dispatcher = PacketDispatcher()
    parsed = dispatcher.dispatch(raw)

    assert parsed.is_malformed is False
    assert len(parsed.parse_errors) == 0

    # Layer 2
    assert parsed.ethernet is not None
    assert parsed.ethernet.src_mac.upper() == "00:11:22:33:44:55"
    assert parsed.ethernet.dst_mac.upper() == "66:77:88:99:AA:BB"
    assert parsed.ethernet.ethertype_name == "IPv4"

    # Layer 3
    assert parsed.network_type == "IPv4"
    assert parsed.ipv4 is not None
    assert parsed.ipv4.src_ip == "192.168.1.100"
    assert parsed.ipv4.dst_ip == "142.250.190.46"
    assert parsed.ipv4.ttl == 64

    # Layer 4
    assert parsed.transport_type == "TCP"
    assert parsed.tcp is not None
    assert parsed.tcp.src_port == 51520
    assert parsed.tcp.dst_port == 443
    assert parsed.tcp.flags.ack is True
    assert parsed.payload_length == 1200
    assert parsed.payload == b"X" * 1200


def test_dispatch_full_udp_packet():
    """Tests full stack dissection: Ether -> IPv4 -> UDP -> Payload."""
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="192.168.1.1", dst="192.168.1.255")
        / UDP(sport=67, dport=68)
        / b"DHCP Discovery Payload"
    )
    raw = bytes(pkt)

    dispatcher = PacketDispatcher()
    parsed = dispatcher.dispatch(raw)

    assert parsed.network_type == "IPv4"
    assert parsed.transport_type == "UDP"
    assert parsed.udp is not None
    assert parsed.udp.src_port == 67
    assert parsed.udp.dst_port == 68
    assert parsed.payload == b"DHCP Discovery Payload"


def test_dispatch_ipv6_tcp_packet():
    """Tests IPv6 packet dispatch."""
    pkt = (
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / TCP(sport=8080, dport=80, flags="S")
        / b"IPv6 Web Request"
    )
    raw = bytes(pkt)

    dispatcher = PacketDispatcher()
    parsed = dispatcher.dispatch(raw)

    assert parsed.network_type == "IPv6"
    assert parsed.ipv6 is not None
    assert parsed.ipv6.src_ip.lower() == "2001:db8::1"
    assert parsed.transport_type == "TCP"
    assert parsed.tcp is not None
    assert parsed.tcp.src_port == 8080
    assert parsed.tcp.flags.syn is True


def test_dispatch_arp_packet():
    """Tests non-IP layer 3 protocol (ARP) handling."""
    pkt = Ether() / ARP(psrc="192.168.1.1", pdst="192.168.1.2")
    raw = bytes(pkt)

    dispatcher = PacketDispatcher()
    parsed = dispatcher.dispatch(raw)

    assert parsed.network_type == "ARP"
    assert parsed.is_malformed is False


def test_dispatch_fragmented_packet():
    """Tests handling of non-first IPv4 fragment where transport header is omitted."""
    pkt = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2", flags=0, frag=10, proto=6)
        / b"Fragment Data Without TCP Header"
    )
    raw = bytes(pkt)

    dispatcher = PacketDispatcher()
    parsed = dispatcher.dispatch(raw)

    assert parsed.network_type == "IPv4"
    assert parsed.transport_type == "Fragment (Non-First)"
    assert parsed.tcp is None
    assert parsed.payload == b"Fragment Data Without TCP Header"


def test_dispatch_malformed_packet_no_crash():
    """Tests that a corrupted or truncated frame never crashes the dispatcher."""
    corrupted_data = b"\x00\x11\x22\x33\x44"  # Truncated Ethernet

    dispatcher = PacketDispatcher()
    parsed = dispatcher.dispatch(corrupted_data)

    assert parsed.is_malformed is True
    assert len(parsed.parse_errors) > 0
    assert "Ethernet parse error" in parsed.parse_errors[0]


def test_dispatch_empty_buffer():
    """Tests dispatching empty byte buffer."""
    dispatcher = PacketDispatcher()
    parsed = dispatcher.dispatch(b"")

    assert parsed.is_malformed is True
    assert "Empty packet buffer" in parsed.parse_errors

