"""Unit tests for multi-client identification and per-client state isolation."""

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from models.alert_model import DecisionAction, DetectionCategory, IDSAlert, Severity
from parser.packet_dispatcher import PacketDispatcher
from server.client_manager import ClientManager


def test_vpn_ip_detection():
    """Verifies that ClientManager accurately detects IP addresses within VPN subnets."""
    cm = ClientManager(vpn_subnets=["10.8.0.0/24", "10.200.0.0/24"])

    assert cm.is_vpn_ip("10.8.0.2") is True
    assert cm.is_vpn_ip("10.8.0.254") is True
    assert cm.is_vpn_ip("10.200.0.50") is True
    assert cm.is_vpn_ip("192.168.1.1") is False
    assert cm.is_vpn_ip("8.8.8.8") is False
    assert cm.is_vpn_ip("127.0.0.1") is False


def test_client_resolution_outbound_and_inbound():
    """Verifies that packets are mapped to client contexts with correct direction."""
    cm = ClientManager(vpn_subnets=["10.8.0.0/24"])
    dispatcher = PacketDispatcher()

    # Outbound packet: Client (10.8.0.5) -> External (93.184.216.34)
    outbound_pkt = Ether() / IP(src="10.8.0.5", dst="93.184.216.34") / TCP(sport=50000, dport=80)
    parsed_out = dispatcher.dispatch(bytes(outbound_pkt))

    client_ctx, is_outbound = cm.resolve_client(parsed_out)
    assert client_ctx.client_ip == "10.8.0.5"
    assert is_outbound is True

    # Inbound packet: External (93.184.216.34) -> Client (10.8.0.5)
    inbound_pkt = Ether() / IP(src="93.184.216.34", dst="10.8.0.5") / TCP(sport=80, dport=50000)
    parsed_in = dispatcher.dispatch(bytes(inbound_pkt))

    client_ctx_in, is_outbound_in = cm.resolve_client(parsed_in)
    assert client_ctx_in.client_ip == "10.8.0.5"
    assert is_outbound_in is False


def test_isolated_flow_tables_per_client():
    """Verifies that FlowManagers are strictly isolated between different clients."""
    cm = ClientManager(vpn_subnets=["10.8.0.0/24"])
    dispatcher = PacketDispatcher()

    # Packet for Client A: 10.8.0.2:4000 -> 8.8.8.8:53
    pkt_a = Ether() / IP(src="10.8.0.2", dst="8.8.8.8") / TCP(sport=4000, dport=53, flags="S", seq=100)
    parsed_a = dispatcher.dispatch(bytes(pkt_a))

    client_a, _ = cm.resolve_client(parsed_a)
    flow_a = client_a.flow_manager.process_packet(parsed_a)

    # Packet for Client B: 10.8.0.3:4000 -> 8.8.8.8:53
    pkt_b = Ether() / IP(src="10.8.0.3", dst="8.8.8.8") / TCP(sport=4000, dport=53, flags="S", seq=100)
    parsed_b = dispatcher.dispatch(bytes(pkt_b))

    client_b, _ = cm.resolve_client(parsed_b)
    flow_b = client_b.flow_manager.process_packet(parsed_b)

    # Both clients have 1 active flow in their own table
    assert client_a.flow_manager.tracker.active_flow_count == 1
    assert client_b.flow_manager.tracker.active_flow_count == 1
    # Flow IDs are tracked independently
    assert client_a.client_ip != client_b.client_ip
    assert client_a.flow_manager != client_b.flow_manager


def test_per_client_statistics_and_alerts():
    """Verifies that metrics and security alerts are tracked per client."""
    cm = ClientManager(vpn_subnets=["10.8.0.0/24"])
    dispatcher = PacketDispatcher()

    pkt = Ether() / IP(src="10.8.0.10", dst="1.1.1.1") / TCP(sport=5000, dport=80)
    parsed = dispatcher.dispatch(bytes(pkt))

    client, is_out = cm.resolve_client(parsed)
    client.record_packet(parsed, is_outbound_from_client=is_out)
    client.record_protocol("HTTP")

    alert = IDSAlert.create(
        alert_id=1,
        timestamp=parsed.timestamp,
        source_ip="10.8.0.10",
        destination_ip="1.1.1.1",
        source_port=5000,
        destination_port=80,
        protocol="HTTP",
        category=DetectionCategory.SIGNATURE_MATCH,
        severity=Severity.HIGH,
        matched_rule="Suspicious URI",
        evidence="/admin probe",
        recommended_action=DecisionAction.ALERT,
    )
    client.record_alert(alert)

    snap = client.get_snapshot()
    assert snap.total_packets == 1
    assert snap.packets_out == 1
    assert snap.packets_in == 0
    assert snap.top_protocol == "HTTP"
    assert snap.alerts_count == 1
    assert snap.severity_counts["HIGH"] == 1

