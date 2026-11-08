"""Unit tests for WireGuard peer connectivity monitoring and status transitions."""

import time

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from parser.packet_dispatcher import PacketDispatcher
from server.client_manager import ClientManager
from server.wireguard_monitor import WireGuardMonitor


def test_monitor_packet_heuristics_connection_transitions():
    """Verifies that WireGuardMonitor detects client connection, disconnection, and reconnection."""
    cm = ClientManager(vpn_subnets=["10.8.0.0/24"])
    cm.register_client("10.8.0.2", "Laptop-Alice")

    monitor = WireGuardMonitor(client_manager=cm, poll_interval=0.1)

    # 1. Initially, no packets have arrived -> HANDSHAKE PENDING
    monitor._poll_via_packet_heuristics()
    stat = monitor.get_peer_status("10.8.0.2")
    assert stat is not None
    assert stat.status == "HANDSHAKE PENDING"

    # 2. Packet arrives from Laptop-Alice -> CONNECTED
    dispatcher = PacketDispatcher()
    pkt = Ether() / IP(src="10.8.0.2", dst="8.8.8.8") / TCP(sport=50000, dport=80)
    parsed = dispatcher.dispatch(bytes(pkt))
    client_ctx, is_out = cm.resolve_client(parsed)
    client_ctx.record_packet(parsed, is_out)

    monitor._poll_via_packet_heuristics()
    stat = monitor.get_peer_status("10.8.0.2")
    assert stat.status == "CONNECTED"
    assert stat.rx_bytes == 0
    assert stat.tx_bytes > 0

    # 3. Simulate client idling / disconnecting (last_seen > 30s ago)
    client_ctx.last_seen = time.time() - 35.0
    monitor._poll_via_packet_heuristics()
    stat = monitor.get_peer_status("10.8.0.2")
    assert stat.status == "DISCONNECTED"

    # 4. Client reconnects with new traffic
    client_ctx.record_packet(parsed, is_out)
    monitor._poll_via_packet_heuristics()
    stat = monitor.get_peer_status("10.8.0.2")
    assert stat.status == "CONNECTED"

