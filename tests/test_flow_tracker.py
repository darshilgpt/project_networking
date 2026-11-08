"""Unit tests for FlowTracker and FlowManager."""

import time
import pytest
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from parser.packet_dispatcher import PacketDispatcher
from flow.flow_tracker import FlowTracker
from flow.flow_manager import FlowManager
from models.flow_model import TCPState


@pytest.fixture
def dispatcher():
    return PacketDispatcher()


@pytest.fixture
def tracker():
    return FlowTracker(tcp_idle_timeout=5.0, max_flows=10)


def test_bidirectional_flow_tracking(dispatcher, tracker):
    """Verifies that packets travelling in opposite directions belong to the same flow."""
    # Packet 1: 192.168.1.10:50000 -> 1.1.1.1:80
    p1 = bytes(Ether() / IP(src="192.168.1.10", dst="1.1.1.1") / TCP(sport=50000, dport=80, flags="S", seq=100))
    pkt1 = dispatcher.dispatch(p1, timestamp=1000.0)

    flow1, is_new1 = tracker.process_packet(pkt1)
    assert is_new1 is True
    assert flow1 is not None
    assert flow1.stats.total_packets == 1
    assert flow1.protocol == "TCP"

    # Packet 2: 1.1.1.1:80 -> 192.168.1.10:50000 (Reverse direction)
    p2 = bytes(Ether() / IP(src="1.1.1.1", dst="192.168.1.10") / TCP(sport=80, dport=50000, flags="SA", seq=200, ack=101))
    pkt2 = dispatcher.dispatch(p2, timestamp=1000.1)

    flow2, is_new2 = tracker.process_packet(pkt2)
    assert is_new2 is False
    assert flow2.flow_id == flow1.flow_id
    assert flow2.stats.total_packets == 2
    assert flow2.stats.packets_forward == 1
    assert flow2.stats.packets_reverse == 1
    assert flow2.stats.duration == pytest.approx(0.1)


def test_tcp_state_machine(dispatcher, tracker):
    """Tests progression from SYN -> SYN-ACK -> ESTABLISHED -> FIN -> CLOSED."""
    # SYN
    p_syn = bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S"))
    flow, _ = tracker.process_packet(dispatcher.dispatch(p_syn, timestamp=100.0))
    assert flow is not None
    assert flow.tcp_state == TCPState.SYN_SENT

    # SYN-ACK
    p_sa = bytes(Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=1234, flags="SA"))
    flow, _ = tracker.process_packet(dispatcher.dispatch(p_sa, timestamp=100.1))
    assert flow.tcp_state == TCPState.SYN_RECEIVED

    # ACK
    p_ack = bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="A"))
    flow, _ = tracker.process_packet(dispatcher.dispatch(p_ack, timestamp=100.2))
    assert flow.tcp_state == TCPState.ESTABLISHED

    # FIN
    p_fin = bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="F"))
    flow, _ = tracker.process_packet(dispatcher.dispatch(p_fin, timestamp=101.0))
    assert flow.tcp_state == TCPState.FIN_WAIT

    # ACK of FIN
    p_fin_ack = bytes(Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=1234, flags="A"))
    flow, _ = tracker.process_packet(dispatcher.dispatch(p_fin_ack, timestamp=101.1))
    assert flow.tcp_state == TCPState.CLOSED


def test_flow_expiration(dispatcher, tracker):
    """Tests expiring idle flows."""
    pkt = dispatcher.dispatch(
        bytes(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=53, dport=1000)),
        timestamp=100.0,
    )
    flow, _ = tracker.process_packet(pkt)
    assert tracker.active_flow_count == 1

    # Before timeout
    expired_none = tracker.expire_flows(current_time=120.0)  # UDP idle timeout is 30.0
    assert len(expired_none) == 0

    # After timeout
    expired = tracker.expire_flows(current_time=135.0)  # 35 seconds idle
    assert len(expired) == 1
    assert tracker.active_flow_count == 0


def test_max_flows_capacity(dispatcher):
    """Tests that FlowTracker bounds memory consumption by evicting oldest flows."""
    small_tracker = FlowTracker(max_flows=3)

    for i in range(5):
        pkt = dispatcher.dispatch(
            bytes(Ether() / IP(src=f"10.0.0.{i+1}", dst="10.0.0.254") / UDP(sport=1000 + i, dport=53)),
            timestamp=200.0 + i,
        )
        small_tracker.process_packet(pkt)

    assert small_tracker.active_flow_count <= 3
