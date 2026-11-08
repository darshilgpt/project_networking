"""Controlled test suite validating fixes for the 4 audit issues:
1. BlockingManager attributes and crash-free summary generation
2. Port scan detection logic (SYN probes, reverse filtering, mid-stream filtering, retries)
3. TTL anomaly validation (link-local multicast filtering, unicast evasion/variance diagnostics)
4. Statistics consistency (intercepted, allow, block, drops, simulation vs active)
"""

import time
import pytest
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP

from dpi.dpi_engine import DPIEngine
from ids.behaviour_detector import BehaviourDetector
from ids.ids_engine import IDSEngine
from ips.blocking_manager import BlockingManager
from ips.decision_engine import DecisionEngine
from models.alert_model import DecisionAction, DetectionCategory, Severity
from network.ip_intelligence import IPIntelligenceEngine
from parser.packet_dispatcher import PacketDispatcher
from models.packet_models import CaptureStats
from utils.formatter import PacketFormatter


# ============================================================================
# ISSUE 1: BlockingManager Attributes and Crash-Free Session Summary
# ============================================================================

def test_issue1_blocking_manager_attributes_and_accounting():
    """Verifies BlockingManager tracks allow_decisions, alert_decisions,
    security_block_decisions, actual_dropped_packets, and simulated_blocks."""
    bm = BlockingManager(active_prevention=False)
    dispatcher = PacketDispatcher()

    assert hasattr(bm, "allow_decisions")
    assert hasattr(bm, "alert_decisions")
    assert hasattr(bm, "security_block_decisions")
    assert hasattr(bm, "simulated_blocks")
    assert hasattr(bm, "actual_dropped_packets")
    assert hasattr(bm, "actual_verified_drops")
    assert hasattr(bm, "intercepted_packets")

    # 1. ALLOW decision
    pkt_allow = dispatcher.dispatch(bytes(Ether() / IP(src="10.8.0.2", dst="8.8.8.8") / TCP()))
    action, msg = bm.handle_decision(DecisionAction.ALLOW, pkt_allow, alerts=[])
    assert action == DecisionAction.ALLOW
    assert bm.allow_decisions == 1
    assert bm.intercepted_packets == 1

    # 2. ALERT decision
    pkt_alert = dispatcher.dispatch(bytes(Ether() / IP(src="10.8.0.2", dst="8.8.8.8") / TCP()))
    action, msg = bm.handle_decision(DecisionAction.ALERT, pkt_alert, alerts=[])
    assert action == DecisionAction.ALERT
    assert bm.alert_decisions == 1
    assert bm.intercepted_packets == 2

    # 3. BLOCK decision in Simulation mode
    pkt_block = dispatcher.dispatch(bytes(Ether() / IP(src="10.8.0.2", dst="8.8.8.8") / TCP()))
    action, msg = bm.handle_decision(DecisionAction.BLOCK, pkt_block, alerts=[])
    assert action == DecisionAction.BLOCK
    assert "SIMULATED" in msg
    assert bm.security_block_decisions == 1
    assert bm.simulated_blocks == 1
    assert bm.actual_dropped_packets == 0
    assert bm.actual_verified_drops == 0
    assert bm.intercepted_packets == 3

    # 4. evaluate_and_enforce pipeline
    res_allow = bm.evaluate_and_enforce(packet=pkt_allow)
    assert res_allow.is_forwarded is True
    assert bm.allow_decisions == 2


def test_issue1_summary_generation_never_crashes_with_missing_attrs(capsys):
    """Verifies print_final_summary gracefully handles missing or uninitialized attributes."""
    class DummyEmptyObject:
        pass

    dummy_bm = DummyEmptyObject()  # Has zero attributes
    dummy_stats = CaptureStats()
    dummy_dpi = DPIEngine()
    dummy_ids = IDSEngine()
    dummy_flows = {"active_flows": 0, "total_flows_seen": 0, "app_breakdown": {}}

    # Must execute cleanly without raising AttributeError
    PacketFormatter.print_final_summary(
        capture_stats=dummy_stats,
        flow_summary=dummy_flows,
        dpi_engine=dummy_dpi,
        ids_engine=dummy_ids,
        blocking_manager=dummy_bm,
    )

    captured = capsys.readouterr()
    assert "FINAL DPI & IDS/IPS SESSION SUMMARY" in captured.out
    assert "Operating Mode" in captured.out
    assert "Allow Decisions               : 0" in captured.out
    assert "Security Block Decisions      : 0" in captured.out


# ============================================================================
# ISSUE 2: Port Scan Detection Logic
# ============================================================================

def test_issue2_port_scan_detection_tcp_syn_probes():
    """Verifies that probing 12 unique destination ports within the time window
    triggers a PORT_SCAN alert with complete evidence."""
    detector = BehaviourDetector()
    dispatcher = PacketDispatcher()
    now = time.time()
    counter = [0]
    next_id = lambda: counter.__setitem__(0, counter[0] + 1) or counter[0]

    src = "10.8.0.5"
    dst = "10.8.0.1"
    alerts = []

    # Client sequentially attempts 12 different ports (ports 1 to 12)
    for p in range(1, 13):
        pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=50000 + p, dport=p, flags="S")
        parsed = dispatcher.dispatch(bytes(pkt), timestamp=now + (p * 0.5))
        res = detector.evaluate(parsed, dpi_result=None, next_alert_id_fn=next_id)
        alerts.extend(res)

    port_scans = [a for a in alerts if a.category == DetectionCategory.PORT_SCAN]
    assert len(port_scans) >= 1
    alert = port_scans[0]
    assert alert.source_ip == src
    assert alert.destination_ip == dst
    assert alert.severity == Severity.HIGH
    assert alert.recommended_action == DecisionAction.BLOCK
    assert "ports" in alert.evidence.lower()


def test_issue2_reverse_direction_packets_do_not_inflate_port_scan():
    """Verifies server response packets (SYN-ACK or RST) sent to client ephemeral ports
    do NOT register as port scanning probes."""
    detector = BehaviourDetector()
    dispatcher = PacketDispatcher()
    now = time.time()
    counter = [0]
    next_id = lambda: counter.__setitem__(0, counter[0] + 1) or counter[0]

    server_ip = "10.8.0.1"
    client_ip = "10.8.0.5"
    alerts = []

    # Server sends back SYN-ACK or RST to 15 different client ephemeral ports
    for p in range(1, 16):
        # SYN-ACK response
        pkt_synack = Ether() / IP(src=server_ip, dst=client_ip) / TCP(sport=80, dport=50000 + p, flags="SA")
        parsed = dispatcher.dispatch(bytes(pkt_synack), timestamp=now + (p * 0.1))
        res = detector.evaluate(parsed, dpi_result=None, next_alert_id_fn=next_id)
        alerts.extend(res)

        # RST response
        pkt_rst = Ether() / IP(src=server_ip, dst=client_ip) / TCP(sport=443, dport=51000 + p, flags="R")
        parsed_rst = dispatcher.dispatch(bytes(pkt_rst), timestamp=now + (p * 0.1))
        res_rst = detector.evaluate(parsed_rst, dpi_result=None, next_alert_id_fn=next_id)
        alerts.extend(res_rst)

    port_scans = [a for a in alerts if a.category == DetectionCategory.PORT_SCAN]
    assert len(port_scans) == 0, f"Expected 0 port scan alerts from server replies, got: {port_scans}"


def test_issue2_midstream_established_packets_do_not_inflate_scan():
    """Verifies normal established TCP connection packets (ACK, PSH-ACK) do NOT
    register as port scan attempts."""
    detector = BehaviourDetector()
    dispatcher = PacketDispatcher()
    now = time.time()
    counter = [0]
    next_id = lambda: counter.__setitem__(0, counter[0] + 1) or counter[0]

    client_ip = "10.8.0.5"
    server_ip = "10.8.0.1"
    alerts = []

    # Client sends established ACK or PSH-ACK packets across multiple ports
    for p in range(1, 16):
        pkt = Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=50000 + p, dport=p, flags="A")
        parsed = dispatcher.dispatch(bytes(pkt), timestamp=now + (p * 0.1))
        res = detector.evaluate(parsed, dpi_result=None, next_alert_id_fn=next_id)
        alerts.extend(res)

        pkt_psh = Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=50000 + p, dport=p, flags="PA") / b"DATA"
        parsed_psh = dispatcher.dispatch(bytes(pkt_psh), timestamp=now + (p * 0.1))
        res_psh = detector.evaluate(parsed_psh, dpi_result=None, next_alert_id_fn=next_id)
        alerts.extend(res_psh)

    port_scans = [a for a in alerts if a.category == DetectionCategory.PORT_SCAN]
    assert len(port_scans) == 0, "Mid-stream packets should not trigger port scan alerts"


def test_issue2_retries_to_same_port_do_not_inflate_unique_ports():
    """Verifies that multiple connection retries to the exact same port (e.g. port 80)
    are treated as 1 unique port probe, not multiple."""
    detector = BehaviourDetector()
    dispatcher = PacketDispatcher()
    now = time.time()
    counter = [0]
    next_id = lambda: counter.__setitem__(0, counter[0] + 1) or counter[0]

    client_ip = "10.8.0.5"
    server_ip = "10.8.0.1"
    alerts = []

    # 15 connection retries to port 80 only
    for i in range(15):
        pkt = Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=50000 + i, dport=80, flags="S")
        parsed = dispatcher.dispatch(bytes(pkt), timestamp=now + (i * 0.2))
        res = detector.evaluate(parsed, dpi_result=None, next_alert_id_fn=next_id)
        alerts.extend(res)

    port_scans = [a for a in alerts if a.category == DetectionCategory.PORT_SCAN]
    assert len(port_scans) == 0, "Repeated retries to the same port must not count as a multi-port scan"


# ============================================================================
# ISSUE 3: TTL Anomaly Validation
# ============================================================================

def test_issue3_link_local_multicast_ttl1_does_not_trigger_alerts():
    """Verifies SSDP (239.255.255.250), mDNS (224.0.0.251), and LLMNR (224.0.0.252)
    with RFC-mandated TTL=1 do not trigger TTL_EVASION_PROBE or corrupt the baseline profile."""
    ip_intel = IPIntelligenceEngine()
    dispatcher = PacketDispatcher()

    multicast_probes = [
        ("192.168.1.10", "239.255.255.250", 1900, "SSDP"),
        ("192.168.1.10", "224.0.0.251", 5353, "mDNS"),
        ("192.168.1.10", "224.0.0.252", 5355, "LLMNR"),
    ]

    for src, dst, dport, name in multicast_probes:
        pkt = Ether() / IP(src=src, dst=dst, ttl=1) / UDP(sport=50000, dport=dport)
        parsed = dispatcher.dispatch(bytes(pkt))
        alerts = ip_intel.evaluate_packet(parsed)

        ttl_alerts = [a for a in alerts if "TTL" in a.alert_type]
        assert len(ttl_alerts) == 0, f"{name} multicast TTL=1 should not trigger TTL alerts, got: {ttl_alerts}"

    # Now verify that subsequent normal unicast traffic from that host is not skewed by the multicast TTL=1
    unicast_pkt = Ether() / IP(src="192.168.1.10", dst="8.8.8.8", ttl=128) / TCP(sport=50000, dport=80, flags="S")
    parsed_unicast = dispatcher.dispatch(bytes(unicast_pkt))
    unicast_alerts = ip_intel.evaluate_packet(parsed_unicast)
    ttl_alerts2 = [a for a in unicast_alerts if "TTL" in a.alert_type]
    assert len(ttl_alerts2) == 0


def test_issue3_unicast_low_ttl_triggers_alert_with_full_evidence():
    """Verifies that low TTL on unicast packets triggers TTL_EVASION_PROBE and
    includes observed TTL, expected range, src, and dst in evidence."""
    ip_intel = IPIntelligenceEngine()
    dispatcher = PacketDispatcher()

    # Unicast packet with TTL=1
    pkt = Ether() / IP(src="10.8.0.2", dst="10.8.0.1", ttl=1) / TCP(sport=50000, dport=80, flags="S")
    parsed = dispatcher.dispatch(bytes(pkt))
    alerts = ip_intel.evaluate_packet(parsed)

    evasion_alerts = [a for a in alerts if a.alert_type == "TTL_EVASION_PROBE"]
    assert len(evasion_alerts) >= 1
    alert = evasion_alerts[0]
    assert alert.source_ip == "10.8.0.2"
    assert alert.destination_ip == "10.8.0.1"
    assert "Observed TTL: 1" in alert.evidence
    assert "Expected TTL range" in alert.evidence
    assert "Source IP: 10.8.0.2" in alert.evidence
    assert "Destination IP: 10.8.0.1" in alert.evidence


def test_issue3_unicast_ttl_variance_triggers_alert_with_full_evidence():
    """Verifies that large TTL jumps in unicast traffic trigger TTL_VARIANCE_SPOOFING_ANOMALY
    with full evidence logging."""
    ip_intel = IPIntelligenceEngine()
    dispatcher = PacketDispatcher()

    # Seed baseline profile with standard Windows TTL=128
    for _ in range(5):
        pkt = Ether() / IP(src="10.8.0.3", dst="10.8.0.1", ttl=128) / TCP(sport=50000, dport=80, flags="S")
        ip_intel.evaluate_packet(dispatcher.dispatch(bytes(pkt)))

    # Sudden jump to Linux default TTL=64 from the same IP (variance |128 - 64| = 64 >= 8)
    pkt_jump = Ether() / IP(src="10.8.0.3", dst="10.8.0.1", ttl=64) / TCP(sport=50000, dport=80, flags="S")
    alerts = ip_intel.evaluate_packet(dispatcher.dispatch(bytes(pkt_jump)))

    variance_alerts = [a for a in alerts if a.alert_type == "TTL_VARIANCE_SPOOFING_ANOMALY"]
    assert len(variance_alerts) >= 1
    alert = variance_alerts[0]
    assert alert.source_ip == "10.8.0.3"
    assert alert.destination_ip == "10.8.0.1"
    assert "Observed TTL: 64" in alert.evidence
    assert "Expected TTL range" in alert.evidence
    assert "Source IP: 10.8.0.3" in alert.evidence
    assert "Destination IP: 10.8.0.1" in alert.evidence


# ============================================================================
# ISSUE 4: Statistics Consistency
# ============================================================================

def test_issue4_simulation_mode_statistics_consistency():
    """Verifies that in Simulation Mode, BLOCK decisions increment simulated_blocks
    and security_block_decisions, but actual_dropped_packets remains 0 and packets are forwarded."""
    bm = BlockingManager(active_prevention=False)
    dispatcher = PacketDispatcher()

    # Process 5 benign packets via handle_decision
    for i in range(5):
        pkt = dispatcher.dispatch(bytes(Ether() / IP(src="10.8.0.2", dst="8.8.8.8") / TCP()))
        action, msg = bm.handle_decision(DecisionAction.ALLOW, pkt, alerts=[])
        assert action == DecisionAction.ALLOW

    # Process 3 block-worthy packets via handle_decision
    for i in range(3):
        pkt = dispatcher.dispatch(bytes(Ether() / IP(src="10.8.0.2", dst="8.8.8.8") / TCP()))
        action, msg = bm.handle_decision(DecisionAction.BLOCK, pkt, alerts=[])
        assert action == DecisionAction.BLOCK
        assert "SIMULATED" in msg

    assert bm.intercepted_packets == 8
    assert bm.allow_decisions == 5
    assert bm.alert_decisions == 0
    assert bm.security_block_decisions == 3
    assert bm.simulated_blocks == 3
    assert bm.actual_dropped_packets == 0
    assert bm.actual_verified_drops == 0
    assert bm.forwarded_or_reinjected_packets == 8


def test_issue4_active_mode_statistics_consistency():
    """Verifies that in Active Mode, BLOCK decisions increment actual_dropped_packets
    and security_block_decisions, while simulated_blocks remains 0 and packets are dropped."""
    from ips.windows_firewall_enforcer import WindowsFirewallEnforcer

    mock_enforcer = WindowsFirewallEnforcer(
        permitted_subnet="10.8.0.0/24,10.10.0.0/24",
        command_executor=lambda cmd: (0, "Ok", ""),
        is_admin=True,
        auto_cleanup_stale=False,
    )
    bm = BlockingManager(active_prevention=True, firewall_enforcer=mock_enforcer)
    dispatcher = PacketDispatcher()

    # Process 4 benign packets
    for i in range(4):
        pkt = dispatcher.dispatch(bytes(Ether() / IP(src="10.8.0.2", dst="8.8.8.8") / TCP()))
        action, msg = bm.handle_decision(DecisionAction.ALLOW, pkt, alerts=[])
        assert action == DecisionAction.ALLOW

    # Process 2 block-worthy packets
    for i in range(2):
        pkt = dispatcher.dispatch(bytes(Ether() / IP(src="10.8.0.2", dst="8.8.8.8") / TCP()))
        action, msg = bm.handle_decision(DecisionAction.BLOCK, pkt, alerts=[])
        assert action == DecisionAction.BLOCK
        assert "ACTUAL BLOCK" in msg

    assert bm.intercepted_packets == 6
    assert bm.allow_decisions == 4
    assert bm.alert_decisions == 0
    assert bm.security_block_decisions == 2
    assert bm.simulated_blocks == 0
    assert bm.actual_dropped_packets == 2
    assert bm.actual_verified_drops == 2
    assert bm.forwarded_or_reinjected_packets == 4
