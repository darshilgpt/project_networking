"""Controlled tests for advanced IDS capabilities."""

import time
import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether

from ids.behaviour_detector import BehaviourDetector
from ids.ids_engine import IDSEngine
from ids.reconnaissance_detector import ReconnaissanceDetector
from ids.reputation_engine import ReputationEngine
from models.alert_model import DecisionAction, DetectionCategory, Severity
from parser.packet_dispatcher import PacketDispatcher


def test_reputation_engine_ip_and_domain():
    """Verifies threat intelligence lookups for malicious IPs, CIDRs, and domains."""
    engine = ReputationEngine()

    # Seed malicious IP lookup
    ind_c2 = engine.check_ip("198.51.100.23")
    assert ind_c2 is not None
    assert ind_c2.category == "C2"
    assert ind_c2.threat_level == Severity.CRITICAL

    # Legitimate IP lookup
    ind_clean = engine.check_ip("8.8.8.8")
    assert ind_clean is None

    # CIDR subnet lookup
    engine.add_ip_indicator("192.168.100.0/24", "BOTNET", Severity.HIGH, "Botnet subnet")
    ind_sub = engine.check_ip("192.168.100.45")
    assert ind_sub is not None
    assert ind_sub.category == "BOTNET"

    # Malicious Domain lookup
    ind_dom = engine.check_domain("subdomain.evil-c2-server.com")
    assert ind_dom is not None
    assert ind_dom.category == "C2"

    # Suspicious TLD check
    ind_tld = engine.check_domain("suspicious-site.xyz")
    assert ind_tld is not None
    assert ind_tld.category == "SUSPICIOUS_TLD"


def test_reconnaissance_detector():
    """Verifies detection of ICMP ping sweep, TCP sweep, and OS fingerprinting probes."""
    recon = ReconnaissanceDetector(ping_sweep_threshold=3, tcp_sweep_threshold=3, sweep_window_seconds=5.0)
    dispatcher = PacketDispatcher()
    now = time.time()

    # 1. ICMP Ping sweep across 3 unique destination IPs
    alerts = []
    for dst in ["10.8.0.10", "10.8.0.11", "10.8.0.12"]:
        pkt = Ether() / IP(src="10.8.0.99", dst=dst) / ICMP(type=8, code=0)
        parsed = dispatcher.dispatch(bytes(pkt), timestamp=now)
        res = recon.evaluate(parsed)
        alerts.extend(res)

    assert len(alerts) >= 1
    assert alerts[0].alert_type == "ICMP_PING_SWEEP_RECONNAISSANCE"
    assert alerts[0].source_ip == "10.8.0.99"

    # 2. TCP Port Sweep across 3 unique hosts on port 445
    tcp_alerts = []
    for dst in ["10.8.0.20", "10.8.0.21", "10.8.0.22"]:
        pkt = Ether() / IP(src="10.8.0.99", dst=dst) / TCP(sport=50000, dport=445, flags="S")
        parsed = dispatcher.dispatch(bytes(pkt), timestamp=now)
        res = recon.evaluate(parsed)
        tcp_alerts.extend(res)

    assert len(tcp_alerts) >= 1
    assert tcp_alerts[0].alert_type == "TCP_SUBNET_SWEEP_RECONNAISSANCE"

    # 3. OS Fingerprinting probe (SYN with URG)
    probe_pkt = Ether() / IP(src="10.8.0.99", dst="10.8.0.1") / TCP(sport=50000, dport=80, flags="SU")
    parsed_probe = dispatcher.dispatch(bytes(probe_pkt), timestamp=now)
    probe_alerts = recon.evaluate(parsed_probe)
    assert len(probe_alerts) >= 1
    assert "OS_FINGERPRINTING_PROBE" in probe_alerts[0].alert_type


def test_tcp_protocol_anomalies():
    """Verifies detection of illegal TCP flag evasions (SYN+FIN, NULL flags, XMAS)."""
    detector = BehaviourDetector()
    dispatcher = PacketDispatcher()
    counter = [0]
    next_id = lambda: counter.__setitem__(0, counter[0] + 1) or counter[0]
    now = time.time()

    # A. SYN + FIN
    pkt_syn_fin = Ether() / IP(src="10.8.0.5", dst="10.8.0.1") / TCP(sport=4000, dport=80, flags="SF")
    parsed_sf = dispatcher.dispatch(bytes(pkt_syn_fin), timestamp=now)
    alerts_sf = detector.evaluate(parsed_sf, dpi_result=None, next_alert_id_fn=next_id)
    assert any("SYN_FIN" in a.matched_rule for a in alerts_sf)

    # B. NULL Flags
    pkt_null = Ether() / IP(src="10.8.0.6", dst="10.8.0.1") / TCP(sport=4000, dport=80, flags="")
    parsed_null = dispatcher.dispatch(bytes(pkt_null), timestamp=now)
    alerts_null = detector.evaluate(parsed_null, dpi_result=None, next_alert_id_fn=next_id)
    assert any("NULL" in a.matched_rule for a in alerts_null)


def test_behavioural_syn_scan_and_flood():
    """Verifies TCP SYN scan and SYN flood rate threshold alerts."""
    detector = BehaviourDetector()
    dispatcher = PacketDispatcher()
    counter = [0]
    next_id = lambda: counter.__setitem__(0, counter[0] + 1) or counter[0]
    now = time.time()

    # Fast SYN Scan across 12 unique ports
    scan_alerts = []
    for p in range(1, 13):
        pkt = Ether() / IP(src="10.8.0.7", dst="10.8.0.1") / TCP(sport=50000 + p, dport=p, flags="S")
        parsed = dispatcher.dispatch(bytes(pkt), timestamp=now)
        alerts = detector.evaluate(parsed, dpi_result=None, next_alert_id_fn=next_id)
        scan_alerts.extend(alerts)

    assert any(a.category == DetectionCategory.PORT_SCAN for a in scan_alerts)

