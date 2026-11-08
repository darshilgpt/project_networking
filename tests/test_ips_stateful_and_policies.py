"""Controlled tests for Stateful Firewall, Per-Client Policies, Rate Limiting, and Expirable Bans."""

import time
import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether

from ips.firewall_policy import (
    AllowlistDenylistManager,
    ClientSecurityPolicy,
    DynamicBlockManager,
    EmergencyKillswitch,
    FirewallRule,
)
from ips.rate_limiter import RateLimiter
from ips.stateful_firewall import ConnectionState, FirewallAction, StatefulFirewall
from models.alert_model import DecisionAction, Severity
from parser.packet_dispatcher import PacketDispatcher


def test_stateful_firewall_tcp_lifecycle():
    """Verifies TCP 3-way handshake state tracking and unsolicited packet dropping."""
    fw = StatefulFirewall()
    dispatcher = PacketDispatcher()
    now = time.time()

    # 1. Outbound SYN initiated by client -> NEW (Allowed)
    syn_pkt = Ether() / IP(src="10.8.0.2", dst="93.184.216.34") / TCP(sport=51000, dport=80, flags="S", seq=100)
    p_syn = dispatcher.dispatch(bytes(syn_pkt), timestamp=now)
    res_syn = fw.evaluate_packet(p_syn, is_outbound_from_client=True)
    assert res_syn.action == FirewallAction.ALLOW
    assert res_syn.state == ConnectionState.NEW

    # 2. Inbound SYN-ACK from server -> ESTABLISHED (Allowed)
    synack_pkt = Ether() / IP(src="93.184.216.34", dst="10.8.0.2") / TCP(sport=80, dport=51000, flags="SA", seq=500, ack=101)
    p_synack = dispatcher.dispatch(bytes(synack_pkt), timestamp=now + 0.05)
    res_synack = fw.evaluate_packet(p_synack, is_outbound_from_client=False)
    assert res_synack.action == FirewallAction.ALLOW
    assert res_synack.state == ConnectionState.ESTABLISHED

    # 3. Inbound unsolicited mid-stream packet without state -> INVALID (Dropped!)
    unsolicited_pkt = Ether() / IP(src="198.51.100.99", dst="10.8.0.2") / TCP(sport=12345, dport=51000, flags="A", seq=1, ack=1)
    p_unsol = dispatcher.dispatch(bytes(unsolicited_pkt), timestamp=now + 0.1)
    res_unsol = fw.evaluate_packet(p_unsol, is_outbound_from_client=False)
    assert res_unsol.action == FirewallAction.DROP
    assert res_unsol.state == ConnectionState.INVALID


def test_client_security_policies():
    """Verifies per-client isolation, blocked protocols, blocked ports, and quarantine."""
    dispatcher = PacketDispatcher()

    # Policy: Client Bob is restricted (Cannot access SSH port 22 or SMB port 445)
    policy_bob = ClientSecurityPolicy(
        client_ip="10.8.0.3",
        client_name="Bob-Restricted",
        blocked_dst_ports={22, 445},
        blocked_protocols={"SSH", "SMB"},
    )

    # A. Bob attempts SSH (port 22) -> Blocked by client policy
    ssh_pkt = Ether() / IP(src="10.8.0.3", dst="192.168.1.50") / TCP(sport=55000, dport=22, flags="S")
    p_ssh = dispatcher.dispatch(bytes(ssh_pkt))
    allowed_ssh, reason_ssh = policy_bob.evaluate(p_ssh)
    assert not allowed_ssh
    assert "Port 22 is blocked" in reason_ssh

    # B. Bob attempts HTTP (port 80) -> Allowed
    http_pkt = Ether() / IP(src="10.8.0.3", dst="192.168.1.50") / TCP(sport=55000, dport=80, flags="S")
    p_http = dispatcher.dispatch(bytes(http_pkt))
    allowed_http, _ = policy_bob.evaluate(p_http)
    assert allowed_http

    # C. Quarantined Client -> Non-DNS traffic blocked
    policy_bob.quarantined = True
    policy_bob.quarantine_reason = "Compromised by Ransomware"
    allowed_quar, reason_quar = policy_bob.evaluate(p_http)
    assert not allowed_quar
    assert "QUARANTINED" in reason_quar

    # DNS (port 53) still permitted for quarantine notifications
    dns_pkt = Ether() / IP(src="10.8.0.3", dst="8.8.8.8") / UDP(sport=55000, dport=53)
    p_dns = dispatcher.dispatch(bytes(dns_pkt))
    allowed_dns, _ = policy_bob.evaluate(p_dns)
    assert allowed_dns


def test_token_bucket_rate_limiter():
    """Verifies packet rate limiting and burst exhaustion."""
    # 5 pps rate, burst capacity 5 tokens
    limiter = RateLimiter(default_pps_limit=5.0, default_pps_burst=5.0)
    now = time.time()

    # First 5 packets consume burst capacity successfully
    for _ in range(5):
        ok, _ = limiter.check_rate_limit("10.8.0.4", packet_bytes=100, now=now)
        assert ok

    # 6th packet exceeds burst allowance without elapsed time -> Rejected
    ok_exceeded, reason = limiter.check_rate_limit("10.8.0.4", packet_bytes=100, now=now)
    assert not ok_exceeded
    assert "rate limit exceeded" in reason.lower()

    # After 1.0 second, 5 tokens regenerate
    ok_regen, _ = limiter.check_rate_limit("10.8.0.4", packet_bytes=100, now=now + 1.0)
    assert ok_regen


def test_dynamic_expirable_blocking():
    """Verifies temporary bans, remaining duration calculation, and auto-expiry."""
    mgr = DynamicBlockManager(default_ban_seconds=10.0)
    now = time.time()

    # Issue dynamic block for 2.0 seconds
    mgr.add_block(ip_address="10.8.0.50", reason="SYN Flood Attack", severity=Severity.CRITICAL, duration_seconds=2.0)

    # Immediately check: blocked
    is_blocked, block = mgr.is_blocked("10.8.0.50", now=now)
    assert is_blocked
    assert block is not None
    assert block.time_remaining(now) > 1.0

    # Check after 3.0 seconds: expired
    is_blocked_later, _ = mgr.is_blocked("10.8.0.50", now=now + 3.0)
    assert not is_blocked_later


def test_emergency_killswitch():
    """Verifies instant fail-open killswitch activation and reset."""
    switch = EmergencyKillswitch()
    assert not switch.is_active

    switch.activate(reason="Power outage maintenance")
    assert switch.is_active
    assert switch.trigger_reason == "Power outage maintenance"

    switch.deactivate()
    assert not switch.is_active

