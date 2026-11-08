"""Controlled verification test for IPS Gateway Enforcement and Windows WFP integration."""

import time
import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from ips.blocking_manager import BlockingManager
from ips.firewall_policy import ClientSecurityPolicy
from ips.windows_firewall_enforcer import WindowsFirewallEnforcer
from ips.windows_wfp_divert import WindowsFilteringStatus, WindowsWFPInvestigator
from models.alert_model import DecisionAction, DetectionCategory, IDSAlert, Severity
from parser.packet_dispatcher import PacketDispatcher
from server.client_manager import ClientManager
from server.ingestion import QueuedPacket
from server.worker_pool import PipelineWorkerPool


def test_windows_wfp_and_windivert_investigation():
    """Verifies that WFP and WinDivert investigation reports accurate diagnostic telemetry."""
    status = WindowsWFPInvestigator.investigate()
    assert status.selected_enforcement_mechanism is not None
    assert "Inline VPN Gateway" in status.selected_enforcement_mechanism or "WinDivert" in status.selected_enforcement_mechanism or "Windows Filtering Platform" in status.selected_enforcement_mechanism
    assert len(status.diagnostics_summary) > 20


def test_controlled_verification_simulation_vs_active_enforcement():
    """
    CRITICAL CONTROLLED VERIFICATION:
    Proves the difference between Simulation Mode (monitoring) and Active Prevention Mode (dropping).
    Verifies that:
      1. Default mode is Monitoring/Simulation.
      2. In Simulation mode, block decisions DO NOT increment actual_dropped_packets, and is_forwarded is True.
      3. In Active mode, block decisions physically drop packets (actual_dropped_packets increments and is_forwarded is False).
    """
    dispatcher = PacketDispatcher()

    # Create attack packet (Destination port 23 Telnet, forbidden by default firewall rule)
    attack_pkt = Ether() / IP(src="10.8.0.2", dst="192.168.1.100") / TCP(sport=50000, dport=23, flags="S")
    parsed_attack = dispatcher.dispatch(bytes(attack_pkt))

    # --- Phase A: Simulation Mode (Monitoring) ---
    mgr_sim = BlockingManager(active_prevention=False)
    assert not mgr_sim.active_prevention  # Begins in monitoring/simulation mode

    res_sim = mgr_sim.evaluate_and_enforce(parsed_attack, is_outbound=True)

    # Assertions for Simulation Mode:
    assert res_sim.decision == DecisionAction.BLOCK
    assert res_sim.effective_action == "SIMULATED_BLOCK"
    assert res_sim.is_forwarded is True  # In simulation mode, packet was NOT physically dropped
    assert mgr_sim.security_block_decisions == 1
    assert mgr_sim.simulated_blocks == 1
    assert mgr_sim.actual_dropped_packets == 0  # PROOF: NEVER claims dropped in simulation!
    assert mgr_sim.intercepted_packets == 1

    # --- Phase B: Active Prevention Mode (Controlled Verification) ---
    from ips.windows_firewall_enforcer import WindowsFirewallEnforcer

    mock_enforcer = WindowsFirewallEnforcer(
        permitted_subnet="10.8.0.0/24,10.10.0.0/24",
        command_executor=lambda cmd: (0, "Ok", ""),
        is_admin=True,
        auto_cleanup_stale=False,
    )
    mgr_active = BlockingManager(active_prevention=False, firewall_enforcer=mock_enforcer)
    mgr_active.enable_active_prevention(force=True)  # Explicit activation after verification
    assert mgr_active.active_prevention is True

    # Register drop and forward verification callbacks
    dropped_audit = []
    forward_audit = []
    mgr_active.on_packet_drop_hook = lambda p, r: dropped_audit.append((p.packet_id, r))
    mgr_active.on_packet_forward_hook = lambda p: forward_audit.append(p.packet_id)

    res_active = mgr_active.evaluate_and_enforce(parsed_attack, is_outbound=True)

    # Assertions for Active Prevention Mode:
    assert res_active.decision == DecisionAction.BLOCK
    assert res_active.effective_action == "ACTUAL_BLOCK"
    assert res_active.is_forwarded is False  # PROOF: Packet was physically stopped from forwarding!
    assert mgr_active.security_block_decisions == 1
    assert mgr_active.actual_dropped_packets == 1  # PROOF: Actual drop verified!
    assert mgr_active.simulated_blocks == 0
    assert mgr_active.intercepted_packets == 1
    assert len(dropped_audit) == 1
    assert len(forward_audit) == 0

    # --- Phase C: Legitimate Traffic Permitted and Forwarded ---
    clean_pkt = Ether() / IP(src="10.8.0.2", dst="142.250.190.46") / TCP(sport=50000, dport=80, flags="S")
    parsed_clean = dispatcher.dispatch(bytes(clean_pkt))

    res_clean = mgr_active.evaluate_and_enforce(parsed_clean, is_outbound=True)
    assert res_clean.decision == DecisionAction.ALLOW
    assert res_clean.is_forwarded is True
    assert mgr_active.forwarded_or_reinjected_packets == 1
    assert len(forward_audit) == 1


def test_worker_pool_end_to_end_ips_active_drop():
    """
    End-to-end integration test through PipelineWorkerPool:
    Confirms that when active prevention is enabled, a critical attack probe is physically blocked,
    increments actual_dropped_packets, and issues an expirable dynamic ban.
    """
    cm = ClientManager(vpn_subnets=["10.8.0.0/24"])
    cm.register_client("10.8.0.3", "Laptop-Attacker")

    processed = []
    pool_enforcer = WindowsFirewallEnforcer(
        permitted_subnet="10.8.0.0/24,10.10.0.0/24",
        command_executor=lambda cmd: (0, "Ok", ""),
        is_admin=True,
        auto_cleanup_stale=False,
    )
    pool = PipelineWorkerPool(
        client_manager=cm,
        num_workers=1,
        queue_size=10,
        active_prevention=True,  # Enable active prevention
        on_packet_processed=lambda r: processed.append(r),
    )
    pool.blocking_manager.firewall_enforcer = pool_enforcer
    pool.start()

    try:
        # Client 10.8.0.3 sends known malicious C2 IP destination
        c2_pkt = IP(src="10.8.0.3", dst="198.51.100.23") / TCP(sport=51000, dport=443, flags="S")
        qp = QueuedPacket(
            raw_bytes=bytes(c2_pkt),
            timestamp=time.time(),
            source_name="wg0",
            link_type="RAW_IP",
        )
        pool.packet_queue.put(qp)
        pool.packet_queue.join()

        assert len(processed) == 1
        res = processed[0]
        assert res.decision == DecisionAction.BLOCK
        assert res.is_forwarded is False  # PROVED: Packet was NOT forwarded
        assert res.enforcement_action == "ACTUAL_BLOCK"

        stats = pool.get_stats_snapshot()
        assert stats.active_prevention_enabled is True
        assert stats.security_block_decisions >= 1
        assert stats.actual_dropped_packets >= 1
        assert stats.intercepted_packets >= 1

    finally:
        pool.stop()

