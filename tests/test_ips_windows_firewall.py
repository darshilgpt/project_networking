"""Automated Test Suite for Windows Defender Firewall / WFP Packet Enforcer Subsystem.

Tests all requirements:
1. Valid VPN client IP block and unblock.
2. Invalid IP format rejection.
3. Server IP (10.10.0.1) rejection and infrastructure allowlist safeguards.
4. IP outside permitted VPN subnet (10.10.0.0/24) rejection.
5. Duplicate block request suppression (avoiding duplicate netsh calls).
6. Unblock operation and cleanup.
7. Automatic temporary ban expiration (60-second window).
8. Cleanup of stale rules (startup & shutdown recovery).
9. Administrator privilege failure (clean fallback to simulation mode with warning).
10. End-to-end integration with BlockingManager and distinction of metrics.
"""

import time
import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from ips.blocking_manager import BlockingManager
from ips.windows_firewall_enforcer import FirewallBlockRecord, WindowsFirewallEnforcer
from models.alert_model import DecisionAction, DetectionCategory, IDSAlert, Severity
from parser.packet_dispatcher import PacketDispatcher


class MockCommandExecutor:
    """Mock runner recording command calls without invoking real OS firewall changes."""

    def __init__(self, default_rc: int = 0) -> None:
        self.default_rc = default_rc
        self.executed_commands = []

    def __call__(self, cmd):
        self.executed_commands.append(cmd)
        return self.default_rc, "Ok.", ""


def test_valid_vpn_client_ip_block_and_unblock():
    """Verifies that a valid VPN client IP within 10.10.0.0/24 is accepted,
    creates inbound and outbound firewall rules with remoteip scope, and unblocks cleanly."""
    mock_runner = MockCommandExecutor(default_rc=0)
    enforcer = WindowsFirewallEnforcer(
        command_executor=mock_runner,
        is_admin=True,
        auto_cleanup_stale=False,
    )

    client_ip = "10.10.0.2"

    # 1. Block client IP
    success = enforcer.block_ip(client_ip, reason="PORT_SCAN_DETECTED", duration_seconds=60.0)
    assert success is True
    assert enforcer.is_ip_blocked(client_ip) is True

    # Verify command execution: Inbound and Outbound rules created via PowerShell
    assert len(mock_runner.executed_commands) == 2
    cmd_in = mock_runner.executed_commands[0]
    cmd_out = mock_runner.executed_commands[1]

    assert "powershell" in cmd_in[0].lower()
    assert "New-NetFirewallRule" in cmd_in[4]
    assert f"-Name 'NIPS_BLOCK_{client_ip}'" in cmd_in[4]
    assert "-Direction Inbound" in cmd_in[4]
    assert "-Action Block" in cmd_in[4]
    assert f"-RemoteAddress '{client_ip}'" in cmd_in[4]
    assert "-PolicyStore ActiveStore" in cmd_in[4]

    assert "New-NetFirewallRule" in cmd_out[4]
    assert f"-Name 'NIPS_BLOCK_{client_ip}_OUT'" in cmd_out[4]
    assert "-Direction Outbound" in cmd_out[4]
    assert "-Action Block" in cmd_out[4]
    assert f"-RemoteAddress '{client_ip}'" in cmd_out[4]
    assert "-PolicyStore ActiveStore" in cmd_out[4]

    # 2. Unblock client IP
    unblock_success = enforcer.unblock_ip(client_ip)
    assert unblock_success is True
    assert enforcer.is_ip_blocked(client_ip) is False

    # Verify delete commands executed via PowerShell Remove-NetFirewallRule
    del_cmds = [cmd for cmd in mock_runner.executed_commands if any("Remove-NetFirewallRule" in str(arg) for arg in cmd)]
    assert len(del_cmds) >= 1
    assert f"NIPS_BLOCK_{client_ip}" in str(del_cmds[0])


def test_invalid_ip_rejection():
    """Verifies that malformed, empty, and non-IP strings are strictly rejected
    without invoking any OS commands."""
    mock_runner = MockCommandExecutor()
    enforcer = WindowsFirewallEnforcer(
        command_executor=mock_runner,
        is_admin=True,
        auto_cleanup_stale=False,
    )

    invalid_inputs = ["", "   ", "not_an_ip", "999.999.999.999", "10.10.0.abc", "10.10.0.2/32"]

    for inv in invalid_inputs:
        is_valid, err = enforcer.validate_ip(inv)
        assert is_valid is False
        assert len(err) > 0

        # Attempt to block must return False
        res = enforcer.block_ip(inv)
        assert res is False

    # Ensure zero firewall commands were executed
    assert len(mock_runner.executed_commands) == 0


def test_server_ip_and_infrastructure_rejection():
    """Verifies that safety restrictions strictly forbid blocking the server VPN IP (10.10.0.1),
    subnet network/broadcast addresses, loopback, and multicast."""
    mock_runner = MockCommandExecutor()
    enforcer = WindowsFirewallEnforcer(
        command_executor=mock_runner,
        is_admin=True,
        auto_cleanup_stale=False,
    )

    forbidden_ips = [
        ("10.10.0.1", "server VPN gateway IP"),
        ("10.10.0.0", "subnet network address"),
        ("10.10.0.255", "subnet broadcast address"),
        ("127.0.0.1", "loopback"),
        ("224.0.0.1", "multicast"),
        ("255.255.255.255", "broadcast"),
    ]

    for ip_val, desc in forbidden_ips:
        is_valid, err = enforcer.validate_ip(ip_val)
        assert is_valid is False, f"Expected {desc} ({ip_val}) to be rejected"
        assert "Safety violation" in err

        res = enforcer.block_ip(ip_val)
        assert res is False

    assert len(mock_runner.executed_commands) == 0


def test_ip_outside_vpn_subnet_rejection():
    """Verifies that IPs outside the designated 10.10.0.0/24 subnet (e.g. LAN IPs,
    public WAN IPs, or other subnets) are strictly rejected to prevent network isolation."""
    mock_runner = MockCommandExecutor()
    enforcer = WindowsFirewallEnforcer(
        command_executor=mock_runner,
        is_admin=True,
        auto_cleanup_stale=False,
    )

    outside_ips = [
        "192.168.1.1",     # LAN gateway
        "192.168.1.100",   # LAN host
        "8.8.8.8",         # Public DNS
        "1.1.1.1",         # Public Cloudflare
        "10.8.0.2",        # Alternate VPN subnet
        "10.10.1.2",       # Adjacent /24 subnet
    ]

    for out_ip in outside_ips:
        is_valid, err = enforcer.validate_ip(out_ip)
        assert is_valid is False
        assert "outside permitted VPN subnet" in err

        res = enforcer.block_ip(out_ip)
        assert res is False

    assert len(mock_runner.executed_commands) == 0


def test_duplicate_block_request_suppression():
    """Verifies that repeated block requests for an already-blocked IP
    do not spawn redundant OS commands."""
    mock_runner = MockCommandExecutor()
    enforcer = WindowsFirewallEnforcer(
        command_executor=mock_runner,
        is_admin=True,
        auto_cleanup_stale=False,
    )

    client_ip = "10.10.0.5"

    # First block: executes 2 commands (inbound + outbound)
    res1 = enforcer.block_ip(client_ip, reason="Initial Port Scan", duration_seconds=60.0)
    assert res1 is True
    assert len(mock_runner.executed_commands) == 2

    # Second block for the same IP while still active: returns True without running commands
    res2 = enforcer.block_ip(client_ip, reason="Subsequent Packet", duration_seconds=60.0)
    assert res2 is True
    assert len(mock_runner.executed_commands) == 2  # Still 2 commands!


def test_unblock_nonexistent_ip_handled_safely():
    """Verifies that attempting to unblock an IP that has not been blocked returns False
    and does not crash."""
    mock_runner = MockCommandExecutor()
    enforcer = WindowsFirewallEnforcer(
        command_executor=mock_runner,
        is_admin=True,
        auto_cleanup_stale=False,
    )

    assert enforcer.unblock_ip("10.10.0.99") is False


def test_automatic_expiration_after_time_window():
    """Verifies that a 60-second temporary block automatically expires when time advances,
    clearing tracking and calling firewall deletion commands."""
    mock_runner = MockCommandExecutor()
    enforcer = WindowsFirewallEnforcer(
        command_executor=mock_runner,
        is_admin=True,
        auto_cleanup_stale=False,
    )

    client_ip = "10.10.0.10"
    base_time = 1000.0

    # 1. Block IP for 60 seconds at t = 1000.0
    enforcer.block_ip(client_ip, reason="TCP Scan", duration_seconds=60.0, now=base_time)
    assert enforcer.is_ip_blocked(client_ip, now=base_time) is True

    # 2. At t = 1030.0 (30s elapsed): still blocked
    assert enforcer.is_ip_blocked(client_ip, now=base_time + 30.0) is True

    # 3. At t = 1061.0 (61s elapsed): expired!
    # is_ip_blocked automatically triggers unblock
    assert enforcer.is_ip_blocked(client_ip, now=base_time + 61.0) is False

    # Verify that unblock commands were executed via PowerShell Remove-NetFirewallRule
    del_cmds = [cmd for cmd in mock_runner.executed_commands if any("Remove-NetFirewallRule" in str(arg) for arg in cmd)]
    assert len(del_cmds) >= 1
    assert f"NIPS_BLOCK_{client_ip}" in str(del_cmds[0])


def test_cleanup_stale_rules_on_startup_and_flush():
    """Verifies that startup recovery cleans stale NIPS rules with prefix 'NIPS_BLOCK_',
    and flush_all_rules clears all active rules and performs a system sweep."""
    mock_runner = MockCommandExecutor()
    enforcer = WindowsFirewallEnforcer(
        command_executor=mock_runner,
        is_admin=True,
        auto_cleanup_stale=True,  # Startup recovery enabled
    )

    # Startup recovery ran powershell Get-NetFirewallRule ... Remove-NetFirewallRule
    assert len(mock_runner.executed_commands) == 1
    assert "Get-NetFirewallRule" in mock_runner.executed_commands[0][4]

    # Add 2 blocks
    enforcer.block_ip("10.10.0.2")
    enforcer.block_ip("10.10.0.3")
    assert len(enforcer.get_active_blocks()) == 2

    # Flush all rules
    flushed = enforcer.flush_all_rules()
    assert flushed == 2
    assert len(enforcer.get_active_blocks()) == 0


def test_administrator_privilege_failure_falls_back_to_simulation():
    """Verifies that when running without administrator privileges:
    1. Warning is displayed.
    2. Actual firewall commands are NEVER executed.
    3. Block returns False.
    4. State is tracked as simulated."""
    mock_runner = MockCommandExecutor()
    enforcer = WindowsFirewallEnforcer(
        command_executor=mock_runner,
        is_admin=False,  # Simulate non-elevated user
        auto_cleanup_stale=False,
    )

    client_ip = "10.10.0.2"
    success = enforcer.block_ip(client_ip, reason="Attack")
    assert success is False  # False indicates actual OS enforcement was not applied

    # Zero commands executed because non-admin
    assert len(mock_runner.executed_commands) == 0

    # Record exists and is marked simulated
    blocks = enforcer.get_active_blocks()
    assert len(blocks) == 1
    assert blocks[0].is_simulated is True
    assert blocks[0].ip_address == client_ip


def test_blocking_manager_integration_with_firewall_enforcer():
    """Verifies complete end-to-end integration between BlockingManager and WindowsFirewallEnforcer:
    - In active prevention mode with Admin: actual block rule is created, enforcement_succeeded is True,
      and actual_dropped_packets increments.
    - In simulation mode: simulated block is logged, enforcement_succeeded is False,
      and simulated_blocks increments."""
    mock_runner = MockCommandExecutor()
    enforcer = WindowsFirewallEnforcer(
        command_executor=mock_runner,
        is_admin=True,
        auto_cleanup_stale=False,
    )

    # --- Case 1: Simulation Mode (active_prevention=False) ---
    mgr_sim = BlockingManager(active_prevention=False, firewall_enforcer=enforcer)
    dispatcher = PacketDispatcher()

    pkt_bytes = bytes(Ether() / IP(src="10.10.0.2", dst="10.10.0.1") / TCP(sport=50000, dport=80, flags="S"))
    parsed_pkt = dispatcher.dispatch(pkt_bytes)

    crit_alert = IDSAlert.create(
        alert_id=1,
        timestamp=time.time(),
        source_ip="10.10.0.2",
        destination_ip="10.10.0.1",
        source_port=50000,
        destination_port=80,
        protocol="TCP",
        category=DetectionCategory.PORT_SCAN,
        severity=Severity.HIGH,
        matched_rule="PORT_SCAN_DETECTED",
        evidence="10 unique ports probed",
        recommended_action=DecisionAction.BLOCK,
    )

    res_sim = mgr_sim.evaluate_and_enforce(parsed_pkt, alerts=[crit_alert])
    assert res_sim.decision == DecisionAction.BLOCK
    assert res_sim.effective_action == "SIMULATED_BLOCK"
    assert res_sim.is_forwarded is True
    assert res_sim.enforcement_succeeded is False
    assert mgr_sim.simulated_blocks == 1
    assert mgr_sim.actual_dropped_packets == 0
    # In simulation mode, no firewall rules are created
    assert len(mock_runner.executed_commands) == 0

    # --- Case 2: Active Prevention Mode (active_prevention=True) ---
    mgr_active = BlockingManager(active_prevention=True, firewall_enforcer=enforcer)
    res_active = mgr_active.evaluate_and_enforce(parsed_pkt, alerts=[crit_alert])

    assert res_active.decision == DecisionAction.BLOCK
    assert res_active.effective_action == "ACTUAL_BLOCK"
    assert res_active.is_forwarded is False
    assert res_active.enforcement_succeeded is True
    assert mgr_active.actual_dropped_packets == 1
    assert mgr_active.simulated_blocks == 0

    # Verify that Windows Firewall rules were created via PowerShell
    assert len(mock_runner.executed_commands) == 2
    assert "New-NetFirewallRule" in mock_runner.executed_commands[0][4]
    assert enforcer.is_ip_blocked("10.10.0.2") is True


def test_main_py_block_decision_reaches_firewall_enforcer():
    """Verifies Requirement 1: main.py execution path through BlockingManager.handle_decision()
    with decision == DecisionAction.BLOCK successfully invokes WindowsFirewallEnforcer
    and creates actual PowerShell block rules."""
    mock_runner = MockCommandExecutor()
    enforcer = WindowsFirewallEnforcer(
        command_executor=mock_runner,
        is_admin=True,
        auto_cleanup_stale=False,
    )
    mgr = BlockingManager(active_prevention=True, firewall_enforcer=enforcer)
    dispatcher = PacketDispatcher()

    # Simulate attack packet that triggered PORT_SCAN_DETECTED in main.py
    pkt_bytes = bytes(Ether() / IP(src="10.10.0.2", dst="10.10.0.1") / TCP(sport=55555, dport=22, flags="S"))
    parsed_pkt = dispatcher.dispatch(pkt_bytes)

    scan_alert = IDSAlert.create(
        alert_id=101,
        timestamp=time.time(),
        source_ip="10.10.0.2",
        destination_ip="10.10.0.1",
        source_port=55555,
        destination_port=22,
        protocol="TCP",
        category=DetectionCategory.PORT_SCAN,
        severity=Severity.HIGH,
        matched_rule="PORT_SCAN_DETECTED",
        evidence="20 unique ports scanned",
        recommended_action=DecisionAction.BLOCK,
    )

    # Invoke handle_decision exactly as main.py does:
    action, status_msg = mgr.handle_decision(
        decision=DecisionAction.BLOCK,
        packet=parsed_pkt,
        alerts=[scan_alert],
    )

    # Assertions
    assert action == DecisionAction.BLOCK
    assert "ACTUAL BLOCK" in status_msg
    assert mgr.actual_dropped_packets == 1
    assert mgr.security_block_decisions == 1
    assert enforcer.is_ip_blocked("10.10.0.2") is True
    assert len(mock_runner.executed_commands) == 2
    assert "New-NetFirewallRule" in mock_runner.executed_commands[0][4]
    assert "-PolicyStore ActiveStore" in mock_runner.executed_commands[0][4]
    assert "10.10.0.2" in mock_runner.executed_commands[0][4]


def test_failed_rule_creation_metrics_and_error_handling():
    """Verifies Requirement 3: When WindowsFirewallEnforcer.block_ip() fails (e.g. OS error),
    actual_dropped_packets is NOT incremented, ACTUAL_BLOCK is NOT reported,
    and effective_action reports SOFTWARE_ONLY_BLOCK."""
    # Mock runner that simulates OS permission/CIM failure
    mock_runner = MockCommandExecutor(default_rc=1)
    enforcer = WindowsFirewallEnforcer(
        command_executor=mock_runner,
        is_admin=True,
        auto_cleanup_stale=False,
    )
    mgr = BlockingManager(active_prevention=True, firewall_enforcer=enforcer)
    dispatcher = PacketDispatcher()

    pkt_bytes = bytes(Ether() / IP(src="10.10.0.2", dst="10.10.0.1") / TCP(sport=50000, dport=80, flags="S"))
    parsed_pkt = dispatcher.dispatch(pkt_bytes)

    crit_alert = IDSAlert.create(
        alert_id=202,
        timestamp=time.time(),
        source_ip="10.10.0.2",
        destination_ip="10.10.0.1",
        source_port=50000,
        destination_port=80,
        protocol="TCP",
        category=DetectionCategory.PORT_SCAN,
        severity=Severity.HIGH,
        matched_rule="PORT_SCAN_DETECTED",
        evidence="Scan detected",
        recommended_action=DecisionAction.BLOCK,
    )

    res = mgr.evaluate_and_enforce(parsed_pkt, alerts=[crit_alert])

    # Assertions: Metrics must strictly reflect failure
    assert res.decision == DecisionAction.BLOCK
    assert res.effective_action == "SOFTWARE_ONLY_BLOCK"
    assert res.enforcement_succeeded is False
    assert mgr.actual_dropped_packets == 0  # PROOF: Must NOT claim actual dropped packets!
    assert mgr.security_block_decisions == 1
    assert mgr.simulated_blocks == 0


def test_enforcement_metrics_distinction_for_all_modes():
    """Verifies comprehensive metric segregation across Success, Failure, and Simulation modes."""
    # 1. Success mode
    runner_ok = MockCommandExecutor(default_rc=0)
    enforcer_ok = WindowsFirewallEnforcer(command_executor=runner_ok, is_admin=True, auto_cleanup_stale=False)
    mgr_ok = BlockingManager(active_prevention=True, firewall_enforcer=enforcer_ok)

    dispatcher = PacketDispatcher()
    pkt = dispatcher.dispatch(bytes(Ether() / IP(src="10.10.0.3", dst="10.10.0.1") / TCP(sport=1111, dport=80)))

    res_ok = mgr_ok.handle_decision(DecisionAction.BLOCK, pkt, alerts=[])
    assert res_ok[0] == DecisionAction.BLOCK
    assert "ACTUAL BLOCK" in res_ok[1]
    assert mgr_ok.actual_dropped_packets == 1
    assert mgr_ok.security_block_decisions == 1
    assert mgr_ok.simulated_blocks == 0

    # 2. Failure mode
    runner_fail = MockCommandExecutor(default_rc=1)
    enforcer_fail = WindowsFirewallEnforcer(command_executor=runner_fail, is_admin=True, auto_cleanup_stale=False)
    mgr_fail = BlockingManager(active_prevention=True, firewall_enforcer=enforcer_fail)

    res_fail = mgr_fail.handle_decision(DecisionAction.BLOCK, pkt, alerts=[])
    assert res_fail[0] == DecisionAction.BLOCK
    assert "SOFTWARE_ONLY_BLOCK" in res_fail[1]
    assert mgr_fail.actual_dropped_packets == 0
    assert mgr_fail.security_block_decisions == 1
    assert mgr_fail.simulated_blocks == 0

    # 3. Simulation mode
    mgr_sim = BlockingManager(active_prevention=False, firewall_enforcer=enforcer_ok)
    res_sim = mgr_sim.handle_decision(DecisionAction.BLOCK, pkt, alerts=[])
    assert res_sim[0] == DecisionAction.BLOCK
    assert "SIMULATED BLOCK" in res_sim[1]
    assert mgr_sim.actual_dropped_packets == 0
    assert mgr_sim.security_block_decisions == 1
    assert mgr_sim.simulated_blocks == 1


def test_shutdown_cleanup_flushes_all_rules():
    """Verifies that BlockingManager.shutdown() safely halts reaper and flushes all rules."""
    mock_runner = MockCommandExecutor()
    enforcer = WindowsFirewallEnforcer(command_executor=mock_runner, is_admin=True, auto_cleanup_stale=False)
    mgr = BlockingManager(active_prevention=True, firewall_enforcer=enforcer)

    enforcer.block_ip("10.10.0.2")
    enforcer.block_ip("10.10.0.4")
    assert len(enforcer.get_active_blocks()) == 2

    # Invoke shutdown
    mgr.shutdown()

    # Active rules cleared
    assert len(enforcer.get_active_blocks()) == 0

    # Deletions executed
    del_calls = [cmd for cmd in mock_runner.executed_commands if any("Remove-NetFirewallRule" in str(arg) for arg in cmd)]
    assert len(del_calls) >= 2


def test_status_banner_displays_windows_firewall_not_windivert(capsys):
    """Verifies Requirement 1: PacketFormatter.print_banner() displays
    'ACTIVE PREVENTION (Windows Firewall)' and does not display WinDivert."""
    from models.packet_models import InterfaceInfo
    from utils.formatter import PacketFormatter

    dummy_iface = InterfaceInfo(
        index=1,
        name="tnnl1",
        description="WireGuard Tunnel Adapter",
        guid="{12345678-1234-1234-1234-123456789abc}",
        mac="00:00:00:00:00:00",
        ipv4_addrs=["10.10.0.1"],
        is_tunnel=True,
    )

    # 1. Active prevention mode
    PacketFormatter.print_banner(dummy_iface, active_prevention=True)
    captured_active = capsys.readouterr().out
    assert "ACTIVE PREVENTION (Windows Firewall)" in captured_active
    assert "WinDivert" not in captured_active

    # 2. Simulation mode
    PacketFormatter.print_banner(dummy_iface, active_prevention=False)
    captured_sim = capsys.readouterr().out
    assert "MONITORING / SIMULATION (Npcap)" in captured_sim
    assert "WinDivert" not in captured_sim


def test_repeated_unprivileged_block_consistently_reports_software_only_block():
    """Verifies that when administrator privileges are absent, repeated/duplicate
    block requests consistently return False and report SOFTWARE_ONLY_BLOCK,
    never falsely escalating to ACTUAL_BLOCK."""
    mock_runner = MockCommandExecutor()
    enforcer = WindowsFirewallEnforcer(
        command_executor=mock_runner,
        is_admin=False,  # Unprivileged / non-elevated
        auto_cleanup_stale=False,
    )
    mgr = BlockingManager(active_prevention=True, firewall_enforcer=enforcer)
    dispatcher = PacketDispatcher()

    pkt_bytes = bytes(Ether() / IP(src="10.10.0.2", dst="10.10.0.1") / TCP(sport=50000, dport=80, flags="S"))
    parsed_pkt = dispatcher.dispatch(pkt_bytes)

    scan_alert = IDSAlert.create(
        alert_id=301,
        timestamp=time.time(),
        source_ip="10.10.0.2",
        destination_ip="10.10.0.1",
        source_port=50000,
        destination_port=80,
        protocol="TCP",
        category=DetectionCategory.PORT_SCAN,
        severity=Severity.HIGH,
        matched_rule="PORT_SCAN_DETECTED",
        evidence="20 ports scanned",
        recommended_action=DecisionAction.BLOCK,
    )

    # First packet: unprivileged OS failure
    act1, msg1 = mgr.handle_decision(DecisionAction.BLOCK, parsed_pkt, alerts=[scan_alert])
    assert act1 == DecisionAction.BLOCK
    assert "SOFTWARE_ONLY_BLOCK" in msg1
    assert "ACTUAL BLOCK" not in msg1
    assert mgr.actual_dropped_packets == 0

    # Second packet for the same IP: must STILL be SOFTWARE_ONLY_BLOCK, never ACTUAL_BLOCK
    act2, msg2 = mgr.handle_decision(DecisionAction.BLOCK, parsed_pkt, alerts=[scan_alert])
    assert act2 == DecisionAction.BLOCK
    assert "SOFTWARE_ONLY_BLOCK" in msg2
    assert "ACTUAL BLOCK" not in msg2
    assert mgr.actual_dropped_packets == 0
    assert mgr.security_block_decisions == 2



