"""Unit tests for Decision Engine and IPS Blocking Manager."""

import pytest
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

from ips.decision_engine import DecisionEngine
from ips.blocking_manager import BlockingManager
from models.alert_model import DecisionAction, DetectionCategory, IDSAlert, Severity
from parser.packet_dispatcher import PacketDispatcher


@pytest.fixture
def dispatcher():
    return PacketDispatcher()


@pytest.fixture
def decision_engine():
    return DecisionEngine()


@pytest.fixture
def blocking_manager():
    return BlockingManager(active_prevention=False)


def test_decision_engine_allow(dispatcher, decision_engine):
    """Tests that benign traffic without alerts yields an ALLOW decision."""
    pkt = dispatcher.dispatch(bytes(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP()))
    action = decision_engine.decide(pkt, dpi_result=None, alerts=[])
    assert action == DecisionAction.ALLOW


def test_decision_engine_alert(dispatcher, decision_engine):
    """Tests that medium severity alerts yield an ALERT decision."""
    pkt = dispatcher.dispatch(bytes(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP()))
    alert = IDSAlert.create(
        alert_id=1,
        timestamp=100.0,
        source_ip="1.1.1.1",
        destination_ip="2.2.2.2",
        source_port=1000,
        destination_port=80,
        protocol="TCP",
        category=DetectionCategory.SIGNATURE_MATCH,
        severity=Severity.MEDIUM,
        matched_rule="Suspicious Path",
        evidence="URI: /admin",
        recommended_action=DecisionAction.ALERT,
    )
    action = decision_engine.decide(pkt, dpi_result=None, alerts=[alert])
    assert action == DecisionAction.ALERT


def test_decision_engine_block(dispatcher, decision_engine):
    """Tests that high severity or block recommendation yields a BLOCK decision."""
    pkt = dispatcher.dispatch(bytes(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP()))
    alert = IDSAlert.create(
        alert_id=2,
        timestamp=100.0,
        source_ip="1.1.1.1",
        destination_ip="2.2.2.2",
        source_port=1000,
        destination_port=80,
        protocol="TCP",
        category=DetectionCategory.PORT_SCAN,
        severity=Severity.HIGH,
        matched_rule="Port Scan",
        evidence="15 ports probed",
        recommended_action=DecisionAction.BLOCK,
    )
    action = decision_engine.decide(pkt, dpi_result=None, alerts=[alert])
    assert action == DecisionAction.BLOCK


def test_simulation_mode_does_not_drop(dispatcher, blocking_manager):
    """Tests that Simulation Mode records simulated blocks without dropping traffic."""
    pkt = dispatcher.dispatch(bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP()))
    action, msg = blocking_manager.handle_decision(DecisionAction.BLOCK, pkt, alerts=[])

    assert action == DecisionAction.BLOCK
    assert "SIMULATED" in msg
    assert blocking_manager.simulated_blocks == 1
    assert blocking_manager.actual_verified_drops == 0


def test_safety_allowlist_override(dispatcher, blocking_manager):
    """Tests that loopback traffic is never blocked even if decision is BLOCK."""
    pkt = dispatcher.dispatch(bytes(Ether(src="00:00:00:00:00:00", dst="00:00:00:00:00:00") / IP(src="127.0.0.1", dst="127.0.0.1") / TCP()))
    action, msg = blocking_manager.handle_decision(DecisionAction.BLOCK, pkt, alerts=[])

    assert action == DecisionAction.ALERT
    assert "Allowlist" in msg
    assert blocking_manager.simulated_blocks == 0


def test_emergency_killswitch(dispatcher):
    """Tests emergency killswitch deactivates active blocking."""
    bm = BlockingManager(active_prevention=True)
    bm.trigger_emergency_killswitch()
    assert bm.active_prevention is False

    pkt = dispatcher.dispatch(bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP()))
    action, msg = bm.handle_decision(DecisionAction.BLOCK, pkt, alerts=[])
    assert "SIMULATED" in msg
    assert bm.actual_verified_drops == 0

