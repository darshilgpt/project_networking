"""Unit tests for Signature and Behavioural IDS Engine."""

import pytest
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP

from dpi.dpi_engine import DPIEngine
from ids.ids_engine import IDSEngine
from models.alert_model import DecisionAction, DetectionCategory, Severity
from parser.packet_dispatcher import PacketDispatcher


@pytest.fixture
def dispatcher():
    return PacketDispatcher()


@pytest.fixture
def dpi_engine():
    return DPIEngine()


@pytest.fixture
def ids_engine():
    return IDSEngine()


def test_signature_detection_http_path(dispatcher, dpi_engine, ids_engine):
    """Tests that an HTTP request to /.env triggers a HIGH severity BLOCK alert."""
    payload = b"GET /.env HTTP/1.1\r\nHost: target.com\r\n\r\n"
    pkt = dispatcher.dispatch(
        bytes(Ether() / IP(src="192.168.1.50", dst="10.0.0.1") / TCP(sport=54321, dport=80, flags="PA") / payload)
    )

    dpi_res = dpi_engine.inspect(pkt)
    alerts = ids_engine.evaluate(pkt, dpi_res)

    assert len(alerts) >= 1
    alert = next(a for a in alerts if a.category == DetectionCategory.SIGNATURE_MATCH)
    assert alert.severity == Severity.HIGH
    assert alert.recommended_action == DecisionAction.BLOCK
    assert "Environment File" in alert.matched_rule


def test_port_scan_detection(dispatcher, dpi_engine, ids_engine):
    """Tests detecting a port scan when a single source probes 16 different destination ports."""
    src = "192.168.1.99"
    dst = "10.0.0.5"

    alerts_found = []
    base_time = 500.0

    for port in range(1, 18):
        pkt = dispatcher.dispatch(
            bytes(Ether() / IP(src=src, dst=dst) / TCP(sport=40000 + port, dport=port, flags="S")),
            timestamp=base_time + (port * 0.1),
        )
        dpi_res = dpi_engine.inspect(pkt)
        alerts = ids_engine.evaluate(pkt, dpi_res)
        for a in alerts:
            if a.category == DetectionCategory.PORT_SCAN:
                alerts_found.append(a)

    assert len(alerts_found) >= 1
    ps_alert = alerts_found[0]
    assert ps_alert.source_ip == src
    assert ps_alert.severity == Severity.HIGH
    assert ps_alert.recommended_action == DecisionAction.BLOCK


def test_syn_flood_detection(dispatcher, dpi_engine, ids_engine):
    """Tests detecting a high TCP SYN rate burst."""
    src = "172.16.5.5"
    dst = "10.0.0.10"
    base_time = 1000.0
    syn_alerts = []

    for i in range(30):
        pkt = dispatcher.dispatch(
            bytes(Ether() / IP(src=src, dst=dst) / TCP(sport=30000 + i, dport=80, flags="S")),
            timestamp=base_time + (i * 0.02),  # 30 SYNs in 0.6 seconds
        )
        dpi_res = dpi_engine.inspect(pkt)
        alerts = ids_engine.evaluate(pkt, dpi_res)
        for a in alerts:
            if a.category == DetectionCategory.SYN_FLOOD:
                syn_alerts.append(a)

    assert len(syn_alerts) >= 1
    assert syn_alerts[0].severity == Severity.CRITICAL
    assert syn_alerts[0].recommended_action == DecisionAction.BLOCK


def test_malformed_packet_detection(dispatcher, dpi_engine, ids_engine):
    """Tests generating an alert when a malformed packet arrives."""
    corrupted_data = b"\x00\x11\x22\x33"  # Truncated Ethernet frame
    pkt = dispatcher.dispatch(corrupted_data)

    dpi_res = dpi_engine.inspect(pkt)
    alerts = ids_engine.evaluate(pkt, dpi_res)

    assert any(a.category == DetectionCategory.MALFORMED_PACKET for a in alerts)

