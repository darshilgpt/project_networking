"""Automated test suite verifying reliable Port Scan Detection across all attack vectors:
1. A scan across 20 unique TCP ports.
2. Repeated packets to one port.
3. Normal HTTP connections.
4. A small number of ordinary connections.
5. UDP port scanning.
6. Different client IPs tracked independently.
7. Tracking per (source IP, destination IP).
8. Old tracking data expires properly to prevent memory growth.
9. Verification of required debug-level logging.
"""

import logging
import time
import pytest
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP

from ids.behaviour_detector import BehaviourDetector
from ids.ids_engine import IDSEngine
from ids.port_scan_detector import PortScanDetector
from models.alert_model import DecisionAction, DetectionCategory, Severity
from parser.packet_dispatcher import PacketDispatcher
from utils.formatter import PacketFormatter


@pytest.fixture
def dispatcher():
    return PacketDispatcher()


@pytest.fixture
def ids_engine():
    return IDSEngine()


def test_normal_http_traffic_no_port_scan(dispatcher, ids_engine):
    """Verifies that normal HTTP and HTTPS traffic to ports 80 and 443
    does not trigger port-scan detection."""
    client_ip = "10.10.0.2"
    server_ip = "10.10.0.1"
    now = time.time()

    alerts = []

    # Simulate 20 HTTP/HTTPS connection flows:
    # SYN -> SYN-ACK (server) -> ACK -> Data (PSH-ACK) -> FIN
    for i in range(20):
        dport = 443 if i % 2 == 0 else 80
        sport = 50000 + i

        # 1. Outbound SYN
        pkt_syn = dispatcher.dispatch(
            bytes(Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=dport, flags="S")),
            timestamp=now + (i * 0.1),
        )
        alerts.extend(ids_engine.evaluate(pkt_syn, dpi_result=None))

        # 2. Server SYN-ACK (reverse direction)
        pkt_sa = dispatcher.dispatch(
            bytes(Ether() / IP(src=server_ip, dst=client_ip) / TCP(sport=dport, dport=sport, flags="SA")),
            timestamp=now + (i * 0.1) + 0.01,
        )
        alerts.extend(ids_engine.evaluate(pkt_sa, dpi_result=None))

        # 3. Client ACK (established)
        pkt_ack = dispatcher.dispatch(
            bytes(Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=dport, flags="A")),
            timestamp=now + (i * 0.1) + 0.02,
        )
        alerts.extend(ids_engine.evaluate(pkt_ack, dpi_result=None))

        # 4. Client HTTP request data
        pkt_data = dispatcher.dispatch(
            bytes(Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=dport, flags="PA") / b"GET / HTTP/1.1\r\n\r\n"),
            timestamp=now + (i * 0.1) + 0.03,
        )
        alerts.extend(ids_engine.evaluate(pkt_data, dpi_result=None))

    port_scans = [a for a in alerts if a.category == DetectionCategory.PORT_SCAN]
    assert len(port_scans) == 0, f"Normal web traffic produced unexpected port scan alerts: {port_scans}"


def test_small_number_of_ordinary_connections_no_false_positive(dispatcher, ids_engine):
    """Verifies that legitimate connections to a small number of ordinary ports (e.g. SSH, HTTP, HTTPS)
    do not trigger port-scan alerts."""
    client_ip = "10.10.0.2"
    server_ip = "10.10.0.1"
    now = time.time()

    alerts = []
    # Client connects to 3 legitimate distinct ports (22, 80, 443)
    for p in [22, 80, 443]:
        pkt = dispatcher.dispatch(
            bytes(Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=51000 + p, dport=p, flags="S")),
            timestamp=now + (p * 0.2),
        )
        alerts.extend(ids_engine.evaluate(pkt, dpi_result=None))

    port_scans = [a for a in alerts if a.category == DetectionCategory.PORT_SCAN]
    assert len(port_scans) == 0, "Few legitimate connections should not trigger port scan alert"


def test_scan_across_20_unique_tcp_ports(dispatcher, ids_engine, caplog):
    """Verifies that scanning across 20 unique TCP ports triggers a PORT_SCAN alert
    with all required fields and generates debug-level logging."""
    client_ip = "10.10.0.2"
    server_ip = "10.10.0.1"
    now = time.time()

    alerts = []

    with caplog.at_level(logging.DEBUG, logger="dpi_ids_ips.ids.port_scan_detector"):
        # Client probes 20 unique ports sequentially
        for port in range(1, 21):
            pkt = dispatcher.dispatch(
                bytes(Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=52000 + port, dport=port, flags="S")),
                timestamp=now + (port * 0.5),
            )
            alerts.extend(ids_engine.evaluate(pkt, dpi_result=None))

    port_scans = [a for a in alerts if a.category == DetectionCategory.PORT_SCAN]
    assert len(port_scans) >= 1, "Expected PORT_SCAN alert for scanning 20 unique TCP ports"

    alert = port_scans[0]
    assert alert.category == DetectionCategory.PORT_SCAN
    assert alert.source_ip == client_ip
    assert alert.destination_ip == server_ip
    assert alert.protocol == "TCP"
    assert alert.severity == Severity.HIGH
    assert alert.recommended_action == DecisionAction.BLOCK

    # Validate evidence content
    ev = alert.evidence
    assert f"Source: {client_ip}" in ev
    assert f"Target: {server_ip}" in ev
    assert "Unique Ports:" in ev
    assert "Protocol: TCP" in ev
    assert "Time Window:" in ev

    # Verify debug logging contains all required fields:
    # Source IP, Destination IP, Destination port, TCP flags, Unique ports currently tracked, Detection threshold, Detection decision
    debug_records = [r.message for r in caplog.records if "[PORT_SCAN_DEBUG]" in r.message]
    assert len(debug_records) >= 20, f"Expected at least 20 debug log records, got {len(debug_records)}"

    sample_log = debug_records[0]
    assert "Source IP:" in sample_log
    assert "Destination IP:" in sample_log
    assert "Destination Port:" in sample_log
    assert "TCP Flags: SYN" in sample_log
    assert "Unique Ports Tracked:" in sample_log
    assert "Detection Threshold:" in sample_log
    assert "Detection Decision:" in sample_log

    # Verify that later records reflect alert generation decision
    alert_logs = [log for log in debug_records if "ALERT_GENERATED" in log]
    assert len(alert_logs) >= 1, "Expected at least one debug log with decision ALERT_GENERATED"

    # Format verification: check that PacketFormatter renders the alert correctly
    formatted = PacketFormatter.format_dpi_packet(
        packet=pkt,
        flow=None,
        dpi_result=None,
        alerts=[alert],
        action=DecisionAction.BLOCK,
        verbosity="normal",
    )
    assert "[IDS ALERT]" in formatted
    assert f"Source: {client_ip}" in formatted
    assert f"Target: {server_ip}" in formatted
    assert "Severity: HIGH" in formatted


def test_repeated_packets_same_port_no_inflation(dispatcher, ids_engine):
    """Verifies that repeated packets and retransmissions targeting one port
    do NOT inflate the unique-port count and do not trigger a port scan alert."""
    client_ip = "10.10.0.2"
    server_ip = "10.10.0.1"
    now = time.time()

    alerts = []

    # Send 30 SYN retries to port 80 only
    for i in range(30):
        pkt = dispatcher.dispatch(
            bytes(Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=53000 + i, dport=80, flags="S")),
            timestamp=now + (i * 0.2),
        )
        alerts.extend(ids_engine.evaluate(pkt, dpi_result=None))

    # Also send 20 ACK packets to port 80
    for i in range(20):
        pkt_ack = dispatcher.dispatch(
            bytes(Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=53000 + i, dport=80, flags="A")),
            timestamp=now + 10.0 + (i * 0.1),
        )
        alerts.extend(ids_engine.evaluate(pkt_ack, dpi_result=None))

    port_scans = [a for a in alerts if a.category == DetectionCategory.PORT_SCAN]
    assert len(port_scans) == 0, f"Repeated packets to a single port should not trigger PORT_SCAN: {port_scans}"


def test_different_client_ips_tracked_independently(dispatcher, ids_engine):
    """Verifies that multiple clients (e.g. 10.10.0.2 and 10.10.0.3) are tracked
    in separate states so their probed ports do not cross-pollinate."""
    client_a = "10.10.0.2"
    client_b = "10.10.0.3"
    server_ip = "10.10.0.1"
    now = time.time()

    alerts = []

    # Client A probes 6 ports (ports 1 to 6)
    for p in range(1, 7):
        pkt_a = dispatcher.dispatch(
            bytes(Ether() / IP(src=client_a, dst=server_ip) / TCP(sport=54000 + p, dport=p, flags="S")),
            timestamp=now + (p * 0.1),
        )
        alerts.extend(ids_engine.evaluate(pkt_a, dpi_result=None))

    # Client B probes 6 different ports (ports 101 to 106)
    for p in range(101, 107):
        pkt_b = dispatcher.dispatch(
            bytes(Ether() / IP(src=client_b, dst=server_ip) / TCP(sport=54000 + p, dport=p, flags="S")),
            timestamp=now + (p * 0.1),
        )
        alerts.extend(ids_engine.evaluate(pkt_b, dpi_result=None))

    # Neither client has reached threshold 10 individually
    assert len([a for a in alerts if a.category == DetectionCategory.PORT_SCAN]) == 0

    # Now Client A probes 5 more ports (ports 7 to 11) -> total 11 unique ports for Client A
    client_a_alerts = []
    for p in range(7, 12):
        pkt_a2 = dispatcher.dispatch(
            bytes(Ether() / IP(src=client_a, dst=server_ip) / TCP(sport=54000 + p, dport=p, flags="S")),
            timestamp=now + 5.0 + (p * 0.1),
        )
        client_a_alerts.extend(ids_engine.evaluate(pkt_a2, dpi_result=None))

    # Client A should trigger PORT_SCAN alert
    a_scans = [a for a in client_a_alerts if a.category == DetectionCategory.PORT_SCAN]
    assert len(a_scans) >= 1
    assert a_scans[0].source_ip == client_a


def test_tracked_per_source_ip_and_destination_ip(dispatcher, ids_engine):
    """Verifies that unique destination ports are tracked per (source_ip, destination_ip) pair."""
    client_ip = "10.10.0.2"
    server_1 = "10.10.0.1"
    server_2 = "10.10.0.5"
    now = time.time()

    alerts = []

    # Client probes 6 ports on Server 1
    for p in range(1, 7):
        pkt1 = dispatcher.dispatch(
            bytes(Ether() / IP(src=client_ip, dst=server_1) / TCP(sport=56000 + p, dport=p, flags="S")),
            timestamp=now + (p * 0.1),
        )
        alerts.extend(ids_engine.evaluate(pkt1, dpi_result=None))

    # Client probes 6 ports on Server 2
    for p in range(1, 7):
        pkt2 = dispatcher.dispatch(
            bytes(Ether() / IP(src=client_ip, dst=server_2) / TCP(sport=56000 + p, dport=p, flags="S")),
            timestamp=now + (p * 0.1),
        )
        alerts.extend(ids_engine.evaluate(pkt2, dpi_result=None))

    # Total ports probed by client across network is 12, but per-target port count is 6 on each.
    # Neither target has reached threshold 10, so neither triggers false alert.
    assert len([a for a in alerts if a.category == DetectionCategory.PORT_SCAN]) == 0

    # Now probe 5 more ports on Server 1 -> 11 unique ports on Server 1
    server1_alerts = []
    for p in range(7, 12):
        pkt1_more = dispatcher.dispatch(
            bytes(Ether() / IP(src=client_ip, dst=server_1) / TCP(sport=56000 + p, dport=p, flags="S")),
            timestamp=now + 5.0 + (p * 0.1),
        )
        server1_alerts.extend(ids_engine.evaluate(pkt1_more, dpi_result=None))

    s1_scans = [a for a in server1_alerts if a.category == DetectionCategory.PORT_SCAN]
    assert len(s1_scans) >= 1
    assert s1_scans[0].destination_ip == server_1


def test_udp_scanning_detected_separately(dispatcher, ids_engine):
    """Verifies that UDP port scanning across 12 unique UDP ports is detected separately
    with protocol set to UDP."""
    client_ip = "10.10.0.2"
    server_ip = "10.10.0.1"
    now = time.time()

    alerts = []

    # 1. Legitimate UDP queries (DNS port 53, SSDP 1900, mDNS 5353) do not trigger scans
    for svc_port in [53, 1900, 5353]:
        pkt_svc = dispatcher.dispatch(
            bytes(Ether() / IP(src=client_ip, dst=server_ip) / UDP(sport=55000, dport=svc_port) / b"QUERY"),
            timestamp=now,
        )
        alerts.extend(ids_engine.evaluate(pkt_svc, dpi_result=None))

    assert len([a for a in alerts if a.category == DetectionCategory.PORT_SCAN]) == 0

    # 2. Client probes 12 unique UDP ports (ports 2000 to 2011)
    for p in range(2000, 2012):
        pkt_udp = dispatcher.dispatch(
            bytes(Ether() / IP(src=client_ip, dst=server_ip) / UDP(sport=55000 + p, dport=p) / b"PROBE"),
            timestamp=now + ((p - 2000) * 0.5),
        )
        alerts.extend(ids_engine.evaluate(pkt_udp, dpi_result=None))

    udp_scans = [a for a in alerts if a.category == DetectionCategory.PORT_SCAN and a.protocol == "UDP"]
    assert len(udp_scans) >= 1, "Expected UDP PORT_SCAN alert"
    assert udp_scans[0].source_ip == client_ip
    assert udp_scans[0].destination_ip == server_ip
    assert "UDP" in udp_scans[0].evidence


def test_old_tracking_data_expires_properly():
    """Verifies that probes older than the sliding window expire to prevent memory growth."""
    detector = PortScanDetector(
        config={"port_scan": {"enabled": True, "time_window_seconds": 10.0, "unique_ports_threshold": 5}}
    )
    dispatcher = PacketDispatcher()
    base_time = 1000.0

    # Send 4 probes at t = 1000s
    for p in range(1, 5):
        pkt = dispatcher.dispatch(
            bytes(Ether() / IP(src="10.10.0.2", dst="10.10.0.1") / TCP(sport=40000 + p, dport=p, flags="S")),
            timestamp=base_time,
        )
        detector.evaluate(pkt, next_alert_id_fn=lambda: 1)

    tracker = detector.trackers[("10.10.0.2", "10.10.0.1")]
    assert len(tracker.probes) == 4

    # Advance time past window: t = 1015s (15s later, window is 10s)
    pkt_future = dispatcher.dispatch(
        bytes(Ether() / IP(src="10.10.0.2", dst="10.10.0.1") / TCP(sport=40010, dport=10, flags="S")),
        timestamp=base_time + 15.0,
    )
    detector.evaluate(pkt_future, next_alert_id_fn=lambda: 2)

    # Older probes from t=1000s must have been purged from the queue
    assert len(tracker.probes) == 1
    assert tracker.probes[0].dst_port == 10


def test_30_unique_ports_generate_one_initial_alert(dispatcher, ids_engine):
    """Verifies that a port scan probing 30 unique ports generates exactly ONE
    initial PORT_SCAN_DETECTED alert at the threshold, suppressing duplicate alerts
    at subsequent ports (e.g. 20 and 30)."""
    client_ip = "10.10.0.2"
    server_ip = "10.10.0.1"
    now = 1000.0

    alerts = []
    # Probe 30 unique TCP ports sequentially (ports 1 to 30)
    for p in range(1, 31):
        pkt = dispatcher.dispatch(
            bytes(Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=50000 + p, dport=p, flags="S")),
            timestamp=now + (p * 0.1),
        )
        res = ids_engine.evaluate(pkt, dpi_result=None)
        alerts.extend(res)

    port_scans = [a for a in alerts if a.category == DetectionCategory.PORT_SCAN]
    # Must generate exactly ONE initial alert, not duplicate alerts at 20 or 30 ports
    assert len(port_scans) == 1, f"Expected exactly 1 alert for 30 ports, got {len(port_scans)}"
    assert port_scans[0].severity == Severity.HIGH
    assert port_scans[0].category == DetectionCategory.PORT_SCAN
    assert port_scans[0].matched_rule == "PORT_SCAN_DETECTED"
    assert port_scans[0].destination_port == 10  # Triggered at threshold (10th port)


def test_repeated_packets_to_existing_ports_do_not_generate_additional_alerts(dispatcher, ids_engine):
    """Verifies that repeated packets and retransmissions targeting existing ports
    during an active scan do not generate additional alerts."""
    client_ip = "10.10.0.2"
    server_ip = "10.10.0.1"
    now = 2000.0

    alerts = []
    # 1. Trigger initial alert with 10 unique ports
    for p in range(1, 11):
        pkt = dispatcher.dispatch(
            bytes(Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=50000 + p, dport=p, flags="S")),
            timestamp=now + (p * 0.1),
        )
        alerts.extend(ids_engine.evaluate(pkt, dpi_result=None))

    assert len([a for a in alerts if a.category == DetectionCategory.PORT_SCAN]) == 1

    # 2. Send 25 repeated packets to already-probed ports (e.g. ports 1, 5, 10)
    for i in range(25):
        target_port = 1 if i % 3 == 0 else (5 if i % 3 == 1 else 10)
        pkt_retry = dispatcher.dispatch(
            bytes(Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=50000 + i, dport=target_port, flags="S")),
            timestamp=now + 5.0 + (i * 0.1),
        )
        alerts.extend(ids_engine.evaluate(pkt_retry, dpi_result=None))

    port_scans = [a for a in alerts if a.category == DetectionCategory.PORT_SCAN]
    # Still exactly ONE initial alert!
    assert len(port_scans) == 1, f"Retries generated unexpected duplicate alerts: {len(port_scans)}"


def test_newly_discovered_ports_update_existing_detection_record(dispatcher):
    """Verifies that newly discovered ports update the active detection record:
    - Current unique destination port count increments.
    - Newly discovered destination ports set is updated.
    - Last activity timestamp is refreshed.
    - First detection timestamp is preserved."""
    detector = PortScanDetector(
        config={"port_scan": {"enabled": True, "time_window_seconds": 300.0, "unique_ports_threshold": 10}}
    )
    src_ip = "10.10.0.2"
    dst_ip = "10.10.0.1"
    now = 3000.0
    counter = [0]
    next_id = lambda: counter.__setitem__(0, counter[0] + 1) or counter[0]

    alerts = []
    # 1. Trigger initial detection with 10 ports (ports 1 to 10)
    for p in range(1, 11):
        pkt = dispatcher.dispatch(
            bytes(Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=50000 + p, dport=p, flags="S")),
            timestamp=now + (p * 0.5),
        )
        alerts.extend(detector.evaluate(pkt, next_alert_id_fn=next_id))

    assert len(alerts) == 1
    record = detector.get_detection_record(src_ip, dst_ip, "TCP")
    assert record is not None
    initial_detection_time = now + (10 * 0.5)
    assert record.first_detection_timestamp == pytest.approx(initial_detection_time, abs=0.01)
    assert record.last_activity_timestamp == pytest.approx(initial_detection_time, abs=0.01)
    assert record.current_unique_destination_port_count == 10
    assert record.unique_destination_port_count == 10
    assert len(record.newly_discovered_ports) == 0
    assert record.destination_ports == set(range(1, 11))

    # 2. Probe 5 newly discovered destination ports (ports 11 to 15)
    new_alerts = []
    last_pkt_time = 0.0
    for p in range(11, 16):
        last_pkt_time = now + 20.0 + (p * 0.5)
        pkt_new = dispatcher.dispatch(
            bytes(Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=50000 + p, dport=p, flags="S")),
            timestamp=last_pkt_time,
        )
        new_alerts.extend(detector.evaluate(pkt_new, next_alert_id_fn=next_id))

    # Alert deduplication: no new alert generated
    assert len(new_alerts) == 0

    # Detection record successfully updated with new intelligence
    assert record.current_unique_destination_port_count == 15
    assert record.newly_discovered_ports == {11, 12, 13, 14, 15}
    assert record.destination_ports == set(range(1, 16))
    assert record.last_activity_timestamp == pytest.approx(last_pkt_time, abs=0.01)
    # First detection timestamp remains unchanged
    assert record.first_detection_timestamp == pytest.approx(initial_detection_time, abs=0.01)


def test_new_scan_after_expiration_generates_new_alert(dispatcher):
    """Verifies that once the configured time window expires without activity,
    the active detection state is purged, and a subsequent new scan correctly
    triggers a brand new PORT_SCAN_DETECTED alert."""
    window = 10.0  # 10 second window for test
    detector = PortScanDetector(
        config={"port_scan": {"enabled": True, "time_window_seconds": window, "unique_ports_threshold": 10}}
    )
    src_ip = "10.10.0.2"
    dst_ip = "10.10.0.1"
    base_time = 5000.0
    counter = [0]
    next_id = lambda: counter.__setitem__(0, counter[0] + 1) or counter[0]

    # --- Scan 1: 10 ports at t=5000s ---
    alerts_scan1 = []
    for p in range(1, 11):
        pkt = dispatcher.dispatch(
            bytes(Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=50000 + p, dport=p, flags="S")),
            timestamp=base_time + (p * 0.1),
        )
        alerts_scan1.extend(detector.evaluate(pkt, next_alert_id_fn=next_id))

    assert len(alerts_scan1) == 1
    assert alerts_scan1[0].matched_rule == "PORT_SCAN_DETECTED"
    assert detector.is_detection_active(src_ip, dst_ip, "TCP", now=base_time + 1.0, window=window) is True

    # Advance time past window (15 seconds after last probe; window is 10s)
    future_time = base_time + 1.0 + 15.0  # t = 5016.0s

    # --- Scan 2: 10 new ports at t=5016s ---
    alerts_scan2 = []
    for p in range(21, 31):
        pkt2 = dispatcher.dispatch(
            bytes(Ether() / IP(src=src_ip, dst=dst_ip) / TCP(sport=50000 + p, dport=p, flags="S")),
            timestamp=future_time + ((p - 20) * 0.1),
        )
        alerts_scan2.extend(detector.evaluate(pkt2, next_alert_id_fn=next_id))

    # Probes 21-29 were BELOW_THRESHOLD; Probe 30 reached threshold 10 in the new window!
    assert len(alerts_scan2) == 1, f"Expected new scan to generate 1 alert, got {len(alerts_scan2)}"
    assert alerts_scan2[0].matched_rule == "PORT_SCAN_DETECTED"
    assert alerts_scan2[0].destination_port == 30


def test_udp_scan_30_unique_ports_one_alert(dispatcher, ids_engine):
    """Verifies that sending UDP datagrams to 30 unique destination ports:
    1. Is captured and parsed by the NIDS.
    2. Generates exactly ONE HIGH-severity UDP_PORT_SCAN_DETECTED alert after threshold.
    3. Contains complete evidence (source IP, destination IP, unique ports, protocol, time window).
    4. Deduplicates subsequent UDP probes up to 30 ports."""
    client_ip = "10.10.0.2"
    server_ip = "10.10.0.1"
    now = 10000.0

    alerts = []
    # Send UDP datagrams to 30 unique destination ports (ports 2001 to 2030)
    for p in range(1, 31):
        target_port = 2000 + p
        raw_bytes = bytes(Ether() / IP(src=client_ip, dst=server_ip) / UDP(sport=55000 + p, dport=target_port) / b"UDP_SCAN_TEST")
        parsed = dispatcher.dispatch(raw_bytes, timestamp=now + (p * 0.1))
        # Verify NIDS captures and parses the UDP packet
        assert parsed is not None
        assert parsed.udp is not None
        assert parsed.udp.dst_port == target_port

        res = ids_engine.evaluate(parsed, dpi_result=None)
        alerts.extend(res)

    udp_alerts = [a for a in alerts if a.category == DetectionCategory.PORT_SCAN and a.protocol == "UDP"]
    # Exactly ONE alert generated after the threshold (10 ports)
    assert len(udp_alerts) == 1, f"Expected 1 UDP_PORT_SCAN_DETECTED alert, got {len(udp_alerts)}"

    alert = udp_alerts[0]
    assert alert.matched_rule == "UDP_PORT_SCAN_DETECTED"
    assert alert.severity == Severity.HIGH
    assert alert.source_ip == client_ip
    assert alert.destination_ip == server_ip
    assert alert.protocol == "UDP"
    assert alert.destination_port == 2010  # Triggered at the 10th port

    # Verify evidence content
    ev = alert.evidence
    assert f"Source: {client_ip}" in ev
    assert f"Target: {server_ip}" in ev
    assert "Unique Ports: 10" in ev
    assert "Protocol: UDP" in ev
    assert "Time Window:" in ev

    # Verify active detection state in detector
    detector = ids_engine.behaviour_detector.port_scan_detector
    record = detector.get_detection_record(client_ip, server_ip, "UDP")
    assert record is not None
    assert record.current_unique_destination_port_count == 30
    assert len(record.newly_discovered_ports) == 20  # Ports 2011 to 2030


def test_udp_repeated_packets_do_not_inflate_count(dispatcher, ids_engine):
    """Verifies that repeated UDP packets targeting the same destination port
    do NOT inflate the unique-port count, before or after detection."""
    client_ip = "10.10.0.2"
    server_ip = "10.10.0.1"
    now = 20000.0

    # 1. Send 20 repeated UDP packets to a single port (port 9000)
    alerts_single = []
    for i in range(20):
        raw_bytes = bytes(Ether() / IP(src=client_ip, dst=server_ip) / UDP(sport=56000 + i, dport=9000) / b"RETRY")
        parsed = dispatcher.dispatch(raw_bytes, timestamp=now + (i * 0.1))
        alerts_single.extend(ids_engine.evaluate(parsed, dpi_result=None))

    # Single port probes must NEVER trigger a port scan
    assert len([a for a in alerts_single if a.category == DetectionCategory.PORT_SCAN and a.protocol == "UDP"]) == 0

    # 2. Probe 10 unique UDP ports to trigger initial alert (ports 9001 to 9010)
    alerts_probe = []
    for p in range(1, 11):
        port = 9000 + p
        raw_bytes = bytes(Ether() / IP(src=client_ip, dst=server_ip) / UDP(sport=56000 + p, dport=port) / b"PROBE")
        parsed = dispatcher.dispatch(raw_bytes, timestamp=now + 5.0 + (p * 0.1))
        alerts_probe.extend(ids_engine.evaluate(parsed, dpi_result=None))

    udp_alerts = [a for a in alerts_probe if a.category == DetectionCategory.PORT_SCAN and a.protocol == "UDP"]
    assert len(udp_alerts) == 1

    # 3. Send 30 repeated UDP packets to existing ports (9001 and 9005)
    alerts_retries = []
    for i in range(30):
        target_p = 9001 if i % 2 == 0 else 9005
        raw_bytes = bytes(Ether() / IP(src=client_ip, dst=server_ip) / UDP(sport=56100 + i, dport=target_p) / b"DUP")
        parsed = dispatcher.dispatch(raw_bytes, timestamp=now + 10.0 + (i * 0.1))
        alerts_retries.extend(ids_engine.evaluate(parsed, dpi_result=None))

    # Retries must be suppressed and not generate duplicate alerts
    assert len([a for a in alerts_retries if a.category == DetectionCategory.PORT_SCAN]) == 0

    # Destination ports count must not inflate
    detector = ids_engine.behaviour_detector.port_scan_detector
    record = detector.get_detection_record(client_ip, server_ip, "UDP")
    assert record.current_unique_destination_port_count == 11  # port 9000 + 10 probed ports


def test_tcp_and_udp_scans_are_independent(dispatcher, ids_engine):
    """Verifies that TCP and UDP port scan states are completely independent:
    - 6 TCP ports + 6 UDP ports do not falsely cross-trigger an alert at 12 ports.
    - Probing 4 more TCP ports triggers TCP PORT_SCAN_DETECTED.
    - Probing 4 more UDP ports triggers UDP UDP_PORT_SCAN_DETECTED."""
    client_ip = "10.10.0.2"
    server_ip = "10.10.0.1"
    now = 30000.0

    alerts = []
    # 6 TCP ports
    for p in range(1, 7):
        pkt_tcp = dispatcher.dispatch(
            bytes(Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=57000 + p, dport=p, flags="S")),
            timestamp=now + (p * 0.1),
        )
        alerts.extend(ids_engine.evaluate(pkt_tcp, dpi_result=None))

    # 6 UDP ports
    for p in range(1, 7):
        pkt_udp = dispatcher.dispatch(
            bytes(Ether() / IP(src=client_ip, dst=server_ip) / UDP(sport=57000 + p, dport=3000 + p) / b"U"),
            timestamp=now + 2.0 + (p * 0.1),
        )
        alerts.extend(ids_engine.evaluate(pkt_udp, dpi_result=None))

    # Neither protocol reached threshold 10 -> Zero alerts
    assert len([a for a in alerts if a.category == DetectionCategory.PORT_SCAN]) == 0

    # Probe 4 more TCP ports (ports 7 to 10) -> TCP reaches 10 ports
    tcp_more_alerts = []
    for p in range(7, 11):
        pkt_tcp = dispatcher.dispatch(
            bytes(Ether() / IP(src=client_ip, dst=server_ip) / TCP(sport=57000 + p, dport=p, flags="S")),
            timestamp=now + 4.0 + (p * 0.1),
        )
        tcp_more_alerts.extend(ids_engine.evaluate(pkt_tcp, dpi_result=None))

    # TCP alert triggered, UDP not triggered
    tcp_scans = [a for a in tcp_more_alerts if a.protocol == "TCP"]
    assert len(tcp_scans) == 1
    assert tcp_scans[0].matched_rule == "PORT_SCAN_DETECTED"
    assert len([a for a in tcp_more_alerts if a.protocol == "UDP"]) == 0

    # Probe 4 more UDP ports (ports 3007 to 3010) -> UDP reaches 10 ports
    udp_more_alerts = []
    for p in range(7, 11):
        pkt_udp = dispatcher.dispatch(
            bytes(Ether() / IP(src=client_ip, dst=server_ip) / UDP(sport=57000 + p, dport=3000 + p) / b"U"),
            timestamp=now + 6.0 + (p * 0.1),
        )
        udp_more_alerts.extend(ids_engine.evaluate(pkt_udp, dpi_result=None))

    # UDP alert triggered independently!
    udp_scans = [a for a in udp_more_alerts if a.protocol == "UDP"]
    assert len(udp_scans) == 1
    assert udp_scans[0].matched_rule == "UDP_PORT_SCAN_DETECTED"
    assert udp_scans[0].severity == Severity.HIGH


