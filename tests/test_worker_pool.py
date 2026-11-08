"""Unit tests for the PipelineWorkerPool and end-to-end packet processing."""

import queue
import time

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from models.alert_model import DecisionAction
from server.client_manager import ClientManager
from server.ingestion import QueuedPacket
from server.worker_pool import PipelineWorkerPool


def test_worker_pool_packet_processing():
    """Verifies that worker threads consume packets and invoke the full DPI/IDS pipeline."""
    cm = ClientManager(vpn_subnets=["10.8.0.0/24"])
    processed_packets = []
    raised_alerts = []

    pool = PipelineWorkerPool(
        client_manager=cm,
        num_workers=2,
        queue_size=100,
        active_prevention=False,
        on_packet_processed=lambda res: processed_packets.append(res),
        on_alert_generated=lambda alert, ctx: raised_alerts.append((alert, ctx)),
    )
    pool.start()

    try:
        # Submit 5 packets
        for i in range(1, 6):
            pkt = Ether() / IP(src="10.8.0.2", dst="93.184.216.34") / TCP(sport=5000 + i, dport=80) / b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
            qp = QueuedPacket(raw_bytes=bytes(pkt), timestamp=time.time(), source_name="test")
            pool.packet_queue.put(qp)

        # Wait for queue to drain
        pool.packet_queue.join()

        stats = pool.get_stats_snapshot()
        assert stats.total_processed == 5
        assert len(processed_packets) == 5

        # Verify client context was populated
        client = cm.get_all_clients()[0]
        assert client.client_ip == "10.8.0.2"
        snap = client.get_snapshot()
        assert snap.total_packets == 5
        assert snap.top_protocol == "HTTP"

    finally:
        pool.stop()


def test_worker_pool_security_alert_trigger():
    """Verifies that malicious payloads trigger IDS alerts within the worker pipeline."""
    cm = ClientManager(vpn_subnets=["10.8.0.0/24"])
    raised_alerts = []

    pool = PipelineWorkerPool(
        client_manager=cm,
        num_workers=1,
        queue_size=50,
        on_alert_generated=lambda alert, ctx: raised_alerts.append(alert),
    )
    pool.start()

    try:
        # Payload matching rule 1002: "Environment File Exfiltration Attempt" (/.env)
        bad_req = b"GET /.env HTTP/1.1\r\nHost: target.com\r\n\r\n"
        pkt = Ether() / IP(src="10.8.0.9", dst="142.250.190.46") / TCP(sport=60000, dport=80) / bad_req

        qp = QueuedPacket(raw_bytes=bytes(pkt), timestamp=time.time(), source_name="test")
        pool.packet_queue.put(qp)

        pool.packet_queue.join()

        assert len(raised_alerts) >= 1
        assert "Environment File Exfiltration" in raised_alerts[0].matched_rule

        # Check client history
        client = cm.resolve_client(pool.dispatcher.dispatch(bytes(pkt)))[0]
        assert client.get_snapshot().alerts_count >= 1

    finally:
        pool.stop()

