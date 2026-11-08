"""Integration tests verifying decrypted WireGuard inner traffic processing across multiple laptops."""

import time

from scapy.layers.inet import IP, TCP, UDP

from models.alert_model import DecisionAction
from server.client_manager import ClientManager
from server.ingestion import QueuedPacket
from server.worker_pool import PipelineWorkerPool


def test_decrypted_wireguard_inner_traffic_multi_laptop_dpi():
    """
    Verifies that decrypted inner IP packets (Layer 3 without Ethernet framing)
    from multiple client laptops are parsed, attributed to each laptop,
    and deeply inspected by the DPI and IDS engines.
    """
    # 1. Setup ClientManager with provisioned peers
    cm = ClientManager(vpn_subnets=["10.8.0.0/24"])
    cm.register_client("10.8.0.2", "Laptop-Alice")
    cm.register_client("10.8.0.3", "Laptop-Bob")

    processed = []
    alerts = []

    pool = PipelineWorkerPool(
        client_manager=cm,
        num_workers=2,
        queue_size=100,
        on_packet_processed=lambda res: processed.append(res),
        on_alert_generated=lambda alert, ctx: alerts.append((alert, ctx)),
    )
    pool.start()

    try:
        # Decrypted inner packet from Laptop-Alice (10.8.0.2): Legitimate HTTP request to Google
        alice_pkt = IP(src="10.8.0.2", dst="142.250.190.46") / TCP(sport=51000, dport=80, flags="PA", seq=1, ack=1) / b"GET /search?q=test HTTP/1.1\r\nHost: www.google.com\r\n\r\n"
        qp_alice = QueuedPacket(
            raw_bytes=bytes(alice_pkt),
            timestamp=time.time(),
            source_name="wg0",
            link_type="RAW_IP",  # Decrypted tunnel traffic has NO Ethernet header
        )

        # Decrypted inner packet from Laptop-Bob (10.8.0.3): Path traversal attack probe
        bob_pkt = IP(src="10.8.0.3", dst="192.168.1.10") / TCP(sport=52000, dport=80, flags="PA", seq=1, ack=1) / b"GET /../../etc/shadow HTTP/1.1\r\nHost: internal-server\r\n\r\n"
        qp_bob = QueuedPacket(
            raw_bytes=bytes(bob_pkt),
            timestamp=time.time(),
            source_name="wg0",
            link_type="RAW_IP",
        )

        pool.packet_queue.put(qp_alice)
        pool.packet_queue.put(qp_bob)

        pool.packet_queue.join()

        # Verify processing results
        assert len(processed) == 2

        # Verify Laptop-Alice attribution and DPI detection
        alice_res = [r for r in processed if r.client.client_ip == "10.8.0.2"][0]
        assert alice_res.client.client_name == "Laptop-Alice"
        assert alice_res.packet.ethernet is None  # Confirms raw L3 inner packet
        assert alice_res.packet.ipv4.src_ip == "10.8.0.2"
        assert alice_res.dpi_result.protocol == "HTTP"
        assert alice_res.decision == DecisionAction.ALLOW

        # Verify Laptop-Bob attribution, DPI detection, and IDS alert
        bob_res = [r for r in processed if r.client.client_ip == "10.8.0.3"][0]
        assert bob_res.client.client_name == "Laptop-Bob"
        assert bob_res.packet.ethernet is None
        assert bob_res.packet.ipv4.src_ip == "10.8.0.3"
        assert bob_res.dpi_result.protocol == "HTTP"
        assert len(bob_res.alerts) >= 1
        assert "Path Traversal" in bob_res.alerts[0].matched_rule
        assert bob_res.decision == DecisionAction.BLOCK

        # Verify client-level metric isolation
        snap_alice = alice_res.client.get_snapshot()
        snap_bob = bob_res.client.get_snapshot()

        assert snap_alice.total_packets == 1
        assert snap_alice.alerts_count == 0

        assert snap_bob.total_packets == 1
        assert snap_bob.alerts_count >= 1
        assert snap_bob.blocked_count >= 1

    finally:
        pool.stop()

