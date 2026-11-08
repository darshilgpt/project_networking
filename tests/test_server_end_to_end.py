"""End-to-end integration tests for the Central Network Security Server."""

import os
import tempfile
import threading
import time

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from server.server import NetworkSecurityServer, ServerConfig


def test_server_pcap_replay_headless():
    """End-to-end test running NetworkSecurityServer on a synthetic multi-client PCAP file."""
    # Synthesize packets for Client A (10.8.0.2) and Client B (10.8.0.3)
    pkts = [
        # Normal HTTP request from Client A
        Ether() / IP(src="10.8.0.2", dst="93.184.216.34") / TCP(sport=51000, dport=80, flags="PA", seq=1, ack=1) / b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
        # Attack probe from Client B (Path Traversal: ../../etc/passwd)
        Ether() / IP(src="10.8.0.3", dst="93.184.216.34") / TCP(sport=52000, dport=80, flags="PA", seq=1, ack=1) / b"GET /../../etc/passwd HTTP/1.1\r\nHost: target.com\r\n\r\n",
        # DNS query from Client A
        Ether() / IP(src="10.8.0.2", dst="8.8.8.8") / UDP(sport=53500, dport=53) / b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01",
    ]

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        pcap_path = tf.name

    try:
        wrpcap(pcap_path, pkts)

        config = ServerConfig(
            pcap_path=pcap_path,
            pcap_rate="fastest",
            workers=2,
            queue_size=100,
            vpn_subnets=["10.8.0.0/24"],
            enable_dashboard=False,  # Headless mode for automated tests
            log_file=None,
        )

        server = NetworkSecurityServer(config)

        # Run server in background thread so test can observe and shut down
        server_thread = threading.Thread(target=server.start, daemon=True)
        server_thread.start()

        # Wait for replay to complete and drain
        server_thread.join(timeout=5.0)

        # Verify processing results
        stats = server.worker_pool.get_stats_snapshot()
        assert stats.total_processed == 3

        # Verify multi-client tracking
        snapshots = {c.client_ip: c for c in server.client_manager.get_client_snapshots()}
        assert "10.8.0.2" in snapshots
        assert "10.8.0.3" in snapshots

        client_a = snapshots["10.8.0.2"]
        client_b = snapshots["10.8.0.3"]

        assert client_a.total_packets == 2
        assert client_b.total_packets == 1
        # Client B triggered path traversal alert
        assert client_b.alerts_count >= 1

    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)

