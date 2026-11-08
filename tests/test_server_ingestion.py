"""Unit tests for modular packet ingestion and bounded queues."""

import os
import queue
import tempfile
import time

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from models.packet_models import InterfaceInfo
from server.ingestion import LiveCaptureSource, PcapReplaySource, QueuedPacket, TunnelCaptureSource


def test_queued_packet_dataclass():
    """Verifies QueuedPacket attributes."""
    qp = QueuedPacket(raw_bytes=b"\x00" * 40, timestamp=100.0, source_name="eth0", link_type="AUTO")
    assert len(qp.raw_bytes) == 40
    assert qp.timestamp == 100.0
    assert qp.source_name == "eth0"
    assert qp.link_type == "AUTO"


def test_pcap_replay_source_burst_mode():
    """Verifies that PcapReplaySource reads packets from disk and queues them in burst mode."""
    # Create temporary pcap file
    pkts = [
        Ether() / IP(src=f"10.8.0.{i}", dst="8.8.8.8") / UDP(sport=5000 + i, dport=53) / b"DNS"
        for i in range(1, 11)
    ]
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        pcap_path = tf.name

    try:
        wrpcap(pcap_path, pkts)

        q = queue.Queue(maxsize=100)
        source = PcapReplaySource(pcap_path=pcap_path, rate="fastest")
        source.start(q)

        # Wait for replay worker to complete
        for _ in range(50):
            if source.completed:
                break
            time.sleep(0.05)

        assert source.completed is True
        assert source.total_ingested == 10
        assert q.qsize() == 10

        item = q.get_nowait()
        assert isinstance(item, QueuedPacket)
        assert len(item.raw_bytes) > 0
    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)


def test_pcap_replay_bounded_queue_drop():
    """Verifies that bounded queue overflows are safely dropped and recorded in stats."""
    pkts = [
        Ether() / IP(src=f"10.8.0.{i}", dst="8.8.8.8") / UDP(sport=5000, dport=53) / b"Payload"
        for i in range(1, 20)
    ]
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        pcap_path = tf.name

    try:
        wrpcap(pcap_path, pkts)

        # Tiny queue capacity of 3
        q = queue.Queue(maxsize=3)
        source = PcapReplaySource(pcap_path=pcap_path, rate="fastest")
        source.start(q)

        for _ in range(50):
            if source.completed:
                break
            time.sleep(0.05)

        stats = source.get_stats()
        assert stats["total_ingested"] == 3
        assert stats["dropped_queue_full"] > 0
    finally:
        if os.path.exists(pcap_path):
            os.remove(pcap_path)


def test_tunnel_capture_source_initialization():
    """Verifies TunnelCaptureSource defaults link_type to RAW_IP when interface is tunnel."""
    iface = InterfaceInfo(
        index=1,
        name="wg0",
        description="WireGuard Tunnel",
        guid="guid-123",
        mac="",
        is_tunnel=True,
        tunnel_type="WireGuard",
    )
    src = TunnelCaptureSource(interface=iface)
    assert src.link_type == "RAW_IP"
    assert "Tunnel[wg0]" in src.name

