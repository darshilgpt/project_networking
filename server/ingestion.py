"""Modular Packet Ingestion Subsystem supporting Live, Tunnel, and PCAP replay."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import logging
import os
import queue
import threading
import time
from typing import Any, Dict, Optional

from scapy.all import sniff
from scapy.packet import Packet as ScapyPacket
from scapy.utils import PcapReader

from models.packet_models import InterfaceInfo

logger = logging.getLogger("dpi_ids_ips.server.ingestion")


@dataclass
class QueuedPacket:
    """Encapsulates a raw packet buffer queued for worker processing."""
    raw_bytes: bytes
    timestamp: float
    source_name: str
    link_type: str = "AUTO"


class PacketSource(ABC):
    """Abstract base class defining the contract for packet ingestion sources."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.is_running = False
        self.total_ingested = 0
        self.dropped_queue_full = 0
        self.bytes_ingested = 0
        self.start_time: float = 0.0

    @abstractmethod
    def start(self, packet_queue: queue.Queue[Optional[QueuedPacket]]) -> None:
        """Starts packet ingestion, dispatching QueuedPacket instances to packet_queue."""
        ...

    @abstractmethod
    def stop(self) -> None:
        """Stops packet ingestion gracefully."""
        ...

    def get_stats(self) -> Dict[str, Any]:
        """Returns snapshot ingestion metrics."""
        duration = max(0.001, (time.time() - self.start_time)) if self.start_time else 0.001
        rate_pps = self.total_ingested / duration if self.is_running else 0.0
        rate_kbps = (self.bytes_ingested * 8 / 1024) / duration if self.is_running else 0.0
        return {
            "source_name": self.name,
            "is_running": self.is_running,
            "total_ingested": self.total_ingested,
            "dropped_queue_full": self.dropped_queue_full,
            "bytes_ingested": self.bytes_ingested,
            "rate_pps": round(rate_pps, 1),
            "rate_kbps": round(rate_kbps, 1),
        }


class LiveCaptureSource(PacketSource):
    """Acquires live packets from an Npcap/Scapy physical or virtual adapter."""

    def __init__(
        self,
        interface: InterfaceInfo,
        bpf_filter: Optional[str] = None,
        packet_count: int = 0,
        timeout: Optional[float] = None,
        link_type: str = "AUTO",
    ) -> None:
        super().__init__(name=f"Live[{interface.name}]")
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.packet_count = packet_count
        self.timeout = timeout
        self.link_type = link_type

        self._queue: Optional[queue.Queue[Optional[QueuedPacket]]] = None
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _on_packet(self, scapy_pkt: ScapyPacket) -> None:
        """Callback invoked by Scapy sniff."""
        if self._stop_event.is_set():
            return

        try:
            raw_bytes = bytes(scapy_pkt) if not isinstance(scapy_pkt, bytes) else scapy_pkt
            pkt_time = float(getattr(scapy_pkt, "time", time.time()))

            qp = QueuedPacket(
                raw_bytes=raw_bytes,
                timestamp=pkt_time,
                source_name=self.interface.name,
                link_type=self.link_type,
            )

            if self._queue is not None:
                try:
                    # Bounded queue: Non-blocking put to safeguard memory
                    self._queue.put_nowait(qp)
                    self.total_ingested += 1
                    self.bytes_ingested += len(raw_bytes)
                except queue.Full:
                    self.dropped_queue_full += 1
        except Exception as e:
            logger.error(f"Error handling captured live packet: {e}")

    def _sniff_worker(self) -> None:
        """Background thread executing Scapy sniff."""
        self.is_running = True
        self.start_time = time.time()
        target_iface = self.interface.scapy_iface or self.interface.scapy_name or self.interface.name

        logger.info(f"Ingestion started on {target_iface} (Filter: {self.bpf_filter})")
        try:
            sniff(
                iface=target_iface,
                prn=self._on_packet,
                filter=self.bpf_filter,
                count=self.packet_count,
                timeout=self.timeout,
                stop_filter=lambda _: self._stop_event.is_set(),
                store=False,
            )
        except Exception as exc:
            logger.error(f"Live sniffing encountered an error on {self.interface.name}: {exc}")
        finally:
            self.is_running = False
            logger.info(f"Ingestion halted on {self.interface.name}")

    def start(self, packet_queue: queue.Queue[Optional[QueuedPacket]]) -> None:
        self._queue = packet_queue
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._sniff_worker, daemon=True, name="LiveCaptureWorker")
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self.is_running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)


class TunnelCaptureSource(LiveCaptureSource):
    """Specialized ingestion source configured for WireGuard or Wintun tunnel adapters."""

    def __init__(
        self,
        interface: InterfaceInfo,
        bpf_filter: Optional[str] = None,
        packet_count: int = 0,
        timeout: Optional[float] = None,
    ) -> None:
        # Tunnel adapters often present raw Layer 3 packets (DLT_RAW)
        super().__init__(
            interface=interface,
            bpf_filter=bpf_filter,
            packet_count=packet_count,
            timeout=timeout,
            link_type="RAW_IP" if interface.is_tunnel else "AUTO",
        )
        self.name = f"Tunnel[{interface.name}]"


class PcapReplaySource(PacketSource):
    """Replays pre-recorded PCAP / PCAPNG packet traces with optional rate pacing."""

    def __init__(
        self,
        pcap_path: str,
        rate: str = "fastest",
        speed_multiplier: float = 1.0,
        loop: bool = False,
        max_packets: int = 0,
    ) -> None:
        """
        Args:
            pcap_path: File system path to the .pcap or .pcapng file.
            rate: 'realtime' (pacing matching inter-packet delays) or 'fastest' (burst mode).
            speed_multiplier: Multiplier when rate='realtime' (e.g. 2.0 = 2x speed).
            loop: Whether to loop back to the beginning upon EOF.
            max_packets: Max packets to replay (0 = until EOF).
        """
        super().__init__(name=f"PCAP[{os.path.basename(pcap_path)}]")
        self.pcap_path = pcap_path
        self.rate = rate.lower()
        self.speed_multiplier = max(0.01, speed_multiplier)
        self.loop = loop
        self.max_packets = max_packets
        self.completed = False

        self._queue: Optional[queue.Queue[Optional[QueuedPacket]]] = None
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def _replay_worker(self) -> None:
        self.is_running = True
        self.completed = False
        self.start_time = time.time()

        if not os.path.exists(self.pcap_path):
            logger.error(f"PCAP file not found: {self.pcap_path}")
            self.is_running = False
            self.completed = True
            return

        logger.info(f"Starting PCAP replay from {self.pcap_path} (Rate: {self.rate})")

        while not self._stop_event.is_set():
            prev_pkt_time: Optional[float] = None
            packet_count = 0

            try:
                with PcapReader(self.pcap_path) as reader:
                    for pkt in reader:
                        if self._stop_event.is_set():
                            break

                        raw_bytes = bytes(pkt)
                        pkt_time = float(getattr(pkt, "time", time.time()))

                        # Handle real-time delay pacing
                        if self.rate == "realtime" and prev_pkt_time is not None:
                            delta = (pkt_time - prev_pkt_time) / self.speed_multiplier
                            if 0 < delta < 10.0:  # Bound sleep to avoid long hangs
                                time.sleep(delta)

                        prev_pkt_time = pkt_time

                        qp = QueuedPacket(
                            raw_bytes=raw_bytes,
                            timestamp=pkt_time,
                            source_name=os.path.basename(self.pcap_path),
                            link_type="AUTO",
                        )

                        if self._queue is not None:
                            # If queue is full, wait briefly before dropping to give workers a chance
                            try:
                                self._queue.put(qp, timeout=0.05)
                                self.total_ingested += 1
                                self.bytes_ingested += len(raw_bytes)
                                packet_count += 1
                            except queue.Full:
                                self.dropped_queue_full += 1

                        if self.max_packets > 0 and packet_count >= self.max_packets:
                            break

            except Exception as e:
                logger.error(f"Error during PCAP replay: {e}")
                break

            if not self.loop or self._stop_event.is_set():
                break

        self.is_running = False
        self.completed = True
        logger.info(f"PCAP replay finished. Total packets: {self.total_ingested}")

    def start(self, packet_queue: queue.Queue[Optional[QueuedPacket]]) -> None:
        self._queue = packet_queue
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._replay_worker, daemon=True, name="PcapReplayWorker")
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self.is_running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

