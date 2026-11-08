"""Continuous live packet capture engine using Npcap through Scapy."""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Optional

from scapy.all import raw, sniff
from scapy.packet import Packet as ScapyPacket

from models.packet_models import CaptureStats, InterfaceInfo, ParsedPacket
from parser.packet_dispatcher import PacketDispatcher

logger = logging.getLogger("dpi_ids_ips.capture.packet_capture")


class LivePacketCapture:
    """Manages real-time packet acquisition and hands off raw bytes to custom parsers."""

    def __init__(
        self,
        interface: InterfaceInfo,
        dispatcher: Optional[PacketDispatcher] = None,
        on_packet: Optional[Callable[[ParsedPacket], None]] = None,
        bpf_filter: Optional[str] = None,
    ) -> None:
        """
        Initializes the live packet capture engine.

        Args:
            interface: Selected InterfaceInfo target.
            dispatcher: PacketDispatcher instance for dissecting frames.
            on_packet: Callback invoked for each parsed packet.
            bpf_filter: Optional BPF filter string.
        """
        self.interface = interface
        self.dispatcher = dispatcher or PacketDispatcher()
        self.on_packet = on_packet
        self.bpf_filter = bpf_filter
        self.stats = CaptureStats()
        self._stop_event = threading.Event()
        self._is_running = False

    def _process_scapy_packet(self, scapy_pkt: ScapyPacket) -> None:
        """Extracts raw packet bytes and feeds them into our custom parser pipeline."""
        try:
            # Scapy provides packet acquisition only; we extract raw bytes
            raw_bytes = bytes(scapy_pkt) if not isinstance(scapy_pkt, bytes) else scapy_pkt
            pkt_time = float(getattr(scapy_pkt, "time", time.time()))

            parsed = self.dispatcher.dispatch(raw_bytes, timestamp=pkt_time)
            self.stats.record_packet(parsed)

            if self.on_packet:
                try:
                    self.on_packet(parsed)
                except Exception as cb_err:
                    logger.error(f"Error in on_packet callback: {cb_err}")

        except Exception as e:
            self.stats.total_errors += 1
            logger.error(f"Unexpected error processing packet: {e}")

    def _stop_filter(self, _: ScapyPacket) -> bool:
        """Checks if the capture loop should terminate."""
        return self._stop_event.is_set()
        

    def stop(self) -> None:
        """Signals the capture engine to stop."""
        self._stop_event.set()
        self._is_running = False

    def start(self, packet_count: int = 0, timeout: Optional[float] = None) -> CaptureStats:
        """
        Starts continuous packet capture on the selected interface.

        Args:
            packet_count: Number of packets to capture (0 for infinite).
            timeout: Maximum capture duration in seconds (None for infinite).

        Returns:
            Final CaptureStats object.
        """
        self._stop_event.clear()
        self._is_running = True
        self.stats.start_time = time.time()

        # Determine best iface argument for Scapy on Windows
        # Preference: scapy_iface object, then scapy_name, then name
        target_iface = self.interface.scapy_iface or self.interface.scapy_name or self.interface.name

        logger.info(f"Starting live capture on interface '{self.interface.name}' (Target: {target_iface})")

        try:
            sniff(
                iface=target_iface,
                prn=self._process_scapy_packet,
                stop_filter=self._stop_filter,
                filter=self.bpf_filter,
                store=False,
                count=packet_count,
                timeout=timeout,
            )
        except KeyboardInterrupt:
            logger.info("Capture interrupted by user (Ctrl+C).")
        except PermissionError as pe:
            logger.error(f"Permission denied while capturing: {pe}. Try running with Administrator privileges.")
            raise
        except Exception as exc:
            logger.error(f"Capture error on interface '{self.interface.name}': {exc}")
            raise
        finally:
            self._is_running = False
            self.stats.last_packet_time = time.time()

        return self.stats
