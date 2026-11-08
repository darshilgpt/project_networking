"""Flow Manager for managing lifecycle, metrics, and memory bounds."""

from __future__ import annotations

import logging
import threading
import time
from typing import Dict, List, Optional

from flow.flow_tracker import FlowTracker
from models.flow_model import Flow
from models.packet_models import ParsedPacket

logger = logging.getLogger("dpi_ids_ips.flow.flow_manager")


class FlowManager:
    """Coordinates flow tracking, periodic cleanup, and flow metrics."""

    def __init__(
        self,
        tracker: Optional[FlowTracker] = None,
        cleanup_interval: float = 10.0,
    ) -> None:
        self.tracker = tracker or FlowTracker()
        self.cleanup_interval = cleanup_interval
        self._last_cleanup = time.time()
        self._lock = threading.Lock()

        # Cumulative metrics
        self.total_flows_seen = 0
        self.total_flows_expired = 0
        self.application_breakdown: Dict[str, int] = {}

    def process_packet(self, packet: ParsedPacket) -> Optional[Flow]:
        """
        Submits a packet to the flow tracker with thread-safe cleanup check.

        Returns:
            The associated Flow instance.
        """
        now = packet.timestamp or time.time()

        with self._lock:
            # Periodic cleanup
            if now - self._last_cleanup >= self.cleanup_interval:
                expired = self.tracker.expire_flows(now)
                self.total_flows_expired += len(expired)
                self._last_cleanup = now

            flow, is_new = self.tracker.process_packet(packet)
            if is_new and flow:
                self.total_flows_seen += 1

            return flow

    def record_application_detection(self, flow: Flow, app_name: str) -> None:
        """Records an application-layer protocol classification for a flow."""
        with self._lock:
            prev_app = flow.application_protocol
            flow.application_protocol = app_name
            if prev_app != app_name:
                self.application_breakdown[app_name] = self.application_breakdown.get(app_name, 0) + 1

    def get_active_flows(self) -> List[Flow]:
        with self._lock:
            return self.tracker.get_all_flows()

    def get_summary_metrics(self) -> Dict[str, int]:
        with self._lock:
            return {
                "active_flows": self.tracker.active_flow_count,
                "total_flows_seen": self.total_flows_seen,
                "total_flows_expired": self.total_flows_expired,
                "app_breakdown": dict(self.application_breakdown),
            }

