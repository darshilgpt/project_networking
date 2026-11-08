"""ICMP anomaly detector handling ping floods, oversized payloads, redirects, and unreachable storms."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import logging
import time
from typing import Deque, Dict, List, Optional, Tuple

from models.packet_models import ICMPHeader, ParsedPacket

logger = logging.getLogger("dpi_ids_ips.network.icmp")


@dataclass
class ICMPAnomalyAlert:
    """Alert raised by the ICMP anomaly detector."""
    alert_type: str
    severity: str
    source_ip: str
    destination_ip: str
    evidence: str
    timestamp: float


class ICMPAnomalyDetector:
    """Evaluates ICMP traffic for flood attacks, redirect evasion, and scanning storms."""

    def __init__(
        self,
        ping_flood_threshold: int = 30,
        flood_window_seconds: float = 2.0,
        unreachable_burst_threshold: int = 15,
        oversized_payload_limit: int = 1024,
    ) -> None:
        self.ping_flood_threshold = ping_flood_threshold
        self.flood_window_seconds = flood_window_seconds
        self.unreachable_burst_threshold = unreachable_burst_threshold
        self.oversized_payload_limit = oversized_payload_limit

        # Trackers: src_ip -> deque of timestamps
        self._echo_tracker: Dict[str, Deque[float]] = {}
        self._unreachable_tracker: Dict[str, Deque[float]] = {}

    def evaluate(self, packet: ParsedPacket) -> List[ICMPAnomalyAlert]:
        """Evaluates an ICMP packet for anomalies."""
        alerts: List[ICMPAnomalyAlert] = []
        if not packet.icmp:
            return alerts

        icmp: ICMPHeader = packet.icmp
        now = packet.timestamp or time.time()
        src_ip = packet.ipv4.src_ip if packet.ipv4 else (packet.ipv6.src_ip if packet.ipv6 else "0.0.0.0")
        dst_ip = packet.ipv4.dst_ip if packet.ipv4 else (packet.ipv6.dst_ip if packet.ipv6 else "0.0.0.0")

        # 1. ICMP Redirect Attack (Type 5)
        # Type 5 is used to update routing tables; rogue redirects allow MitM/hijacking
        if not icmp.is_ipv6 and icmp.icmp_type == 5:
            alerts.append(
                ICMPAnomalyAlert(
                    alert_type="ICMP_REDIRECT_ATTACK",
                    severity="CRITICAL",
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    evidence=f"ICMP Redirect (Type 5, Code {icmp.code}) message received from {src_ip}. Potential route hijacking attempt.",
                    timestamp=now,
                )
            )

        # 2. Oversized ICMP Payload / Ping of Death Indicator
        payload_len = packet.payload_length or len(packet.payload)
        if payload_len > self.oversized_payload_limit:
            alerts.append(
                ICMPAnomalyAlert(
                    alert_type="OVERSIZED_ICMP_PAYLOAD",
                    severity="HIGH",
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    evidence=f"Oversized ICMP payload ({payload_len} bytes, exceeds safe threshold {self.oversized_payload_limit}). Possible buffer overflow / Ping of Death probe.",
                    timestamp=now,
                )
            )

        # 3. Ping Flood Detection (Echo Request: Type 8 for IPv4, Type 128 for IPv6)
        is_echo_req = (not icmp.is_ipv6 and icmp.icmp_type == 8) or (icmp.is_ipv6 and icmp.icmp_type == 128)
        if is_echo_req:
            if src_ip not in self._echo_tracker:
                self._echo_tracker[src_ip] = deque()
            q = self._echo_tracker[src_ip]
            q.append(now)
            while q and now - q[0] > self.flood_window_seconds:
                q.popleft()

            if len(q) >= self.ping_flood_threshold:
                alerts.append(
                    ICMPAnomalyAlert(
                        alert_type="ICMP_PING_FLOOD",
                        severity="HIGH",
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        evidence=f"ICMP Echo Request flood: {len(q)} pings within {self.flood_window_seconds}s from {src_ip}.",
                        timestamp=now,
                    )
                )

        # 4. Destination Unreachable Storm (Type 3 for IPv4, Type 1 for IPv6)
        is_unreachable = (not icmp.is_ipv6 and icmp.icmp_type == 3) or (icmp.is_ipv6 and icmp.icmp_type == 1)
        if is_unreachable:
            if src_ip not in self._unreachable_tracker:
                self._unreachable_tracker[src_ip] = deque()
            uq = self._unreachable_tracker[src_ip]
            uq.append(now)
            while uq and now - uq[0] > self.flood_window_seconds:
                uq.popleft()

            if len(uq) >= self.unreachable_burst_threshold:
                alerts.append(
                    ICMPAnomalyAlert(
                        alert_type="ICMP_UNREACHABLE_STORM",
                        severity="MEDIUM",
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        evidence=f"ICMP Unreachable Storm: {len(uq)} unreachable errors in {self.flood_window_seconds}s. Strong indicator of active port/UDP scan.",
                        timestamp=now,
                    )
                )

        return alerts
