"""Reliable Port Scan Detection Subsystem with Per-(Source, Target) Tracking and Debug Logging.

Detects:
- TCP SYN scanning (half-open probes)
- TCP connect scanning (connection initiation attempts)
- UDP port scanning (probes across unprivileged/target UDP ports)
- Stealth scanning (NULL, FIN, XMAS scans)
- Repeated connection attempts across multiple destination ports

Key Features:
- Per-(source_ip, destination_ip) isolated tracking state
- Deduplication of retransmissions and multi-packet flows
- Sliding time window with automatic cleanup
- Configurable thresholds and time windows
- Comprehensive debug-level logging tracking source, target, port, flags, unique ports, threshold, and decision
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import logging
import time
from typing import Callable, Deque, Dict, List, Optional, Set, Tuple

from models.alert_model import DecisionAction, DetectionCategory, IDSAlert, Severity
from models.packet_models import ParsedPacket, TCPFlags

logger = logging.getLogger("dpi_ids_ips.ids.port_scan_detector")


def format_tcp_flags(flags: Optional[TCPFlags]) -> str:
    """Formats active TCP control flags into a concise readable string."""
    if not flags:
        return "NONE"
    active = []
    if flags.syn:
        active.append("SYN")
    if flags.ack:
        active.append("ACK")
    if flags.fin:
        active.append("FIN")
    if flags.rst:
        active.append("RST")
    if flags.psh:
        active.append("PSH")
    if flags.urg:
        active.append("URG")
    if flags.ece:
        active.append("ECE")
    if flags.cwr:
        active.append("CWR")
    return "+".join(active) if active else "NONE"


@dataclass
class PortProbeRecord:
    """Represents a validated connection or port probe attempt."""
    timestamp: float
    dst_ip: str
    dst_port: int
    protocol: str  # "TCP" or "UDP"
    scan_type: str  # "SYN_SCAN", "CONNECT_SCAN", "UDP_SCAN", "STEALTH_SCAN"


@dataclass
class ScanDetectionRecord:
    """Active scan detection record tracking an ongoing port scan with alert deduplication.

    Attributes:
        source_ip: Probing client IP.
        destination_ip: Target server/host IP.
        protocol: Transport protocol ('TCP' or 'UDP').
        first_detection_timestamp: Time when initial alert was triggered.
        last_activity_timestamp: Time of the latest probe or activity for this scan.
        destination_ports: Set of all unique destination ports probed.
        initial_ports: Set of ports probed up to initial alert.
        newly_discovered_ports: Set of ports discovered after initial alert was triggered.
        initial_alert_id: Identifier of the initial IDS alert.
        initial_alert: Reference to the initial IDSAlert object.
    """
    source_ip: str
    destination_ip: str
    protocol: str
    first_detection_timestamp: float
    last_activity_timestamp: float
    destination_ports: Set[int]
    initial_ports: Set[int]
    newly_discovered_ports: Set[int]
    initial_alert_id: int
    initial_alert: Optional[IDSAlert] = None

    @property
    def current_unique_destination_port_count(self) -> int:
        """Returns the current unique destination port count."""
        return len(self.destination_ports)

    @property
    def unique_destination_port_count(self) -> int:
        """Alias for current unique destination port count."""
        return len(self.destination_ports)

    @property
    def current_unique_port_count(self) -> int:
        """Alias for unique port count."""
        return len(self.destination_ports)

    @property
    def unique_ports_count(self) -> int:
        """Alias for unique port count."""
        return len(self.destination_ports)

    @property
    def first_detection_time(self) -> float:
        """Alias for first detection timestamp."""
        return self.first_detection_timestamp

    @property
    def last_activity_time(self) -> float:
        """Alias for last activity timestamp."""
        return self.last_activity_timestamp

    @property
    def ports(self) -> Set[int]:
        """Alias for all discovered destination ports."""
        return self.destination_ports

    def record_port(self, dst_port: int, now: float) -> bool:
        """
        Updates the detection record with a destination port.
        Always updates last_activity_timestamp.
        If dst_port is newly discovered, adds it to destination_ports and newly_discovered_ports.
        Returns True if newly discovered, False if already known.
        """
        self.last_activity_timestamp = now
        if dst_port not in self.destination_ports:
            self.destination_ports.add(dst_port)
            self.newly_discovered_ports.add(dst_port)
            return True
        return False

    def is_expired(self, now: float, window: float) -> bool:
        """
        Determines whether the active detection state has expired after the configured time window.
        """
        return (now - self.last_activity_timestamp) >= window

    def get_summary(self) -> str:
        """Provides a human-readable telemetry summary of the detection state."""
        return (
            f"Scan Key: ({self.source_ip}, {self.destination_ip}, {self.protocol}) | "
            f"Unique Ports: {self.current_unique_destination_port_count} | "
            f"New Ports Since Alert: {len(self.newly_discovered_ports)} | "
            f"First Detection: {self.first_detection_timestamp:.2f} | "
            f"Last Activity: {self.last_activity_timestamp:.2f}"
        )


class TargetPortScanTracker:
    """Maintains sliding window state for a specific (source_ip, destination_ip) pair."""

    def __init__(self, source_ip: str, destination_ip: str) -> None:
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        # Probes deque: store PortProbeRecord
        self.probes: Deque[PortProbeRecord] = deque()
        # Map (dst_port, protocol) -> last seen timestamp for retransmission suppression
        self.recent_attempts: Dict[Tuple[int, str], float] = {}
        # Active detection states per protocol: protocol -> ScanDetectionRecord
        self.active_detections: Dict[str, ScanDetectionRecord] = {}
        # Cooldown per protocol: protocol -> last alert timestamp
        self.last_alert_time: Dict[str, float] = {}
        # Track last alerted unique port count to trigger updates when count grows significantly
        self.last_alerted_port_count: Dict[str, int] = {}
        self.last_active_time: float = time.time()

    @property
    def active_detection(self) -> Optional[ScanDetectionRecord]:
        """Returns the primary active detection record if any."""
        return next(iter(self.active_detections.values()), None)

    def record_probe(
        self,
        now: float,
        dst_port: int,
        protocol: str,
        scan_type: str,
        dedup_window: float = 5.0,
    ) -> bool:
        """
        Records a probe attempt. Suppresses immediate retransmissions to the same port.
        Returns True if a new unique attempt was recorded, False if deduplicated/retransmitted.
        """
        self.last_active_time = now
        key = (dst_port, protocol)
        last_seen = self.recent_attempts.get(key)

        if last_seen is not None and (now - last_seen) < dedup_window:
            # Retransmission or repeated packet from the same connection attempt within dedup window
            self.recent_attempts[key] = now
            return False

        self.recent_attempts[key] = now
        self.probes.append(
            PortProbeRecord(
                timestamp=now,
                dst_ip=self.destination_ip,
                dst_port=dst_port,
                protocol=protocol,
                scan_type=scan_type,
            )
        )
        return True

    def purge_aged(self, now: float, window: float) -> None:
        """Removes records older than the sliding time window."""
        while self.probes and (now - self.probes[0].timestamp) > window:
            self.probes.popleft()

        # Prune recent_attempts dictionary
        cutoff = now - (window * 1.5)
        stale_keys = [k for k, ts in self.recent_attempts.items() if ts < cutoff]
        for k in stale_keys:
            del self.recent_attempts[k]

    def get_unique_ports(self, protocol: Optional[str] = None) -> Set[int]:
        """Returns the set of unique destination ports probed in the active window."""
        if protocol:
            return {p.dst_port for p in self.probes if p.protocol == protocol}
        return {p.dst_port for p in self.probes}


class PortScanDetector:
    """Tracks port scanning behaviors per (source_ip, destination_ip) and generates IDS alerts."""

    # Default common UDP service response ports to exclude from port scan alerts
    EXCLUDED_UDP_SRC_PORTS: Set[int] = {53, 67, 68, 123, 1900, 5353}

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self.config = config or {}
        # Tracking state keyed by (source_ip, destination_ip)
        self.trackers: Dict[Tuple[str, str], TargetPortScanTracker] = {}
        # Active detection states keyed by (source_ip, destination_ip, protocol)
        self.active_detections: Dict[Tuple[str, str, str], ScanDetectionRecord] = {}
        self._last_cleanup_time = time.time()

    def update_config(self, config: Dict[str, Any]) -> None:
        """Updates runtime configuration."""
        self.config = config

    def get_detection_record(
        self,
        source_ip: str,
        destination_ip: str,
        protocol: str = "TCP",
    ) -> Optional[ScanDetectionRecord]:
        """Returns the active detection record for the given (source_ip, destination_ip, protocol) key."""
        return self.active_detections.get((source_ip, destination_ip, protocol))

    def is_detection_active(
        self,
        source_ip: str,
        destination_ip: str,
        protocol: str = "TCP",
        now: Optional[float] = None,
        window: float = 300.0,
    ) -> bool:
        """Checks if a detection state is active and non-expired for the given key."""
        record = self.active_detections.get((source_ip, destination_ip, protocol))
        if record is None:
            return False
        if now is not None and record.is_expired(now, window):
            return False
        return True

    def purge_expired_detections(self, now: float, window: float) -> List[Tuple[str, str, str]]:
        """
        Expires detection states after the configured time window has elapsed without activity.
        Returns the list of expired detection keys.
        """
        expired_keys = [
            key for key, record in self.active_detections.items()
            if record.is_expired(now, window)
        ]
        for key in expired_keys:
            src_ip, dst_ip, proto = key
            del self.active_detections[key]
            tracker = self.trackers.get((src_ip, dst_ip))
            if tracker:
                tracker.active_detections.pop(proto, None)
                tracker.purge_aged(now, window)
            logger.debug(
                f"[PORT_SCAN_DEBUG] Detection state expired for key ({src_ip}, {dst_ip}, {proto}) "
                f"after {window:.1f}s time window."
            )
        return expired_keys

    def _get_or_create_tracker(self, src_ip: str, dst_ip: str) -> TargetPortScanTracker:
        key = (src_ip, dst_ip)
        if key not in self.trackers:
            self.trackers[key] = TargetPortScanTracker(source_ip=src_ip, destination_ip=dst_ip)
        return self.trackers[key]

    def _cleanup_inactive_trackers(self, now: float, max_idle: float = 600.0) -> None:
        """Prunes tracking states for targets inactive longer than max_idle seconds."""
        if now - self._last_cleanup_time < 60.0:
            return
        self._last_cleanup_time = now

        inactive_keys = [
            key for key, tracker in self.trackers.items()
            if (now - tracker.last_active_time) > max_idle and len(tracker.probes) == 0
        ]
        for key in inactive_keys:
            del self.trackers[key]

    @staticmethod
    def identify_probe(packet: ParsedPacket) -> Tuple[bool, str, str, str]:
        """
        Determines whether a parsed packet represents a port probe.
        
        Returns:
            Tuple of (is_probe: bool, protocol: str, scan_type: str, flags_str: str)
        """
        if packet.tcp and packet.tcp.dst_port > 0:
            f = packet.tcp.flags
            flags_str = format_tcp_flags(f)

            # 1. Connection initiation: SYN without ACK (used by SYN scan & connect scan)
            if f.syn and not f.ack:
                return True, "TCP", "SYN_SCAN", flags_str

            # 2. Stealth scans:
            # NULL scan (no flags set)
            if not (f.syn or f.ack or f.rst or f.fin or f.psh or f.urg):
                return True, "TCP", "STEALTH_SCAN_NULL", flags_str
            # FIN scan (FIN without ACK)
            if f.fin and not (f.syn or f.ack or f.rst or f.psh or f.urg):
                return True, "TCP", "STEALTH_SCAN_FIN", flags_str
            # XMAS scan (FIN + PSH + URG)
            if f.fin and f.psh and f.urg and not (f.syn or f.ack or f.rst):
                return True, "TCP", "STEALTH_SCAN_XMAS", flags_str

            # Mid-stream packets (ACK, PSH-ACK) and server replies (SYN-ACK, RST) are NOT probes
            return False, "TCP", "", flags_str

        elif packet.udp and packet.udp.dst_port > 0:
            # Exclude standard service replies
            if packet.udp.src_port not in PortScanDetector.EXCLUDED_UDP_SRC_PORTS:
                return True, "UDP", "UDP_SCAN", "UDP"
            return False, "UDP", "", "UDP_EXCLUDED"

        return False, "", "", "NONE"

    def evaluate(
        self,
        packet: ParsedPacket,
        next_alert_id_fn: Callable[[], int],
    ) -> List[IDSAlert]:
        """
        Evaluates the incoming packet against port scanning baselines.
        Logs comprehensive debug telemetry for every packet evaluated.
        """
        alerts: List[IDSAlert] = []

        is_probe, proto, scan_type, flags_str = self.identify_probe(packet)

        now = packet.timestamp or time.time()
        src_ip = packet.ipv4.src_ip if packet.ipv4 else (packet.ipv6.src_ip if packet.ipv6 else "")
        dst_ip = packet.ipv4.dst_ip if packet.ipv4 else (packet.ipv6.dst_ip if packet.ipv6 else "")
        src_port = packet.tcp.src_port if packet.tcp else (packet.udp.src_port if packet.udp else 0)
        dst_port = packet.tcp.dst_port if packet.tcp else (packet.udp.dst_port if packet.udp else 0)

        if not src_ip or not dst_ip or dst_port <= 0:
            return alerts

        # Load configuration parameters
        ps_cfg = self.config.get("port_scan", {})
        window = float(ps_cfg.get("time_window_seconds", 300.0))
        threshold = int(ps_cfg.get("unique_ports_threshold", 10))
        severity_str = ps_cfg.get("severity", "HIGH")
        action_str = ps_cfg.get("action", "BLOCK")

        # Protocol-specific thresholds if configured
        if proto == "UDP":
            udp_cfg = self.config.get("udp_scan", {})
            if not udp_cfg.get("enabled", ps_cfg.get("enabled", True)):
                return alerts
            threshold = int(
                udp_cfg.get(
                    "unique_udp_ports_threshold",
                    udp_cfg.get("unique_ports_threshold", threshold),
                )
            )
            window = float(udp_cfg.get("time_window_seconds", window))
            severity_str = udp_cfg.get("severity", "HIGH")
            action_str = udp_cfg.get("action", "BLOCK")
        else:
            if not ps_cfg.get("enabled", True):
                return alerts

        # 1. Expire stale detection states past the configured time window
        self.purge_expired_detections(now, window)

        # 2. Key for active detection state: (source_ip, destination_ip, protocol)
        detection_key = (src_ip, dst_ip, proto)
        tracker = self._get_or_create_tracker(src_ip, dst_ip)

        # 3. Check if an active detection state already exists for this scan
        active_record = self.active_detections.get(detection_key)

        if active_record is not None:
            # Active scan is already detected and alerted!
            # Do NOT generate duplicate alerts for subsequent packets belonging to this scan.
            unique_count = active_record.current_unique_destination_port_count

            if is_probe:
                # Update tracker low-level state
                tracker.record_probe(now, dst_port, proto, scan_type)
                tracker.purge_aged(now, window)

                # Update the existing detection record
                is_new_port = active_record.record_port(dst_port, now)
                unique_count = active_record.current_unique_destination_port_count

                if is_new_port:
                    decision_str = (
                        f"ACTIVE_SCAN_UPDATED (New port {dst_port} discovered, "
                        f"total: {unique_count} unique ports, alert suppressed)"
                    )
                else:
                    decision_str = (
                        f"ACTIVE_SCAN_SUPPRESSED (Duplicate/retransmission to port {dst_port}, "
                        f"total: {unique_count} unique ports)"
                    )
            else:
                active_record.last_activity_timestamp = now
                decision_str = f"NOT_A_PROBE (Active scan ongoing for {detection_key})"

            logger.debug(
                f"[PORT_SCAN_DEBUG] Source IP: {src_ip} | Destination IP: {dst_ip} | "
                f"Destination Port: {dst_port} | TCP Flags: {flags_str} | "
                f"Unique Ports Tracked: {unique_count} | Detection Threshold: {threshold} | "
                f"Detection Decision: {decision_str}"
            )
            return alerts

        # 4. If no active detection state, evaluate incoming packet towards threshold
        if not is_probe:
            current_unique = len(tracker.get_unique_ports(proto if proto in ("TCP", "UDP") else None))
            logger.debug(
                f"[PORT_SCAN_DEBUG] Source IP: {src_ip} | Destination IP: {dst_ip} | "
                f"Destination Port: {dst_port} | TCP Flags: {flags_str} | "
                f"Unique Ports Tracked: {current_unique} | Detection Threshold: {threshold} | "
                f"Detection Decision: NOT_A_PROBE"
            )
            return alerts

        # Record probe attempt and purge aged records in sliding window
        is_new_attempt = tracker.record_probe(now, dst_port, proto, scan_type)
        tracker.purge_aged(now, window)

        # Periodic cleanup of inactive tracking entries
        self._cleanup_inactive_trackers(now, max_idle=window * 2)

        # Count unique destination ports probed specifically on this destination IP
        unique_ports = tracker.get_unique_ports(proto)
        unique_count = len(unique_ports)

        decision_str = ""

        if not is_new_attempt:
            decision_str = f"RETRANSMISSION_DEDUPLICATED (Port {dst_port} already recorded)"
        elif unique_count < threshold:
            decision_str = f"BELOW_THRESHOLD ({unique_count}/{threshold} unique ports)"
        else:
            # Threshold reached: Generate ONE initial PORT_SCAN_DETECTED alert
            sample_ports = sorted(list(unique_ports))[:10]
            sample_str = ", ".join(str(p) for p in sample_ports)
            if unique_count > 10:
                sample_str += f", ... (+{unique_count - 10} more)"

            rule_name = "UDP_PORT_SCAN_DETECTED" if proto == "UDP" else "PORT_SCAN_DETECTED"
            evidence = (
                f"Source: {src_ip} | Target: {dst_ip} | "
                f"Unique Ports: {unique_count} | Protocol: {proto} | "
                f"Time Window: {window:.0f}s | Probed Ports: [{sample_str}]"
            )

            alert_id = next_alert_id_fn()
            alert = IDSAlert.create(
                alert_id=alert_id,
                timestamp=now,
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=src_port,
                destination_port=dst_port,
                protocol=proto,
                category=DetectionCategory.PORT_SCAN,
                severity=Severity[severity_str],
                matched_rule=rule_name,
                evidence=evidence,
                recommended_action=DecisionAction[action_str],
                packet_id=packet.packet_id,
            )
            alerts.append(alert)

            # Create and maintain active detection state
            record = ScanDetectionRecord(
                source_ip=src_ip,
                destination_ip=dst_ip,
                protocol=proto,
                first_detection_timestamp=now,
                last_activity_timestamp=now,
                destination_ports=set(unique_ports),
                initial_ports=set(unique_ports),
                newly_discovered_ports=set(),
                initial_alert_id=alert_id,
                initial_alert=alert,
            )
            self.active_detections[detection_key] = record
            tracker.active_detections[proto] = record
            decision_str = f"ALERT_GENERATED ({rule_name} triggered with {unique_count} unique ports)"

        # Emit mandatory debug-level logging
        logger.debug(
            f"[PORT_SCAN_DEBUG] Source IP: {src_ip} | Destination IP: {dst_ip} | "
            f"Destination Port: {dst_port} | TCP Flags: {flags_str} | "
            f"Unique Ports Tracked: {unique_count} | Detection Threshold: {threshold} | "
            f"Detection Decision: {decision_str}"
        )

        return alerts
