"""Network Reconnaissance, Subnet Sweep, and OS Fingerprinting Detector."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
import logging
import time
from typing import Deque, Dict, List, Optional, Set, Tuple

from models.alert_model import DecisionAction, DetectionCategory, IDSAlert, Severity
from models.packet_models import ParsedPacket

logger = logging.getLogger("dpi_ids_ips.ids.reconnaissance")


@dataclass
class ReconAlert:
    """Security alert raised for network reconnaissance activity."""
    alert_type: str
    severity: Severity
    source_ip: str
    destination_ip: str
    evidence: str
    timestamp: float


class ReconnaissanceDetector:
    """Detects subnet sweeps (ICMP, ARP, TCP), OS fingerprinting, and service enumeration."""

    def __init__(
        self,
        ping_sweep_threshold: int = 5,
        arp_sweep_threshold: int = 8,
        tcp_sweep_threshold: int = 5,
        sweep_window_seconds: float = 5.0,
    ) -> None:
        self.ping_sweep_threshold = ping_sweep_threshold
        self.arp_sweep_threshold = arp_sweep_threshold
        self.tcp_sweep_threshold = tcp_sweep_threshold
        self.sweep_window_seconds = sweep_window_seconds

        # Sliding window state:
        # src_ip -> deque[(timestamp, dst_ip)]
        self._ping_sweep_tracker: Dict[str, Deque[Tuple[float, str]]] = defaultdict(deque)
        self._arp_sweep_tracker: Dict[str, Deque[Tuple[float, str]]] = defaultdict(deque)
        # (src_ip, dport) -> deque[(timestamp, dst_ip)]
        self._tcp_sweep_tracker: Dict[Tuple[str, int], Deque[Tuple[float, str]]] = defaultdict(deque)

        # Alert cooldown to prevent alert spamming: (src_ip, alert_type) -> timestamp
        self._alert_cooldowns: Dict[Tuple[str, str], float] = {}

    def _is_cooldown_active(self, src_ip: str, alert_type: str, now: float, cooldown: float = 4.0) -> bool:
        key = (src_ip, alert_type)
        last = self._alert_cooldowns.get(key, 0.0)
        if now - last < cooldown:
            return True
        self._alert_cooldowns[key] = now
        return False

    def evaluate(self, packet: ParsedPacket) -> List[ReconAlert]:
        """Evaluates a packet for reconnaissance and scanning sweeps."""
        alerts: List[ReconAlert] = []
        now = packet.timestamp or time.time()

        src_ip = packet.ipv4.src_ip if packet.ipv4 else (packet.ipv6.src_ip if packet.ipv6 else None)
        dst_ip = packet.ipv4.dst_ip if packet.ipv4 else (packet.ipv6.dst_ip if packet.ipv6 else None)

        # 1. ICMP Ping Sweep Detection (One source pinging multiple destination IPs)
        if packet.icmp and src_ip and dst_ip:
            is_echo = (not packet.icmp.is_ipv6 and packet.icmp.icmp_type == 8) or (packet.icmp.is_ipv6 and packet.icmp.icmp_type == 128)
            if is_echo:
                q = self._ping_sweep_tracker[src_ip]
                q.append((now, dst_ip))
                while q and now - q[0][0] > self.sweep_window_seconds:
                    q.popleft()

                unique_targets = {target for _, target in q}
                if len(unique_targets) >= self.ping_sweep_threshold:
                    if not self._is_cooldown_active(src_ip, "PING_SWEEP", now):
                        alerts.append(
                            ReconAlert(
                                alert_type="ICMP_PING_SWEEP_RECONNAISSANCE",
                                severity=Severity.MEDIUM,
                                source_ip=src_ip,
                                destination_ip=dst_ip,
                                evidence=(
                                    f"Host {src_ip} pinged {len(unique_targets)} unique destinations "
                                    f"within {self.sweep_window_seconds:.1f}s. Subnet discovery sweep."
                                ),
                                timestamp=now,
                            )
                        )

        # 2. TCP Port Sweep Detection (One source scanning same port across multiple target IPs)
        if packet.tcp and src_ip and dst_ip and packet.tcp.flags.syn and not packet.tcp.flags.ack:
            dport = packet.tcp.dst_port
            key = (src_ip, dport)
            tq = self._tcp_sweep_tracker[key]
            tq.append((now, dst_ip))
            while tq and now - tq[0][0] > self.sweep_window_seconds:
                tq.popleft()

            unique_hosts = {target for _, target in tq}
            if len(unique_hosts) >= self.tcp_sweep_threshold:
                if not self._is_cooldown_active(src_ip, f"TCP_SWEEP_{dport}", now):
                    alerts.append(
                        ReconAlert(
                            alert_type="TCP_SUBNET_SWEEP_RECONNAISSANCE",
                            severity=Severity.HIGH,
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            evidence=(
                                f"Host {src_ip} probed destination port {dport} across {len(unique_hosts)} "
                                f"unique subnet hosts within {self.sweep_window_seconds:.1f}s."
                            ),
                            timestamp=now,
                        )
                    )

            # 3. OS Fingerprinting Probe Detection
            # Nmap / Zmap OS detection probe heuristics:
            # - SYN with anomalous TCP window sizes (e.g. 1024, 2048, 3072, 4096)
            # - SYN packet with URG or PSH set
            win = packet.tcp.window_size
            f = packet.tcp.flags
            if (f.syn and f.urg) or (f.syn and f.psh):
                if not self._is_cooldown_active(src_ip, "TCP_OS_PROBE", now):
                    alerts.append(
                        ReconAlert(
                            alert_type="OS_FINGERPRINTING_PROBE",
                            severity=Severity.HIGH,
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            evidence=f"Anomalous TCP SYN flags (URG={f.urg}, PSH={f.psh}) characteristic of OS fingerprinting probe.",
                            timestamp=now,
                        )
                    )
            elif win in (1024, 2048, 3072, 4096) and dport in (80, 443, 22, 445):
                # Check for suspicious low-window scanning probe
                if not self._is_cooldown_active(src_ip, "SCAN_PROBE_WINDOW", now, cooldown=10.0):
                    alerts.append(
                        ReconAlert(
                            alert_type="OS_SCANNER_PROBE_SIGNATURE",
                            severity=Severity.LOW,
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            evidence=f"SYN packet with fixed window size {win} matching active network scanner signature.",
                            timestamp=now,
                        )
                    )

        # 4. ARP Sweep Detection (Dissected ARP payload)
        if packet.network_type == "ARP" and packet.payload and len(packet.payload) >= 28:
            # Target IP is at offset 24:28
            try:
                import socket
                target_ip = socket.inet_ntoa(packet.payload[24:28])
                sender_ip = socket.inet_ntoa(packet.payload[14:18])
                if sender_ip not in ("0.0.0.0", target_ip):
                    aq = self._arp_sweep_tracker[sender_ip]
                    aq.append((now, target_ip))
                    while aq and now - aq[0][0] > self.sweep_window_seconds:
                        aq.popleft()

                    unique_arp_targets = {t for _, t in aq}
                    if len(unique_arp_targets) >= self.arp_sweep_threshold:
                        if not self._is_cooldown_active(sender_ip, "ARP_SWEEP", now):
                            alerts.append(
                                ReconAlert(
                                    alert_type="ARP_SUBNET_SWEEP_RECONNAISSANCE",
                                    severity=Severity.HIGH,
                                    source_ip=sender_ip,
                                    destination_ip=target_ip,
                                    evidence=(
                                        f"Host {sender_ip} issued ARP queries for {len(unique_arp_targets)} "
                                        f"unique IPs in {self.sweep_window_seconds:.1f}s. Layer 2 reconnaissance."
                                    ),
                                    timestamp=now,
                                )
                            )
            except Exception:
                pass

        return alerts

