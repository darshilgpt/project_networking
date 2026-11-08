"""IP Intelligence, CIDR classification, IP spoofing detection, and TTL hop-count analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import logging
import time
from typing import Dict, List, Optional, Tuple

from models.packet_models import ParsedPacket

logger = logging.getLogger("dpi_ids_ips.network.ip_intelligence")


@dataclass
class IPIntelligenceAlert:
    """Security alert raised by the IP intelligence subsystem."""
    alert_type: str
    severity: str
    source_ip: str
    destination_ip: str
    evidence: str
    timestamp: float


@dataclass
class HostTTLProfile:
    """Maintains observed TTL history and estimated hops for a host."""
    inferred_initial_ttl: int
    estimated_hops: int
    last_observed_ttl: int
    ttl_variance_count: int = 0
    history: List[int] = field(default_factory=list)

    @property
    def baseline_ttl(self) -> int:
        """Returns the median observed TTL as a stable baseline."""
        if not self.history:
            return self.last_observed_ttl
        sorted_h = sorted(self.history)
        return sorted_h[len(sorted_h) // 2]


class IPIntelligenceEngine:
    """Evaluates CIDR subnets, identifies IP spoofing/Land attacks, and analyzes TTL hop counts."""

    # Special Bogon / Martian Subnets (RFC 6890 / RFC 5735)
    BOGONS = [
        ipaddress.ip_network("0.0.0.0/8"),       # Current network ("this" network)
        ipaddress.ip_network("127.0.0.0/8"),     # Loopback
        ipaddress.ip_network("169.254.0.0/16"),   # Link-local
        ipaddress.ip_network("224.0.0.0/4"),     # Multicast (cannot be source)
        ipaddress.ip_network("240.0.0.0/4"),     # Reserved
        ipaddress.ip_network("255.255.255.255/32"), # Broadcast
    ]

    RFC1918_PRIVATE = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("100.64.0.0/10"),   # Shared CGNAT space (RFC 6598)
    ]

    def __init__(
        self,
        local_subnets: Optional[List[str]] = None,
        ttl_variance_threshold: int = 8,
        low_ttl_threshold: int = 2,
    ) -> None:
        self.ttl_variance_threshold = ttl_variance_threshold
        self.low_ttl_threshold = low_ttl_threshold
        self.local_networks = [
            ipaddress.ip_network(s.strip(), strict=False) for s in (local_subnets or ["10.8.0.0/24", "10.178.3.0/24"])
        ]
        # IP -> HostTTLProfile
        self.ttl_profiles: Dict[str, HostTTLProfile] = {}

    @classmethod
    def classify_ip(cls, ip_str: str) -> str:
        """Classifies an IP address into standard architectural categories."""
        if not ip_str or ip_str in ("None", "0.0.0.0"):
            return "UNKNOWN"
        try:
            addr = ipaddress.ip_address(ip_str)
            if addr.is_loopback:
                return "LOOPBACK"
            if addr.is_multicast:
                return "MULTICAST"
            if addr.is_link_local:
                return "LINK_LOCAL"
            if any(addr in net for net in cls.RFC1918_PRIVATE):
                return "RFC1918_PRIVATE"
            if addr.is_private:
                return "PRIVATE"
            return "PUBLIC_INTERNET"
        except ValueError:
            return "INVALID"

    @staticmethod
    def infer_initial_ttl(observed_ttl: int) -> int:
        """Infers the probable initial TTL based on operating system standards."""
        if observed_ttl <= 64:
            return 64   # Linux / Android / macOS / iOS
        elif observed_ttl <= 128:
            return 128  # Windows
        else:
            return 255  # Network gear / Cisco / Solaris

    def evaluate_packet(self, packet: ParsedPacket) -> List[IPIntelligenceAlert]:
        """Runs IP spoofing, Land attack, and TTL hop-count anomaly checks."""
        alerts: List[IPIntelligenceAlert] = []
        now = packet.timestamp or time.time()

        src_ip = packet.ipv4.src_ip if packet.ipv4 else (packet.ipv6.src_ip if packet.ipv6 else None)
        dst_ip = packet.ipv4.dst_ip if packet.ipv4 else (packet.ipv6.dst_ip if packet.ipv6 else None)
        if not src_ip or not dst_ip:
            return alerts

        src_port = packet.tcp.src_port if packet.tcp else (packet.udp.src_port if packet.udp else 0)
        dst_port = packet.tcp.dst_port if packet.tcp else (packet.udp.dst_port if packet.udp else 0)

        # --- 1. Land Attack Detection (Source IP == Dest IP and Source Port == Dest Port) ---
        if src_ip == dst_ip and src_port > 0 and src_port == dst_port:
            alerts.append(
                IPIntelligenceAlert(
                    alert_type="LAND_ATTACK_IP_SPOOF",
                    severity="CRITICAL",
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    evidence=f"Land Attack detected: Source {src_ip}:{src_port} is identical to Destination {dst_ip}:{dst_port}.",
                    timestamp=now,
                )
            )

        # --- 2. Bogon / Martian Source IP Spoofing Detection ---
        try:
            s_addr = ipaddress.ip_address(src_ip)
            if s_addr.version == 4:
                # Check if routable packet has a bogon source (e.g. 127.0.0.1 or multicast)
                if s_addr.is_multicast or s_addr.is_loopback or str(s_addr).startswith("0."):
                    alerts.append(
                        IPIntelligenceAlert(
                            alert_type="BOGON_SOURCE_IP_SPOOF",
                            severity="HIGH",
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            evidence=f"Illegal Bogon/Martian source IP '{src_ip}' detected in transit to {dst_ip}.",
                            timestamp=now,
                        )
                    )
        except ValueError:
            pass

        # --- 3. TTL and Hop-Count Analysis ---
        if packet.ipv4:
            ttl = packet.ipv4.ttl
            initial_ttl = self.infer_initial_ttl(ttl)
            hops = max(0, initial_ttl - ttl)

            # Check if destination is link-scoped multicast, broadcast, or local discovery port
            is_link_local_or_multicast = False
            try:
                d_addr = ipaddress.ip_address(dst_ip)
                if d_addr.is_multicast or d_addr.is_link_local or dst_ip == "255.255.255.255":
                    is_link_local_or_multicast = True
            except ValueError:
                pass

            if dst_port in (1900, 5353, 5355, 67, 68):
                is_link_local_or_multicast = True

            # Expected range for this initial TTL (allowing up to 30 internet transit hops)
            min_expected = max(1, initial_ttl - 30)
            max_expected = initial_ttl

            # A. TTL Evasion Check (Only for routable unicast packets)
            if not is_link_local_or_multicast and ttl <= self.low_ttl_threshold:
                alerts.append(
                    IPIntelligenceAlert(
                        alert_type="TTL_EVASION_PROBE",
                        severity="MEDIUM",
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        evidence=(
                            f"Routable packet with abnormally low TTL. "
                            f"Observed TTL: {ttl} | Expected TTL range: [{min_expected}, {max_expected}] (inferred OS initial TTL: {initial_ttl}) | "
                            f"Source IP: {src_ip} | Destination IP: {dst_ip}. "
                            f"Potential traceroute probe or IDS hop-evasion attempt."
                        ),
                        timestamp=now,
                    )
                )

            # B. TTL Profile Tracking per Source Host (for routable unicast traffic)
            if not is_link_local_or_multicast:
                profile = self.ttl_profiles.get(src_ip)
                if not profile:
                    profile = HostTTLProfile(
                        inferred_initial_ttl=initial_ttl,
                        estimated_hops=hops,
                        last_observed_ttl=ttl,
                        history=[ttl],
                    )
                    self.ttl_profiles[src_ip] = profile
                else:
                    baseline = profile.baseline_ttl
                    diff = abs(ttl - baseline)
                    profile.history.append(ttl)
                    if len(profile.history) > 50:
                        profile.history.pop(0)

                    # Check for erratic TTL jumps for the same host
                    if diff >= self.ttl_variance_threshold:
                        profile.ttl_variance_count += 1
                        alerts.append(
                            IPIntelligenceAlert(
                                alert_type="TTL_VARIANCE_SPOOFING_ANOMALY",
                                severity="MEDIUM",
                                source_ip=src_ip,
                                destination_ip=dst_ip,
                                evidence=(
                                    f"Erratic TTL variance for {src_ip}. "
                                    f"Observed TTL: {ttl} (differs by {diff} from host baseline {baseline}) | "
                                    f"Expected TTL range: [{min_expected}, {max_expected}] (inferred initial: {profile.inferred_initial_ttl}) | "
                                    f"Source IP: {src_ip} | Destination IP: {dst_ip}. "
                                    f"Indicates source IP spoofing or asymmetric path manipulation."
                                ),
                                timestamp=now,
                            )
                        )
                    profile.last_observed_ttl = ttl

        return alerts
