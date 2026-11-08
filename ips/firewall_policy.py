"""Firewall Policy, Per-Client Rules, Allowlist/Denylist, Dynamic Expirable Blocking, and Emergency Killswitch."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import json
import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from models.alert_model import DecisionAction, IDSAlert, Severity
from models.packet_models import ParsedPacket

logger = logging.getLogger("dpi_ids_ips.ips.firewall_policy")


@dataclass
class FirewallRule:
    """Static or protocol-based firewall rule."""
    rule_id: str
    action: DecisionAction  # ALLOW or BLOCK
    protocol: str = "ANY"  # TCP, UDP, ICMP, DNS, HTTP, TLS, ANY
    src_cidr: Optional[str] = None
    dst_cidr: Optional[str] = None
    src_ports: Optional[Set[int]] = None
    dst_ports: Optional[Set[int]] = None
    direction: str = "BOTH"  # INBOUND, OUTBOUND, BOTH
    description: str = ""
    enabled: bool = True

    def matches(self, packet: ParsedPacket, is_outbound: bool) -> bool:
        """Evaluates whether a packet matches this firewall rule."""
        if not self.enabled:
            return False

        # Direction check
        if self.direction == "INBOUND" and is_outbound:
            return False
        if self.direction == "OUTBOUND" and not is_outbound:
            return False

        # Protocol check
        if self.protocol != "ANY":
            proto = packet.transport_type.upper() if packet.transport_type != "None" else packet.network_type.upper()
            if self.protocol.upper() != proto:
                return False

        src_ip = packet.ipv4.src_ip if packet.ipv4 else (packet.ipv6.src_ip if packet.ipv6 else "")
        dst_ip = packet.ipv4.dst_ip if packet.ipv4 else (packet.ipv6.dst_ip if packet.ipv6 else "")
        src_port = packet.tcp.src_port if packet.tcp else (packet.udp.src_port if packet.udp else 0)
        dst_port = packet.tcp.dst_port if packet.tcp else (packet.udp.dst_port if packet.udp else 0)

        # Port checks
        if self.src_ports and src_port not in self.src_ports:
            return False
        if self.dst_ports and dst_port not in self.dst_ports:
            return False

        # IP CIDR checks
        if self.src_cidr and src_ip:
            try:
                if ipaddress.ip_address(src_ip) not in ipaddress.ip_network(self.src_cidr, strict=False):
                    return False
            except ValueError:
                return False

        if self.dst_cidr and dst_ip:
            try:
                if ipaddress.ip_address(dst_ip) not in ipaddress.ip_network(self.dst_cidr, strict=False):
                    return False
            except ValueError:
                return False

        return True


@dataclass
class ClientSecurityPolicy:
    """Client-specific security isolation and enforcement profile."""
    client_ip: str
    client_name: str = ""
    allowed_protocols: Set[str] = field(default_factory=lambda: {"ANY"})
    blocked_protocols: Set[str] = field(default_factory=set)
    allowed_dst_ports: Optional[Set[int]] = None
    blocked_dst_ports: Set[int] = field(default_factory=set)  # e.g. {22, 23, 445}
    quarantined: bool = False
    quarantine_reason: str = ""
    max_bandwidth_bps: Optional[int] = None

    def evaluate(self, packet: ParsedPacket, app_proto: str = "") -> Tuple[bool, str]:
        """
        Evaluates a client packet against its dedicated security profile.

        Returns:
            Tuple of (is_allowed, reason)
        """
        # Quarantined client check
        if self.quarantined:
            # Only allow essential DNS resolving so client can reach notification portals
            dst_port = packet.tcp.dst_port if packet.tcp else (packet.udp.dst_port if packet.udp else 0)
            if dst_port != 53:
                return False, f"Client {self.client_ip} is QUARANTINED: {self.quarantine_reason}"

        dst_port = packet.tcp.dst_port if packet.tcp else (packet.udp.dst_port if packet.udp else 0)
        proto = app_proto.upper() if app_proto and app_proto != "None" else (
            packet.transport_type.upper() if packet.transport_type != "None" else packet.network_type.upper()
        )

        # Check explicitly blocked destination ports
        if dst_port in self.blocked_dst_ports:
            return False, f"Port {dst_port} is blocked by client security policy"

        # Check explicitly blocked protocols
        if proto in self.blocked_protocols:
            return False, f"Protocol {proto} is prohibited by client policy"

        # Check whitelist if restricted
        if "ANY" not in self.allowed_protocols and proto not in self.allowed_protocols:
            return False, f"Protocol {proto} not permitted in client allowlist"

        if self.allowed_dst_ports is not None and dst_port not in self.allowed_dst_ports:
            return False, f"Destination port {dst_port} not permitted in client allowlist"

        return True, "Client policy permitted"


@dataclass
class TemporaryBlock:
    """Represents a temporary dynamic ban on an IP address."""
    ip_address: str
    reason: str
    severity: Severity
    blocked_at: float
    duration_seconds: float
    expires_at: float
    trigger_alert_id: Optional[int] = None

    def is_expired(self, now: Optional[float] = None) -> bool:
        ts = now or time.time()
        return ts >= self.expires_at

    def time_remaining(self, now: Optional[float] = None) -> float:
        ts = now or time.time()
        return max(0.0, self.expires_at - ts)


class DynamicBlockManager:
    """Maintains expirable dynamic IP blocks initiated by IDS decisions."""

    def __init__(self, default_ban_seconds: float = 60.0) -> None:
        self.default_ban_seconds = default_ban_seconds
        # ip -> TemporaryBlock
        self._active_blocks: Dict[str, TemporaryBlock] = {}
        self.total_dynamic_blocks_created = 0

    def add_block(
        self,
        ip_address: str,
        reason: str,
        severity: Severity = Severity.HIGH,
        duration_seconds: Optional[float] = None,
        alert_id: Optional[int] = None,
    ) -> TemporaryBlock:
        """Issues a temporary block on an IP address."""
        now = time.time()
        dur = duration_seconds or self.default_ban_seconds
        block = TemporaryBlock(
            ip_address=ip_address,
            reason=reason,
            severity=severity,
            blocked_at=now,
            duration_seconds=dur,
            expires_at=now + dur,
            trigger_alert_id=alert_id,
        )
        self._active_blocks[ip_address] = block
        self.total_dynamic_blocks_created += 1
        logger.warning(f"DYNAMIC BLOCK ISSUED: IP {ip_address} blocked for {dur:.0f}s. Reason: {reason}")
        return block

    def unblock(self, ip_address: str) -> bool:
        """Manually releases a dynamic block."""
        if ip_address in self._active_blocks:
            del self._active_blocks[ip_address]
            logger.info(f"Dynamic block for IP {ip_address} manually cleared.")
            return True
        return False

    def is_blocked(self, ip_address: str, now: Optional[float] = None) -> Tuple[bool, Optional[TemporaryBlock]]:
        """Checks if an IP is currently under an active non-expired block."""
        ts = now or time.time()
        block = self._active_blocks.get(ip_address)
        if not block:
            return False, None
        if block.is_expired(ts):
            del self._active_blocks[ip_address]
            logger.info(f"Dynamic block on IP {ip_address} expired.")
            return False, None
        return True, block

    def clean_expired(self, now: Optional[float] = None) -> int:
        """Removes all expired bans."""
        ts = now or time.time()
        expired = [ip for ip, b in self._active_blocks.items() if b.is_expired(ts)]
        for ip in expired:
            del self._active_blocks[ip]
        return len(expired)

    def get_expired_blocks(self, now: Optional[float] = None) -> List[str]:
        """Returns list of expired block IPs."""
        ts = now or time.time()
        return [ip for ip, b in self._active_blocks.items() if b.is_expired(ts)]

    def get_all_active_blocks(self) -> List[TemporaryBlock]:
        """Returns all currently active dynamic blocks."""
        self.clean_expired()
        return list(self._active_blocks.values())


class AllowlistDenylistManager:
    """Manages static allowlists (system exemptions) and denylists (forbidden targets)."""

    def __init__(self) -> None:
        # Allowlists: Traffic to/from these is NEVER blocked
        self.allowlisted_ips: Set[str] = {"127.0.0.1", "::1", "0.0.0.0", "255.255.255.255"}
        self.allowlisted_subnets: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.allowlisted_ports: Set[int] = {67, 68, 5353}  # DHCP, mDNS

        # Denylists: Traffic to/from these is IMMEDIATELY blocked unconditionally
        self.denylisted_ips: Set[str] = set()
        self.denylisted_subnets: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.denylisted_domains: Set[str] = set()

    def add_allowlist_ip(self, ip_or_cidr: str) -> None:
        if "/" in ip_or_cidr:
            self.allowlisted_subnets.append(ipaddress.ip_network(ip_or_cidr, strict=False))
        else:
            self.allowlisted_ips.add(ip_or_cidr)

    def add_denylist_ip(self, ip_or_cidr: str) -> None:
        if "/" in ip_or_cidr:
            self.denylisted_subnets.append(ipaddress.ip_network(ip_or_cidr, strict=False))
        else:
            self.denylisted_ips.add(ip_or_cidr)

    def add_denylist_domain(self, domain: str) -> None:
        self.denylisted_domains.add(domain.strip().lower().rstrip("."))

    def is_allowlisted(self, packet: ParsedPacket) -> bool:
        """Determines if a packet is protected by the safety allowlist."""
        src_ip = packet.ipv4.src_ip if packet.ipv4 else (packet.ipv6.src_ip if packet.ipv6 else "")
        dst_ip = packet.ipv4.dst_ip if packet.ipv4 else (packet.ipv6.dst_ip if packet.ipv6 else "")
        src_port = packet.tcp.src_port if packet.tcp else (packet.udp.src_port if packet.udp else 0)
        dst_port = packet.tcp.dst_port if packet.tcp else (packet.udp.dst_port if packet.udp else 0)

        if src_ip in self.allowlisted_ips or dst_ip in self.allowlisted_ips:
            return True

        if src_port in self.allowlisted_ports or dst_port in self.allowlisted_ports:
            return True

        try:
            if src_ip:
                s_addr = ipaddress.ip_address(src_ip)
                if any(s_addr in net for net in self.allowlisted_subnets):
                    return True
            if dst_ip:
                d_addr = ipaddress.ip_address(dst_ip)
                if any(d_addr in net for net in self.allowlisted_subnets):
                    return True
        except ValueError:
            pass

        return False

    def is_denylisted(self, packet: ParsedPacket, query_domain: Optional[str] = None) -> Tuple[bool, str]:
        """Checks if packet matches static denylists."""
        src_ip = packet.ipv4.src_ip if packet.ipv4 else (packet.ipv6.src_ip if packet.ipv6 else "")
        dst_ip = packet.ipv4.dst_ip if packet.ipv4 else (packet.ipv6.dst_ip if packet.ipv6 else "")

        if src_ip in self.denylisted_ips:
            return True, f"Source IP {src_ip} is in static denylist"
        if dst_ip in self.denylisted_ips:
            return True, f"Destination IP {dst_ip} is in static denylist"

        try:
            if src_ip:
                s_addr = ipaddress.ip_address(src_ip)
                if any(s_addr in net for net in self.denylisted_subnets):
                    return True, f"Source IP {src_ip} in denylisted CIDR"
            if dst_ip:
                d_addr = ipaddress.ip_address(dst_ip)
                if any(d_addr in net for net in self.denylisted_subnets):
                    return True, f"Destination IP {dst_ip} in denylisted CIDR"
        except ValueError:
            pass

        if query_domain:
            clean = query_domain.strip().lower().rstrip(".")
            if clean in self.denylisted_domains:
                return True, f"Domain '{clean}' is in static domain denylist"

        return False, ""


class EmergencyKillswitch:
    """Instant fail-open emergency disable switch."""

    def __init__(self) -> None:
        self.is_active: bool = False
        self.triggered_at: Optional[float] = None
        self.trigger_reason: str = ""

    def activate(self, reason: str = "Administrator Emergency Override") -> None:
        """Instantly disables active blocking."""
        self.is_active = True
        self.triggered_at = time.time()
        self.trigger_reason = reason
        logger.critical(f"EMERGENCY KILLSWITCH ACTIVATED: {reason}. All packet blocking suspended.")

    def deactivate(self) -> None:
        """Restores normal protection operation."""
        self.is_active = False
        self.triggered_at = None
        self.trigger_reason = ""
        logger.info("Emergency killswitch deactivated. Normal IPS enforcement resumed.")

