"""Multi-client identification and per-client isolated flow tracking subsystem."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import logging
import threading
import time
from typing import Dict, List, Optional, Set, Tuple

from flow.flow_manager import FlowManager
from models.alert_model import IDSAlert, Severity
from models.packet_models import ParsedPacket
from reassembly.tcp_reassembler import TCPReassembler

logger = logging.getLogger("dpi_ids_ips.server.client_manager")


@dataclass
class ClientStatsSnapshot:
    """Read-only snapshot of a client's metrics for dashboard and logging."""
    client_ip: str
    client_name: str
    total_packets: int
    packets_in: int
    packets_out: int
    total_bytes: int
    bytes_in: int
    bytes_out: int
    active_flows: int
    top_protocol: str
    protocol_counts: Dict[str, int]
    alerts_count: int
    severity_counts: Dict[str, int]
    blocked_count: int
    last_seen: float
    is_active: bool
    os_guess: str = "Unknown"
    vendor: str = "Unknown"
    ja3_count: int = 0
    dns_queries_count: int = 0
    tunneling_flags_count: int = 0
    retransmission_count: int = 0
    out_of_order_count: int = 0


class ClientContext:
    """Maintains completely isolated flow tracking, TCP reassembly, and stats for one client."""

    def __init__(self, client_ip: str, client_name: Optional[str] = None) -> None:
        self.client_ip = client_ip
        self.client_name = client_name or f"Client-{client_ip}"
        self.created_at = time.time()
        self.last_seen = time.time()

        # Dedicated isolated flow tracking & TCP reassembly
        self.flow_manager = FlowManager()
        self.tcp_reassembler = TCPReassembler()

        # Thread safety lock for client-level stats
        self._lock = threading.Lock()

        # Per-client metrics
        self.packets_in = 0
        self.packets_out = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.protocol_counts: Dict[str, int] = {}
        self.alerts: List[IDSAlert] = []
        self.severity_counts: Dict[str, int] = {
            Severity.LOW.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.HIGH.value: 0,
            Severity.CRITICAL.value: 0,
        }
        self.blocked_count = 0

        # Network intelligence & device profiling
        self.os_guess = "Unknown"
        self.vendor = "Unknown"
        self.ja3_fingerprints: Set[str] = set()
        self.dns_queries_count = 0
        self.tunneling_flags_count = 0
        self.retransmission_count = 0
        self.out_of_order_count = 0

    def record_os_vendor(self, os_guess: Optional[str] = None, vendor: Optional[str] = None) -> None:
        """Records inferred OS and hardware vendor for this client."""
        with self._lock:
            if os_guess and os_guess != "Unknown":
                self.os_guess = os_guess
            if vendor and vendor != "Unknown":
                self.vendor = vendor

    def record_ja3(self, ja3_hash: str) -> None:
        """Records a TLS JA3 fingerprint hash seen from this client."""
        if not ja3_hash:
            return
        with self._lock:
            self.ja3_fingerprints.add(ja3_hash)

    def record_dns_query(self, is_tunneling: bool = False) -> None:
        """Tracks DNS queries and tunneling flags for this client."""
        with self._lock:
            self.dns_queries_count += 1
            if is_tunneling:
                self.tunneling_flags_count += 1

    def record_tcp_metrics(self, is_retransmission: bool = False, is_out_of_order: bool = False) -> None:
        """Tracks TCP quality and reordering anomalies for this client."""
        with self._lock:
            if is_retransmission:
                self.retransmission_count += 1
            if is_out_of_order:
                self.out_of_order_count += 1

    def record_packet(self, packet: ParsedPacket, is_outbound_from_client: bool) -> None:
        """Records packet volume and direction for this client."""
        length = packet.raw_length or len(packet.payload)
        now = packet.timestamp or time.time()

        with self._lock:
            self.last_seen = max(self.last_seen, now)
            if is_outbound_from_client:
                self.packets_out += 1
                self.bytes_out += length
            else:
                self.packets_in += 1
                self.bytes_in += length

    def record_protocol(self, protocol_name: str) -> None:
        """Records an application-layer protocol classification."""
        if not protocol_name or protocol_name in ("None", "Unknown"):
            return
        with self._lock:
            self.protocol_counts[protocol_name] = self.protocol_counts.get(protocol_name, 0) + 1

    def record_alert(self, alert: IDSAlert) -> None:
        """Logs an alert against this client's history."""
        with self._lock:
            self.alerts.append(alert)
            sev = alert.severity.value
            self.severity_counts[sev] = self.severity_counts.get(sev, 0) + 1
            if getattr(alert, "recommended_action", None) and alert.recommended_action.value == "BLOCK":
                self.blocked_count += 1

    def get_snapshot(self, idle_threshold: float = 30.0) -> ClientStatsSnapshot:
        """Generates an atomic snapshot of client statistics."""
        with self._lock:
            total_pkts = self.packets_in + self.packets_out
            total_bytes = self.bytes_in + self.bytes_out
            top_proto = "None"
            if self.protocol_counts:
                top_proto = max(self.protocol_counts.items(), key=lambda kv: kv[1])[0]

            active_flows = self.flow_manager.tracker.active_flow_count
            is_active = (time.time() - self.last_seen) < idle_threshold

            return ClientStatsSnapshot(
                client_ip=self.client_ip,
                client_name=self.client_name,
                total_packets=total_pkts,
                packets_in=self.packets_in,
                packets_out=self.packets_out,
                total_bytes=total_bytes,
                bytes_in=self.bytes_in,
                bytes_out=self.bytes_out,
                active_flows=active_flows,
                top_protocol=top_proto,
                protocol_counts=dict(self.protocol_counts),
                alerts_count=len(self.alerts),
                severity_counts=dict(self.severity_counts),
                blocked_count=self.blocked_count,
                last_seen=self.last_seen,
                is_active=is_active,
                os_guess=self.os_guess,
                vendor=self.vendor,
                ja3_count=len(self.ja3_fingerprints),
                dns_queries_count=self.dns_queries_count,
                tunneling_flags_count=self.tunneling_flags_count,
                retransmission_count=self.retransmission_count,
                out_of_order_count=self.out_of_order_count,
            )


class ClientManager:
    """Manages VPN client registration, subnet detection, and isolated contexts."""

    def __init__(
        self,
        vpn_subnets: Optional[List[str]] = None,
        predefined_clients: Optional[Dict[str, str]] = None,
        auto_discover_clients: bool = True,
    ) -> None:
        """
        Args:
            vpn_subnets: List of CIDR subnets (e.g. ['10.8.0.0/24', '10.200.0.0/24']).
            predefined_clients: Mapping of IP string to custom client name.
            auto_discover_clients: If True, dynamically creates ClientContext for encountered VPN IPs.
        """
        self._networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in vpn_subnets or ["10.8.0.0/24"]:
            try:
                self._networks.append(ipaddress.ip_network(cidr.strip(), strict=False))
            except ValueError as ve:
                logger.warning(f"Invalid VPN CIDR specification '{cidr}': {ve}")

        self._clients: Dict[str, ClientContext] = {}
        self._predefined = predefined_clients or {}
        self._auto_discover = auto_discover_clients
        self._lock = threading.Lock()

        # Fallback context for non-VPN host traffic
        self._default_context = ClientContext(client_ip="Host/Gateway", client_name="Host/Non-VPN Traffic")

        # Initialize any predefined clients upfront
        for ip_str, name in self._predefined.items():
            self._clients[ip_str] = ClientContext(client_ip=ip_str, client_name=name)

        # Fast cache for IP -> is_vpn check
        self._ip_cache: Dict[str, bool] = {}

    def is_vpn_ip(self, ip_str: str) -> bool:
        """Determines whether an IP address belongs to the configured VPN networks."""
        if not ip_str or ip_str in ("0.0.0.0", "255.255.255.255", "127.0.0.1", "::1"):
            return False

        with self._lock:
            if ip_str in self._ip_cache:
                return self._ip_cache[ip_str]

        try:
            addr = ipaddress.ip_address(ip_str)
            is_vpn = any(addr in net for net in self._networks)
        except ValueError:
            is_vpn = False

        with self._lock:
            # Bound cache size
            if len(self._ip_cache) > 2048:
                self._ip_cache.clear()
            self._ip_cache[ip_str] = is_vpn

        return is_vpn

    def resolve_client(self, packet: ParsedPacket) -> Tuple[ClientContext, bool]:
        """
        Maps a packet to its corresponding client context and direction.

        Returns:
            Tuple of (ClientContext, is_outbound_from_client)
        """
        src_ip = packet.ipv4.src_ip if packet.ipv4 else (packet.ipv6.src_ip if packet.ipv6 else None)
        dst_ip = packet.ipv4.dst_ip if packet.ipv4 else (packet.ipv6.dst_ip if packet.ipv6 else None)

        if not src_ip and not dst_ip:
            return self._default_context, True

        # Check outbound: client is sender
        if src_ip and (src_ip in self._clients or self.is_vpn_ip(src_ip)):
            client = self._get_or_create_client(src_ip)
            return client, True

        # Check inbound: client is receiver
        if dst_ip and (dst_ip in self._clients or self.is_vpn_ip(dst_ip)):
            client = self._get_or_create_client(dst_ip)
            return client, False

        # If no VPN subnet matched, check if either is a private IP and predefined
        if src_ip and src_ip in self._predefined:
            return self._get_or_create_client(src_ip), True
        if dst_ip and dst_ip in self._predefined:
            return self._get_or_create_client(dst_ip), False

        return self._default_context, True

    def _get_or_create_client(self, ip_str: str) -> ClientContext:
        """Retrieves or creates a ClientContext safely."""
        with self._lock:
            if ip_str not in self._clients:
                custom_name = self._predefined.get(ip_str)
                self._clients[ip_str] = ClientContext(client_ip=ip_str, client_name=custom_name)
                logger.info(f"Registered new active VPN client: {ip_str} ({custom_name or 'Auto-discovered'})")
            return self._clients[ip_str]

    def register_client(self, client_ip: str, client_name: str) -> ClientContext:
        """Manually registers an alias for a client IP."""
        with self._lock:
            self._predefined[client_ip] = client_name
            if client_ip in self._clients:
                self._clients[client_ip].client_name = client_name
            else:
                self._clients[client_ip] = ClientContext(client_ip, client_name)
            return self._clients[client_ip]

    def get_all_clients(self) -> List[ClientContext]:
        """Returns all registered client contexts including fallback."""
        with self._lock:
            return list(self._clients.values())

    def get_client_snapshots(self) -> List[ClientStatsSnapshot]:
        """Returns read-only metric snapshots of all clients."""
        with self._lock:
            contexts = list(self._clients.values())
        return [ctx.get_snapshot() for ctx in contexts]

    def get_total_client_count(self) -> int:
        with self._lock:
            return len(self._clients)

