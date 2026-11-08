"""Network Topology and Host Discovery engine."""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
import time
from typing import Any, Dict, List, Optional, Set

from models.packet_models import ParsedPacket

logger = logging.getLogger("dpi_ids_ips.network.topology")

KNOWN_OUIS = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "08:00:27": "Oracle VirtualBox",
    "0a:00:27": "Oracle VirtualBox",
    "dc:a6:32": "Raspberry Pi",
    "b8:27:eb": "Raspberry Pi",
    "00:1a:11": "Google",
    "00:1a:2b": "Cisco",
    "00:00:0c": "Cisco",
    "d0:39:57": "Realtek",
    "00:15:5d": "Microsoft Hyper-V",
}


@dataclass
class DiscoveredHost:
    """Discovered network host metadata and role profile."""
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: str = "Unknown"
    os_guess: str = "Unknown"
    roles: Set[str] = field(default_factory=lambda: {"CLIENT"})
    observed_open_ports: Set[int] = field(default_factory=set)
    packet_count: int = 0
    byte_count: int = 0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip_address,
            "mac": self.mac_address or "N/A",
            "hostname": self.hostname or "N/A",
            "vendor": self.vendor,
            "os_guess": self.os_guess,
            "roles": list(self.roles),
            "open_ports": sorted(list(self.observed_open_ports)),
            "packets": self.packet_count,
            "bytes": self.byte_count,
            "last_seen": self.last_seen,
        }


class NetworkTopologyDiscovery:
    """Discovers and maps network topology, host devices, hardware vendors, and network roles."""

    def __init__(self) -> None:
        # IP -> DiscoveredHost
        self.hosts: Dict[str, DiscoveredHost] = {}

    @staticmethod
    def lookup_vendor(mac: str) -> str:
        """Resolves MAC address prefix to hardware vendor."""
        if not mac or len(mac) < 8:
            return "Unknown"
        prefix = mac.lower()[:8]
        return KNOWN_OUIS.get(prefix, "Standard Hardware")

    @staticmethod
    def guess_os(ttl: int, window_size: Optional[int] = None) -> str:
        """Estimates client operating system from TTL and TCP window size baselines."""
        if ttl <= 64:
            if window_size == 65535:
                return "macOS / iOS"
            return "Linux / Android"
        elif ttl <= 128:
            return "Windows 10 / 11"
        else:
            return "Network Device / BSD"

    def record_packet(self, packet: ParsedPacket) -> None:
        """Extracts topology and host intelligence from an observed packet."""
        now = packet.timestamp or time.time()
        length = packet.raw_length or len(packet.payload)

        src_ip = packet.ipv4.src_ip if packet.ipv4 else (packet.ipv6.src_ip if packet.ipv6 else None)
        dst_ip = packet.ipv4.dst_ip if packet.ipv4 else (packet.ipv6.dst_ip if packet.ipv6 else None)
        if not src_ip:
            return

        src_mac = packet.ethernet.src_mac if packet.ethernet else None

        host = self.hosts.get(src_ip)
        if not host:
            host = DiscoveredHost(
                ip_address=src_ip,
                mac_address=src_mac,
                vendor=self.lookup_vendor(src_mac) if src_mac else "Unknown",
                first_seen=now,
                last_seen=now,
            )
            self.hosts[src_ip] = host
        else:
            host.last_seen = now
            if src_mac and not host.mac_address:
                host.mac_address = src_mac
                host.vendor = self.lookup_vendor(src_mac)

        host.packet_count += 1
        host.byte_count += length

        # OS Fingerprint from TTL
        if packet.ipv4 and host.os_guess == "Unknown":
            win = packet.tcp.window_size if packet.tcp else None
            host.os_guess = self.guess_os(packet.ipv4.ttl, win)

        # Role Discovery from Ports & Traffic
        if packet.tcp:
            # If host sends SYN-ACK from a port, that port is OPEN on this host
            if packet.tcp.flags.syn and packet.tcp.flags.ack:
                host.observed_open_ports.add(packet.tcp.src_port)
                if packet.tcp.src_port in (80, 443, 8080, 8443):
                    host.roles.add("WEB_SERVER")
                elif packet.tcp.src_port == 22:
                    host.roles.add("SSH_SERVER")
        elif packet.udp:
            if packet.udp.src_port == 53:
                host.roles.add("DNS_SERVER")
            elif packet.udp.src_port == 67:
                host.roles.add("DHCP_SERVER")

    def get_all_hosts(self) -> List[DiscoveredHost]:
        """Returns all discovered network hosts."""
        return list(self.hosts.values())
