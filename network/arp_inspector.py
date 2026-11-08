"""ARP protocol dissector and spoofing / cache poisoning detector."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import logging
import socket
import struct
import time
from typing import Deque, Dict, List, Optional, Tuple

logger = logging.getLogger("dpi_ids_ips.network.arp")


@dataclass
class ARPPacket:
    """Dissected ARP message."""
    hw_type: int
    proto_type: int
    hw_size: int
    proto_size: int
    opcode: int  # 1 = Request, 2 = Reply
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str
    is_gratuitous: bool = False

    @property
    def opcode_name(self) -> str:
        return "REQUEST" if self.opcode == 1 else ("REPLY" if self.opcode == 2 else f"OPCODE_{self.opcode}")


@dataclass
class ARPMonitorAlert:
    """Alert raised by the ARP monitor."""
    alert_type: str
    severity: str
    ip_address: str
    mac_address: str
    evidence: str
    timestamp: float


class ARPInspector:
    """Dissects raw ARP frames and detects ARP poisoning, conflicts, and gratuitous floods."""

    def __init__(
        self,
        gratuitous_flood_threshold: int = 10,
        flood_window_seconds: float = 3.0,
    ) -> None:
        self.gratuitous_flood_threshold = gratuitous_flood_threshold
        self.flood_window_seconds = flood_window_seconds

        # IP -> (Learned MAC, timestamp)
        self.ip_to_mac_table: Dict[str, Tuple[str, float]] = {}
        # IP -> sliding window deque of timestamps for gratuitous announcements
        self._gratuitous_tracker: Dict[str, Deque[float]] = {}

        self.total_arp_parsed = 0
        self.total_spoof_alerts = 0

    @staticmethod
    def _mac_to_str(mac_bytes: bytes) -> str:
        return ":".join(f"{b:02x}" for b in mac_bytes)

    def parse(self, raw_l3_data: bytes) -> Optional[ARPPacket]:
        """Dissects an ARP payload (typically 28 bytes for IPv4 on Ethernet)."""
        if len(raw_l3_data) < 28:
            return None

        hw_type, proto_type, hw_size, proto_size, opcode = struct.unpack("!HHBBH", raw_l3_data[:8])
        if hw_size != 6 or proto_size != 4:
            return None

        sender_mac_raw, sender_ip_raw, target_mac_raw, target_ip_raw = struct.unpack(
            "!6s4s6s4s", raw_l3_data[8:28]
        )

        sender_mac = self._mac_to_str(sender_mac_raw)
        target_mac = self._mac_to_str(target_mac_raw)
        sender_ip = socket.inet_ntoa(sender_ip_raw)
        target_ip = socket.inet_ntoa(target_ip_raw)

        # Gratuitous ARP: sender_ip == target_ip or target_mac is broadcast/zeros
        is_gratuitous = (sender_ip == target_ip) or (target_mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"))

        self.total_arp_parsed += 1
        return ARPPacket(
            hw_type=hw_type,
            proto_type=proto_type,
            hw_size=hw_size,
            proto_size=proto_size,
            opcode=opcode,
            sender_mac=sender_mac,
            sender_ip=sender_ip,
            target_mac=target_mac,
            target_ip=target_ip,
            is_gratuitous=is_gratuitous,
        )

    def inspect(self, arp: ARPPacket, timestamp: Optional[float] = None) -> List[ARPMonitorAlert]:
        """
        Inspects an ARP packet for spoofing, conflicts, and flood attacks.

        Returns:
            List of ARPMonitorAlert instances.
        """
        alerts: List[ARPMonitorAlert] = []
        now = timestamp or time.time()
        s_ip = arp.sender_ip
        s_mac = arp.sender_mac

        # Ignore invalid/probe sender IP 0.0.0.0
        if s_ip == "0.0.0.0":
            return alerts

        # 1. Invalid Sender MAC Anomaly
        if s_mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            alerts.append(
                ARPMonitorAlert(
                    alert_type="INVALID_ARP_SENDER_MAC",
                    severity="HIGH",
                    ip_address=s_ip,
                    mac_address=s_mac,
                    evidence=f"ARP packet claims illegal sender MAC '{s_mac}' for IP {s_ip}.",
                    timestamp=now,
                )
            )

        # 2. ARP Cache Poisoning / Spoofing Detection
        if s_ip in self.ip_to_mac_table:
            known_mac, first_seen = self.ip_to_mac_table[s_ip]
            if known_mac.lower() != s_mac.lower():
                self.total_spoof_alerts += 1
                evidence = (
                    f"ARP Spoofing / IP Conflict Detected! IP {s_ip} was previously mapped to MAC "
                    f"'{known_mac}', but is now claimed by MAC '{s_mac}' (Opcode: {arp.opcode_name})."
                )
                alerts.append(
                    ARPMonitorAlert(
                        alert_type="ARP_CACHE_POISONING",
                        severity="CRITICAL",
                        ip_address=s_ip,
                        mac_address=s_mac,
                        evidence=evidence,
                        timestamp=now,
                    )
                )
        else:
            # Learn new IP -> MAC binding
            self.ip_to_mac_table[s_ip] = (s_mac, now)

        # 3. Gratuitous ARP Flood Detection
        if arp.is_gratuitous:
            if s_ip not in self._gratuitous_tracker:
                self._gratuitous_tracker[s_ip] = deque()
            q = self._gratuitous_tracker[s_ip]
            q.append(now)
            while q and now - q[0] > self.flood_window_seconds:
                q.popleft()

            if len(q) >= self.gratuitous_flood_threshold:
                alerts.append(
                    ARPMonitorAlert(
                        alert_type="GRATUITOUS_ARP_FLOOD",
                        severity="HIGH",
                        ip_address=s_ip,
                        mac_address=s_mac,
                        evidence=f"Gratuitous ARP flood: {len(q)} announcements within {self.flood_window_seconds}s.",
                        timestamp=now,
                    )
                )

        return alerts
