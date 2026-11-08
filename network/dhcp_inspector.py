"""DHCP / BOOTP protocol inspector and rogue server / starvation attack detector."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import logging
import socket
import struct
import time
from typing import Deque, Dict, List, Optional, Set

logger = logging.getLogger("dpi_ids_ips.network.dhcp")

DHCP_MESSAGE_TYPES = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    4: "DECLINE",
    5: "ACK",
    6: "NAK",
    7: "RELEASE",
    8: "INFORM",
}


@dataclass
class DHCPMessage:
    """Dissected DHCP datagram."""
    op: int  # 1 = BOOTREQUEST, 2 = BOOTREPLY
    xid: int
    ciaddr: str
    yiaddr: str
    siaddr: str
    giaddr: str
    client_mac: str
    message_type: str = "UNKNOWN"
    message_type_code: int = 0
    requested_ip: Optional[str] = None
    server_identifier: Optional[str] = None
    hostname: Optional[str] = None
    options: Dict[int, bytes] = field(default_factory=dict)


@dataclass
class DHCPAlert:
    """Alert raised by the DHCP monitor."""
    alert_type: str
    severity: str
    server_ip: str
    client_mac: str
    evidence: str
    timestamp: float


class DHCPInspector:
    """Dissects DHCP traffic and detects rogue DHCP servers and starvation attacks."""

    MAGIC_COOKIE = b"\x63\x82\x53\x63"
    MIN_HEADER_LEN = 240

    def __init__(
        self,
        authorized_dhcp_servers: Optional[Set[str]] = None,
        starvation_threshold: int = 15,
        starvation_window_seconds: float = 3.0,
    ) -> None:
        self.authorized_servers: Set[str] = authorized_dhcp_servers or set()
        self.starvation_threshold = starvation_threshold
        self.starvation_window_seconds = starvation_window_seconds

        # Client MAC -> sliding window of requests
        self._request_tracker: Deque[Tuple[float, str]] = deque()
        self.total_dhcp_messages = 0

    @staticmethod
    def _mac_to_str(mac_bytes: bytes) -> str:
        return ":".join(f"{b:02x}" for b in mac_bytes[:6])

    def parse(self, udp_payload: bytes) -> Optional[DHCPMessage]:
        """Dissects a DHCP UDP payload."""
        if len(udp_payload) < self.MIN_HEADER_LEN:
            return None

        op, htype, hlen, hops, xid, secs, flags = struct.unpack("!BBBBIHH", udp_payload[:12])
        ciaddr = socket.inet_ntoa(udp_payload[12:16])
        yiaddr = socket.inet_ntoa(udp_payload[16:20])
        siaddr = socket.inet_ntoa(udp_payload[20:24])
        giaddr = socket.inet_ntoa(udp_payload[24:28])
        chaddr = self._mac_to_str(udp_payload[28:44])

        cookie = udp_payload[236:240]
        if cookie != self.MAGIC_COOKIE:
            return None

        msg = DHCPMessage(
            op=op,
            xid=xid,
            ciaddr=ciaddr,
            yiaddr=yiaddr,
            siaddr=siaddr,
            giaddr=giaddr,
            client_mac=chaddr,
        )

        # Parse DHCP Options (TLV)
        offset = 240
        data_len = len(udp_payload)
        while offset < data_len:
            opt_type = udp_payload[offset]
            if opt_type == 255:  # End Option
                break
            if opt_type == 0:  # Pad Option
                offset += 1
                continue

            if offset + 1 >= data_len:
                break
            opt_len = udp_payload[offset + 1]
            opt_val = udp_payload[offset + 2 : offset + 2 + opt_len]
            msg.options[opt_type] = opt_val
            offset += 2 + opt_len

            # Option 53: DHCP Message Type
            if opt_type == 53 and len(opt_val) >= 1:
                code = opt_val[0]
                msg.message_type_code = code
                msg.message_type = DHCP_MESSAGE_TYPES.get(code, f"CODE_{code}")
            # Option 50: Requested IP
            elif opt_type == 50 and len(opt_val) == 4:
                msg.requested_ip = socket.inet_ntoa(opt_val)
            # Option 54: Server Identifier
            elif opt_type == 54 and len(opt_val) == 4:
                msg.server_identifier = socket.inet_ntoa(opt_val)
            # Option 12: Host Name
            elif opt_type == 12:
                try:
                    msg.hostname = opt_val.decode("utf-8", errors="replace")
                except Exception:
                    pass

        self.total_dhcp_messages += 1
        return msg

    def inspect(self, dhcp: DHCPMessage, src_ip: str, timestamp: Optional[float] = None) -> List[DHCPAlert]:
        """Inspects parsed DHCP message for Rogue Servers and Starvation."""
        alerts: List[DHCPAlert] = []
        now = timestamp or time.time()

        # 1. Rogue DHCP Server Detection (OFFER or ACK)
        if dhcp.message_type in ("OFFER", "ACK"):
            server_ip = dhcp.server_identifier or src_ip
            if self.authorized_servers and server_ip not in self.authorized_servers:
                evidence = (
                    f"Rogue DHCP Server Detected: {server_ip} emitted unauthorized DHCP {dhcp.message_type} "
                    f"offering IP {dhcp.yiaddr} to MAC {dhcp.client_mac}."
                )
                alerts.append(
                    DHCPAlert(
                        alert_type="ROGUE_DHCP_SERVER",
                        severity="CRITICAL",
                        server_ip=server_ip,
                        client_mac=dhcp.client_mac,
                        evidence=evidence,
                        timestamp=now,
                    )
                )

        # 2. DHCP Starvation Detection (Rapid DISCOVER bursts from varying MACs)
        if dhcp.message_type in ("DISCOVER", "REQUEST"):
            self._request_tracker.append((now, dhcp.client_mac))
            while self._request_tracker and now - self._request_tracker[0][0] > self.starvation_window_seconds:
                self._request_tracker.popleft()

            unique_macs = {mac for _, mac in self._request_tracker}
            if len(self._request_tracker) >= self.starvation_threshold and len(unique_macs) >= (self.starvation_threshold // 2):
                alerts.append(
                    DHCPAlert(
                        alert_type="DHCP_STARVATION_ATTACK",
                        severity="HIGH",
                        server_ip=src_ip,
                        client_mac=dhcp.client_mac,
                        evidence=(
                            f"DHCP Starvation / Pool Exhaustion: {len(self._request_tracker)} requests from "
                            f"{len(unique_macs)} unique MACs within {self.starvation_window_seconds}s."
                        ),
                        timestamp=now,
                    )
                )

        return alerts
