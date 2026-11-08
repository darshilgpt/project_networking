"""Network Flow data models for bidirectional connection tracking."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Tuple

from models.packet_models import ParsedPacket


class TCPState(str, Enum):
    """RFC 793 TCP connection lifecycle states."""
    NEW = "NEW"
    LISTEN = "LISTEN"
    SYN_SENT = "SYN_SENT"
    SYN_RECEIVED = "SYN_RECEIVED"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT_1 = "FIN_WAIT_1"
    FIN_WAIT_2 = "FIN_WAIT_2"
    FIN_WAIT = "FIN_WAIT"  # Alias for compatibility
    CLOSE_WAIT = "CLOSE_WAIT"
    CLOSING = "CLOSING"
    LAST_ACK = "LAST_ACK"
    TIME_WAIT = "TIME_WAIT"
    CLOSED = "CLOSED"
    RESET = "RESET"


@dataclass(frozen=True)
class FlowKey:
    """Canonical 5-tuple identifying a bidirectional network flow."""
    ip_a: str
    port_a: int
    ip_b: str
    port_b: int
    protocol: str

    @classmethod
    def from_packet(cls, packet: ParsedPacket) -> Tuple[Optional[FlowKey], bool]:
        """
        Derives the canonical FlowKey and direction from a ParsedPacket.

        Returns:
            Tuple of (Optional[FlowKey], is_forward_direction)
            is_forward is True if the packet moves from endpoint A to B, False otherwise.
        """
        src_ip = None
        dst_ip = None
        if packet.ipv4:
            src_ip = packet.ipv4.src_ip
            dst_ip = packet.ipv4.dst_ip
        elif packet.ipv6:
            src_ip = packet.ipv6.src_ip
            dst_ip = packet.ipv6.dst_ip

        if not src_ip or not dst_ip:
            return None, True

        src_port = 0
        dst_port = 0
        protocol = "OTHER"

        if packet.tcp:
            src_port = packet.tcp.src_port
            dst_port = packet.tcp.dst_port
            protocol = "TCP"
        elif packet.udp:
            src_port = packet.udp.src_port
            dst_port = packet.udp.dst_port
            protocol = "UDP"
        elif packet.icmp:
            protocol = "ICMP"
        else:
            protocol = packet.network_type

        # Canonical normalization so (A->B) and (B->A) yield identical FlowKeys
        endpoint_src = (src_ip, src_port)
        endpoint_dst = (dst_ip, dst_port)

        if endpoint_src <= endpoint_dst:
            key = cls(
                ip_a=src_ip,
                port_a=src_port,
                ip_b=dst_ip,
                port_b=dst_port,
                protocol=protocol,
            )
            is_forward = True
        else:
            key = cls(
                ip_a=dst_ip,
                port_a=dst_port,
                ip_b=src_ip,
                port_b=src_port,
                protocol=protocol,
            )
            is_forward = False

        return key, is_forward


@dataclass
class FlowStats:
    """Statistics for a bidirectional network flow."""
    packets_forward: int = 0
    packets_reverse: int = 0
    bytes_forward: int = 0
    bytes_reverse: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0

    # Advanced TCP metrics
    retransmitted_packets: int = 0
    out_of_order_packets: int = 0
    duplicate_acks: int = 0
    last_seq_forward: int = 0
    last_seq_reverse: int = 0
    last_ack_forward: int = 0
    last_ack_reverse: int = 0
    consecutive_dup_acks: int = 0

    @property
    def total_packets(self) -> int:
        return self.packets_forward + self.packets_reverse

    @property
    def total_bytes(self) -> int:
        return self.bytes_forward + self.bytes_reverse

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)


@dataclass
class Flow:
    """Represents a stateful bidirectional connection flow."""
    flow_id: int
    key: FlowKey
    initiator_ip: str
    initiator_port: int
    responder_ip: str
    responder_port: int
    protocol: str
    stats: FlowStats = field(default_factory=FlowStats)
    tcp_state: TCPState = TCPState.NEW
    application_protocol: str = "Unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)
    is_active: bool = True

    @property
    def source_repr(self) -> str:
        return f"{self.initiator_ip}:{self.initiator_port}" if self.initiator_port else self.initiator_ip

    @property
    def dest_repr(self) -> str:
        return f"{self.responder_ip}:{self.responder_port}" if self.responder_port else self.responder_ip

    def summary(self) -> str:
        return (
            f"Flow ID: {self.flow_id} | {self.source_repr} <-> {self.dest_repr} | "
            f"Proto: {self.protocol} | Pkts: {self.stats.total_packets} | "
            f"Bytes: {self.stats.total_bytes} | Duration: {self.stats.duration:.2f}s | "
            f"App: {self.application_protocol}"
        )

