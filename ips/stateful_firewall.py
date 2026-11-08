"""Stateful Firewall engine maintaining connection states and evaluating directional traffic."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import logging
import time
from typing import Dict, List, Optional, Set, Tuple

from models.flow_model import Flow, TCPState
from models.packet_models import ParsedPacket

logger = logging.getLogger("dpi_ids_ips.ips.stateful_firewall")


class ConnectionState(str, Enum):
    """Firewall connection tracking states."""
    NEW = "NEW"
    ESTABLISHED = "ESTABLISHED"
    RELATED = "RELATED"
    INVALID = "INVALID"
    CLOSED = "CLOSED"


class FirewallAction(str, Enum):
    """Firewall filtering actions."""
    ALLOW = "ALLOW"
    DROP = "DROP"
    REJECT = "REJECT"  # Drop and send TCP RST / ICMP Unreachable


@dataclass
class StatefulConnectionEntry:
    """Entry in the stateful connection tracking table."""
    conn_id: str
    protocol: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    state: ConnectionState = ConnectionState.NEW
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packets_forward: int = 0
    packets_reverse: int = 0
    bytes_forward: int = 0
    bytes_reverse: int = 0
    tcp_state: Optional[str] = None
    is_blocked: bool = False
    block_reason: str = ""

    def is_expired(self, now: float, timeout_table: Dict[str, float]) -> bool:
        """Determines if the connection has timed out based on protocol and state."""
        timeout = timeout_table.get(f"{self.protocol}_{self.state.value}", 300.0)
        return (now - self.last_seen) > timeout


@dataclass
class FirewallEvaluationResult:
    """Decision output of stateful firewall packet evaluation."""
    action: FirewallAction
    state: ConnectionState
    reason: str
    matched_rule: Optional[str] = None
    is_stateful_match: bool = False


class StatefulFirewall:
    """
    Stateful packet inspection engine tracking TCP handshakes, UDP streams, and ICMP correlation.
    Enforces state-based filtering (NEW, ESTABLISHED, RELATED, INVALID).
    """

    DEFAULT_TIMEOUTS = {
        "TCP_NEW": 30.0,
        "TCP_ESTABLISHED": 3600.0,
        "TCP_CLOSED": 30.0,
        "UDP_NEW": 30.0,
        "UDP_ESTABLISHED": 180.0,
        "ICMP_NEW": 15.0,
        "ICMP_ESTABLISHED": 30.0,
    }

    def __init__(self, default_inbound_action: FirewallAction = FirewallAction.DROP) -> None:
        self.default_inbound_action = default_inbound_action
        self.state_table: Dict[str, StatefulConnectionEntry] = {}
        self.timeouts = dict(self.DEFAULT_TIMEOUTS)

        # Metrics
        self.total_evaluated = 0
        self.state_new_count = 0
        self.state_established_count = 0
        self.state_related_count = 0
        self.state_invalid_count = 0
        self.total_dropped = 0

    @staticmethod
    def build_conn_key(proto: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
        return f"{proto}:{src_ip}:{src_port}->{dst_ip}:{dst_port}"

    @staticmethod
    def build_reverse_key(proto: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
        return f"{proto}:{dst_ip}:{dst_port}->{src_ip}:{src_port}"

    def clean_expired(self, now: Optional[float] = None) -> int:
        """Purges aged connection tracking entries."""
        ts = now or time.time()
        expired_keys = [k for k, v in self.state_table.items() if v.is_expired(ts, self.timeouts)]
        for k in expired_keys:
            del self.state_table[k]
        return len(expired_keys)

    def evaluate_packet(
        self,
        packet: ParsedPacket,
        is_outbound_from_client: bool,
    ) -> FirewallEvaluationResult:
        """
        Statefully tracks and inspects packet headers.

        Args:
            packet: Dissected packet.
            is_outbound_from_client: True if originating from internal/VPN client, False if inbound from external WAN.

        Returns:
            FirewallEvaluationResult
        """
        self.total_evaluated += 1
        now = packet.timestamp or time.time()
        length = packet.raw_length or len(packet.payload)

        # Periodically expire old connections
        if self.total_evaluated % 500 == 0:
            self.clean_expired(now)

        proto = packet.transport_type if packet.transport_type != "None" else packet.network_type
        src_ip = packet.ipv4.src_ip if packet.ipv4 else (packet.ipv6.src_ip if packet.ipv6 else "0.0.0.0")
        dst_ip = packet.ipv4.dst_ip if packet.ipv4 else (packet.ipv6.dst_ip if packet.ipv6 else "0.0.0.0")
        src_port = packet.tcp.src_port if packet.tcp else (packet.udp.src_port if packet.udp else 0)
        dst_port = packet.tcp.dst_port if packet.tcp else (packet.udp.dst_port if packet.udp else 0)

        fwd_key = self.build_conn_key(proto, src_ip, src_port, dst_ip, dst_port)
        rev_key = self.build_reverse_key(proto, src_ip, src_port, dst_ip, dst_port)

        # Check existing connection table
        entry = self.state_table.get(fwd_key)
        is_reverse = False
        if not entry:
            entry = self.state_table.get(rev_key)
            if entry:
                is_reverse = True

        # --- 1. TCP Stateful Tracking ---
        if packet.tcp:
            tcp = packet.tcp
            flags = tcp.flags

            # A. Invalid Flag Combinations
            if (flags.syn and flags.fin) or (flags.syn and flags.rst) or (not any([flags.syn, flags.ack, flags.fin, flags.rst, flags.psh, flags.urg])):
                self.state_invalid_count += 1
                self.total_dropped += 1
                return FirewallEvaluationResult(
                    action=FirewallAction.DROP,
                    state=ConnectionState.INVALID,
                    reason="Invalid TCP flag combination in stateful filter",
                )

            # B. Existing Connection Update
            if entry:
                entry.last_seen = now
                if is_reverse:
                    entry.packets_reverse += 1
                    entry.bytes_reverse += length
                else:
                    entry.packets_forward += 1
                    entry.bytes_forward += length

                # If connection was blocked by flow policy
                if entry.is_blocked:
                    self.total_dropped += 1
                    return FirewallEvaluationResult(
                        action=FirewallAction.DROP,
                        state=entry.state,
                        reason=f"Connection is blocked: {entry.block_reason}",
                        is_stateful_match=True,
                    )

                # State Transitions
                if flags.rst:
                    entry.state = ConnectionState.CLOSED
                elif flags.fin:
                    entry.state = ConnectionState.CLOSED
                elif entry.state == ConnectionState.NEW:
                    if is_reverse and flags.syn and flags.ack:
                        # SYN-ACK received in return direction
                        entry.state = ConnectionState.ESTABLISHED
                        self.state_established_count += 1
                    elif not is_reverse and flags.ack and not flags.syn:
                        # Client completing 3-way handshake with ACK
                        entry.state = ConnectionState.ESTABLISHED
                        self.state_established_count += 1

                return FirewallEvaluationResult(
                    action=FirewallAction.ALLOW,
                    state=entry.state,
                    reason=f"Stateful TCP match ({entry.state.value})",
                    is_stateful_match=True,
                )

            # C. New Connection Attempt (No existing entry)
            # Legitimate new TCP connection MUST start with SYN and NO ACK
            if flags.syn and not flags.ack:
                # Outbound client initiated new connection
                new_entry = StatefulConnectionEntry(
                    conn_id=fwd_key,
                    protocol="TCP",
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    state=ConnectionState.NEW,
                    created_at=now,
                    last_seen=now,
                    packets_forward=1,
                    bytes_forward=length,
                )
                self.state_table[fwd_key] = new_entry
                self.state_new_count += 1
                return FirewallEvaluationResult(
                    action=FirewallAction.ALLOW,
                    state=ConnectionState.NEW,
                    reason="New stateful TCP connection initiated (SYN)",
                )

            # Unsolicited mid-stream TCP packet with ACK/FIN for non-existent session
            self.state_invalid_count += 1
            if not is_outbound_from_client:
                # Inbound unsolicited packet without state -> INVALID
                self.total_dropped += 1
                return FirewallEvaluationResult(
                    action=FirewallAction.DROP,
                    state=ConnectionState.INVALID,
                    reason="Inbound TCP packet does not belong to established connection (INVALID)",
                )
            else:
                # Outbound client reconnecting mid-stream or late ACK
                return FirewallEvaluationResult(
                    action=FirewallAction.ALLOW,
                    state=ConnectionState.NEW,
                    reason="Outbound TCP packet permitted",
                )

        # --- 2. UDP Pseudo-State Tracking ---
        elif packet.udp:
            if entry:
                entry.last_seen = now
                if is_reverse:
                    entry.packets_reverse += 1
                    entry.bytes_reverse += length
                    if entry.state == ConnectionState.NEW:
                        entry.state = ConnectionState.ESTABLISHED
                        self.state_established_count += 1
                else:
                    entry.packets_forward += 1
                    entry.bytes_forward += length

                if entry.is_blocked:
                    self.total_dropped += 1
                    return FirewallEvaluationResult(
                        action=FirewallAction.DROP,
                        state=entry.state,
                        reason=f"UDP Flow is blocked: {entry.block_reason}",
                        is_stateful_match=True,
                    )

                return FirewallEvaluationResult(
                    action=FirewallAction.ALLOW,
                    state=entry.state,
                    reason=f"Stateful UDP match ({entry.state.value})",
                    is_stateful_match=True,
                )

            # New UDP connection
            if is_outbound_from_client:
                new_entry = StatefulConnectionEntry(
                    conn_id=fwd_key,
                    protocol="UDP",
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    state=ConnectionState.NEW,
                    created_at=now,
                    last_seen=now,
                    packets_forward=1,
                    bytes_forward=length,
                )
                self.state_table[fwd_key] = new_entry
                self.state_new_count += 1
                return FirewallEvaluationResult(
                    action=FirewallAction.ALLOW,
                    state=ConnectionState.NEW,
                    reason="Outbound UDP session initiated",
                )
            else:
                # Inbound unsolicited UDP datagram
                self.state_invalid_count += 1
                self.total_dropped += 1
                return FirewallEvaluationResult(
                    action=self.default_inbound_action,
                    state=ConnectionState.INVALID,
                    reason="Unsolicited inbound UDP datagram without established outbound flow",
                )

        # --- 3. ICMP Correlation Tracking ---
        elif packet.icmp:
            icmp = packet.icmp
            is_echo_req = (not icmp.is_ipv6 and icmp.icmp_type == 8) or (icmp.is_ipv6 and icmp.icmp_type == 128)
            is_echo_rep = (not icmp.is_ipv6 and icmp.icmp_type == 0) or (icmp.is_ipv6 and icmp.icmp_type == 129)

            if is_echo_req:
                new_entry = StatefulConnectionEntry(
                    conn_id=fwd_key,
                    protocol="ICMP",
                    src_ip=src_ip,
                    src_port=0,
                    dst_ip=dst_ip,
                    dst_port=0,
                    state=ConnectionState.NEW,
                    created_at=now,
                    last_seen=now,
                    packets_forward=1,
                    bytes_forward=length,
                )
                self.state_table[fwd_key] = new_entry
                self.state_new_count += 1
                return FirewallEvaluationResult(
                    action=FirewallAction.ALLOW,
                    state=ConnectionState.NEW,
                    reason="Outbound ICMP Echo Request initiated",
                )

            if is_echo_rep:
                if rev_key in self.state_table:
                    entry = self.state_table[rev_key]
                    entry.last_seen = now
                    entry.state = ConnectionState.ESTABLISHED
                    self.state_related_count += 1
                    return FirewallEvaluationResult(
                        action=FirewallAction.ALLOW,
                        state=ConnectionState.ESTABLISHED,
                        reason="Inbound ICMP Echo Reply correlated with outbound Echo Request (RELATED/ESTABLISHED)",
                        is_stateful_match=True,
                    )
                else:
                    self.state_invalid_count += 1
                    self.total_dropped += 1
                    return FirewallEvaluationResult(
                        action=FirewallAction.DROP,
                        state=ConnectionState.INVALID,
                        reason="Unsolicited ICMP Echo Reply without matching Echo Request",
                    )

        # Default fallback for other protocols
        return FirewallEvaluationResult(
            action=FirewallAction.ALLOW,
            state=ConnectionState.NEW,
            reason="Non-stateful protocol permitted",
        )

    def block_connection(self, proto: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int, reason: str = "") -> bool:
        """Marks a connection entry as blocked in the state table for flow-based fast drops."""
        fwd_key = self.build_conn_key(proto, src_ip, src_port, dst_ip, dst_port)
        rev_key = self.build_reverse_key(proto, src_ip, src_port, dst_ip, dst_port)
        found = False
        if fwd_key in self.state_table:
            self.state_table[fwd_key].is_blocked = True
            self.state_table[fwd_key].block_reason = reason
            found = True
        if rev_key in self.state_table:
            self.state_table[rev_key].is_blocked = True
            self.state_table[rev_key].block_reason = reason
            found = True
        return found

