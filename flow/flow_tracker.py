"""Flow Tracker for stateful connection tracking across bidirectional traffic."""

from __future__ import annotations

import logging
import time
from typing import Dict, List, Optional, Tuple

from models.flow_model import Flow, FlowKey, FlowStats, TCPState
from models.packet_models import ParsedPacket

logger = logging.getLogger("dpi_ids_ips.flow.flow_tracker")


class FlowTracker:
    """Tracks network conversations (flows) using canonical 5-tuples."""

    def __init__(
        self,
        tcp_idle_timeout: float = 60.0,
        tcp_closed_timeout: float = 10.0,
        udp_idle_timeout: float = 30.0,
        other_idle_timeout: float = 15.0,
        max_flows: int = 10000,
    ) -> None:
        """
        Initializes FlowTracker.

        Args:
            tcp_idle_timeout: Timeout in seconds for active TCP flows.
            tcp_closed_timeout: Timeout in seconds for closed/reset TCP flows.
            udp_idle_timeout: Timeout in seconds for UDP flows.
            other_idle_timeout: Timeout for ICMP and other flows.
            max_flows: Maximum number of active flows to keep in memory.
        """
        self.tcp_idle_timeout = tcp_idle_timeout
        self.tcp_closed_timeout = tcp_closed_timeout
        self.udp_idle_timeout = udp_idle_timeout
        self.other_idle_timeout = other_idle_timeout
        self.max_flows = max_flows

        self._flows: Dict[FlowKey, Flow] = {}
        self._flow_id_counter = 0

    @property
    def active_flow_count(self) -> int:
        return len(self._flows)

    def _update_tcp_state(self, current_state: TCPState, packet: ParsedPacket, is_forward: bool) -> TCPState:
        """Advances the TCP connection state machine according to observed flags."""
        if not packet.tcp:
            return current_state

        flags = packet.tcp.flags

        # Reset flag immediately closes flow
        if flags.rst:
            return TCPState.RESET

        # State transitions
        if current_state == TCPState.NEW:
            if flags.syn and not flags.ack:
                return TCPState.SYN_SENT
            elif flags.syn and flags.ack:
                return TCPState.SYN_RECEIVED
            elif flags.ack:
                return TCPState.ESTABLISHED

        elif current_state == TCPState.SYN_SENT:
            if flags.syn and flags.ack:
                return TCPState.SYN_RECEIVED
            elif flags.ack and not flags.syn:
                return TCPState.ESTABLISHED

        elif current_state == TCPState.SYN_RECEIVED:
            if flags.ack and not flags.syn:
                return TCPState.ESTABLISHED

        elif current_state == TCPState.ESTABLISHED:
            if flags.fin:
                return TCPState.FIN_WAIT

        elif current_state == TCPState.FIN_WAIT:
            if flags.ack or flags.fin:
                return TCPState.CLOSED

        return current_state

    def process_packet(self, packet: ParsedPacket) -> Tuple[Optional[Flow], bool]:
        """
        Updates flow tracking with a new packet.

        Args:
            packet: ParsedPacket from Phase 1.

        Returns:
            Tuple of (Flow, is_new_flow)
        """
        key, is_forward = FlowKey.from_packet(packet)
        if key is None:
            return None, False

        now = packet.timestamp or time.time()

        # Clean expired flows if capacity is nearly reached
        if len(self._flows) >= self.max_flows:
            self.expire_flows(now)

        if key in self._flows:
            flow = self._flows[key]
            is_new = False
            # Update stats
            if is_forward:
                flow.stats.packets_forward += 1
                flow.stats.bytes_forward += packet.raw_length
            else:
                flow.stats.packets_reverse += 1
                flow.stats.bytes_reverse += packet.raw_length

            flow.stats.last_seen = now

            if packet.tcp:
                flow.tcp_state = self._update_tcp_state(flow.tcp_state, packet, is_forward)

        else:
            # Enforce max flows limit by evicting oldest if still at capacity
            if len(self._flows) >= self.max_flows:
                oldest_key = min(self._flows.keys(), key=lambda k: self._flows[k].stats.last_seen)
                del self._flows[oldest_key]

            self._flow_id_counter += 1
            is_new = True

            src_ip = packet.ipv4.src_ip if packet.ipv4 else (packet.ipv6.src_ip if packet.ipv6 else "")
            dst_ip = packet.ipv4.dst_ip if packet.ipv4 else (packet.ipv6.dst_ip if packet.ipv6 else "")
            src_port = packet.tcp.src_port if packet.tcp else (packet.udp.src_port if packet.udp else 0)
            dst_port = packet.tcp.dst_port if packet.tcp else (packet.udp.dst_port if packet.udp else 0)

            stats = FlowStats(
                packets_forward=1 if is_forward else 0,
                packets_reverse=0 if is_forward else 1,
                bytes_forward=packet.raw_length if is_forward else 0,
                bytes_reverse=0 if is_forward else packet.raw_length,
                first_seen=now,
                last_seen=now,
            )

            initial_state = TCPState.NEW
            if packet.tcp:
                initial_state = self._update_tcp_state(TCPState.NEW, packet, is_forward)

            flow = Flow(
                flow_id=self._flow_id_counter,
                key=key,
                initiator_ip=src_ip,
                initiator_port=src_port,
                responder_ip=dst_ip,
                responder_port=dst_port,
                protocol=key.protocol,
                stats=stats,
                tcp_state=initial_state,
            )
            self._flows[key] = flow

        return flow, is_new

    def get_flow(self, key: FlowKey) -> Optional[Flow]:
        """Retrieves a flow by its canonical key."""
        return self._flows.get(key)

    def expire_flows(self, current_time: Optional[float] = None) -> List[Flow]:
        """
        Scans and expires idle or closed flows according to configured timeouts.

        Returns:
            List of expired Flow objects removed from the table.
        """
        now = current_time or time.time()
        expired: List[Flow] = []
        keys_to_remove: List[FlowKey] = []

        for key, flow in self._flows.items():
            idle_duration = now - flow.stats.last_seen

            if flow.protocol == "TCP":
                if flow.tcp_state in (TCPState.CLOSED, TCPState.RESET):
                    timeout = self.tcp_closed_timeout
                else:
                    timeout = self.tcp_idle_timeout
            elif flow.protocol == "UDP":
                timeout = self.udp_idle_timeout
            else:
                timeout = self.other_idle_timeout

            if idle_duration > timeout:
                flow.is_active = False
                expired.append(flow)
                keys_to_remove.append(key)

        for k in keys_to_remove:
            del self._flows[k]

        return expired

    def get_all_flows(self) -> List[Flow]:
        """Returns all currently active flows."""
        return list(self._flows.values())

