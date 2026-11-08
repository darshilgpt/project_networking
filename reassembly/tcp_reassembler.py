"""TCP Stream Reassembly Engine with out-of-order, duplicate, and retransmission support."""

from __future__ import annotations

import logging
import time
from typing import Dict, List, Optional, Tuple

from models.flow_model import FlowKey
from models.packet_models import ParsedPacket

logger = logging.getLogger("dpi_ids_ips.reassembly.tcp_reassembler")


class DirectionalTCPStream:
    """Reassembles TCP payload in one direction of a connection."""

    def __init__(self, max_buffer_bytes: int = 512 * 1024) -> None:
        self.max_buffer_bytes = max_buffer_bytes
        self.expected_seq: Optional[int] = None
        # Out-of-order buffer: {seq_num: payload_bytes}
        self.out_of_order: Dict[int, bytes] = {}
        # Contiguous reassembled buffer
        self.reassembled = bytearray()
        self.last_activity: float = time.time()
        self.is_terminated: bool = False

        # Metrics
        self.total_payload_bytes: int = 0
        self.retransmitted_segments: int = 0
        self.out_of_order_segments: int = 0
        self.duplicate_segments: int = 0
        self.has_overlap_conflict: bool = False
        self.overlap_conflict_count: int = 0
        self.last_event: str = "INIT"

    @property
    def buffered_bytes_count(self) -> int:
        return sum(len(p) for p in self.out_of_order.values())

    def get_sequence_holes(self) -> List[Tuple[int, int]]:
        """Returns list of pending sequence gaps (hole_start, hole_end)."""
        if self.expected_seq is None or not self.out_of_order:
            return []
        holes = []
        curr = self.expected_seq
        for off in sorted(self.out_of_order.keys()):
            if off > curr:
                holes.append((curr, off))
            curr = max(curr, off + len(self.out_of_order[off]))
        return holes

    def push_segment(self, seq: int, payload: bytes, flags: Any, timestamp: float) -> bytes:
        """
        Pushes a TCP segment into the reassembler.

        Args:
            seq: 32-bit TCP sequence number.
            payload: Segment payload bytes.
            flags: TCPFlags object from ParsedPacket.
            timestamp: Capture timestamp.

        Returns:
            Newly available contiguous bytes that were reassembled by this segment.
        """
        self.last_activity = timestamp
        newly_reassembled = bytearray()

        if flags.fin or flags.rst:
            self.is_terminated = True

        # Handle SYN sequence consumption
        if flags.syn:
            self.expected_seq = (seq + 1) & 0xFFFFFFFF
            if not payload:
                self.last_event = "SYN"
                return b""
            seq = (seq + 1) & 0xFFFFFFFF

        if not payload:
            self.last_event = "ACK_ONLY"
            return b""

        if self.expected_seq is None:
            self.expected_seq = seq

        seq_len = len(payload)
        expected = self.expected_seq

        # 1. Check for complete duplicate / old retransmission
        diff = (seq - expected) & 0xFFFFFFFF
        if diff > 0x80000000:
            bytes_behind = (expected - seq) & 0xFFFFFFFF
            if bytes_behind >= seq_len:
                self.retransmitted_segments += 1
                self.duplicate_segments += 1
                self.last_event = "DUPLICATE"
                return b""
            else:
                self.retransmitted_segments += 1
                # Check for conflicting overlapping payload bytes
                prev_overlap = self.reassembled[len(self.reassembled) - (seq_len - bytes_behind) :]
                new_overlap = payload[: bytes_behind]
                if prev_overlap and new_overlap and prev_overlap != new_overlap:
                    self.has_overlap_conflict = True
                    self.overlap_conflict_count += 1
                    self.last_event = "OVERLAP_CONFLICT"
                else:
                    self.last_event = "RETRANSMISSION"

                payload = payload[bytes_behind:]
                seq = expected
                seq_len = len(payload)

        # 2. In-order arrival (seq matches expected)
        if seq == self.expected_seq:
            self.last_event = "IN_ORDER"
            self.reassembled.extend(payload)
            newly_reassembled.extend(payload)
            self.expected_seq = (self.expected_seq + seq_len) & 0xFFFFFFFF
            self.total_payload_bytes += seq_len

            # Drain contiguous segments from out-of-order buffer
            self._drain_contiguous(newly_reassembled)

        # 3. Out-of-order arrival (seq > expected, a gap/hole exists)
        else:
            self.out_of_order_segments += 1
            self.last_event = "OUT_OF_ORDER"
            if self.buffered_bytes_count + seq_len <= self.max_buffer_bytes:
                # Check overlap conflict with any buffered segments
                for b_seq, b_data in self.out_of_order.items():
                    o_start = max(seq, b_seq)
                    o_end = min(seq + seq_len, b_seq + len(b_data))
                    if o_start < o_end:
                        sub_new = payload[o_start - seq : o_end - seq]
                        sub_buf = b_data[o_start - b_seq : o_end - b_seq]
                        if sub_new != sub_buf:
                            self.has_overlap_conflict = True
                            self.overlap_conflict_count += 1
                            self.last_event = "OVERLAP_CONFLICT"
                self.out_of_order[seq] = payload
            else:
                logger.warning("TCP reassembly buffer exceeded limit; dropping out-of-order segment.")

        return bytes(newly_reassembled)

        return bytes(newly_reassembled)

    def _drain_contiguous(self, target_buf: bytearray) -> None:
        """Drains any buffered out-of-order segments that have now become contiguous."""
        while self.expected_seq in self.out_of_order:
            buffered_payload = self.out_of_order.pop(self.expected_seq)
            target_buf.extend(buffered_payload)
            self.reassembled.extend(buffered_payload)
            self.expected_seq = (self.expected_seq + len(buffered_payload)) & 0xFFFFFFFF
            self.total_payload_bytes += len(buffered_payload)

    def get_stream_bytes(self) -> bytes:
        """Returns all contiguous data reassembled so far."""
        return bytes(self.reassembled)

    def clear(self) -> None:
        """Frees buffers."""
        self.out_of_order.clear()
        self.reassembled.clear()


class TCPReassembler:
    """Manages bidirectional TCP stream reassembly for active flows."""

    def __init__(
        self,
        max_buffer_per_stream: int = 512 * 1024,
        stream_timeout: float = 60.0,
    ) -> None:
        self.max_buffer_per_stream = max_buffer_per_stream
        self.stream_timeout = stream_timeout
        # Mapping: FlowKey -> (forward_stream, reverse_stream)
        self._streams: Dict[FlowKey, Tuple[DirectionalTCPStream, DirectionalTCPStream]] = {}

    def process_packet(self, packet: ParsedPacket) -> Tuple[bytes, bytes]:
        """
        Processes a packet through TCP stream reassembly.

        Args:
            packet: ParsedPacket.

        Returns:
            Tuple of (newly_reassembled_chunk, full_stream_data_so_far)
        """
        if not packet.tcp:
            return b"", b""

        key, is_forward = FlowKey.from_packet(packet)
        if key is None:
            return b"", b""

        if key not in self._streams:
            fwd_stream = DirectionalTCPStream(self.max_buffer_per_stream)
            rev_stream = DirectionalTCPStream(self.max_buffer_per_stream)
            self._streams[key] = (fwd_stream, rev_stream)

        fwd_stream, rev_stream = self._streams[key]
        target_stream = fwd_stream if is_forward else rev_stream

        ts = packet.timestamp or time.time()
        new_chunk = target_stream.push_segment(
            seq=packet.tcp.seq_num,
            payload=packet.payload,
            flags=packet.tcp.flags,
            timestamp=ts,
        )

        return new_chunk, target_stream.get_stream_bytes()

    def get_stream(self, key: FlowKey) -> Optional[Tuple[DirectionalTCPStream, DirectionalTCPStream]]:
        """Retrieves bidirectional stream pair for a flow."""
        return self._streams.get(key)

    def expire_streams(self, current_time: Optional[float] = None) -> int:
        """Removes idle or terminated TCP streams."""
        now = current_time or time.time()
        keys_to_remove = []

        for key, (fwd, rev) in self._streams.items():
            last_activity = max(fwd.last_activity, rev.last_activity)
            if (now - last_activity > self.stream_timeout) or (fwd.is_terminated and rev.is_terminated):
                keys_to_remove.append(key)

        for k in keys_to_remove:
            fwd, rev = self._streams.pop(k)
            fwd.clear()
            rev.clear()

        return len(keys_to_remove)
