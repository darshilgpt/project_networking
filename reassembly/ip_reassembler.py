"""IPv4 and IPv6 Fragmentation Reassembly Engine with overlap anomaly detection."""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
import struct
import time
from typing import Dict, List, Optional, Tuple

from models.packet_models import IPv4Header, IPv6Header, ParsedPacket

logger = logging.getLogger("dpi_ids_ips.reassembly.ip_reassembler")


@dataclass
class IPFragmentEntry:
    """Represents a received fragment within an in-flight IP datagram."""
    offset: int
    length: int
    data: bytes
    more_fragments: bool
    timestamp: float


class IPReassemblySession:
    """Maintains fragment state and holes for a single fragmented IP datagram."""

    def __init__(
        self,
        key: Tuple[str, str, int, int],
        first_header: Optional[IPv4Header | IPv6Header] = None,
        timeout: float = 30.0,
    ) -> None:
        self.key = key  # (src_ip, dst_ip, protocol, identification)
        self.first_header = first_header
        self.timeout = timeout
        self.created_at = time.time()
        self.last_activity = time.time()

        # Offset -> Fragment data
        self.fragments: Dict[int, bytes] = {}
        self.total_data_length: Optional[int] = None
        self.has_overlapping_conflict: bool = False
        self.overlap_details: str = ""

    def add_fragment(
        self,
        offset: int,
        data: bytes,
        more_fragments: bool,
        timestamp: float,
    ) -> bool:
        """
        Adds a fragment chunk to the reassembly buffer.

        Returns:
            True if the fragment completed the full datagram, False otherwise.
        """
        self.last_activity = timestamp
        frag_len = len(data)

        # If MF is False, this is the final fragment, defining total data length
        if not more_fragments:
            self.total_data_length = offset + frag_len

        # Check for overlapping fragment anomalies
        frag_end = offset + frag_len
        for existing_off, existing_data in self.fragments.items():
            existing_end = existing_off + len(existing_data)
            # Check if ranges overlap
            overlap_start = max(offset, existing_off)
            overlap_end = min(frag_end, existing_end)
            if overlap_start < overlap_end:
                # Compare the overlapping bytes
                s1 = data[overlap_start - offset : overlap_end - offset]
                s2 = existing_data[overlap_start - existing_off : overlap_end - existing_off]
                if s1 != s2:
                    self.has_overlapping_conflict = True
                    self.overlap_details = (
                        f"Conflicting bytes in overlap [{overlap_start}:{overlap_end}]. "
                        f"Existing fragment [{existing_off}:{existing_end}] vs New [{offset}:{frag_end}]."
                    )
                    logger.warning(f"Overlapping fragment evasion anomaly detected: {self.overlap_details}")

        # Store fragment
        self.fragments[offset] = data
        return self.is_complete()

    def is_complete(self) -> bool:
        """Checks if all holes are filled up to the final fragment boundary."""
        if self.total_data_length is None:
            return False

        # Sort fragments by offset
        sorted_offsets = sorted(self.fragments.keys())
        expected_next = 0
        for off in sorted_offsets:
            if off > expected_next:
                # Gap / missing fragment
                return False
            data_len = len(self.fragments[off])
            expected_next = max(expected_next, off + data_len)

        return expected_next >= self.total_data_length

    def assemble(self) -> bytes:
        """Assembles and returns contiguous datagram payload."""
        if not self.is_complete() or self.total_data_length is None:
            return b""

        buf = bytearray(self.total_data_length)
        for off, data in sorted(self.fragments.items()):
            buf[off : off + len(data)] = data

        return bytes(buf)


class IPReassembler:
    """Coordinates fragmentation tracking and reassembly for IPv4 and IPv6 traffic."""

    def __init__(self, timeout: float = 30.0, max_active_sessions: int = 5000) -> None:
        self.timeout = timeout
        self.max_active_sessions = max_active_sessions
        # Key: (src_ip, dst_ip, protocol, identification) -> IPReassemblySession
        self._sessions: Dict[Tuple[str, str, int, int], IPReassemblySession] = {}

        # Telemetry metrics
        self.total_fragments_seen = 0
        self.total_datagrams_reassembled = 0
        self.total_timed_out_sessions = 0
        self.total_overlapping_anomalies = 0

    def process_packet(
        self, packet: ParsedPacket
    ) -> Tuple[Optional[bytes], bool, bool, str]:
        """
        Processes an in-flight packet for IPv4 or IPv6 fragmentation.

        Returns:
            Tuple of:
            - reassembled_payload: bytes if datagram just completed, else None
            - is_fragment: True if this packet is a fragment
            - has_overlap_anomaly: True if fragment conflict evasion was detected
            - anomaly_evidence: Description of conflict if any
        """
        now = packet.timestamp or time.time()
        self._expire_old_sessions(now)

        # 1. Check IPv4 Fragmentation
        if packet.ipv4 and packet.ipv4.is_fragmented:
            self.total_fragments_seen += 1
            h = packet.ipv4
            key = (h.src_ip, h.dst_ip, h.protocol_code, h.identification)

            session = self._sessions.get(key)
            if not session:
                if len(self._sessions) >= self.max_active_sessions:
                    # Evict oldest session
                    oldest_key = min(self._sessions.keys(), key=lambda k: self._sessions[k].last_activity)
                    del self._sessions[oldest_key]
                session = IPReassemblySession(key=key, first_header=h, timeout=self.timeout)
                self._sessions[key] = session

            is_done = session.add_fragment(
                offset=h.fragment_offset,
                data=packet.payload,
                more_fragments=h.flag_mf,
                timestamp=now,
            )

            has_anomaly = session.has_overlapping_conflict
            anomaly_details = session.overlap_details
            if has_anomaly:
                self.total_overlapping_anomalies += 1

            if is_done:
                reassembled = session.assemble()
                del self._sessions[key]
                self.total_datagrams_reassembled += 1
                return reassembled, True, has_anomaly, anomaly_details

            return None, True, has_anomaly, anomaly_details

        # 2. Check IPv6 Fragmentation (Extension Header 44)
        if packet.ipv6 and packet.ipv6.extension_headers:
            for ext in packet.ipv6.extension_headers:
                if ext.next_header_code == 44:  # IPV6_EXT_FRAGMENT
                    # Fragment header: NextHeader(1B), Reserved(1B), Offset+M(2B), Ident(4B)
                    if len(ext.data) >= 8:
                        self.total_fragments_seen += 1
                        _, _, off_m, ident = struct.unpack("!BBHI", ext.data[:8])
                        offset = (off_m >> 3) * 8
                        more_fragments = bool(off_m & 0x01)
                        upper_proto = packet.ipv6.upper_protocol_code

                        key = (packet.ipv6.src_ip, packet.ipv6.dst_ip, upper_proto, ident)
                        session = self._sessions.get(key)
                        if not session:
                            session = IPReassemblySession(key=key, first_header=packet.ipv6, timeout=self.timeout)
                            self._sessions[key] = session

                        is_done = session.add_fragment(
                            offset=offset,
                            data=packet.payload,
                            more_fragments=more_fragments,
                            timestamp=now,
                        )

                        has_anomaly = session.has_overlapping_conflict
                        anomaly_details = session.overlap_details
                        if is_done:
                            reassembled = session.assemble()
                            del self._sessions[key]
                            self.total_datagrams_reassembled += 1
                            return reassembled, True, has_anomaly, anomaly_details

                        return None, True, has_anomaly, anomaly_details

        return None, False, False, ""

    def _expire_old_sessions(self, now: float) -> None:
        """Cleans up incomplete fragmented datagrams that exceeded timeout."""
        expired = [k for k, s in self._sessions.items() if now - s.last_activity > self.timeout]
        for k in expired:
            del self._sessions[k]
            self.total_timed_out_sessions += 1
