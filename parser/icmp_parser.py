"""ICMP and ICMPv6 packet parser."""

from __future__ import annotations

import struct
from typing import Tuple

from models.packet_models import ICMPHeader

ICMPV4_TYPES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    9: "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
}

ICMPV4_CODES = {
    (3, 0): "Net Unreachable",
    (3, 1): "Host Unreachable",
    (3, 2): "Protocol Unreachable",
    (3, 3): "Port Unreachable",
    (3, 4): "Fragmentation Needed and DF set",
    (3, 5): "Source Route Failed",
    (11, 0): "TTL Expired in Transit",
    (11, 1): "Fragment Reassembly Time Exceeded",
}

ICMPV6_TYPES = {
    1: "Destination Unreachable",
    2: "Packet Too Big",
    3: "Time Exceeded",
    4: "Parameter Problem",
    128: "Echo Request",
    129: "Echo Reply",
    133: "Router Solicitation",
    134: "Router Advertisement",
    135: "Neighbor Solicitation",
    136: "Neighbor Advertisement",
    137: "Redirect",
}


class ICMPParser:
    """Dissects raw ICMP (IPv4) and ICMPv6 headers."""

    MIN_HEADER_LEN = 4

    @classmethod
    def parse(cls, data: bytes, is_ipv6: bool = False) -> Tuple[ICMPHeader, bytes]:
        """
        Parses an ICMP / ICMPv6 packet header from raw bytes.

        Args:
            data: Raw transport/control layer bytes.
            is_ipv6: True if originating from IPv6 (ICMPv6).

        Returns:
            Tuple of (ICMPHeader, payload_bytes)

        Raises:
            ValueError: If the buffer is truncated (< 4 bytes).
        """
        if len(data) < cls.MIN_HEADER_LEN:
            raise ValueError(f"ICMP packet truncated: expected at least {cls.MIN_HEADER_LEN} bytes, got {len(data)}")

        icmp_type, code, checksum = struct.unpack("!BBH", data[:cls.MIN_HEADER_LEN])

        header_len = 8 if len(data) >= 8 else cls.MIN_HEADER_LEN
        rest_of_header = data[cls.MIN_HEADER_LEN:header_len]
        payload = data[header_len:]

        if is_ipv6:
            type_name = ICMPV6_TYPES.get(icmp_type, f"ICMPv6 Type {icmp_type}")
            code_name = f"Code {code}"
        else:
            type_name = ICMPV4_TYPES.get(icmp_type, f"ICMP Type {icmp_type}")
            code_name = ICMPV4_CODES.get((icmp_type, code), f"Code {code}")

        header = ICMPHeader(
            icmp_type=icmp_type,
            type_name=type_name,
            code=code,
            code_name=code_name,
            checksum=checksum,
            rest_of_header=rest_of_header,
            raw_header=data[:header_len],
            is_ipv6=is_ipv6,
        )

        return header, payload

