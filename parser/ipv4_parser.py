"""IPv4 packet parser utilizing Python struct and socket modules."""

from __future__ import annotations

import socket
import struct
from typing import Tuple

from models.packet_models import IPv4Header

# Common IP protocol numbers
IP_PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6 Encapsulation",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
}


def calculate_checksum(header_bytes: bytes) -> bool:
    """
    Validates the IPv4 header checksum according to RFC 791 / RFC 1071.
    If the checksum is correct, the ones-complement sum of all 16-bit words
    including the checksum field equals 0xFFFF (or 0 when complemented).
    """
    if len(header_bytes) % 2 != 0:
        header_bytes += b"\x00"

    total = 0
    for i in range(0, len(header_bytes), 2):
        word = (header_bytes[i] << 8) + header_bytes[i + 1]
        total += word

    # Fold 32-bit total into 16 bits
    while (total >> 16) > 0:
        total = (total & 0xFFFF) + (total >> 16)

    # Inverted sum should be 0 (i.e., total == 0xFFFF)
    return (~total & 0xFFFF) == 0


class IPv4Parser:
    """Dissects raw IPv4 packet headers."""

    MIN_HEADER_LEN = 20

    @classmethod
    def parse(cls, data: bytes) -> Tuple[IPv4Header, bytes]:
        """
        Parses an IPv4 header from raw bytes.

        Args:
            data: Raw network layer bytes.

        Returns:
            Tuple of (IPv4Header, payload_bytes)

        Raises:
            ValueError: If the buffer is truncated, version is not 4, or IHL is invalid.
        """
        if len(data) < cls.MIN_HEADER_LEN:
            raise ValueError(f"IPv4 packet truncated: expected at least {cls.MIN_HEADER_LEN} bytes, got {len(data)}")

        (
            ver_ihl,
            tos,
            total_length,
            identification,
            flags_fo,
            ttl,
            protocol,
            checksum,
            src_ip_raw,
            dst_ip_raw,
        ) = struct.unpack("!BBHHHBBH4s4s", data[:cls.MIN_HEADER_LEN])

        version = (ver_ihl >> 4) & 0x0F
        ihl = ver_ihl & 0x0F

        if version != 4:
            raise ValueError(f"Invalid IPv4 version: {version}")

        if ihl < 5:
            raise ValueError(f"Invalid IPv4 header length (IHL): {ihl} (minimum 5 words / 20 bytes)")

        header_len = ihl * 4
        if len(data) < header_len:
            raise ValueError(f"IPv4 packet truncated for options: header expects {header_len} bytes, got {len(data)}")

        dscp = (tos >> 2) & 0x3F
        ecn = tos & 0x03

        # Flags: 3 bits (Bit 0 = Reserved, Bit 1 = DF, Bit 2 = MF)
        flag_df = bool((flags_fo >> 14) & 0x01)
        flag_mf = bool((flags_fo >> 13) & 0x01)
        # Fragment offset is in 8-byte units
        fragment_offset = (flags_fo & 0x1FFF) * 8

        src_ip = socket.inet_ntoa(src_ip_raw)
        dst_ip = socket.inet_ntoa(dst_ip_raw)

        options = data[cls.MIN_HEADER_LEN:header_len]
        raw_header = data[:header_len]

        # Checksum validation
        checksum_valid = calculate_checksum(raw_header)

        # Slice payload based on total_length, accounting for Ethernet padding or truncation
        # If total_length > header_len, payload ends at total_length
        if total_length >= header_len:
            payload_end = min(total_length, len(data))
            payload = data[header_len:payload_end]
        else:
            # Malformed total length less than header
            payload = data[header_len:]

        protocol_name = IP_PROTOCOLS.get(protocol, f"Unknown ({protocol})")

        header = IPv4Header(
            version=version,
            ihl=ihl,
            header_length=header_len,
            dscp=dscp,
            ecn=ecn,
            total_length=total_length,
            identification=identification,
            flags_raw=flags_fo >> 13,
            flag_df=flag_df,
            flag_mf=flag_mf,
            fragment_offset=fragment_offset,
            ttl=ttl,
            protocol_code=protocol,
            protocol_name=protocol_name,
            checksum=checksum,
            checksum_valid=checksum_valid,
            src_ip=src_ip,
            dst_ip=dst_ip,
            options=options,
            raw_header=raw_header,
        )

        return header, payload

