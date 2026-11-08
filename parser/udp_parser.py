"""UDP datagram parser utilizing Python struct module."""

from __future__ import annotations

import struct
from typing import Tuple

from models.packet_models import UDPHeader


class UDPParser:
    """Dissects raw UDP datagram headers."""

    HEADER_LEN = 8

    @classmethod
    def parse(cls, data: bytes) -> Tuple[UDPHeader, bytes]:
        """
        Parses a UDP datagram header from raw bytes.

        Args:
            data: Raw transport layer bytes.

        Returns:
            Tuple of (UDPHeader, payload_bytes)

        Raises:
            ValueError: If the buffer is truncated (< 8 bytes) or length field < 8.
        """
        if len(data) < cls.HEADER_LEN:
            raise ValueError(f"UDP packet truncated: expected at least {cls.HEADER_LEN} bytes, got {len(data)}")

        src_port, dst_port, length, checksum = struct.unpack("!HHHH", data[:cls.HEADER_LEN])

        if length < cls.HEADER_LEN:
            raise ValueError(f"Invalid UDP length field: {length} bytes (minimum {cls.HEADER_LEN} bytes)")

        # Handle payload according to specified UDP length
        # Accounting for potential Ethernet padding or snaplen truncation
        if len(data) >= length:
            payload = data[cls.HEADER_LEN:length]
        else:
            # Packet was truncated during capture
            payload = data[cls.HEADER_LEN:]

        header = UDPHeader(
            src_port=src_port,
            dst_port=dst_port,
            length=length,
            checksum=checksum,
            payload_length=len(payload),
            raw_header=data[:cls.HEADER_LEN],
        )

        return header, payload

