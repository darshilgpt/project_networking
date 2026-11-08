"""TCP segment parser with bitmask flag dissection and TCP options support."""

from __future__ import annotations

import struct
from typing import List, Tuple

from models.packet_models import TCPFlags, TCPHeader, TCPOption

TCP_OPTION_NAMES = {
    0: "End of Option List (EOL)",
    1: "No-Operation (NOP)",
    2: "Maximum Segment Size (MSS)",
    3: "Window Scale",
    4: "SACK Permitted",
    5: "SACK",
    8: "Timestamp",
}


def parse_tcp_options(options_bytes: bytes) -> List[TCPOption]:
    """Parses raw TCP option bytes into structured TCPOption objects."""
    options: List[TCPOption] = []
    i = 0
    total_len = len(options_bytes)

    while i < total_len:
        kind = options_bytes[i]

        if kind == 0:  # End of Option List
            options.append(TCPOption(kind=0, name="EOL", length=1))
            break

        if kind == 1:  # No-Operation (NOP)
            options.append(TCPOption(kind=1, name="NOP", length=1))
            i += 1
            continue

        # Options with length field
        if i + 1 >= total_len:
            # Truncated option header
            break

        opt_len = options_bytes[i + 1]
        if opt_len < 2 or (i + opt_len) > total_len:
            # Corrupted length field
            break

        opt_data = options_bytes[i + 2 : i + opt_len]
        opt_name = TCP_OPTION_NAMES.get(kind, f"Unknown ({kind})")
        decoded_val = None

        if kind == 2 and len(opt_data) == 2:  # MSS
            decoded_val = struct.unpack("!H", opt_data)[0]
        elif kind == 3 and len(opt_data) == 1:  # Window scale
            decoded_val = opt_data[0]
        elif kind == 8 and len(opt_data) == 8:  # Timestamp
            ts_val, ts_ecr = struct.unpack("!II", opt_data)
            decoded_val = {"ts_val": ts_val, "ts_ecr": ts_ecr}

        options.append(
            TCPOption(
                kind=kind,
                name=opt_name,
                length=opt_len,
                data=opt_data,
                decoded=decoded_val,
            )
        )
        i += opt_len

    return options


class TCPParser:
    """Dissects raw TCP segment headers."""

    MIN_HEADER_LEN = 20

    @classmethod
    def parse(cls, data: bytes) -> Tuple[TCPHeader, bytes]:
        """
        Parses a TCP segment header from raw bytes.

        Args:
            data: Raw transport layer bytes.

        Returns:
            Tuple of (TCPHeader, payload_bytes)

        Raises:
            ValueError: If the buffer is truncated or data offset is invalid (< 5).
        """
        if len(data) < cls.MIN_HEADER_LEN:
            raise ValueError(f"TCP segment truncated: expected at least {cls.MIN_HEADER_LEN} bytes, got {len(data)}")

        (
            src_port,
            dst_port,
            seq_num,
            ack_num,
            offset_flags,
            window_size,
            checksum,
            urgent_pointer,
        ) = struct.unpack("!HHIIHHHH", data[:cls.MIN_HEADER_LEN])

        data_offset = (offset_flags >> 12) & 0x0F
        if data_offset < 5:
            raise ValueError(f"Invalid TCP data offset: {data_offset} (minimum 5 words / 20 bytes)")

        header_len = data_offset * 4
        if len(data) < header_len:
            raise ValueError(f"TCP segment truncated for options: header expects {header_len} bytes, got {len(data)}")

        flags = TCPFlags(
            cwr=bool((offset_flags >> 7) & 0x01),
            ece=bool((offset_flags >> 6) & 0x01),
            urg=bool((offset_flags >> 5) & 0x01),
            ack=bool((offset_flags >> 4) & 0x01),
            psh=bool((offset_flags >> 3) & 0x01),
            rst=bool((offset_flags >> 2) & 0x01),
            syn=bool((offset_flags >> 1) & 0x01),
            fin=bool(offset_flags & 0x01),
            raw_value=offset_flags & 0x01FF,
        )

        options: List[TCPOption] = []
        if header_len > cls.MIN_HEADER_LEN:
            options_raw = data[cls.MIN_HEADER_LEN:header_len]
            options = parse_tcp_options(options_raw)

        payload = data[header_len:]
        raw_header = data[:header_len]

        header = TCPHeader(
            src_port=src_port,
            dst_port=dst_port,
            seq_num=seq_num,
            ack_num=ack_num,
            data_offset=data_offset,
            header_length=header_len,
            flags=flags,
            window_size=window_size,
            checksum=checksum,
            urgent_pointer=urgent_pointer,
            options=options,
            payload_length=len(payload),
            raw_header=raw_header,
        )

        return header, payload

