"""IPv6 packet parser with extension header traversal."""

from __future__ import annotations

import socket
import struct
from typing import List, Tuple

from models.packet_models import IPv6ExtensionHeader, IPv6Header
from parser.ipv4_parser import IP_PROTOCOLS

# IPv6 Extension Header codes
IPV6_EXT_HOPOPT = 0
IPV6_EXT_ROUTING = 43
IPV6_EXT_FRAGMENT = 44
IPV6_EXT_ESP = 50
IPV6_EXT_AH = 51
IPV6_EXT_DESTOPT = 60
IPV6_EXT_MOBILITY = 135
IPV6_NO_NEXT = 59

IPV6_EXT_HEADERS = {
    IPV6_EXT_HOPOPT: "Hop-by-Hop Options",
    IPV6_EXT_ROUTING: "Routing",
    IPV6_EXT_FRAGMENT: "Fragment Header",
    IPV6_EXT_ESP: "Encapsulating Security Payload",
    IPV6_EXT_AH: "Authentication Header",
    IPV6_EXT_DESTOPT: "Destination Options",
    IPV6_EXT_MOBILITY: "Mobility Header",
}


class IPv6Parser:
    """Dissects raw IPv6 packet headers and traverses extension headers."""

    BASE_HEADER_LEN = 40

    @classmethod
    def parse(cls, data: bytes) -> Tuple[IPv6Header, bytes]:
        """
        Parses an IPv6 packet header and processes extension headers.

        Args:
            data: Raw network layer bytes.

        Returns:
            Tuple of (IPv6Header, payload_bytes)

        Raises:
            ValueError: If the buffer is truncated or version != 6.
        """
        if len(data) < cls.BASE_HEADER_LEN:
            raise ValueError(f"IPv6 packet truncated: expected at least {cls.BASE_HEADER_LEN} bytes, got {len(data)}")

        vtf, payload_len, next_hdr, hop_limit, src_raw, dst_raw = struct.unpack(
            "!IHBB16s16s", data[:cls.BASE_HEADER_LEN]
        )

        version = (vtf >> 28) & 0x0F
        traffic_class = (vtf >> 20) & 0xFF
        flow_label = vtf & 0xFFFFF

        if version != 6:
            raise ValueError(f"Invalid IPv6 version: {version}")

        src_ip = socket.inet_ntop(socket.AF_INET6, src_raw)
        dst_ip = socket.inet_ntop(socket.AF_INET6, dst_raw)

        # Slice payload according to IPv6 payload_len if available
        available_data = data[cls.BASE_HEADER_LEN:]
        if payload_len > 0 and len(available_data) >= payload_len:
            curr_data = available_data[:payload_len]
        else:
            curr_data = available_data

        extension_headers: List[IPv6ExtensionHeader] = []
        curr_next_hdr = next_hdr
        offset = 0

        # Extension header traversal
        max_extensions = 10  # Prevent infinite loops on cyclic/malformed headers
        ext_count = 0

        while curr_next_hdr in IPV6_EXT_HEADERS and ext_count < max_extensions:
            ext_count += 1
            remaining = curr_data[offset:]

            if curr_next_hdr == IPV6_EXT_ESP:
                # ESP payload is encrypted; cannot inspect inner header
                break

            if curr_next_hdr == IPV6_EXT_FRAGMENT:
                # Fragment header is fixed 8 bytes
                if len(remaining) < 8:
                    break
                next_in_chain = remaining[0]
                ext_len = 8
                ext_obj = IPv6ExtensionHeader(
                    next_header_code=curr_next_hdr,
                    next_header_name="Fragment Header",
                    header_length=ext_len,
                    data=remaining[:ext_len],
                )
                extension_headers.append(ext_obj)
                offset += ext_len
                curr_next_hdr = next_in_chain
                # If fragment offset != 0, inner transport header is not present
                break

            if curr_next_hdr == IPV6_EXT_AH:
                # Authentication header length: (payload_len + 2) * 4 bytes
                if len(remaining) < 8:
                    break
                next_in_chain = remaining[0]
                ah_len_field = remaining[1]
                ext_len = (ah_len_field + 2) * 4
                if len(remaining) < ext_len:
                    break
                ext_obj = IPv6ExtensionHeader(
                    next_header_code=curr_next_hdr,
                    next_header_name="Authentication Header",
                    header_length=ext_len,
                    data=remaining[:ext_len],
                )
                extension_headers.append(ext_obj)
                offset += ext_len
                curr_next_hdr = next_in_chain
                continue

            # Generic extension headers (Hop-by-Hop, Routing, Destination Options, Mobility)
            if len(remaining) < 8:
                break

            next_in_chain = remaining[0]
            ext_len_field = remaining[1]
            ext_len = (ext_len_field + 1) * 8

            if len(remaining) < ext_len:
                break

            ext_name = IPV6_EXT_HEADERS.get(curr_next_hdr, f"Extension 0x{curr_next_hdr:02X}")
            ext_obj = IPv6ExtensionHeader(
                next_header_code=curr_next_hdr,
                next_header_name=ext_name,
                header_length=ext_len,
                data=remaining[:ext_len],
            )
            extension_headers.append(ext_obj)
            offset += ext_len
            curr_next_hdr = next_in_chain

        upper_protocol_name = IP_PROTOCOLS.get(curr_next_hdr, f"Unknown ({curr_next_hdr})")
        payload = curr_data[offset:]

        header = IPv6Header(
            version=version,
            traffic_class=traffic_class,
            flow_label=flow_label,
            payload_length=payload_len,
            next_header_code=next_hdr,
            next_header_name=IP_PROTOCOLS.get(next_hdr, f"Protocol {next_hdr}"),
            hop_limit=hop_limit,
            src_ip=src_ip,
            dst_ip=dst_ip,
            extension_headers=extension_headers,
            upper_protocol_code=curr_next_hdr,
            upper_protocol_name=upper_protocol_name,
            raw_header=data[:cls.BASE_HEADER_LEN + offset],
        )

        return header, payload

