"""Ethernet II frame parser utilizing Python struct module."""

from __future__ import annotations

import struct
from typing import Tuple

from models.packet_models import EthernetHeader

# Standard EtherType definitions
ETHERTYPE_MAP = {
    0x0800: "IPv4",
    0x86DD: "IPv6",
    0x0806: "ARP",
    0x8035: "RARP",
    0x8100: "802.1Q VLAN",
    0x88A8: "802.1ad Service VLAN",
    0x8847: "MPLS Unicast",
    0x8848: "MPLS Multicast",
    0x8863: "PPPoE Discovery",
    0x8864: "PPPoE Session",
    0x888E: "802.1X EAPOL",
    0x88CC: "LLDP",
}

VLAN_ETHERTYPES = {0x8100, 0x88A8}


def format_mac(raw_bytes: bytes) -> str:
    """Formats 6 raw bytes into a colon-separated MAC address."""
    return ":".join(f"{b:02X}" for b in raw_bytes)


class EthernetParser:
    """Dissects raw Ethernet II frames."""

    MIN_HEADER_LEN = 14

    @classmethod
    def parse(cls, data: bytes) -> Tuple[EthernetHeader, bytes]:
        """
        Parses an Ethernet II frame from raw bytes.

        Args:
            data: Raw frame bytes.

        Returns:
            Tuple of (EthernetHeader, remaining_payload_bytes)

        Raises:
            ValueError: If the frame is truncated (< 14 bytes or < 18 for VLAN).
        """
        if len(data) < cls.MIN_HEADER_LEN:
            raise ValueError(f"Ethernet frame truncated: expected at least {cls.MIN_HEADER_LEN} bytes, got {len(data)}")

        dst_mac_raw, src_mac_raw, ethertype = struct.unpack("!6s6sH", data[:cls.MIN_HEADER_LEN])
        dst_mac = format_mac(dst_mac_raw)
        src_mac = format_mac(src_mac_raw)

        header_len = cls.MIN_HEADER_LEN
        vlan_id = None
        vlan_pcp = None

        # Check for 802.1Q / 802.1ad VLAN tags
        if ethertype in VLAN_ETHERTYPES:
            if len(data) < cls.MIN_HEADER_LEN + 4:
                raise ValueError(f"VLAN tagged Ethernet frame truncated: expected at least 18 bytes, got {len(data)}")

            tci, inner_ethertype = struct.unpack("!HH", data[cls.MIN_HEADER_LEN:cls.MIN_HEADER_LEN + 4])
            vlan_pcp = (tci >> 13) & 0x07
            vlan_id = tci & 0x0FFF
            ethertype = inner_ethertype
            header_len += 4

        ethertype_name = ETHERTYPE_MAP.get(ethertype, f"Unknown (0x{ethertype:04X})")

        header = EthernetHeader(
            src_mac=src_mac,
            dst_mac=dst_mac,
            ethertype_code=ethertype,
            ethertype_name=ethertype_name,
            vlan_id=vlan_id,
            vlan_pcp=vlan_pcp,
            raw_header=data[:header_len],
        )

        payload = data[header_len:]
        return header, payload

