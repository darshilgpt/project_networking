"""Packet dispatcher orchestrating multi-layer protocol dissection."""

from __future__ import annotations

from datetime import datetime
import time
from typing import Optional

from models.packet_models import ParsedPacket
from parser.ethernet_parser import EthernetParser
from parser.icmp_parser import ICMPParser
from parser.ipv4_parser import IPv4Parser
from parser.ipv6_parser import IPv6Parser
from parser.tcp_parser import TCPParser
from parser.udp_parser import UDPParser


class PacketDispatcher:
    """Central pipeline coordinator for decoding raw network frames."""

    def __init__(self) -> None:
        self._packet_counter = 0

    @staticmethod
    def detect_link_type(raw_bytes: bytes) -> str:
        """
        Determines whether a buffer is standard Ethernet (L2) or Raw IP (L3 / WireGuard tunnel).
        """
        if len(raw_bytes) < 14:
            if len(raw_bytes) >= 20 and (raw_bytes[0] >> 4) in (4, 6):
                return "RAW_IP"
            return "ETHERNET"

        ethertype = (raw_bytes[12] << 8) | raw_bytes[13]
        if ethertype in (0x0800, 0x86DD, 0x8100, 0x88A8, 0x0806):
            return "ETHERNET"

        version = raw_bytes[0] >> 4
        if version == 4:
            ihl = raw_bytes[0] & 0x0F
            if ihl >= 5 and len(raw_bytes) >= ihl * 4:
                return "RAW_IP"
        elif version == 6:
            if len(raw_bytes) >= 40:
                return "RAW_IP"

        return "ETHERNET"

    def dispatch(
        self,
        raw_bytes: bytes,
        timestamp: Optional[float] = None,
        link_type: str = "AUTO",
    ) -> ParsedPacket:
        """
        Dissects a raw packet buffer through Ethernet/Raw-IP, Network, and Transport layers.

        Args:
            raw_bytes: Raw packet bytes received from network interface or tunnel.
            timestamp: Capture timestamp (defaults to current time if None).
            link_type: 'AUTO', 'ETHERNET', or 'RAW_IP' (useful for WireGuard tunnels).

        Returns:
            ParsedPacket dataclass populated with decoded layer headers.
        """
        self._packet_counter += 1
        ts = timestamp if timestamp is not None else time.time()
        dt_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]

        parsed = ParsedPacket(
            packet_id=self._packet_counter,
            timestamp=ts,
            datetime_str=dt_str,
            raw_length=len(raw_bytes),
        )

        if not raw_bytes:
            parsed.is_malformed = True
            parsed.parse_errors.append("Empty packet buffer")
            return parsed

        effective_link = link_type.upper()
        if effective_link == "AUTO":
            effective_link = self.detect_link_type(raw_bytes)

        l4_payload = raw_bytes
        transport_proto_code = None
        is_ipv6 = False
        is_fragmented = False

        if effective_link == "RAW_IP":
            # --- Layer 3 directly: Decrypted WireGuard Tunnel / Raw IP ---
            version = raw_bytes[0] >> 4
            if version == 4:
                parsed.network_type = "IPv4"
                try:
                    ip_header, l4_payload = IPv4Parser.parse(raw_bytes)
                    parsed.ipv4 = ip_header
                    transport_proto_code = ip_header.protocol_code
                    is_fragmented = ip_header.fragment_offset > 0
                except Exception as e:
                    parsed.is_malformed = True
                    parsed.parse_errors.append(f"IPv4 parse error (Raw IP): {e}")
                    parsed.payload = raw_bytes
                    parsed.payload_length = len(raw_bytes)
                    return parsed
            elif version == 6:
                parsed.network_type = "IPv6"
                is_ipv6 = True
                try:
                    ip6_header, l4_payload = IPv6Parser.parse(raw_bytes)
                    parsed.ipv6 = ip6_header
                    transport_proto_code = ip6_header.upper_protocol_code
                except Exception as e:
                    parsed.is_malformed = True
                    parsed.parse_errors.append(f"IPv6 parse error (Raw IP): {e}")
                    parsed.payload = raw_bytes
                    parsed.payload_length = len(raw_bytes)
                    return parsed
            else:
                parsed.is_malformed = True
                parsed.parse_errors.append(f"Unknown Raw IP version {version}")
                parsed.payload = raw_bytes
                parsed.payload_length = len(raw_bytes)
                return parsed
        else:
            # --- Layer 2: Ethernet Frame ---
            try:
                eth_header, l3_payload = EthernetParser.parse(raw_bytes)
                parsed.ethernet = eth_header
            except Exception as e:
                parsed.is_malformed = True
                parsed.parse_errors.append(f"Ethernet parse error: {e}")
                parsed.payload = raw_bytes
                parsed.payload_length = len(raw_bytes)
                return parsed

            # --- Layer 3: Network Layer (IPv4 / IPv6 / Other) ---
            l4_payload = l3_payload

            if eth_header.ethertype_code == 0x0800:  # IPv4
                parsed.network_type = "IPv4"
                try:
                    ip_header, l4_payload = IPv4Parser.parse(l3_payload)
                    parsed.ipv4 = ip_header
                    transport_proto_code = ip_header.protocol_code
                    is_fragmented = ip_header.fragment_offset > 0
                except Exception as e:
                    parsed.is_malformed = True
                    parsed.parse_errors.append(f"IPv4 parse error: {e}")
                    parsed.payload = l3_payload
                    parsed.payload_length = len(l3_payload)
                    return parsed

            elif eth_header.ethertype_code == 0x86DD:  # IPv6
                parsed.network_type = "IPv6"
                is_ipv6 = True
                try:
                    ip6_header, l4_payload = IPv6Parser.parse(l3_payload)
                    parsed.ipv6 = ip6_header
                    transport_proto_code = ip6_header.upper_protocol_code
                except Exception as e:
                    parsed.is_malformed = True
                    parsed.parse_errors.append(f"IPv6 parse error: {e}")
                    parsed.payload = l3_payload
                    parsed.payload_length = len(l3_payload)
                    return parsed

            elif eth_header.ethertype_code == 0x0806:  # ARP
                parsed.network_type = "ARP"
                parsed.payload = l3_payload
                parsed.payload_length = len(l3_payload)
                return parsed

            else:
                parsed.network_type = eth_header.ethertype_name
                parsed.payload = l3_payload
                parsed.payload_length = len(l3_payload)
                return parsed

        # If fragmented at non-zero offset, transport header is not present
        if is_fragmented:
            parsed.transport_type = "Fragment (Non-First)"
            parsed.payload = l4_payload
            parsed.payload_length = len(l4_payload)
            return parsed

        # --- Layer 4: Transport Layer (TCP / UDP / ICMP / Other) ---
        if transport_proto_code == 6:  # TCP
            parsed.transport_type = "TCP"
            try:
                tcp_header, app_payload = TCPParser.parse(l4_payload)
                parsed.tcp = tcp_header
                parsed.payload = app_payload
                parsed.payload_length = len(app_payload)
            except Exception as e:
                parsed.is_malformed = True
                parsed.parse_errors.append(f"TCP parse error: {e}")
                parsed.payload = l4_payload
                parsed.payload_length = len(l4_payload)

        elif transport_proto_code == 17:  # UDP
            parsed.transport_type = "UDP"
            try:
                udp_header, app_payload = UDPParser.parse(l4_payload)
                parsed.udp = udp_header
                parsed.payload = app_payload
                parsed.payload_length = len(app_payload)
            except Exception as e:
                parsed.is_malformed = True
                parsed.parse_errors.append(f"UDP parse error: {e}")
                parsed.payload = l4_payload
                parsed.payload_length = len(l4_payload)

        elif (transport_proto_code == 1 and not is_ipv6) or (transport_proto_code == 58 and is_ipv6):  # ICMP / ICMPv6
            parsed.transport_type = "ICMPv6" if is_ipv6 else "ICMP"
            try:
                icmp_header, app_payload = ICMPParser.parse(l4_payload, is_ipv6=is_ipv6)
                parsed.icmp = icmp_header
                parsed.payload = app_payload
                parsed.payload_length = len(app_payload)
            except Exception as e:
                parsed.is_malformed = True
                parsed.parse_errors.append(f"ICMP parse error: {e}")
                parsed.payload = l4_payload
                parsed.payload_length = len(l4_payload)

        else:
            # Other upper-layer protocol (e.g. IGMP, GRE, ESP, etc.)
            parsed.transport_type = f"Proto {transport_proto_code}" if transport_proto_code is not None else "None"
            parsed.payload = l4_payload
            parsed.payload_length = len(l4_payload)

        return parsed

