"""Application Layer Protocol Detector based on payload signatures and structure."""

from __future__ import annotations

from dpi.dns_inspector import DNSInspector
from dpi.http_inspector import HTTPInspector
from dpi.tls_inspector import TLSInspector
from models.packet_models import ParsedPacket


class ProtocolDetector:
    """Identifies the application layer protocol from raw bytes and connection metadata."""

    @classmethod
    def detect(cls, payload: bytes, packet: ParsedPacket) -> str:
        """
        Determines the application-layer protocol for a packet or reassembled stream.

        Args:
            payload: Contiguous application payload bytes.
            packet: Associated ParsedPacket instance.

        Returns:
            Protocol string: "HTTP", "TLS", "DNS", "QUIC", "SSDP", or "Unknown".
        """
        if not payload:
            return "None"

        # 1. TLS Check (Magic bytes 0x16 0x03 0x01..04, etc.)
        if TLSInspector.is_tls(payload):
            return "TLS"

        # 2. HTTP Check (Methods GET, POST, or HTTP/1.x)
        if HTTPInspector.is_http(payload):
            return "HTTP"

        # 3. DNS Check
        src_port = packet.tcp.src_port if packet.tcp else (packet.udp.src_port if packet.udp else 0)
        dst_port = packet.tcp.dst_port if packet.tcp else (packet.udp.dst_port if packet.udp else 0)
        is_udp = packet.udp is not None

        if DNSInspector.is_dns(payload, is_udp=is_udp, src_port=src_port, dst_port=dst_port):
            return "DNS"

        # 4. QUIC / HTTP/3 (UDP port 443 with QUIC header flags)
        if is_udp and (src_port == 443 or dst_port == 443):
            return "QUIC/HTTP3"

        # 5. SSDP (UDP port 1900 or M-SEARCH)
        if is_udp and (dst_port == 1900 or src_port == 1900 or b"M-SEARCH" in payload):
            return "SSDP"

        # 6. Fallback based on well-known ports if payload signature is ambiguous
        if src_port == 80 or dst_port == 80:
            return "HTTP"
        elif src_port == 443 or dst_port == 443:
            return "TLS"
        elif src_port == 53 or dst_port == 53:
            return "DNS"

        return "Unknown"

