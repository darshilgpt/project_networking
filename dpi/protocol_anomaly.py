"""Protocol Anomaly and Evasion Detector covering HTTP smuggling, TCP flag anomalies, and fragment evasion."""

from __future__ import annotations

from dataclasses import dataclass
import logging
import re
from typing import List, Optional

from models.packet_models import ParsedPacket

logger = logging.getLogger("dpi_ids_ips.dpi.anomaly")


@dataclass
class ProtocolAnomalyAlert:
    """Alert raised for protocol anomalies and evasion attempts."""
    anomaly_type: str
    severity: str
    protocol: str
    evidence: str
    source_ip: str
    destination_ip: str
    timestamp: float


class ProtocolAnomalyDetector:
    """Detects HTTP request smuggling, method tampering, directory traversal, and TCP flag anomalies."""

    TRAVERSAL_REGEX = re.compile(r"(\.\./|\.\.\\|%2e%2e|%252e%252e|\.\.%2f|\.\.%5c)", re.IGNORECASE)
    VALID_HTTP_METHODS = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"}

    @classmethod
    def evaluate(cls, packet: ParsedPacket, dpi_result: Optional[Any] = None) -> List[ProtocolAnomalyAlert]:
        """Evaluates packet headers and DPI results for evasion and anomalies."""
        alerts: List[ProtocolAnomalyAlert] = []
        now = packet.timestamp or 0.0

        src_ip = packet.ipv4.src_ip if packet.ipv4 else (packet.ipv6.src_ip if packet.ipv6 else "0.0.0.0")
        dst_ip = packet.ipv4.dst_ip if packet.ipv4 else (packet.ipv6.dst_ip if packet.ipv6 else "0.0.0.0")

        # --- 1. TCP Control Flag Evasion Anomalies ---
        if packet.tcp:
            f = packet.tcp.flags
            # A. SYN + FIN (Used to bypass stateful packet filters)
            if f.syn and f.fin:
                alerts.append(
                    ProtocolAnomalyAlert(
                        anomaly_type="TCP_SYN_FIN_EVASION",
                        severity="HIGH",
                        protocol="TCP",
                        evidence="Illegal TCP flag combination: Both SYN and FIN are set simultaneously.",
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        timestamp=now,
                    )
                )

            # B. NULL Flags (No control flags set)
            if not (f.syn or f.ack or f.fin or f.rst or f.psh or f.urg):
                alerts.append(
                    ProtocolAnomalyAlert(
                        anomaly_type="TCP_NULL_FLAGS_SCAN",
                        severity="HIGH",
                        protocol="TCP",
                        evidence="TCP NULL segment: Zero control flags set. Common in stealth OS fingerprinting.",
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        timestamp=now,
                    )
                )

            # C. XMAS Tree (FIN + PSH + URG)
            if f.fin and f.psh and f.urg:
                alerts.append(
                    ProtocolAnomalyAlert(
                        anomaly_type="TCP_XMAS_SCAN_EVASION",
                        severity="HIGH",
                        protocol="TCP",
                        evidence="TCP XMAS Tree: FIN, PSH, and URG flags all active. Stealth scan / firewall probe.",
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        timestamp=now,
                    )
                )

            # D. SYN + RST
            if f.syn and f.rst:
                alerts.append(
                    ProtocolAnomalyAlert(
                        anomaly_type="TCP_SYN_RST_ANOMALY",
                        severity="MEDIUM",
                        protocol="TCP",
                        evidence="Contradictory TCP flags: Both SYN and RST are set.",
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        timestamp=now,
                    )
                )

        # --- 2. Tiny Fragment Evasion ---
        if packet.ipv4 and packet.ipv4.is_fragmented and packet.ipv4.fragment_offset == 0:
            if packet.payload_length < 8:
                alerts.append(
                    ProtocolAnomalyAlert(
                        anomaly_type="IP_TINY_FRAGMENT_EVASION",
                        severity="HIGH",
                        protocol="IPv4",
                        evidence=f"Tiny fragment evasion: Fragment 0 payload length is {packet.payload_length} < 8 bytes.",
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        timestamp=now,
                    )
                )

        # --- 3. HTTP Protocol Anomalies & Smuggling ---
        if dpi_result and dpi_result.metadata and "http" in dpi_result.metadata:
            http_m = dpi_result.metadata["http"]

            # A. HTTP Request Smuggling (Both Transfer-Encoding and Content-Length)
            headers = http_m.headers if hasattr(http_m, "headers") else {}
            has_te = any("transfer-encoding" in k.lower() for k in headers.keys())
            has_cl = any("content-length" in k.lower() for k in headers.keys())
            if has_te and has_cl:
                alerts.append(
                    ProtocolAnomalyAlert(
                        anomaly_type="HTTP_REQUEST_SMUGGLING_INDICATOR",
                        severity="CRITICAL",
                        protocol="HTTP",
                        evidence="HTTP Request Smuggling hazard: Both Transfer-Encoding and Content-Length headers present.",
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        timestamp=now,
                    )
                )

            # B. HTTP Method Tampering / Dangerous Methods
            if http_m.method and http_m.method.upper() not in cls.VALID_HTTP_METHODS:
                alerts.append(
                    ProtocolAnomalyAlert(
                        anomaly_type="HTTP_METHOD_ANOMALY",
                        severity="MEDIUM",
                        protocol="HTTP",
                        evidence=f"Non-standard or dangerous HTTP method: '{http_m.method}'.",
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        timestamp=now,
                    )
                )

            # C. URL Double Encoding / Traversal Evasion
            uri = http_m.uri or ""
            if cls.TRAVERSAL_REGEX.search(uri):
                alerts.append(
                    ProtocolAnomalyAlert(
                        anomaly_type="HTTP_DIRECTORY_TRAVERSAL_EVASION",
                        severity="HIGH",
                        protocol="HTTP",
                        evidence=f"Directory traversal / URL encoding evasion sequence in URI: '{uri}'.",
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        timestamp=now,
                    )
                )

            # D. Null Byte Injection in URI
            if "%00" in uri or "\x00" in uri:
                alerts.append(
                    ProtocolAnomalyAlert(
                        anomaly_type="HTTP_NULL_BYTE_INJECTION",
                        severity="HIGH",
                        protocol="HTTP",
                        evidence=f"Null byte (%00) injection detected in HTTP URI: '{uri}'.",
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        timestamp=now,
                    )
                )

        return alerts
