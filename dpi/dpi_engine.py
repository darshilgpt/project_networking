"""Main DPI Engine coordinating protocol identification, inspection, and rule matching."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Tuple

from dpi.dns_inspector import DNSInspector, DNSMetadata
from dpi.http_inspector import HTTPInspector, HTTPMetadata
from dpi.protocol_detector import ProtocolDetector
from dpi.signature_matcher import SignatureMatcher
from dpi.tls_inspector import TLSInspector, TLSMetadata
from models.alert_model import DPIResult
from models.flow_model import Flow
from models.packet_models import ParsedPacket

logger = logging.getLogger("dpi_ids_ips.dpi.dpi_engine")


class DPIEngine:
    """Performs deep inspection of application payloads and TCP reassembled streams."""

    def __init__(self, matcher: Optional[SignatureMatcher] = None) -> None:
        self.matcher = matcher or SignatureMatcher()
        self.total_inspections = 0
        self.total_payload_bytes = 0
        self.signature_matches_count = 0
        self.protocol_counts: Dict[str, int] = {}

    def inspect(
        self,
        packet: ParsedPacket,
        flow: Optional[Flow] = None,
        reassembled_payload: Optional[bytes] = None,
    ) -> DPIResult:
        """
        Deeply inspects packet or reassembled stream data.

        Args:
            packet: ParsedPacket from Phase 1.
            flow: Associated Flow instance.
            reassembled_payload: Reassembled TCP data if available, or None for raw packet payload.

        Returns:
            DPIResult containing classified protocol, extracted metadata, and rule matches.
        """
        payload = reassembled_payload if reassembled_payload is not None else packet.payload
        is_reassembled = reassembled_payload is not None
        flow_id = flow.flow_id if flow else None

        self.total_inspections += 1
        self.total_payload_bytes += len(payload)

        result = DPIResult(
            flow_id=flow_id,
            reconstructed_stream=is_reassembled,
            stream_length=len(payload),
        )

        if not payload:
            result.protocol = "None"
            return result

        # 1. Identify Application Protocol
        detected_proto = ProtocolDetector.detect(payload, packet)
        result.protocol = detected_proto
        self.protocol_counts[detected_proto] = self.protocol_counts.get(detected_proto, 0) + 1

        fields: Dict[str, Any] = {}

        # 2. Protocol-Specific Deep Inspection
        try:
            if detected_proto == "HTTP":
                http_meta = HTTPInspector.inspect(payload)
                if http_meta:
                    result.metadata["http"] = http_meta
                    fields["uri"] = http_meta.uri or ""
                    fields["method"] = http_meta.method or ""
                    fields["host"] = http_meta.host or ""
                    fields["user_agent"] = http_meta.user_agent or ""
                    fields["content_type"] = http_meta.content_type or ""
                    fields["body"] = http_meta.body_preview

            elif detected_proto == "DNS":
                is_udp = packet.udp is not None
                dns_meta = DNSInspector.inspect(payload, is_udp=is_udp)
                if dns_meta:
                    result.metadata["dns"] = dns_meta
                    qnames = [q.name for q in dns_meta.questions]
                    fields["query_name"] = qnames[0] if qnames else ""
                    fields["all_queries"] = qnames
                    fields["rcode"] = dns_meta.rcode_name
                    if dns_meta.is_suspicious_domain:
                        result.metadata["dns_suspicious_reasons"] = dns_meta.suspicious_reasons

            elif detected_proto == "TLS":
                tls_meta = TLSInspector.inspect(payload)
                if tls_meta:
                    result.metadata["tls"] = tls_meta
                    fields["sni"] = tls_meta.sni or ""
                    fields["handshake_type"] = tls_meta.handshake_type or ""
                    fields["client_version"] = tls_meta.client_version_name or ""
                    fields["is_encrypted"] = tls_meta.is_encrypted_application_data

            elif detected_proto == "QUIC/HTTP3":
                result.metadata["quic"] = {"info": "QUIC / HTTP/3 UDP Datagram"}

            elif detected_proto == "SSDP":
                result.metadata["ssdp"] = {"info": "SSDP UPnP Discovery"}

        except Exception as insp_err:
            result.inspection_errors.append(f"Inspection error in {detected_proto}: {insp_err}")
            logger.error(f"Error inspecting {detected_proto} payload: {insp_err}")

        # 3. Signature & Pattern Matching
        try:
            matches = self.matcher.match(
                protocol=detected_proto,
                fields=fields,
                raw_payload=payload,
            )
            result.matched_signatures = matches
            if matches:
                self.signature_matches_count += len(matches)
        except Exception as match_err:
            result.inspection_errors.append(f"Signature match error: {match_err}")
            logger.error(f"Signature matcher error: {match_err}")

        return result

