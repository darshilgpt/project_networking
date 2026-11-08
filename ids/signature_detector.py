"""Signature-based IDS Detector converting DPI matches into structured IDSAlerts."""

from __future__ import annotations

import time
from typing import List

from models.alert_model import DecisionAction, DetectionCategory, IDSAlert, Severity
from models.alert_model import DPIResult
from models.packet_models import ParsedPacket


class SignatureDetector:
    """Evaluates DPI signature match findings and emits alerts."""

    def __init__(self) -> None:
        pass

    def evaluate(
        self,
        packet: ParsedPacket,
        dpi_result: DPIResult,
        next_alert_id_fn: Any,
    ) -> List[IDSAlert]:
        """
        Generates alerts for any signatures matched by the DPI engine.

        Args:
            packet: Current ParsedPacket.
            dpi_result: DPIResult from DPIEngine.
            next_alert_id_fn: Callable returning incrementing alert IDs.

        Returns:
            List of generated IDSAlert objects.
        """
        alerts: List[IDSAlert] = []
        if not dpi_result.matched_signatures:
            return alerts

        src_ip = packet.ipv4.src_ip if packet.ipv4 else (packet.ipv6.src_ip if packet.ipv6 else "")
        dst_ip = packet.ipv4.dst_ip if packet.ipv4 else (packet.ipv6.dst_ip if packet.ipv6 else "")
        src_port = packet.tcp.src_port if packet.tcp else (packet.udp.src_port if packet.udp else 0)
        dst_port = packet.tcp.dst_port if packet.tcp else (packet.udp.dst_port if packet.udp else 0)
        proto = packet.transport_type if packet.transport_type != "None" else packet.network_type
        ts = packet.timestamp or time.time()

        for match in dpi_result.matched_signatures:
            sev_str = match.get("severity", "MEDIUM").upper()
            try:
                severity = Severity[sev_str]
            except KeyError:
                severity = Severity.MEDIUM

            act_str = match.get("action", "ALERT").upper()
            try:
                action = DecisionAction[act_str]
            except KeyError:
                action = DecisionAction.ALERT

            evidence = f"Matched {match.get('matched_field')}: '{match.get('matched_value')}' on pattern '{match.get('pattern')}'"

            alert = IDSAlert.create(
                alert_id=next_alert_id_fn(),
                timestamp=ts,
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=src_port,
                destination_port=dst_port,
                protocol=proto,
                category=DetectionCategory.SIGNATURE_MATCH,
                severity=severity,
                matched_rule=match.get("name", f"Rule_{match.get('id')}"),
                evidence=evidence,
                recommended_action=action,
                packet_id=packet.packet_id,
            )
            alerts.append(alert)

        return alerts

