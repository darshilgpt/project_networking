"""Central Intrusion Detection System Engine coordinating signature and behavioural detectors."""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from ids.behaviour_detector import BehaviourDetector
from ids.signature_detector import SignatureDetector
from models.alert_model import DPIResult, IDSAlert, Severity
from models.packet_models import ParsedPacket

logger = logging.getLogger("dpi_ids_ips.ids.ids_engine")


class IDSEngine:
    """Evaluates packet streams against signature rules and behavioural baselines."""

    def __init__(
        self,
        signature_detector: Optional[SignatureDetector] = None,
        behaviour_detector: Optional[BehaviourDetector] = None,
    ) -> None:
        self.signature_detector = signature_detector or SignatureDetector()
        self.behaviour_detector = behaviour_detector or BehaviourDetector()

        self._alert_id_counter = 0
        self.alerts_history: List[IDSAlert] = []

        # Metrics
        self.total_alerts = 0
        self.severity_counts: Dict[str, int] = {
            Severity.LOW.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.HIGH.value: 0,
            Severity.CRITICAL.value: 0,
        }
        self.category_counts: Dict[str, int] = {}

    def _next_alert_id(self) -> int:
        self._alert_id_counter += 1
        return self._alert_id_counter

    def evaluate(self, packet: ParsedPacket, dpi_result: Optional[DPIResult]) -> List[IDSAlert]:
        """
        Runs both signature and behavioural analysis on the packet.

        Args:
            packet: ParsedPacket from Phase 1.
            dpi_result: DPIResult from DPIEngine.

        Returns:
            List of generated IDSAlert objects.
        """
        alerts: List[IDSAlert] = []

        # 1. Signature-based inspection
        if dpi_result:
            sig_alerts = self.signature_detector.evaluate(packet, dpi_result, self._next_alert_id)
            alerts.extend(sig_alerts)

        # 2. Behavioural analysis (Rate thresholds, scans, floods, errors)
        beh_alerts = self.behaviour_detector.evaluate(packet, dpi_result, self._next_alert_id)
        alerts.extend(beh_alerts)

        # Record statistics
        for alert in alerts:
            self.total_alerts += 1
            self.alerts_history.append(alert)
            sev = alert.severity.value
            self.severity_counts[sev] = self.severity_counts.get(sev, 0) + 1
            cat = alert.category.value
            self.category_counts[cat] = self.category_counts.get(cat, 0) + 1

        return alerts

