"""Decision Engine evaluating DPI results and IDS alerts to yield ALLOW / ALERT / BLOCK."""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from models.alert_model import DecisionAction, DPIResult, IDSAlert, Severity
from models.flow_model import Flow
from models.packet_models import ParsedPacket

logger = logging.getLogger("dpi_ids_ips.ips.decision_engine")


class DecisionEngine:
    """Arbiter that decides whether to ALLOW, ALERT, or BLOCK traffic."""

    def __init__(self) -> None:
        self.decision_counts: Dict[str, int] = {
            DecisionAction.ALLOW.value: 0,
            DecisionAction.ALERT.value: 0,
            DecisionAction.BLOCK.value: 0,
        }

    def decide(
        self,
        packet: ParsedPacket,
        dpi_result: Optional[DPIResult],
        alerts: List[IDSAlert],
        flow: Optional[Flow] = None,
    ) -> DecisionAction:
        """
        Determines the appropriate security action.

        Policy precedence:
            1. If any alert has recommended_action == BLOCK or severity == CRITICAL: BLOCK
            2. Else if any alert has recommended_action == ALERT or severity in (HIGH, MEDIUM): ALERT
            3. Else: ALLOW

        Args:
            packet: ParsedPacket.
            dpi_result: DPIResult.
            alerts: List of IDSAlerts.
            flow: Associated Flow.

        Returns:
            DecisionAction enum (ALLOW, ALERT, or BLOCK).
        """
        action = DecisionAction.ALLOW

        if alerts:
            has_block = any(
                a.recommended_action == DecisionAction.BLOCK or a.severity == Severity.CRITICAL
                for a in alerts
            )
            if has_block:
                action = DecisionAction.BLOCK
            else:
                action = DecisionAction.ALERT

        self.decision_counts[action.value] = self.decision_counts.get(action.value, 0) + 1
        return action

