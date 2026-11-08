"""Alert, DPI inspection result, and Decision Engine models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Alert severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectionCategory(str, Enum):
    """Categorization for intrusion detection events."""
    SIGNATURE_MATCH = "SIGNATURE_MATCH"
    PORT_SCAN = "PORT_SCAN"
    SYN_SCAN = "SYN_SCAN"
    UDP_SCAN = "UDP_SCAN"
    STEALTH_SCAN = "STEALTH_SCAN"
    SYN_FLOOD = "SYN_FLOOD"
    SUSPICIOUS_DNS = "SUSPICIOUS_DNS"
    DNS_TUNNELING = "DNS_TUNNELING"
    ARP_SPOOFING = "ARP_SPOOFING"
    DHCP_SECURITY = "DHCP_SECURITY"
    DHCP_ANOMALY = "DHCP_ANOMALY"
    ICMP_ANOMALY = "ICMP_ANOMALY"
    IP_SPOOFING = "IP_SPOOFING"
    TTL_ANOMALY = "TTL_ANOMALY"
    PROTOCOL_EVASION = "PROTOCOL_EVASION"
    EVASION_TECHNIQUE = "EVASION_TECHNIQUE"
    PROTOCOL_ANOMALY = "PROTOCOL_ANOMALY"
    CONNECTION_FAILURE = "CONNECTION_FAILURE"
    MALFORMED_PACKET = "MALFORMED_PACKET"
    BEHAVIOURAL_ANOMALY = "BEHAVIOURAL_ANOMALY"
    RECONNAISSANCE = "RECONNAISSANCE"
    THREAT_REPUTATION = "THREAT_REPUTATION"


class DecisionAction(str, Enum):
    """Enforcement decisions."""
    ALLOW = "ALLOW"
    ALERT = "ALERT"
    BLOCK = "BLOCK"


@dataclass
class IDSAlert:
    """Represents a security alert raised by the IDS engine."""
    alert_id: int
    timestamp: float
    datetime_str: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    category: DetectionCategory
    severity: Severity
    matched_rule: str
    evidence: str
    recommended_action: DecisionAction = DecisionAction.ALERT
    packet_id: Optional[int] = None

    @classmethod
    def create(
        cls,
        alert_id: int,
        timestamp: float,
        source_ip: str,
        destination_ip: str,
        source_port: int,
        destination_port: int,
        protocol: str,
        category: DetectionCategory,
        severity: Severity,
        matched_rule: str,
        evidence: str,
        recommended_action: DecisionAction = DecisionAction.ALERT,
        packet_id: Optional[int] = None,
    ) -> IDSAlert:
        dt_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S.%f")[:-3]
        return cls(
            alert_id=alert_id,
            timestamp=timestamp,
            datetime_str=dt_str,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=source_port,
            destination_port=destination_port,
            protocol=protocol,
            category=category,
            severity=severity,
            matched_rule=matched_rule,
            evidence=evidence,
            recommended_action=recommended_action,
            packet_id=packet_id,
        )

    def summary(self) -> str:
        return (
            f"[ALERT #{self.alert_id}] [{self.severity.value}] {self.category.value} | "
            f"{self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port} | "
            f"Rule: {self.matched_rule} | Evidence: {self.evidence}"
        )


@dataclass
class DPIResult:
    """Contains dissected application metadata and signature match results."""
    flow_id: Optional[int]
    protocol: str = "Unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)
    matched_signatures: List[Dict[str, Any]] = field(default_factory=list)
    reconstructed_stream: bool = False
    stream_length: int = 0
    inspection_errors: List[str] = field(default_factory=list)

