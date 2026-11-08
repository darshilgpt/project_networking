"""Behavioural Intrusion Detection System tracking rate anomalies, scans, floods, and advanced protocol anomalies."""

from __future__ import annotations

from collections import defaultdict, deque
import json
import logging
import os
import time
from typing import Any, Callable, Deque, Dict, List, Optional, Set, Tuple

from dpi.protocol_anomaly import ProtocolAnomalyDetector
from models.alert_model import DecisionAction, DetectionCategory, DPIResult, IDSAlert, Severity
from models.packet_models import ParsedPacket
from ids.port_scan_detector import PortScanDetector
from ids.reconnaissance_detector import ReconnaissanceDetector
from ids.reputation_engine import ReputationEngine
from network.arp_inspector import ARPInspector
from network.dhcp_inspector import DHCPInspector
from network.icmp_detector import ICMPAnomalyDetector
from network.ip_intelligence import IPIntelligenceEngine
from network.topology_discovery import NetworkTopologyDiscovery

logger = logging.getLogger("dpi_ids_ips.ids.behaviour_detector")


class BehaviourDetector:
    """Detects traffic volume anomalies, port scanning, SYN floods, failure bursts, and protocol evasions."""

    def __init__(self, config_path: Optional[str] = None) -> None:
        self.config: Dict[str, Any] = {}
        self.load_config(config_path)

        # Sliding window state trackers: {source_ip: deque[(timestamp, ...)]}
        self._port_scan_tracker: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        self._syn_scan_tracker: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        self._udp_scan_tracker: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        self._syn_flood_tracker: Dict[str, Deque[float]] = defaultdict(deque)
        self._dns_query_tracker: Dict[str, Deque[float]] = defaultdict(deque)
        self._nxdomain_tracker: Dict[str, Deque[float]] = defaultdict(deque)
        self._conn_failure_tracker: Dict[str, Deque[float]] = defaultdict(deque)

        # Specialized network intelligence detectors
        arp_cfg = self.config.get("arp_spoofing", {})
        self.arp_inspector = ARPInspector(
            gratuitous_flood_threshold=arp_cfg.get("gratuitous_flood_threshold", 10)
        )

        dhcp_cfg = self.config.get("dhcp_security", {})
        self.dhcp_inspector = DHCPInspector(
            starvation_threshold=dhcp_cfg.get("starvation_threshold", 15)
        )

        icmp_cfg = self.config.get("icmp_anomaly", {})
        self.icmp_detector = ICMPAnomalyDetector(
            ping_flood_threshold=icmp_cfg.get("ping_flood_threshold", 30),
            unreachable_burst_threshold=icmp_cfg.get("unreachable_burst_threshold", 15),
            oversized_payload_limit=icmp_cfg.get("oversized_payload_limit", 1024),
        )

        ttl_cfg = self.config.get("ttl_analysis", {})
        self.ip_intelligence = IPIntelligenceEngine(
            ttl_variance_threshold=ttl_cfg.get("variance_threshold", 5)
        )

        self.topology_discovery = NetworkTopologyDiscovery()
        self.protocol_anomaly = ProtocolAnomalyDetector()
        self.reputation_engine = ReputationEngine()
        self.recon_detector = ReconnaissanceDetector()
        self.port_scan_detector = PortScanDetector(config=self.config)

        # Suppress repeated alert spamming per IP within cooldown (seconds)
        self._alert_cooldowns: Dict[Tuple[str, str], float] = {}

    def load_config(self, config_path: Optional[str] = None) -> None:
        """Loads behavioural detection thresholds from JSON."""
        path = config_path or os.path.join(os.path.dirname(__file__), "..", "rules", "ids_rules.json")
        default_config = {
            "port_scan": {"enabled": True, "time_window_seconds": 300.0, "unique_ports_threshold": 10, "severity": "HIGH", "action": "BLOCK"},
            "syn_scan": {"enabled": True, "time_window_seconds": 300.0, "unique_syn_ports_threshold": 10, "severity": "HIGH", "action": "BLOCK"},
            "udp_scan": {"enabled": True, "time_window_seconds": 300.0, "unique_udp_ports_threshold": 10, "severity": "HIGH", "action": "BLOCK"},
            "syn_flood": {"enabled": True, "time_window_seconds": 2.0, "syn_rate_threshold": 25, "severity": "CRITICAL", "action": "BLOCK"},
            "dns_anomaly": {"enabled": True, "max_query_rate_per_sec": 40, "nxdomain_threshold": 10, "severity": "MEDIUM", "action": "ALERT"},
            "dns_tunneling": {"enabled": True, "severity": "HIGH", "action": "ALERT"},
            "arp_spoofing": {"enabled": True, "gratuitous_flood_threshold": 10, "severity": "CRITICAL", "action": "BLOCK"},
            "dhcp_security": {"enabled": True, "starvation_threshold": 15, "severity": "HIGH", "action": "ALERT"},
            "icmp_anomaly": {"enabled": True, "ping_flood_threshold": 30, "unreachable_burst_threshold": 15, "oversized_payload_limit": 1024, "severity": "HIGH", "action": "ALERT"},
            "ip_spoofing": {"enabled": True, "severity": "CRITICAL", "action": "BLOCK"},
            "ttl_analysis": {"enabled": True, "variance_threshold": 5, "severity": "MEDIUM", "action": "ALERT"},
            "protocol_evasion": {"enabled": True, "severity": "HIGH", "action": "BLOCK"},
            "connection_failures": {"enabled": True, "time_window_seconds": 10.0, "rst_threshold": 10, "severity": "LOW", "action": "ALERT"},
            "malformed_packet": {"enabled": True, "severity": "MEDIUM", "action": "ALERT"},
        }
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self.config = json.load(f)
                logger.info(f"Loaded behavioural IDS config from '{path}'")
                if hasattr(self, "port_scan_detector"):
                    self.port_scan_detector.update_config(self.config)
                return
            except Exception as e:
                logger.error(f"Failed loading IDS rules from {path}: {e}")

        self.config = default_config
        if hasattr(self, "port_scan_detector"):
            self.port_scan_detector.update_config(self.config)

    def _is_cooldown_active(self, src_ip: str, category: str, now: float, cooldown: float = 3.0) -> bool:
        """Prevents flooding terminal with identical alert per packet burst."""
        key = (src_ip, category)
        last_alert = self._alert_cooldowns.get(key, 0.0)
        if now - last_alert < cooldown:
            return True
        self._alert_cooldowns[key] = now
        return False

    def evaluate(
        self,
        packet: ParsedPacket,
        dpi_result: Optional[DPIResult],
        next_alert_id_fn: Callable[[], int],
    ) -> List[IDSAlert]:
        """
        Analyzes the packet for behavioural anomalies and returns generated alerts.
        """
        alerts: List[IDSAlert] = []
        now = packet.timestamp or time.time()

        src_ip = ""
        dst_ip = ""
        if packet.ipv4:
            src_ip = packet.ipv4.src_ip
            dst_ip = packet.ipv4.dst_ip
        elif packet.ipv6:
            src_ip = packet.ipv6.src_ip
            dst_ip = packet.ipv6.dst_ip
        elif packet.ethernet:
            src_ip = packet.ethernet.src_mac
            dst_ip = packet.ethernet.dst_mac
        else:
            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"

        src_port = packet.tcp.src_port if packet.tcp else (packet.udp.src_port if packet.udp else 0)
        dst_port = packet.tcp.dst_port if packet.tcp else (packet.udp.dst_port if packet.udp else 0)
        proto = packet.transport_type if packet.transport_type != "None" else packet.network_type

        # --- 1. Malformed Packet Detection ---
        m_cfg = self.config.get("malformed_packet", {})
        if m_cfg.get("enabled", True) and (packet.is_malformed or packet.parse_errors):
            if not self._is_cooldown_active(src_ip, "malformed", now):
                err_msg = "; ".join(packet.parse_errors) if packet.parse_errors else "Malformed packet structure"
                alerts.append(
                    IDSAlert.create(
                        alert_id=next_alert_id_fn(),
                        timestamp=now,
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        source_port=src_port,
                        destination_port=dst_port,
                        protocol=proto,
                        category=DetectionCategory.MALFORMED_PACKET,
                        severity=Severity.MEDIUM,
                        matched_rule="Malformed Packet Header Structure",
                        evidence=err_msg,
                        recommended_action=DecisionAction.ALERT,
                        packet_id=packet.packet_id,
                    )
                )

        # --- 2. Port Scanning Detection (TCP SYN, Connect, UDP, Stealth, Multi-Port Probes) ---
        ps_alerts = self.port_scan_detector.evaluate(packet, next_alert_id_fn)
        alerts.extend(ps_alerts)

        # --- 3. SYN Flood Detection ---
        sf_cfg = self.config.get("syn_flood", {})
        if sf_cfg.get("enabled", True) and packet.tcp and packet.tcp.flags.syn and not packet.tcp.flags.ack:
            window = sf_cfg.get("time_window_seconds", 2.0)
            threshold = sf_cfg.get("syn_rate_threshold", 25)

            syn_q = self._syn_flood_tracker[src_ip]
            syn_q.append(now)
            while syn_q and now - syn_q[0] > window:
                syn_q.popleft()

            if len(syn_q) >= threshold:
                if not self._is_cooldown_active(src_ip, "syn_flood", now):
                    alerts.append(
                        IDSAlert.create(
                            alert_id=next_alert_id_fn(),
                            timestamp=now,
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            source_port=src_port,
                            destination_port=dst_port,
                            protocol="TCP",
                            category=DetectionCategory.SYN_FLOOD,
                            severity=Severity[sf_cfg.get("severity", "CRITICAL")],
                            matched_rule=f"TCP SYN Flood Rate ({threshold} SYNs in {window}s)",
                            evidence=f"Received {len(syn_q)} TCP SYN packets in {window:.1f}s from {src_ip}",
                            recommended_action=DecisionAction[sf_cfg.get("action", "BLOCK")],
                            packet_id=packet.packet_id,
                        )
                    )

        # --- 4. DNS Anomalies & Query Floods ---
        dns_cfg = self.config.get("dns_anomaly", {})
        if dns_cfg.get("enabled", True) and dpi_result and dpi_result.protocol == "DNS":
            dns_meta = dpi_result.metadata.get("dns")
            if dns_meta:
                # DGA / high-entropy or excessive domain heuristics
                if dns_meta.is_suspicious_domain:
                    reasons = "; ".join(dns_meta.suspicious_reasons)
                    if not self._is_cooldown_active(src_ip, "dns_dga", now):
                        alerts.append(
                            IDSAlert.create(
                                alert_id=next_alert_id_fn(),
                                timestamp=now,
                                source_ip=src_ip,
                                destination_ip=dst_ip,
                                source_port=src_port,
                                destination_port=dst_port,
                                protocol="DNS",
                                category=DetectionCategory.SUSPICIOUS_DNS,
                                severity=Severity.MEDIUM,
                                matched_rule="Suspicious DNS Domain Pattern / DGA",
                                evidence=reasons,
                                recommended_action=DecisionAction.ALERT,
                                packet_id=packet.packet_id,
                            )
                        )

                # Query flood check
                if not dns_meta.is_response:
                    dq = self._dns_query_tracker[src_ip]
                    dq.append(now)
                    while dq and now - dq[0] > 1.0:
                        dq.popleft()
                    max_rate = dns_cfg.get("max_query_rate_per_sec", 40)
                    if len(dq) >= max_rate and not self._is_cooldown_active(src_ip, "dns_flood", now):
                        alerts.append(
                            IDSAlert.create(
                                alert_id=next_alert_id_fn(),
                                timestamp=now,
                                source_ip=src_ip,
                                destination_ip=dst_ip,
                                source_port=src_port,
                                destination_port=dst_port,
                                protocol="DNS",
                                category=DetectionCategory.SUSPICIOUS_DNS,
                                severity=Severity.MEDIUM,
                                matched_rule=f"DNS Query Flood ({max_rate} queries/sec)",
                                evidence=f"Query rate reached {len(dq)} queries/sec",
                                recommended_action=DecisionAction.ALERT,
                                packet_id=packet.packet_id,
                            )
                        )

                # Repeated NXDOMAIN check
                if dns_meta.is_response and dns_meta.rcode_name == "NXDOMAIN":
                    nx_q = self._nxdomain_tracker[dst_ip]
                    nx_q.append(now)
                    while nx_q and now - nx_q[0] > 5.0:
                        nx_q.popleft()
                    nx_thresh = dns_cfg.get("nxdomain_threshold", 10)
                    if len(nx_q) >= nx_thresh and not self._is_cooldown_active(dst_ip, "nxdomain_flood", now):
                        alerts.append(
                            IDSAlert.create(
                                alert_id=next_alert_id_fn(),
                                timestamp=now,
                                source_ip=src_ip,
                                destination_ip=dst_ip,
                                source_port=src_port,
                                destination_port=dst_port,
                                protocol="DNS",
                                category=DetectionCategory.SUSPICIOUS_DNS,
                                severity=Severity.LOW,
                                matched_rule=f"Excessive NXDOMAIN Responses ({nx_thresh} in 5s)",
                                evidence=f"Host received {len(nx_q)} NXDOMAIN errors in 5s",
                                recommended_action=DecisionAction.ALERT,
                                packet_id=packet.packet_id,
                            )
                        )

                # DNS Tunneling detection
                dt_cfg = self.config.get("dns_tunneling", {})
                if dt_cfg.get("enabled", True) and getattr(dns_meta, "is_dns_tunneling", False):
                    reasons = "; ".join(dns_meta.tunneling_indicators) if dns_meta.tunneling_indicators else "DNS Tunneling characteristics detected"
                    if not self._is_cooldown_active(src_ip, "dns_tunneling", now):
                        alerts.append(
                            IDSAlert.create(
                                alert_id=next_alert_id_fn(),
                                timestamp=now,
                                source_ip=src_ip,
                                destination_ip=dst_ip,
                                source_port=src_port,
                                destination_port=dst_port,
                                protocol="DNS",
                                category=DetectionCategory.DNS_TUNNELING,
                                severity=Severity[dt_cfg.get("severity", "HIGH")],
                                matched_rule="DNS Tunneling Pattern Detected",
                                evidence=reasons,
                                recommended_action=DecisionAction[dt_cfg.get("action", "ALERT")],
                                packet_id=packet.packet_id,
                            )
                        )

                # DNS Domain Reputation Check
                if dns_meta.query_name:
                    rep_dom = self.reputation_engine.check_domain(dns_meta.query_name)
                    if rep_dom and not self._is_cooldown_active(dns_meta.query_name, f"REP_DOM_{rep_dom.category}", now):
                        alerts.append(
                            IDSAlert.create(
                                alert_id=next_alert_id_fn(),
                                timestamp=now,
                                source_ip=src_ip,
                                destination_ip=dst_ip,
                                source_port=src_port,
                                destination_port=dst_port,
                                protocol="DNS",
                                category=DetectionCategory.THREAT_REPUTATION,
                                severity=rep_dom.threat_level,
                                matched_rule=f"Domain Threat Intelligence: {rep_dom.category}",
                                evidence=f"Queried domain '{dns_meta.query_name}' flagged in threat reputation: {rep_dom.description}",
                                recommended_action=DecisionAction.BLOCK if rep_dom.threat_level in (Severity.CRITICAL, Severity.HIGH) else DecisionAction.ALERT,
                                packet_id=packet.packet_id,
                            )
                        )

        # --- 5. Connection Failures (RST Burst) ---
        cf_cfg = self.config.get("connection_failures", {})
        if cf_cfg.get("enabled", True) and packet.tcp and packet.tcp.flags.rst:
            window = cf_cfg.get("time_window_seconds", 10.0)
            threshold = cf_cfg.get("rst_threshold", 10)

            rst_q = self._conn_failure_tracker[src_ip]
            rst_q.append(now)
            while rst_q and now - rst_q[0] > window:
                rst_q.popleft()

            if len(rst_q) >= threshold and not self._is_cooldown_active(src_ip, "rst_burst", now):
                alerts.append(
                    IDSAlert.create(
                        alert_id=next_alert_id_fn(),
                        timestamp=now,
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        source_port=src_port,
                        destination_port=dst_port,
                        protocol="TCP",
                        category=DetectionCategory.CONNECTION_FAILURE,
                        severity=Severity[cf_cfg.get("severity", "LOW")],
                        matched_rule=f"TCP Connection Failure / Reset Burst ({threshold} RSTs in {window}s)",
                        evidence=f"Observed {len(rst_q)} TCP RST flags from {src_ip} in {window:.1f}s",
                        recommended_action=DecisionAction[cf_cfg.get("action", "ALERT")],
                        packet_id=packet.packet_id,
                    )
                )

        # --- 6. ARP Monitoring & Spoofing Detection ---
        arp_cfg = self.config.get("arp_spoofing", {})
        if arp_cfg.get("enabled", True):
            is_arp = packet.network_type == "ARP" or (packet.ethernet and packet.ethernet.ethertype_code == 0x0806)
            if is_arp and packet.payload:
                arp_pkt = self.arp_inspector.parse(packet.payload)
                if arp_pkt:
                    arp_alerts = self.arp_inspector.inspect(arp_pkt, timestamp=now)
                    for a in arp_alerts:
                        if not self._is_cooldown_active(a.ip_address, a.alert_type, now):
                            alerts.append(
                                IDSAlert.create(
                                    alert_id=next_alert_id_fn(),
                                    timestamp=now,
                                    source_ip=a.ip_address,
                                    destination_ip=dst_ip,
                                    source_port=0,
                                    destination_port=0,
                                    protocol="ARP",
                                    category=DetectionCategory.ARP_SPOOFING,
                                    severity=Severity[a.severity] if a.severity in Severity.__members__ else Severity.HIGH,
                                    matched_rule=f"ARP Security: {a.alert_type}",
                                    evidence=a.evidence,
                                    recommended_action=DecisionAction.BLOCK if a.severity == "CRITICAL" else DecisionAction.ALERT,
                                    packet_id=packet.packet_id,
                                )
                            )

        # --- 7. DHCP Monitoring & Starvation Detection ---
        dhcp_cfg = self.config.get("dhcp_security", {})
        if dhcp_cfg.get("enabled", True) and packet.udp and (packet.udp.src_port in (67, 68) or packet.udp.dst_port in (67, 68)) and packet.payload:
            dhcp_msg = self.dhcp_inspector.parse(packet.payload)
            if dhcp_msg:
                dhcp_alerts = self.dhcp_inspector.inspect(dhcp_msg, src_ip=src_ip, timestamp=now)
                for da in dhcp_alerts:
                    if not self._is_cooldown_active(da.server_ip or src_ip, da.alert_type, now):
                        alerts.append(
                            IDSAlert.create(
                                alert_id=next_alert_id_fn(),
                                timestamp=now,
                                source_ip=da.server_ip or src_ip,
                                destination_ip=dst_ip,
                                source_port=src_port,
                                destination_port=dst_port,
                                protocol="DHCP",
                                category=DetectionCategory.DHCP_ANOMALY,
                                severity=Severity[da.severity] if da.severity in Severity.__members__ else Severity.HIGH,
                                matched_rule=f"DHCP Security: {da.alert_type}",
                                evidence=da.evidence,
                                recommended_action=DecisionAction.BLOCK if da.severity == "CRITICAL" else DecisionAction.ALERT,
                                packet_id=packet.packet_id,
                            )
                        )

        # --- 8. ICMP Anomaly Detection ---
        icmp_cfg = self.config.get("icmp_anomaly", {})
        if icmp_cfg.get("enabled", True) and packet.icmp:
            icmp_alerts = self.icmp_detector.evaluate(packet)
            for ia in icmp_alerts:
                if not self._is_cooldown_active(ia.source_ip, ia.alert_type, now):
                    alerts.append(
                        IDSAlert.create(
                            alert_id=next_alert_id_fn(),
                            timestamp=now,
                            source_ip=ia.source_ip,
                            destination_ip=ia.destination_ip,
                            source_port=0,
                            destination_port=0,
                            protocol="ICMP",
                            category=DetectionCategory.ICMP_ANOMALY,
                            severity=Severity[ia.severity] if ia.severity in Severity.__members__ else Severity.HIGH,
                            matched_rule=f"ICMP Anomaly: {ia.alert_type}",
                            evidence=ia.evidence,
                            recommended_action=DecisionAction.BLOCK if ia.severity == "CRITICAL" else DecisionAction.ALERT,
                            packet_id=packet.packet_id,
                        )
                    )

        # --- 9. IP Intelligence & Spoofing / TTL Hop-Count Analysis ---
        ip_cfg = self.config.get("ip_spoofing", {})
        ttl_cfg = self.config.get("ttl_analysis", {})
        if ip_cfg.get("enabled", True) or ttl_cfg.get("enabled", True):
            ip_alerts = self.ip_intelligence.evaluate_packet(packet)
            for ipa in ip_alerts:
                if not self._is_cooldown_active(ipa.source_ip, ipa.alert_type, now):
                    cat = DetectionCategory.IP_SPOOFING if ("LAND" in ipa.alert_type or "BOGON" in ipa.alert_type) else DetectionCategory.TTL_ANOMALY
                    alerts.append(
                        IDSAlert.create(
                            alert_id=next_alert_id_fn(),
                            timestamp=now,
                            source_ip=ipa.source_ip,
                            destination_ip=ipa.destination_ip,
                            source_port=src_port,
                            destination_port=dst_port,
                            protocol=proto,
                            category=cat,
                            severity=Severity[ipa.severity] if ipa.severity in Severity.__members__ else Severity.HIGH,
                            matched_rule=f"IP Intelligence: {ipa.alert_type}",
                            evidence=ipa.evidence,
                            recommended_action=DecisionAction.BLOCK if ipa.severity == "CRITICAL" else DecisionAction.ALERT,
                            packet_id=packet.packet_id,
                        )
                    )

        # --- 10. Network Topology Discovery Recording ---
        self.topology_discovery.record_packet(packet)

        # --- 11. Protocol Anomaly & Evasion Detection ---
        pe_cfg = self.config.get("protocol_evasion", {})
        if pe_cfg.get("enabled", True):
            proto_alerts = self.protocol_anomaly.evaluate(packet, dpi_result)
            for pa in proto_alerts:
                if not self._is_cooldown_active(pa.source_ip, pa.anomaly_type, now):
                    if "SCAN" in pa.anomaly_type:
                        cat = DetectionCategory.STEALTH_SCAN
                    elif "EVASION" in pa.anomaly_type or "SMUGGLING" in pa.anomaly_type or "FRAGMENT" in pa.anomaly_type:
                        cat = DetectionCategory.EVASION_TECHNIQUE
                    else:
                        cat = DetectionCategory.PROTOCOL_ANOMALY

                    alerts.append(
                        IDSAlert.create(
                            alert_id=next_alert_id_fn(),
                            timestamp=now,
                            source_ip=pa.source_ip,
                            destination_ip=pa.destination_ip,
                            source_port=src_port,
                            destination_port=dst_port,
                            protocol=pa.protocol,
                            category=cat,
                            severity=Severity[pa.severity] if pa.severity in Severity.__members__ else Severity.HIGH,
                            matched_rule=f"Protocol Evasion: {pa.anomaly_type}",
                            evidence=pa.evidence,
                            recommended_action=DecisionAction.BLOCK if pa.severity in ("CRITICAL", "HIGH") else DecisionAction.ALERT,
                            packet_id=packet.packet_id,
                        )
                    )

        # --- 12. Threat Intelligence / IP Reputation ---
        rep_src = self.reputation_engine.check_ip(src_ip)
        if rep_src and not self._is_cooldown_active(src_ip, f"REP_IP_{rep_src.category}", now):
            alerts.append(
                IDSAlert.create(
                    alert_id=next_alert_id_fn(),
                    timestamp=now,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=src_port,
                    destination_port=dst_port,
                    protocol=proto,
                    category=DetectionCategory.THREAT_REPUTATION,
                    severity=rep_src.threat_level,
                    matched_rule=f"Threat Intelligence: {rep_src.category}",
                    evidence=f"Source IP {src_ip} flagged in reputation database: {rep_src.description}",
                    recommended_action=DecisionAction.BLOCK if rep_src.threat_level == Severity.CRITICAL else DecisionAction.ALERT,
                    packet_id=packet.packet_id,
                )
            )

        rep_dst = self.reputation_engine.check_ip(dst_ip)
        if rep_dst and not self._is_cooldown_active(dst_ip, f"REP_DST_IP_{rep_dst.category}", now):
            alerts.append(
                IDSAlert.create(
                    alert_id=next_alert_id_fn(),
                    timestamp=now,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=src_port,
                    destination_port=dst_port,
                    protocol=proto,
                    category=DetectionCategory.THREAT_REPUTATION,
                    severity=rep_dst.threat_level,
                    matched_rule=f"Threat Intelligence: {rep_dst.category}",
                    evidence=f"Destination IP {dst_ip} flagged in reputation database: {rep_dst.description}",
                    recommended_action=DecisionAction.BLOCK if rep_dst.threat_level == Severity.CRITICAL else DecisionAction.ALERT,
                    packet_id=packet.packet_id,
                )
            )

        # --- 13. Network Reconnaissance & Sweeps ---
        recon_alerts = self.recon_detector.evaluate(packet)
        for ra in recon_alerts:
            alerts.append(
                IDSAlert.create(
                    alert_id=next_alert_id_fn(),
                    timestamp=now,
                    source_ip=ra.source_ip,
                    destination_ip=ra.destination_ip,
                    source_port=src_port,
                    destination_port=dst_port,
                    protocol=proto,
                    category=DetectionCategory.RECONNAISSANCE,
                    severity=ra.severity,
                    matched_rule=f"Reconnaissance: {ra.alert_type}",
                    evidence=ra.evidence,
                    recommended_action=DecisionAction.BLOCK if ra.severity in (Severity.CRITICAL, Severity.HIGH) else DecisionAction.ALERT,
                    packet_id=packet.packet_id,
                )
            )

        return alerts
