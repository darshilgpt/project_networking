"""Terminal output formatter for real-time packet monitoring, DPI inspection, and IDS/IPS summary."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from models.alert_model import DecisionAction, DetectionCategory, DPIResult, IDSAlert, Severity
from models.flow_model import Flow
from models.packet_models import CaptureStats, InterfaceInfo, ParsedPacket


class PacketFormatter:
    """Formats dissected packets, DPI results, alerts, and session statistics."""

    @staticmethod
    def print_banner(iface: InterfaceInfo, active_prevention: bool = False) -> None:
        """Prints the monitor startup banner."""
        mode_str = "ACTIVE PREVENTION (Windows Firewall)" if active_prevention else "MONITORING / SIMULATION (Npcap)"
        print()
        print("=" * 60)
        print("REAL-TIME DEEP PACKET INSPECTION & IDS/IPS MONITOR")
        print("=" * 60)
        print(f"Interface : {iface.name}")
        print(f"Mode      : {mode_str}")
        print("Status    : CAPTURING & INSPECTING")
        print("=" * 60)
        print()

    @staticmethod
    def format_dpi_packet(
        packet: ParsedPacket,
        flow: Optional[Flow],
        dpi_result: Optional[DPIResult],
        alerts: List[IDSAlert],
        action: DecisionAction,
        verbosity: str = "normal",
    ) -> str:
        """
        Formats a packet and its DPI/IDS evaluation according to the Phase 2 specification.
        """
        src = ""
        dst = ""
        if packet.ipv4:
            src = packet.ipv4.src_ip
            dst = packet.ipv4.dst_ip
        elif packet.ipv6:
            src = packet.ipv6.src_ip
            dst = packet.ipv6.dst_ip
        elif packet.ethernet:
            src = packet.ethernet.src_mac
            dst = packet.ethernet.dst_mac

        proto = packet.transport_type if packet.transport_type != "None" else packet.network_type
        if packet.tcp:
            src = f"{src}:{packet.tcp.src_port}"
            dst = f"{dst}:{packet.tcp.dst_port}"
        elif packet.udp:
            src = f"{src}:{packet.udp.src_port}"
            dst = f"{dst}:{packet.udp.dst_port}"

        app_name = dpi_result.protocol if dpi_result else "Unknown"

        if verbosity == "compact":
            alert_tag = f" [ALERT: {len(alerts)}]" if alerts else ""
            action_tag = f" [{action.value}]"
            return f"#{packet.packet_id} [{packet.datetime_str}] {proto}/{app_name} {src} -> {dst}{alert_tag}{action_tag}"

        lines = []
        lines.append(f"[PACKET] {proto} {src} -> {dst}")
        if flow:
            lines.append(f"[FLOW] Flow ID: {flow.flow_id} (Packets: {flow.stats.total_packets})")

        if app_name not in ("None", "Unknown"):
            lines.append(f"[APP] {app_name} Detected")

        # DPI Layer Details
        if dpi_result and dpi_result.metadata:
            meta = dpi_result.metadata

            if "http" in meta:
                http_m = meta["http"]
                if http_m.is_request:
                    lines.append(f"[DPI] HTTP {http_m.method} {http_m.uri}")
                    if http_m.host:
                        lines.append(f"[DPI] Host: {http_m.host}")
                    if verbosity == "detailed" and http_m.user_agent:
                        lines.append(f"[DPI] User-Agent: {http_m.user_agent}")
                else:
                    lines.append(f"[DPI] HTTP Response: {http_m.status_code} {http_m.reason_phrase or ''}")

            elif "dns" in meta:
                dns_m = meta["dns"]
                if dns_m.questions:
                    q_str = ", ".join(f"{q.name} ({q.qtype_name})" for q in dns_m.questions)
                    lines.append(f"[DPI] Query: {q_str}")
                if dns_m.is_response and dns_m.answers:
                    a_str = ", ".join(f"{a.name} -> {a.rdata}" for a in dns_m.answers[:2])
                    lines.append(f"[DPI] Answer: {a_str}")

            elif "tls" in meta:
                tls_m = meta["tls"]
                if tls_m.is_handshake and tls_m.handshake_type == "ClientHello":
                    lines.append("[DPI] TLS ClientHello Identified")
                    if tls_m.sni:
                        lines.append(f"[DPI] SNI: {tls_m.sni}")
                    if verbosity == "detailed" and tls_m.client_version_name:
                        lines.append(f"[DPI] Version: {tls_m.client_version_name}")
                elif tls_m.is_encrypted_application_data:
                    lines.append("[DPI] Encrypted Application Data (TLS Payload)")

            elif "quic" in meta:
                lines.append("[DPI] QUIC / HTTP/3 Traffic")

            elif "ssdp" in meta:
                lines.append("[DPI] SSDP UPnP Local Discovery")

        # IDS Findings
        if alerts:
            for alert in alerts:
                if alert.category == DetectionCategory.PORT_SCAN:
                    lines.append(f"[IDS ALERT] {alert.matched_rule}")
                    lines.append(f"Source: {alert.source_ip}")
                    lines.append(f"Target: {alert.destination_ip}")
                    lines.append(f"Severity: {alert.severity.value}")
                    lines.append(f"Timestamp: {alert.datetime_str}")
                    lines.append(f"[EVIDENCE] {alert.evidence}")
                else:
                    lines.append(f"[IDS] {alert.matched_rule}")
                    lines.append(f"[SEVERITY] {alert.severity.value}")
                    if verbosity == "detailed":
                        lines.append(f"[EVIDENCE] {alert.evidence}")
        else:
            lines.append("[IDS] No Threat Detected")

        # Final Decision Action
        lines.append(f"[ACTION] {action.value}")
        lines.append("---")
        lines.append("")

        return "\n".join(lines)

    @staticmethod
    def print_final_summary(
        capture_stats: CaptureStats,
        flow_summary: Dict[str, Any],
        dpi_engine: Any,
        ids_engine: Any,
        blocking_manager: Any,
    ) -> None:
        """Prints the comprehensive final statistics required by Phase 2."""
        duration = max(0.001, (capture_stats.last_packet_time or time.time()) - capture_stats.start_time)
        rate = capture_stats.total_captured / duration

        print()
        print("=" * 60)
        print("FINAL DPI & IDS/IPS SESSION SUMMARY")
        print("=" * 60)

        # 1. Packet Statistics
        print("PACKET STATISTICS:")
        print(f"  Total Packets Captured        : {capture_stats.total_captured}")
        print(f"  Successfully Parsed           : {capture_stats.total_parsed}")
        print(f"  Packets Passed to DPI         : {dpi_engine.total_inspections}")
        print(f"  Packets Successfully Inspected: {dpi_engine.total_inspections}")
        print(f"  Packets Skipped               : 0")
        print(f"  Inspection / Malformed Errors : {capture_stats.total_errors}")
        print(f"  Capture Duration              : {duration:.2f}s ({rate:.1f} pkts/s)")
        print(f"  Total Data Transferred        : {capture_stats.bytes_captured / 1024:.2f} KB")
        print("-" * 60)

        # 2. Protocol Statistics
        app_breakdown = flow_summary.get("app_breakdown", {})
        print("PROTOCOL STATISTICS:")
        print(f"  Active Flows Tracked          : {flow_summary.get('active_flows', 0)}")
        print(f"  Total Flows Seen              : {flow_summary.get('total_flows_seen', 0)}")
        print(f"  Expired Flows Cleaned         : {flow_summary.get('total_flows_expired', 0)}")
        print(f"  HTTP Flows                    : {app_breakdown.get('HTTP', 0)}")
        print(f"  DNS Flows                     : {app_breakdown.get('DNS', 0)}")
        print(f"  TLS Flows                     : {app_breakdown.get('TLS', 0)}")
        print(f"  QUIC / HTTP3 Flows            : {app_breakdown.get('QUIC/HTTP3', 0)}")
        print(f"  Unknown / Other Flows         : {app_breakdown.get('Unknown', 0)}")
        print(f"  TCP Segments Captured         : {capture_stats.tcp_count}")
        print(f"  UDP Datagrams Captured        : {capture_stats.udp_count}")
        print("-" * 60)

        # 3. DPI Statistics
        print("DPI STATISTICS:")
        print(f"  Total Payload Bytes Inspected : {dpi_engine.total_payload_bytes} bytes ({dpi_engine.total_payload_bytes / 1024:.2f} KB)")
        print(f"  Total Inspections Run         : {dpi_engine.total_inspections}")
        print(f"  Signature Matches Found       : {dpi_engine.signature_matches_count}")
        print("-" * 60)

        # 4. IDS Statistics
        print("IDS STATISTICS:")
        print(f"  Total Security Alerts Raised  : {ids_engine.total_alerts}")
        print(f"  Critical Severity Alerts      : {ids_engine.severity_counts.get(Severity.CRITICAL.value, 0)}")
        print(f"  High Severity Alerts          : {ids_engine.severity_counts.get(Severity.HIGH.value, 0)}")
        print(f"  Medium Severity Alerts        : {ids_engine.severity_counts.get(Severity.MEDIUM.value, 0)}")
        print(f"  Low Severity Alerts           : {ids_engine.severity_counts.get(Severity.LOW.value, 0)}")
        if ids_engine.category_counts:
            print("  Detection Categories:")
            for cat, cnt in ids_engine.category_counts.items():
                print(f"    - {cat:<24}: {cnt}")
        print("-" * 60)

        # 5. IPS Statistics
        print("IPS STATISTICS:")
        allow_decs = getattr(blocking_manager, "allow_decisions", 0)
        alert_decs = getattr(blocking_manager, "alert_decisions", 0)
        sim_blocks = getattr(blocking_manager, "simulated_blocks", 0)
        actual_drops = getattr(blocking_manager, "actual_verified_drops", getattr(blocking_manager, "actual_dropped_packets", 0))
        sec_blocks = getattr(blocking_manager, "security_block_decisions", sim_blocks + actual_drops)
        intercepted = getattr(blocking_manager, "intercepted_packets", allow_decs + alert_decs + sec_blocks)
        forwarded = getattr(blocking_manager, "forwarded_or_reinjected_packets", allow_decs + alert_decs + sim_blocks)
        is_active = getattr(blocking_manager, "active_prevention", False)

        mode_str = "ACTIVE PREVENTION" if is_active else "MONITORING / SIMULATION"
        print(f"  Operating Mode                : {mode_str}")
        print(f"  Total Intercepted Packets     : {intercepted}")
        print(f"  Allow Decisions               : {allow_decs}")
        print(f"  Alert Decisions               : {alert_decs}")
        print(f"  Security Block Decisions      : {sec_blocks}")
        print(f"  Simulated Block Decisions     : {sim_blocks}")
        print(f"  Actual Verified Packet Drops  : {actual_drops}")
        print(f"  Forwarded / Permitted Packets : {forwarded}")
        print("-" * 60)

        # 6. Detailed Suspicious Packets & Alerts Log
        print("SUSPICIOUS PACKETS & SECURITY ALERTS LOG:")
        alerts: List[IDSAlert] = getattr(ids_engine, "alerts_history", [])
        if alerts:
            for idx, a in enumerate(alerts, 1):
                proto = a.protocol or "IP"
                src = f"{a.source_ip}:{a.source_port}" if a.source_port else a.source_ip
                dst = f"{a.destination_ip}:{a.destination_port}" if a.destination_port else a.destination_ip
                action_str = f"[{a.recommended_action.value}]"
                pkt_ref = f"Packet #{a.packet_id}" if a.packet_id is not None else "N/A"

                print(f"  [{idx}] Alert #{a.alert_id} | {pkt_ref} | Time: {a.datetime_str}")
                print(f"      Severity   : {a.severity.value:<8} | Category: {a.category.value}")
                print(f"      Connection : {proto} {src} -> {dst}")
                print(f"      Rule       : {a.matched_rule}")
                print(f"      Evidence   : {a.evidence}")
                print(f"      Action     : {action_str}")
                if idx < len(alerts):
                    print()
        else:
            print("  No suspicious packets or security threats detected during this capture session.")
        print("=" * 60)
        print()
