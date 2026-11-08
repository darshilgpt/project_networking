"""Main entry point for Real-Time DPI & Network Intrusion Detection/Prevention System (Phase 1 & Phase 2)."""

from __future__ import annotations

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)

import argparse
import logging
import signal
import sys
from typing import Optional

from capture.interface_manager import InterfaceManager
from capture.packet_capture import LivePacketCapture
from dpi.dpi_engine import DPIEngine
from flow.flow_manager import FlowManager
from ids.ids_engine import IDSEngine
from ips.blocking_manager import BlockingManager
from ips.decision_engine import DecisionEngine
from models.packet_models import InterfaceInfo, ParsedPacket
from parser.packet_dispatcher import PacketDispatcher
from reassembly.tcp_reassembler import TCPReassembler
from utils.formatter import PacketFormatter
from utils.logger import setup_logger

logger = setup_logger("dpi_ids_ips", level=logging.INFO)


def parse_arguments() -> argparse.Namespace:
    """Parses command-line arguments for Phase 1 & Phase 2."""
    parser = argparse.ArgumentParser(
        description="Real-Time Deep Packet Inspection & Network Intrusion Detection/Prevention System",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-i",
        "--interface",
        type=str,
        default=None,
        help="Interface number or name to capture on (default: interactive selection / Wi-Fi auto-detect)",
    )
    parser.add_argument(
        "-l",
        "--list-interfaces",
        action="store_true",
        help="List all available network interfaces and exit",
    )
    parser.add_argument(
        "-c",
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture before stopping (0 = continuous)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=None,
        help="Maximum capture duration in seconds (None = continuous)",
    )
    parser.add_argument(
        "-f",
        "--filter",
        type=str,
        default=None,
        help="Optional BPF capture filter (e.g. 'tcp', 'udp', 'ip and port 80')",
    )
    parser.add_argument(
        "-v",
        "--verbosity",
        choices=["normal", "detailed", "compact"],
        default="normal",
        help="Terminal display verbosity level",
    )
    parser.add_argument(
        "--ips-active",
        action="store_true",
        default=False,
        help="Enable Active Prevention Mode (default: Monitoring / Simulation)",
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default=None,
        help="Optional file path to write application logs",
    )
    return parser.parse_args()


def main() -> int:
    """Application main execution routine."""
    args = parse_arguments()

    if args.log_file:
        setup_logger("dpi_ids_ips", level=logging.INFO, log_file=args.log_file)

    try:
        interfaces = InterfaceManager.get_interfaces()
    except Exception as e:
        print(f"[!] Error discovering network interfaces: {e}", file=sys.stderr)
        print("[!] Ensure Npcap is installed and running with appropriate permissions.", file=sys.stderr)
        return 1

    if args.list_interfaces:
        InterfaceManager.display_interfaces(interfaces)
        return 0

    if not interfaces:
        print("[!] No usable network interfaces found. Please check Npcap driver installation.", file=sys.stderr)
        return 1

    # Select target interface
    try:
        selected_iface = InterfaceManager.select_interface(interfaces, choice_input=args.interface)
    except ValueError as ve:
        print(f"[!] Invalid interface selection: {ve}", file=sys.stderr)
        return 1

    print(f"\nSelected interface: {selected_iface.name} ({selected_iface.description})")

    # Initialize Phase 1 Dispatcher
    dispatcher = PacketDispatcher()

    # Initialize Phase 2 Pipeline Components
    flow_manager = FlowManager()
    tcp_reassembler = TCPReassembler()
    dpi_engine = DPIEngine()
    ids_engine = IDSEngine()
    decision_engine = DecisionEngine()
    blocking_manager = BlockingManager(active_prevention=args.ips_active)

    capture_instance: Optional[LivePacketCapture] = None

    def on_packet_received(packet: ParsedPacket) -> None:
        """Processes each captured packet through the complete Phase 2 DPI & IDS/IPS pipeline."""
        # 1. Flow Tracking
        flow = flow_manager.process_packet(packet)

        # 2. TCP Stream Reassembly (if TCP with payload)
        reassembled_data = None
        if packet.tcp and packet.payload:
            new_chunk, full_stream = tcp_reassembler.process_packet(packet)
            reassembled_data = full_stream if full_stream else packet.payload

        # 3. Deep Packet Inspection (DPI)
        dpi_result = dpi_engine.inspect(
            packet=packet,
            flow=flow,
            reassembled_payload=reassembled_data,
        )

        # Record protocol back into flow
        if flow and dpi_result.protocol not in ("None", "Unknown"):
            flow_manager.record_application_detection(flow, dpi_result.protocol)

        # 4. Intrusion Detection System (IDS)
        alerts = ids_engine.evaluate(packet=packet, dpi_result=dpi_result)

        # 5. Decision Engine & IPS Action
        raw_decision = decision_engine.decide(packet=packet, dpi_result=dpi_result, alerts=alerts, flow=flow)
        effective_action, status_msg = blocking_manager.handle_decision(raw_decision, packet=packet, alerts=alerts)

        # 6. Real-Time Terminal Output
        formatted = PacketFormatter.format_dpi_packet(
            packet=packet,
            flow=flow,
            dpi_result=dpi_result,
            alerts=alerts,
            action=effective_action,
            verbosity=args.verbosity,
        )
        print(formatted, flush=True)

    capture_instance = LivePacketCapture(
        interface=selected_iface,
        dispatcher=dispatcher,
        on_packet=on_packet_received,
        bpf_filter=args.filter,
    )

    def sigint_handler(signum: int, frame: object) -> None:
        if capture_instance is not None:
            capture_instance.stop()

    signal.signal(signal.SIGINT, sigint_handler)

    PacketFormatter.print_banner(selected_iface, active_prevention=args.ips_active)

    try:
        stats = capture_instance.start(packet_count=args.count, timeout=args.timeout)
        PacketFormatter.print_final_summary(
            capture_stats=stats,
            flow_summary=flow_manager.get_summary_metrics(),
            dpi_engine=dpi_engine,
            ids_engine=ids_engine,
            blocking_manager=blocking_manager,
        )
    except PermissionError:
        print("\n[!] Insufficient permissions to capture live packets.", file=sys.stderr)
        print("[!] On Windows, please run PowerShell or your IDE as Administrator.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCapture halted by user.")
        if capture_instance is not None:
            PacketFormatter.print_final_summary(
                capture_stats=capture_instance.stats,
                flow_summary=flow_manager.get_summary_metrics(),
                dpi_engine=dpi_engine,
                ids_engine=ids_engine,
                blocking_manager=blocking_manager,
            )
    except Exception as exc:
        print(f"\n[!] Unexpected error during capture: {exc}", file=sys.stderr)
        return 1
    finally:
        blocking_manager.shutdown()

    return 0


if __name__ == "__main__":
    sys.exit(main())
