"""Central Application Entry Point for Windows Network Security Server."""

from __future__ import annotations

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)

import argparse
import logging
import sys

from capture.interface_manager import InterfaceManager
from server.server import NetworkSecurityServer, ServerConfig
from server.windows_gateway import WindowsGatewayManager
from server.wireguard_manager import WireGuardManager


def parse_arguments() -> argparse.Namespace:
    """Parses command-line arguments for the Central Network Security Server."""
    parser = argparse.ArgumentParser(
        description="Centralised Windows Network Security Server with Multi-Client DPI & IDS/IPS",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Ingestion arguments
    ingest_group = parser.add_argument_group("Ingestion Options")
    ingest_group.add_argument(
        "-i",
        "--interface",
        type=str,
        default=None,
        help="Interface number or name to capture on (default: interactive selection / Wi-Fi detect)",
    )
    ingest_group.add_argument(
        "-t",
        "--tunnel",
        action="store_true",
        default=False,
        help="Capture on WireGuard or Wintun virtual tunnel adapter",
    )
    ingest_group.add_argument(
        "-p",
        "--pcap",
        type=str,
        default=None,
        help="Path to a PCAP or PCAPNG trace file to replay for offline testing",
    )
    ingest_group.add_argument(
        "--pcap-rate",
        choices=["fastest", "realtime"],
        default="fastest",
        help="PCAP replay speed ('fastest' for burst throughput, 'realtime' for timestamp pacing)",
    )
    ingest_group.add_argument(
        "-f",
        "--filter",
        type=str,
        default=None,
        help="Optional BPF capture filter (e.g. 'tcp', 'udp', 'port 53')",
    )
    ingest_group.add_argument(
        "-l",
        "--list-interfaces",
        action="store_true",
        help="List all network adapters (highlighting Wi-Fi and WireGuard tunnels) and exit",
    )

    # Multi-client & VPN configuration
    vpn_group = parser.add_argument_group("VPN & Client Identification")
    vpn_group.add_argument(
        "--vpn-subnet",
        type=str,
        default="10.8.0.0/24,10.10.0.0/24",
        help="Comma-separated CIDR subnets identifying VPN clients (e.g. '10.8.0.0/24,10.200.0.0/24')",
    )

    # WireGuard VPN Endpoint Management
    wg_group = parser.add_argument_group("WireGuard VPN Endpoint Management")
    wg_group.add_argument(
        "--wg-setup",
        action="store_true",
        default=False,
        help="Generate cryptographically signed WireGuard server and multi-client configuration files",
    )
    wg_group.add_argument(
        "--peers",
        type=str,
        default="Laptop-1,Laptop-2,Laptop-3",
        help="Comma-separated client peer names to provision (used with --wg-setup)",
    )
    wg_group.add_argument(
        "--wg-endpoint",
        type=str,
        default=None,
        help="External endpoint IP:port of the WireGuard server for client configs (e.g. 10.178.3.152:51820)",
    )
    wg_group.add_argument(
        "--wg-diagnose",
        action="store_true",
        default=False,
        help="Run Windows IP routing, NAT, and gateway diagnostics and exit",
    )
    wg_group.add_argument(
        "--wg-peers-file",
        type=str,
        default="wireguard_config/wireguard_peers.json",
        help="Path to wireguard_peers.json to pre-load client names and VPN IP mappings",
    )

    # Pipeline & Performance
    perf_group = parser.add_argument_group("Worker Pool & Queue Bounds")
    perf_group.add_argument(
        "-w",
        "--workers",
        type=int,
        default=4,
        help="Number of concurrent pipeline worker threads",
    )
    perf_group.add_argument(
        "-q",
        "--queue-size",
        type=int,
        default=10000,
        help="Maximum capacity of bounded packet queue",
    )

    # Security & Enforcement
    sec_group = parser.add_argument_group("Security Enforcement")
    sec_group.add_argument(
        "--ips-active",
        action="store_true",
        default=False,
        help="Enable Active Prevention Mode (default: Monitoring / Safe Simulation)",
    )

    # Dashboard & Logging
    ui_group = parser.add_argument_group("Dashboard & Diagnostics")
    ui_group.add_argument(
        "--no-dashboard",
        action="store_true",
        default=False,
        help="Disable interactive terminal dashboard (headless / service mode)",
    )
    ui_group.add_argument(
        "--refresh-rate",
        type=float,
        default=2.0,
        help="Dashboard UI refresh rate in Hertz",
    )
    ui_group.add_argument(
        "--log-file",
        type=str,
        default="security_server.log",
        help="File path for persistent structured server logs",
    )

    return parser.parse_args()


def main() -> int:
    """Central server execution routine."""
    args = parse_arguments()

    if args.list_interfaces:
        try:
            ifaces = InterfaceManager.get_interfaces()
            InterfaceManager.display_interfaces(ifaces)
            return 0
        except Exception as e:
            print(f"[!] Error discovering interfaces: {e}", file=sys.stderr)
            return 1

    if args.wg_diagnose:
        diag = WindowsGatewayManager.run_diagnostics(vpn_subnet=args.vpn_subnet)
        WindowsGatewayManager.print_gateway_report(diag)
        return 0

    if args.wg_setup:
        peer_list = [p.strip() for p in args.peers.split(",") if p.strip()]
        print(f"\n[+] Provisioning WireGuard server and {len(peer_list)} client configurations...")
        manager = WireGuardManager(
            config_dir="wireguard_config",
            subnet_cidr=args.vpn_subnet,
            server_endpoint=args.wg_endpoint,
        )
        server_cfg = manager.initialize_server(peer_names=peer_list)
        files = manager.save_configs()

        print(f"[+] Server configuration written to: {files['server_conf']}")
        print(f"[+] Client peer configurations created in wireguard_config/clients/:")
        for p in server_cfg.peers:
            print(f"    - {p.peer_name} -> Assigned VPN IP: {p.assigned_ip} (Config: {p.peer_name.lower().replace(' ', '_')}.conf)")
        print("\n[i] Next Steps:")
        print("    1. Configure Windows Gateway & NAT: Run 'powershell -ExecutionPolicy Bypass -File scripts/setup_wireguard_gateway.ps1' as Admin.")
        print("    2. Start WireGuard Tunnel on Windows: 'wireguard.exe /installtunnelservice wireguard_config\\wg0.conf'")
        print("    3. Transfer each client .conf file to the corresponding client laptop and import into WireGuard.")
        print("    4. Start Central Security Server: 'python server_main.py --tunnel'\n")
        return 0

    # Parse subnets
    subnets = [s.strip() for s in args.vpn_subnet.split(",") if s.strip()]

    config = ServerConfig(
        interface=args.interface,
        is_tunnel=args.tunnel,
        pcap_path=args.pcap,
        pcap_rate=args.pcap_rate,
        bpf_filter=args.filter,
        workers=args.workers,
        queue_size=args.queue_size,
        active_prevention=args.ips_active,
        vpn_subnets=subnets,
        wireguard_peers_file=args.wg_peers_file,
        enable_dashboard=not args.no_dashboard,
        dashboard_refresh_hz=args.refresh_rate,
        log_file=args.log_file,
    )

    try:
        server = NetworkSecurityServer(config)
        server.start()
        return 0
    except KeyboardInterrupt:
        print("\nServer halted by user.")
        return 0
    except Exception as exc:
        print(f"\n[!] Fatal server error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

