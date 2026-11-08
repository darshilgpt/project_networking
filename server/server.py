"""Central Network Security Server orchestrator coordinating ingestion, workers, and telemetry."""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
import os
import signal
import sys
import time
from typing import Dict, List, Optional

from capture.interface_manager import InterfaceManager
from models.alert_model import IDSAlert
from models.packet_models import InterfaceInfo
from server.client_manager import ClientContext, ClientManager
from server.dashboard import LiveTerminalDashboard
from server.ingestion import LiveCaptureSource, PacketSource, PcapReplaySource, TunnelCaptureSource
from server.windows_gateway import WindowsGatewayManager
from server.wireguard_manager import WireGuardManager
from server.wireguard_monitor import WireGuardMonitor
from server.worker_pool import PipelineWorkerPool, ProcessedPacketResult
from utils.logger import setup_logger

logger = logging.getLogger("dpi_ids_ips.server")


@dataclass
class ServerConfig:
    """Configuration options for the Central Network Security Server."""
    # Ingestion mode
    interface: Optional[str] = None
    is_tunnel: bool = False
    pcap_path: Optional[str] = None
    pcap_rate: str = "fastest"  # 'fastest' or 'realtime'
    bpf_filter: Optional[str] = None

    # Pipeline configuration
    workers: int = 4
    queue_size: int = 10000
    active_prevention: bool = False

    # VPN Client identification
    vpn_subnets: List[str] = field(default_factory=lambda: ["10.8.0.0/24", "10.10.0.0/24"])
    predefined_clients: Dict[str, str] = field(default_factory=dict)
    wireguard_peers_file: Optional[str] = "wireguard_config/wireguard_peers.json"

    # Telemetry and logging
    enable_dashboard: bool = True
    dashboard_refresh_hz: float = 2.0
    log_file: Optional[str] = "security_server.log"
    log_level: int = logging.INFO


class NetworkSecurityServer:
    """Coordinates packet acquisition, worker processing pool, client telemetry, and UI."""

    def __init__(self, config: ServerConfig) -> None:
        self.config = config
        self._is_running = False
        self._shutdown_event = False

        # Initialize structured logging
        self.logger = setup_logger(
            name="dpi_ids_ips",
            level=config.log_level,
            log_file=config.log_file,
        )

        # Pre-load peers mapping from wireguard_peers.json if present
        if config.wireguard_peers_file and os.path.exists(config.wireguard_peers_file):
            loaded_peers = WireGuardManager.load_peers_mapping(config.wireguard_peers_file)
            for ip, name in loaded_peers.items():
                if ip not in config.predefined_clients:
                    config.predefined_clients[ip] = name
            logger.info(f"Loaded {len(loaded_peers)} registered WireGuard client peers from {config.wireguard_peers_file}")

        # 1. Multi-Client Manager
        self.client_manager = ClientManager(
            vpn_subnets=config.vpn_subnets,
            predefined_clients=config.predefined_clients,
        )

        # 2. Worker Pool with bounded queue
        self.worker_pool = PipelineWorkerPool(
            client_manager=self.client_manager,
            num_workers=config.workers,
            queue_size=config.queue_size,
            active_prevention=config.active_prevention,
            on_alert_generated=self._on_alert_raised,
        )

        # 3. WireGuard Peer Connectivity Monitor
        self.wireguard_monitor = WireGuardMonitor(
            client_manager=self.client_manager,
            interface_name="wg0",
        )

        # 4. Resolve Packet Source
        self.source = self._build_packet_source()

        # 5. Live Terminal Dashboard
        self.dashboard = LiveTerminalDashboard(
            worker_pool=self.worker_pool,
            client_manager=self.client_manager,
            packet_source=self.source,
            refresh_rate_hz=config.dashboard_refresh_hz,
            enable_interactive=config.enable_dashboard,
            wireguard_monitor=self.wireguard_monitor,
        )

    def _on_alert_raised(self, alert: IDSAlert, client: ClientContext) -> None:
        """Invoked immediately whenever an IDS security rule triggers."""
        logger.warning(
            f"SECURITY ALERT [{alert.severity.value}] [{alert.category.value}] "
            f"Client: {client.client_name} ({alert.source_ip}) -> {alert.destination_ip} | "
            f"Rule: {alert.matched_rule} | Action: {alert.recommended_action.value} | "
            f"Evidence: {alert.evidence}"
        )

    # --- IPS Enforcement Control APIs ---

    def enable_active_prevention(self) -> None:
        """Enables active dropping of verified attack packets."""
        self.worker_pool.blocking_manager.enable_active_prevention()

    def disable_active_prevention(self) -> None:
        """Reverts to safe monitoring and simulation mode."""
        self.worker_pool.blocking_manager.disable_active_prevention()

    def trigger_emergency_killswitch(self, reason: str = "Admin Emergency Disable") -> None:
        """Instantly disables packet blocking in fail-open bypass mode."""
        self.worker_pool.blocking_manager.trigger_emergency_killswitch(reason)

    def reset_emergency_killswitch(self) -> None:
        """Reactivates normal IPS enforcement."""
        self.worker_pool.blocking_manager.reset_emergency_killswitch()

    def register_client_policy(self, policy: ClientSecurityPolicy) -> None:
        """Applies a dedicated security policy for a client."""
        self.worker_pool.blocking_manager.register_client_policy(policy)

    def add_firewall_rule(self, rule: FirewallRule) -> None:
        """Adds a static or protocol firewall rule."""
        self.worker_pool.blocking_manager.add_firewall_rule(rule)

    def add_temporary_block(self, ip_address: str, duration_seconds: float, reason: str) -> None:
        """Issues a temporary dynamic block on an IP address."""
        self.worker_pool.blocking_manager.add_temporary_block(ip_address, duration_seconds, reason)

    def unblock_ip(self, ip_address: str) -> bool:
        """Manually releases an active dynamic block."""
        return self.worker_pool.blocking_manager.unblock_ip(ip_address)

    def _build_packet_source(self) -> PacketSource:
        """Instantiates the appropriate modular packet ingestion source."""
        # A. PCAP Replay Mode
        if self.config.pcap_path:
            if not os.path.exists(self.config.pcap_path):
                raise FileNotFoundError(f"PCAP file not found: {self.config.pcap_path}")
            return PcapReplaySource(
                pcap_path=self.config.pcap_path,
                rate=self.config.pcap_rate,
            )

        # B. Live Network Adapter Capture (Physical, Wi-Fi, or WireGuard Tunnel)
        interfaces = InterfaceManager.get_interfaces()
        if not interfaces:
            raise RuntimeError("No network interfaces detected. Check Npcap installation.")

        # WireGuard Tunnel mode requested explicitly
        if self.config.is_tunnel:
            tunnel_iface = InterfaceManager.find_tunnel_interface(interfaces)
            if tunnel_iface:
                logger.info(f"Auto-selected WireGuard tunnel adapter: {tunnel_iface.name}")
                return TunnelCaptureSource(
                    interface=tunnel_iface,
                    bpf_filter=self.config.bpf_filter,
                )
            logger.warning("No designated WireGuard/Wintun tunnel interface detected; falling back to selection.")

        selected_iface = InterfaceManager.select_interface(
            interfaces=interfaces,
            choice_input=self.config.interface,
        )

        if selected_iface.is_tunnel:
            return TunnelCaptureSource(
                interface=selected_iface,
                bpf_filter=self.config.bpf_filter,
            )

        return LiveCaptureSource(
            interface=selected_iface,
            bpf_filter=self.config.bpf_filter,
        )

    def start(self) -> None:
        """Starts all server subsystems and enters the execution loop."""
        self._is_running = True
        logger.info("Initializing Network Security Server subsystems...")

        # Setup OS signal handlers for graceful termination if running in main thread
        try:
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
        except (ValueError, AttributeError):
            pass

        # 1. Start worker pool
        self.worker_pool.start()

        # 2. Start WireGuard peer monitor
        self.wireguard_monitor.start()

        # 3. Start ingestion source
        self.source.start(self.worker_pool.packet_queue)

        # 4. Start live terminal dashboard
        self.dashboard.start()

        logger.info("Network Security Server running. Press Ctrl+C for graceful shutdown.")

        # Main supervision loop
        try:
            while self._is_running:
                time.sleep(1.0 / self.config.dashboard_refresh_hz)
                self.dashboard.update()

                # If PCAP replay finishes, auto-stop after draining
                if isinstance(self.source, PcapReplaySource) and self.source.completed:
                    if self.worker_pool.packet_queue.empty():
                        time.sleep(0.5)
                        self.dashboard.update()
                        break
        except KeyboardInterrupt:
            logger.info("KeyboardInterrupt received.")
        finally:
            self.stop()

    def _signal_handler(self, signum: int, frame: object) -> None:
        """Handles shutdown signals gracefully."""
        if not self._shutdown_event:
            self._shutdown_event = True
            logger.info(f"Signal {signum} received; initiating graceful server shutdown...")
            self._is_running = False

    def stop(self) -> None:
        """Gracefully halts ingestion, drains packet queues, stops workers, and prints summary."""
        if not self._is_running and self._shutdown_event:
            return
        self._is_running = False
        self._shutdown_event = True

        logger.info("Stopping packet ingestion...")
        self.source.stop()

        # Stop WireGuard monitor
        self.wireguard_monitor.stop()

        # Wait briefly for workers to finish remaining items in queue
        drain_timeout = 2.0
        t0 = time.time()
        while not self.worker_pool.packet_queue.empty() and (time.time() - t0) < drain_timeout:
            time.sleep(0.1)

        logger.info("Stopping worker threads...")
        self.worker_pool.stop()

        logger.info("Stopping terminal dashboard...")
        self.dashboard.stop()

        # Render final session summary
        self.dashboard.print_final_server_summary()
        logger.info("Server shutdown complete.")
