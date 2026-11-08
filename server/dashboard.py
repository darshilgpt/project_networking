"""Live Terminal Dashboard displaying server health, client metrics, DPI, and alerts."""

from __future__ import annotations

from datetime import datetime
import os
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from rich import box
from rich.console import Console, RenderableType
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from models.alert_model import IDSAlert, Severity
from server.client_manager import ClientManager, ClientStatsSnapshot
from server.ingestion import PacketSource
from server.worker_pool import PipelineWorkerPool, ServerPipelineStats


class LiveTerminalDashboard:
    """Manages the rich live terminal display for the Central Security Server."""

    def __init__(
        self,
        worker_pool: PipelineWorkerPool,
        client_manager: ClientManager,
        packet_source: PacketSource,
        refresh_rate_hz: float = 2.0,
        enable_interactive: bool = True,
        wireguard_monitor: Optional[Any] = None,
    ) -> None:
        self.worker_pool = worker_pool
        self.client_manager = client_manager
        self.packet_source = packet_source
        self.refresh_rate_hz = max(0.5, refresh_rate_hz)
        self.enable_interactive = enable_interactive and sys.stdout.isatty()
        self.wireguard_monitor = wireguard_monitor

        self.console = Console()
        self._live: Optional[Live] = None
        self._start_time = time.time()
        self._is_running = False

    def _format_bytes(self, num_bytes: int) -> str:
        """Converts bytes to human readable format."""
        for unit in ["B", "KB", "MB", "GB"]:
            if num_bytes < 1024.0:
                return f"{num_bytes:.1f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.1f} TB"

    def _format_uptime(self) -> str:
        """Returns uptime formatted as HH:MM:SS."""
        elapsed = int(time.time() - self._start_time)
        hrs = elapsed // 3600
        mins = (elapsed % 3600) // 60
        secs = elapsed % 60
        return f"{hrs:02d}:{mins:02d}:{secs:02d}"

    def build_header_panel(self, stats: ServerPipelineStats, src_stats: Dict[str, Any]) -> Panel:
        """Constructs the top server status and telemetry panel."""
        uptime = self._format_uptime()
        source_name = src_stats.get("source_name", "Unknown")
        ingested = src_stats.get("total_ingested", 0)
        q_drops = src_stats.get("dropped_queue_full", 0)

        # Host resource metrics
        res_info = ""
        if HAS_PSUTIL:
            try:
                cpu = psutil.cpu_percent()
                mem = psutil.virtual_memory().percent
                res_info = f" | CPU: {cpu:.1f}% | Mem: {mem:.1f}%"
            except Exception:
                pass

        q_pct = (stats.queue_current_size / max(1, stats.queue_capacity)) * 100
        q_style = "green" if q_pct < 70 else ("yellow" if q_pct < 90 else "bold red")

        grid = Table.grid(expand=True)
        grid.add_column(justify="left", ratio=2)
        grid.add_column(justify="right", ratio=1)

        mode_text = "[bold green]ACTIVE PREVENTION[/bold green]" if stats.active_prevention_enabled else "[bold yellow]SIMULATION (MONITORING)[/bold yellow]"
        killswitch_text = " [bold red blink]KILLSWITCH ACTIVE[/bold red blink]" if self.worker_pool.blocking_manager.killswitch.is_active else ""

        line1 = (
            f"[bold cyan]CENTRAL WINDOWS NETWORK SECURITY SERVER (IDS/IPS)[/bold cyan] "
            f"[bold green]● RUNNING[/bold green] | Mode: {mode_text}{killswitch_text} | Uptime: [bold white]{uptime}[/bold white]{res_info}"
        )
        line2 = (
            f"Ingestion: [bold yellow]{source_name}[/bold yellow] | "
            f"Workers: [bold cyan]{stats.active_workers}[/bold cyan] | "
            f"Queue: [{q_style}]{stats.queue_current_size}/{stats.queue_capacity} ({q_pct:.1f}%)[/{q_style}] "
            f"(Peak: {stats.queue_high_watermark})"
        )
        rate_mbps = (stats.bytes_per_sec * 8) / 1_000_000
        line3 = (
            f"Processed: [bold white]{stats.total_processed:,}[/bold white] pkts "
            f"({self._format_bytes(stats.total_bytes)}) | "
            f"Throughput: [bold green]{stats.packets_per_sec:,.0f} pps[/bold green] ({rate_mbps:.2f} Mbps) | "
            f"Ingest Drops: [{'bold red' if q_drops > 0 else 'green'}]{q_drops}[/]"
        )
        line4 = (
            f"IPS Telemetry: Intercepted: [bold cyan]{stats.intercepted_packets:,}[/bold cyan] | "
            f"Block Decisions: [bold yellow]{stats.security_block_decisions:,}[/bold yellow] | "
            f"Actual Drops: [bold red]{stats.actual_dropped_packets:,}[/bold red] | "
            f"Forwarded: [bold green]{stats.forwarded_or_reinjected_packets:,}[/bold green] | "
            f"Simulated: [yellow]{stats.simulated_blocks:,}[/yellow]"
        )

        grid.add_row(line1)
        grid.add_row(line2)
        grid.add_row(line3)
        grid.add_row(line4)

        return Panel(grid, box=box.ROUNDED, border_style="blue", padding=(0, 1))

    def build_clients_table(self, clients: List[ClientStatsSnapshot]) -> Table:
        """Constructs the connected VPN clients and traffic table."""
        table = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
            header_style="bold magenta",
            title="[bold white]CONNECTED CLIENTS & TRAFFIC TELEMETRY[/bold white]",
            title_justify="left",
        )
        table.add_column("Client / Alias", style="cyan", ratio=2)
        table.add_column("VPN IP", style="bright_white", ratio=2)
        table.add_column("Pkts (In/Out)", justify="right", ratio=2)
        table.add_column("Volume", justify="right", ratio=2)
        table.add_column("Flows", justify="right", ratio=1)
        table.add_column("Top Proto", justify="center", ratio=1)
        table.add_column("Alerts (L/M/H/C)", justify="center", ratio=2)
        table.add_column("Status", justify="center", ratio=1)

        if not clients:
            table.add_row("No clients active", "-", "0 / 0", "0 B", "0", "-", "0 / 0 / 0 / 0", "[dim]IDLE[/dim]")
            return table

        for c in clients:
            wg_stat = self.wireguard_monitor.get_peer_status(c.client_ip) if self.wireguard_monitor else None
            if wg_stat:
                if wg_stat.status == "CONNECTED":
                    status_text = "[bold green]CONNECTED[/bold green]"
                elif wg_stat.status == "HANDSHAKE PENDING":
                    status_text = "[yellow]PENDING[/yellow]"
                else:
                    status_text = "[bold red]DISCONNECTED[/bold red]"
                endpoint_suffix = f" ({wg_stat.endpoint})" if wg_stat.endpoint and wg_stat.endpoint != "-" else ""
            else:
                status_text = "[bold green]ACTIVE[/bold green]" if c.is_active else "[dim]IDLE[/dim]"
                endpoint_suffix = ""

            pkts_str = f"{c.packets_in:,} / {c.packets_out:,}"
            vol_str = self._format_bytes(c.total_bytes)

            sev = c.severity_counts
            sev_str = (
                f"[blue]{sev.get('LOW', 0)}[/blue]/"
                f"[yellow]{sev.get('MEDIUM', 0)}[/yellow]/"
                f"[bright_red]{sev.get('HIGH', 0)}[/bright_red]/"
                f"[bold red]{sev.get('CRITICAL', 0)}[/bold red]"
            )

            table.add_row(
                f"{c.client_name}{endpoint_suffix}",
                c.client_ip,
                pkts_str,
                vol_str,
                str(c.active_flows),
                c.top_protocol if c.top_protocol != "None" else "-",
                sev_str,
                status_text,
            )

        return table

    def build_dpi_summary_table(self) -> Table:
        """Constructs the Deep Packet Inspection and Application Protocol breakdown."""
        table = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
            header_style="bold cyan",
            title="[bold white]DEEP PACKET INSPECTION (DPI) & PROTOCOLS[/bold white]",
            title_justify="left",
        )
        table.add_column("Protocol", style="bold white", ratio=2)
        table.add_column("Inspections", justify="right", ratio=2)
        table.add_column("Matches", justify="right", ratio=2)

        dpi_eng = self.worker_pool.dpi_engine
        proto_counts = dict(dpi_eng.protocol_counts)

        if not proto_counts:
            table.add_row("Pending packets...", "0", "0")
            return table

        for proto, count in sorted(proto_counts.items(), key=lambda kv: kv[1], reverse=True)[:6]:
            table.add_row(proto, f"{count:,}", "-")

        table.add_row(
            "[bold]Total Inspections[/bold]",
            f"[bold]{dpi_eng.total_inspections:,}[/bold]",
            f"[bold]{dpi_eng.signature_matches_count:,}[/bold]",
        )
        return table

    def build_alerts_table(self) -> Table:
        """Constructs the recent Security Alerts and IDS events table."""
        table = Table(
            box=box.SIMPLE_HEAD,
            expand=True,
            header_style="bold red",
            title="[bold white]RECENT INTRUSION DETECTION (IDS) ALERTS[/bold white]",
            title_justify="left",
        )
        table.add_column("Time", style="dim", ratio=1)
        table.add_column("Severity", justify="center", ratio=1)
        table.add_column("Client / Source", style="cyan", ratio=2)
        table.add_column("Category", style="yellow", ratio=2)
        table.add_column("Rule / Detection", style="white", ratio=3)
        table.add_column("Action", justify="center", ratio=1)

        recent = list(self.worker_pool.recent_alerts)[:7]
        if not recent:
            table.add_row("-", "[green]NOMINAL[/green]", "All Clean", "-", "No threats detected", "[green]ALLOW[/green]")
            return table

        for alert, client_name in recent:
            sev_style = {
                Severity.LOW.value: "blue",
                Severity.MEDIUM.value: "yellow",
                Severity.HIGH.value: "bold bright_red",
                Severity.CRITICAL.value: "bold red reverse",
            }.get(alert.severity.value, "white")

            action_val = getattr(alert, "recommended_action", None)
            act_text = action_val.value if action_val else "ALERT"
            act_style = "bold red" if act_text == "BLOCK" else ("yellow" if act_text == "ALERT" else "green")

            rule_clean = alert.matched_rule[:35] + "..." if len(alert.matched_rule) > 35 else alert.matched_rule

            table.add_row(
                alert.datetime_str[-8:],
                f"[{sev_style}]{alert.severity.value}[/{sev_style}]",
                f"{client_name} ({alert.source_ip})",
                alert.category.value,
                rule_clean,
                f"[{act_style}]{act_text}[/{act_style}]",
            )

        return table

    def render_dashboard(self) -> RenderableType:
        """Composes the full terminal layout."""
        stats = self.worker_pool.get_stats_snapshot()
        src_stats = self.packet_source.get_stats()
        clients = self.client_manager.get_client_snapshots()

        header = self.build_header_panel(stats, src_stats)
        clients_tbl = self.build_clients_table(clients)
        dpi_tbl = self.build_dpi_summary_table()
        alerts_tbl = self.build_alerts_table()

        layout = Layout()
        layout.split_column(
            Layout(header, name="header", size=5),
            Layout(clients_tbl, name="clients", ratio=3),
            Layout(name="lower", ratio=3),
        )
        layout["lower"].split_row(
            Layout(dpi_tbl, name="dpi", ratio=1),
            Layout(alerts_tbl, name="alerts", ratio=2),
        )

        return layout

    def start(self) -> None:
        """Starts live dashboard rendering."""
        self._is_running = True
        self._start_time = time.time()
        if self.enable_interactive:
            self._live = Live(
                self.render_dashboard(),
                console=self.console,
                refresh_per_second=self.refresh_rate_hz,
                screen=False,
            )
            self._live.start()

    def update(self) -> None:
        """Pushes a refresh frame to the terminal."""
        if self._live and self.enable_interactive:
            self._live.update(self.render_dashboard())

    def stop(self) -> None:
        """Stops live dashboard rendering."""
        self._is_running = False
        if self._live:
            try:
                self._live.stop()
            except Exception:
                pass
            self._live = None

    def print_final_server_summary(self) -> None:
        """Prints a comprehensive terminal summary card upon server termination."""
        stats = self.worker_pool.get_stats_snapshot()
        src_stats = self.packet_source.get_stats()
        clients = self.client_manager.get_client_snapshots()
        uptime = self._format_uptime()

        self.console.print("\n" + "=" * 70, style="bold cyan")
        self.console.print("     CENTRAL NETWORK SECURITY SERVER - FINAL SESSION SUMMARY", style="bold white")
        self.console.print("=" * 70, style="bold cyan")
        self.console.print(f"Uptime               : {uptime}")
        self.console.print(f"Total Packets Ingested: {src_stats.get('total_ingested', 0):,}")
        self.console.print(f"Total Packets Dissected: {stats.total_processed:,}")
        self.console.print(f"Total Traffic Volume : {self._format_bytes(stats.total_bytes)}")
        self.console.print(f"Queue Dropped Packets: {src_stats.get('dropped_queue_full', 0):,}")
        self.console.print(f"Total Security Alerts : {stats.total_alerts:,}")
        self.console.print(f"Total Blocks / Drops : {stats.total_blocks:,}")
        self.console.print("-" * 70, style="dim cyan")
        self.console.print("  [bold white]IPS Enforcement Breakdown:[/bold white]")
        self.console.print(f"  - Mode                  : {'ACTIVE PREVENTION' if stats.active_prevention_enabled else 'SIMULATION / MONITORING'}")
        self.console.print(f"  - Intercepted Packets   : {stats.intercepted_packets:,}")
        self.console.print(f"  - Security Block Decs   : {stats.security_block_decisions:,}")
        self.console.print(f"  - Actual Dropped Packets: {stats.actual_dropped_packets:,}")
        self.console.print(f"  - Forwarded / Allowed   : {stats.forwarded_or_reinjected_packets:,}")
        self.console.print(f"  - Simulated Blocks      : {stats.simulated_blocks:,}")
        self.console.print("-" * 70, style="dim cyan")

        self.console.print("\n[bold white]Registered Clients:[/bold white]")
        for c in clients:
            self.console.print(
                f"  - {c.client_name} ({c.client_ip}): "
                f"{c.total_packets:,} pkts, {self._format_bytes(c.total_bytes)}, "
                f"Flows: {c.active_flows}, Alerts: {c.alerts_count}"
            )

        self.console.print("=" * 70 + "\n", style="bold cyan")

