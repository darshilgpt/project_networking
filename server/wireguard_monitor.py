"""WireGuard peer connectivity monitor tracking handshakes, endpoints, and session state."""

from __future__ import annotations

from dataclasses import dataclass
import logging
import os
import shutil
import subprocess
import threading
import time
from typing import Dict, List, Optional

from server.client_manager import ClientContext, ClientManager

logger = logging.getLogger("dpi_ids_ips.server.wireguard_monitor")


@dataclass
class PeerConnectivityStatus:
    """Real-time connectivity status for a WireGuard peer."""
    public_key: str
    assigned_ip: str
    peer_name: str
    endpoint: str
    latest_handshake_ts: float
    handshake_age_seconds: float
    rx_bytes: int
    tx_bytes: int
    status: str  # 'CONNECTED', 'HANDSHAKE PENDING', 'DISCONNECTED'


class WireGuardMonitor:
    """Monitors live WireGuard peer handshakes, transfer metrics, and connection transitions."""

    def __init__(
        self,
        client_manager: ClientManager,
        interface_name: str = "wg0",
        poll_interval: float = 3.0,
        handshake_timeout: float = 180.0,
        wg_binary_path: Optional[str] = None,
    ) -> None:
        """
        Args:
            client_manager: Server's ClientManager to synchronize client statuses.
            interface_name: WireGuard tunnel name (default: wg0).
            poll_interval: Seconds between status polls.
            handshake_timeout: Maximum age of handshake in seconds before marking DISCONNECTED.
            wg_binary_path: Path to wg.exe or None to auto-discover in PATH or Program Files.
        """
        self.client_manager = client_manager
        self.interface_name = interface_name
        self.poll_interval = poll_interval
        self.handshake_timeout = handshake_timeout

        self.wg_binary = wg_binary_path or self._find_wg_binary()
        self._is_running = False
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

        # Lock for peer status map
        self._lock = threading.Lock()
        self._peer_statuses: Dict[str, PeerConnectivityStatus] = {}

    @staticmethod
    def _find_wg_binary() -> Optional[str]:
        """Locates wg.exe in system PATH or standard WireGuard install paths."""
        found = shutil.which("wg") or shutil.which("wireguard")
        if found:
            return found

        candidates = [
            r"C:\Program Files\WireGuard\wg.exe",
            r"C:\Program Files\WireGuard\wireguard.exe",
            r"C:\Program Files (x86)\WireGuard\wg.exe",
        ]
        for c in candidates:
            if os.path.exists(c):
                return c
        return None

    def start(self) -> None:
        """Starts the background WireGuard peer monitor thread."""
        self._stop_event.clear()
        self._is_running = True
        self._thread = threading.Thread(target=self._monitor_loop, name="WireGuardMonitor", daemon=True)
        self._thread.start()
        logger.info(f"WireGuard peer monitor started (Binary: {self.wg_binary or 'Packet-Heuristic Fallback'})")

    def stop(self) -> None:
        """Stops the peer monitor cleanly."""
        self._stop_event.set()
        self._is_running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        logger.info("WireGuard peer monitor stopped.")

    def _monitor_loop(self) -> None:
        """Periodically polls WireGuard status and synchronizes with ClientManager."""
        while not self._stop_event.is_set():
            try:
                if self.wg_binary and os.path.exists(self.wg_binary):
                    self._poll_via_wg_binary()
                else:
                    self._poll_via_packet_heuristics()
            except Exception as e:
                logger.debug(f"WireGuard monitor poll encountered: {e}")

            time.sleep(self.poll_interval)

    def _poll_via_wg_binary(self) -> None:
        """Queries 'wg.exe show <iface> dump' and updates peer states."""
        if not self.wg_binary:
            return

        try:
            res = subprocess.run(
                [self.wg_binary, "show", self.interface_name, "dump"],
                capture_output=True,
                text=True,
                timeout=2.0,
            )
            if res.returncode != 0:
                self._poll_via_packet_heuristics()
                return

            lines = res.stdout.strip().splitlines()
            if len(lines) <= 1:
                return

            now = time.time()
            # Peer line format: public_key preshared_key endpoint allowed_ips latest_handshake transfer_rx transfer_tx persistent_keepalive
            for line in lines[1:]:
                parts = line.strip().split("\t")
                if len(parts) < 8:
                    parts = line.strip().split()
                if len(parts) < 7:
                    continue

                pub_key = parts[0]
                endpoint = parts[2] if parts[2] != "(none)" else "-"
                allowed_ips = parts[3]
                handshake_ts = float(parts[4]) if parts[4].isdigit() else 0.0
                rx_bytes = int(parts[5]) if parts[5].isdigit() else 0
                tx_bytes = int(parts[6]) if parts[6].isdigit() else 0

                assigned_ip = allowed_ips.split("/")[0] if allowed_ips else ""
                handshake_age = (now - handshake_ts) if handshake_ts > 0 else 999999.0

                if handshake_ts == 0.0:
                    status = "HANDSHAKE PENDING"
                elif handshake_age <= self.handshake_timeout:
                    status = "CONNECTED"
                else:
                    status = "DISCONNECTED"

                peer_name = f"Peer-{assigned_ip}"
                for ctx in self.client_manager.get_all_clients():
                    if ctx.client_ip == assigned_ip:
                        peer_name = ctx.client_name
                        break

                p_status = PeerConnectivityStatus(
                    public_key=pub_key,
                    assigned_ip=assigned_ip,
                    peer_name=peer_name,
                    endpoint=endpoint,
                    latest_handshake_ts=handshake_ts,
                    handshake_age_seconds=round(handshake_age, 1),
                    rx_bytes=rx_bytes,
                    tx_bytes=tx_bytes,
                    status=status,
                )

                with self._lock:
                    self._peer_statuses[assigned_ip] = p_status

        except Exception as exc:
            logger.debug(f"Error querying wg binary: {exc}")
            self._poll_via_packet_heuristics()

    def _poll_via_packet_heuristics(self) -> None:
        """Infers connection state from live packet arrival timestamps in ClientManager."""
        now = time.time()
        for ctx in self.client_manager.get_all_clients():
            if ctx.client_ip in ("Host/Gateway", "127.0.0.1"):
                continue

            idle_time = now - ctx.last_seen
            if (ctx.packets_in + ctx.packets_out) == 0:
                status = "HANDSHAKE PENDING"
            elif idle_time <= 30.0:
                status = "CONNECTED"
            else:
                status = "DISCONNECTED"

            p_status = PeerConnectivityStatus(
                public_key="N/A (Packet Tracked)",
                assigned_ip=ctx.client_ip,
                peer_name=ctx.client_name,
                endpoint="Dynamic",
                latest_handshake_ts=ctx.last_seen,
                handshake_age_seconds=round(idle_time, 1),
                rx_bytes=ctx.bytes_in,
                tx_bytes=ctx.bytes_out,
                status=status,
            )
            with self._lock:
                self._peer_statuses[ctx.client_ip] = p_status

    def get_peer_status(self, client_ip: str) -> Optional[PeerConnectivityStatus]:
        """Returns the real-time status of a peer by VPN IP."""
        with self._lock:
            return self._peer_statuses.get(client_ip)

    def get_all_peer_statuses(self) -> List[PeerConnectivityStatus]:
        """Returns status snapshots for all monitored peers."""
        with self._lock:
            return list(self._peer_statuses.values())

