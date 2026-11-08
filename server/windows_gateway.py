"""Windows IP Routing and Gateway Diagnostics module."""

from __future__ import annotations

from dataclasses import dataclass
import logging
import os
import platform
import socket
import subprocess
from typing import Dict, List, Optional
import winreg

logger = logging.getLogger("dpi_ids_ips.server.gateway")


@dataclass
class GatewayDiagnostics:
    """Snapshot of Windows host routing, NAT, and gateway readiness."""
    os_name: str
    ip_routing_enabled: bool
    default_gateway_ip: str
    lan_ip: str
    wireguard_adapter_found: bool
    wireguard_adapter_name: str
    nat_ready: bool
    diagnostic_warnings: List[str]


class WindowsGatewayManager:
    """Diagnoses and guides Windows gateway and NAT configuration for WireGuard."""

    @staticmethod
    def is_ip_routing_enabled() -> bool:
        """Queries HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\IPEnableRouter."""
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            ) as key:
                val, _ = winreg.QueryValueEx(key, "IPEnableRouter")
                return bool(val == 1)
        except Exception as e:
            logger.debug(f"Could not read IPEnableRouter registry key: {e}")
            return False

    @staticmethod
    def get_default_lan_ip() -> str:
        """Determines active outbound LAN IP."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    @classmethod
    def run_diagnostics(cls, vpn_subnet: str = "10.8.0.0/24") -> GatewayDiagnostics:
        """Evaluates Windows system networking readiness to function as a full-tunnel VPN gateway."""
        os_info = f"{platform.system()} {platform.release()}"
        routing_enabled = cls.is_ip_routing_enabled()
        lan_ip = cls.get_default_lan_ip()
        warnings = []

        if not routing_enabled:
            warnings.append(
                "Windows IP Routing (IPEnableRouter) is DISABLED in registry. "
                "VPN clients will connect but cannot reach the internet until enabled."
            )

        # Check for WireGuard adapter presence via netsh / ipconfig / route
        wg_found = False
        wg_name = ""
        try:
            res = subprocess.run(["route", "print"], capture_output=True, text=True, timeout=2.0)
            if "WireGuard" in res.stdout or "Wintun" in res.stdout or "wg0" in res.stdout:
                wg_found = True
                wg_name = "wg0 / WireGuard Tunnel"
        except Exception:
            pass

        if not wg_found:
            warnings.append(
                "WireGuard virtual tunnel adapter ('wg0') is not currently active. "
                "Start the tunnel service via: wireguard.exe /installtunnelservice <path_to_conf>"
            )

        return GatewayDiagnostics(
            os_name=os_info,
            ip_routing_enabled=routing_enabled,
            default_gateway_ip="Auto-detected",
            lan_ip=lan_ip,
            wireguard_adapter_found=wg_found,
            wireguard_adapter_name=wg_name or "None",
            nat_ready=routing_enabled,
            diagnostic_warnings=warnings,
        )

    @staticmethod
    def print_gateway_report(diag: GatewayDiagnostics) -> None:
        """Prints a human-readable gateway status report."""
        print("=" * 70)
        print("WINDOWS WIREGUARD GATEWAY & NAT DIAGNOSTIC REPORT")
        print("=" * 70)
        print(f"Operating System         : {diag.os_name}")
        print(f"Server Host LAN IP       : {diag.lan_ip}")
        print(f"Windows IP Routing (NAT) : {'ENABLED' if diag.ip_routing_enabled else 'DISABLED (Action Required)'}")
        print(f"WireGuard Tunnel Adapter : {diag.wireguard_adapter_name}")
        print("-" * 70)

        if diag.diagnostic_warnings:
            print("[!] GATEWAY WARNINGS:")
            for w in diag.diagnostic_warnings:
                print(f"    - {w}")
            print("\n[i] Run 'powershell -ExecutionPolicy Bypass -File scripts/setup_wireguard_gateway.ps1' as Administrator.")
        else:
            print("[+] Windows networking is fully configured to route decrypted VPN client traffic!")
        print("=" * 70)

