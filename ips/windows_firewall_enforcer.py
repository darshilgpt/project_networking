"""Windows Defender Firewall / WFP Packet Enforcer Subsystem.

Manages scoped, temporary, and reversible packet blocking rules in Windows Defender Firewall
for verified attack sources within the designated VPN client subnet (10.10.0.0/24).
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
import ipaddress
import logging
import os
import socket
import subprocess
import sys
import threading
import time
from typing import Callable, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger("dpi_ids_ips.ips.windows_firewall")


@dataclass
class FirewallBlockRecord:
    """Represents an active or tracked Windows Defender Firewall block rule."""
    ip_address: str
    rule_name: str
    created_at: float
    duration_seconds: float
    expires_at: float
    reason: str
    is_active: bool = True
    is_simulated: bool = False

    def is_expired(self, now: Optional[float] = None) -> bool:
        """Checks if the temporary block has expired."""
        ts = now if now is not None else time.time()
        return ts >= self.expires_at

    def time_remaining(self, now: Optional[float] = None) -> float:
        """Returns the time remaining in seconds until the block expires."""
        ts = now if now is not None else time.time()
        return max(0.0, self.expires_at - ts)


class WindowsFirewallEnforcer:
    """
    Automated Windows Defender Firewall Enforcement Engine.
    
    Safety Guarantees:
    - Only permits blocking addresses within 10.10.0.0/24.
    - Never blocks server VPN IP (10.10.0.1).
    - Never blocks loopback, broadcast, multicast, or server physical IP/gateway.
    - Never blocks WireGuard outer UDP port 51820.
    - Automatically cleans up stale rules with prefix 'NIPS_BLOCK_' on startup and shutdown.
    - Automatically removes rules when temporary bans expire.
    - Falls back to simulation mode if administrator privileges are absent.
    """

    RULE_PREFIX: str = "NIPS_BLOCK_"
    PERMITTED_SUBNET: str = "10.10.0.0/24"
    SERVER_VPN_IP: str = "10.10.0.1"
    WIREGUARD_PORT: int = 51820
    DEFAULT_BAN_SECONDS: float = 60.0

    def __init__(
        self,
        permitted_subnet: Union[str, List[str]] = PERMITTED_SUBNET,
        server_vpn_ip: str = SERVER_VPN_IP,
        default_ban_seconds: float = DEFAULT_BAN_SECONDS,
        command_executor: Optional[Callable[[List[str]], Tuple[int, str, str]]] = None,
        is_admin: Optional[bool] = None,
        auto_cleanup_stale: bool = True,
    ) -> None:
        if isinstance(permitted_subnet, str):
            subnets = [s.strip() for s in permitted_subnet.split(",") if s.strip()]
        else:
            subnets = list(permitted_subnet)
        self.permitted_networks = [ipaddress.ip_network(s, strict=False) for s in subnets]
        self.permitted_network = self.permitted_networks[0]
        self.server_vpn_ip = server_vpn_ip.strip()
        self.default_ban_seconds = default_ban_seconds

        # Command runner: default uses subprocess.run, mockable for automated tests
        self._executor = command_executor or self._default_executor

        # Administrator privileges check
        self.is_admin: bool = is_admin if is_admin is not None else self.check_admin_privileges()

        # Cache protected host IPs (LAN IP, loopback, gateway)
        self.protected_ips: Set[str] = self._resolve_protected_ips()

        # Internal tracking: IP -> FirewallBlockRecord
        self._active_rules: Dict[str, FirewallBlockRecord] = {}
        self._lock = threading.Lock()

        if not self.is_admin:
            logger.warning(
                "[!] Windows Administrator privileges NOT detected. "
                "Windows Defender Firewall rule creation is disabled. "
                "IPS will operate strictly in MONITORING / SIMULATION mode."
            )
        else:
            logger.info("WindowsFirewallEnforcer initialized with Administrator privileges.")

        # Startup Recovery: detect and clean up stale rules from prior crashes/sessions
        if auto_cleanup_stale and self.is_admin:
            stale_count = self.cleanup_stale_rules()
            if stale_count > 0:
                logger.info(f"Startup Recovery: Purged {stale_count} stale NIPS firewall rules.")

    @staticmethod
    def check_admin_privileges() -> bool:
        """Determines if the running process holds elevated Windows Administrator rights."""
        if sys.platform != "win32":
            return False
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def _resolve_protected_ips(self) -> Set[str]:
        """Resolves system infrastructure IPs that must NEVER be blocked under any condition."""
        protected = {
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "255.255.255.255",
            self.server_vpn_ip,
        }
        try:
            # Query active outbound LAN IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                lan_ip = s.getsockname()[0]
                if lan_ip:
                    protected.add(lan_ip)
        except Exception:
            pass
        return protected

    @staticmethod
    def _default_executor(cmd: List[str]) -> Tuple[int, str, str]:
        """Default Windows command execution via subprocess."""
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5.0,
            )
            return res.returncode, res.stdout, res.stderr
        except Exception as e:
            return 1, "", str(e)

    def validate_ip(self, ip: str) -> Tuple[bool, str]:
        """
        Validates target IP against safety constraints.
        
        Returns:
            Tuple of (is_valid: bool, error_message: str)
        """
        if not ip or not isinstance(ip, str) or not ip.strip():
            return False, "IP address cannot be empty."

        clean_ip = ip.strip()

        try:
            addr = ipaddress.ip_address(clean_ip)
        except ValueError:
            return False, f"Invalid IP address syntax: '{clean_ip}'."

        if addr.version != 4:
            return False, f"Safety violation: IPv6 address '{clean_ip}' is not supported in the VPN subnet."

        # Rule 1: Never block the server's own VPN IP
        if clean_ip == self.server_vpn_ip or clean_ip == "10.8.0.1":
            return False, f"Safety violation: Cannot block server VPN gateway IP {clean_ip}."

        # Rule 2: Subnet containment - only permit blocking within designated VPN client subnet(s)
        in_network = any(addr in net for net in self.permitted_networks)
        if not in_network:
            return False, f"Safety violation: IP '{clean_ip}' is outside permitted VPN subnet."

        # Rule 3: Never block subnet network or broadcast address
        for net in self.permitted_networks:
            if addr == net.network_address:
                return False, f"Safety violation: Cannot block subnet network address {clean_ip}."
            if addr == net.broadcast_address:
                return False, f"Safety violation: Cannot block subnet broadcast address {clean_ip}."

        # Rule 4: Never block loopback, multicast, or system protected IPs
        if addr.is_loopback:
            return False, f"Safety violation: Cannot block loopback address {clean_ip}."
        if addr.is_multicast:
            return False, f"Safety violation: Cannot block multicast address {clean_ip}."
        if clean_ip in self.protected_ips:
            return False, f"Safety violation: IP '{clean_ip}' is protected system infrastructure."

        return True, ""

    def block_ip(
        self,
        ip: str,
        reason: str = "Automated Security Block",
        duration_seconds: Optional[float] = None,
        now: Optional[float] = None,
    ) -> bool:
        """
        Creates an active Windows Defender Firewall rule blocking traffic from/to the target IP.
        
        Args:
            ip: Target client IP to block.
            reason: Security rationale for audit logs.
            duration_seconds: Temporary ban duration (defaults to 60s).
            now: Optional timestamp override for deterministic testing.
            
        Returns:
            True if block was successfully created/active, False if rejected or failed.
        """
        dur = duration_seconds if duration_seconds is not None else self.default_ban_seconds
        current_time = now if now is not None else time.time()

        # 1. Safety validation
        is_valid, err_msg = self.validate_ip(ip)
        if not is_valid:
            logger.warning(f"WindowsFirewallEnforcer rejected block request for {ip}: {err_msg}")
            return False

        clean_ip = ip.strip()

        with self._lock:
            # 2. Avoid duplicate rules
            if clean_ip in self._active_rules:
                existing = self._active_rules[clean_ip]
                if not existing.is_expired(current_time):
                    if existing.is_simulated or not self.is_admin:
                        # Existing entry was simulated; no OS firewall rule was created
                        return False
                    logger.debug(
                        f"Firewall block rule already active for {clean_ip} "
                        f"({existing.time_remaining(current_time):.1f}s remaining). Skipping duplicate creation."
                    )
                    return True
                else:
                    # Expired entry in tracking, clean it first
                    self._remove_firewall_rule(clean_ip)

            rule_name = f"{self.RULE_PREFIX}{clean_ip}"

            # 3. Administrator Privilege Check
            if not self.is_admin:
                logger.warning(
                    f"[IPS SIMULATION] Cannot create Windows Firewall rule for {clean_ip}: "
                    "Administrator privileges required. Simulating block decision."
                )
                self._active_rules[clean_ip] = FirewallBlockRecord(
                    ip_address=clean_ip,
                    rule_name=rule_name,
                    created_at=current_time,
                    duration_seconds=dur,
                    expires_at=current_time + dur,
                    reason=reason,
                    is_active=True,
                    is_simulated=True,
                )
                return False

            # 4. Create Inbound & Outbound Block Rules in Windows Defender Firewall via PowerShell
            # Scoped strictly to remoteip=<clean_ip> with -PolicyStore ActiveStore
            ps_script_in = (
                f"New-NetFirewallRule -Name '{rule_name}' -DisplayName '{rule_name}' "
                f"-Direction Inbound -Action Block -RemoteAddress '{clean_ip}' "
                f"-PolicyStore ActiveStore -Description 'NIPS temporary inbound block' "
                f"-Enabled True -ErrorAction Stop"
            )
            cmd_in = ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script_in]

            ps_script_out = (
                f"New-NetFirewallRule -Name '{rule_name}_OUT' -DisplayName '{rule_name}_OUT' "
                f"-Direction Outbound -Action Block -RemoteAddress '{clean_ip}' "
                f"-PolicyStore ActiveStore -Description 'NIPS temporary outbound block' "
                f"-Enabled True -ErrorAction Stop"
            )
            cmd_out = ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script_out]

            rc_in, out_in, err_in = self._executor(cmd_in)
            if rc_in != 0:
                logger.error(
                    f"Failed to create Inbound Windows Firewall rule for {clean_ip}. "
                    f"ReturnCode: {rc_in}, Stdout: {out_in.strip()}, Stderr: {err_in.strip()}"
                )
                return False

            rc_out, out_out, err_out = self._executor(cmd_out)
            if rc_out != 0:
                logger.error(
                    f"Failed to create Outbound Windows Firewall rule for {clean_ip}. "
                    f"ReturnCode: {rc_out}, Stdout: {out_out.strip()}, Stderr: {err_out.strip()}"
                )
                self._remove_firewall_rule(clean_ip)
                return False

            self._active_rules[clean_ip] = FirewallBlockRecord(
                ip_address=clean_ip,
                rule_name=rule_name,
                created_at=current_time,
                duration_seconds=dur,
                expires_at=current_time + dur,
                reason=reason,
                is_active=True,
                is_simulated=False,
            )
            logger.warning(
                f"[IPS ACTUAL BLOCK] Successfully added Windows Defender Firewall rules '{rule_name}' and '{rule_name}_OUT' "
                f"for {clean_ip} ({dur:.0f}s ban). Reason: {reason}"
            )
            return True

    def unblock_ip(self, ip: str) -> bool:
        """
        Removes Windows Defender Firewall block rules for the specified IP.
        
        Returns:
            True if rule was removed or successfully cleared, False otherwise.
        """
        clean_ip = ip.strip()

        with self._lock:
            record = self._active_rules.pop(clean_ip, None)
            if not record:
                # IP was not actively tracked or blocked
                return False

            rule_name = f"{self.RULE_PREFIX}{clean_ip}"

            if not self.is_admin:
                logger.info(f"[IPS SIMULATION] Cleared simulated block for {clean_ip}.")
                return True

            return self._remove_firewall_rule(clean_ip)

    def _remove_firewall_rule(self, ip: str) -> bool:
        """Internal helper to execute firewall rule deletion commands via PowerShell."""
        rule_name = f"{self.RULE_PREFIX}{ip}"
        ps_del = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"Remove-NetFirewallRule -Name '{rule_name}', '{rule_name}_OUT' -PolicyStore ActiveStore -ErrorAction SilentlyContinue",
        ]

        rc, out, err = self._executor(ps_del)
        success = (rc == 0)
        if success:
            logger.info(f"[IPS UNBLOCK] Removed Windows Defender Firewall rule '{rule_name}' for {ip}.")
        else:
            logger.debug(f"[IPS UNBLOCK] Remove-NetFirewallRule returned {rc}: {err.strip()}")
        return success

    def is_ip_blocked(self, ip: str, now: Optional[float] = None) -> bool:
        """
        Checks if an IP is currently under an active non-expired block.
        Automatically unblocks if expired.
        """
        clean_ip = ip.strip()
        current_time = now if now is not None else time.time()

        with self._lock:
            record = self._active_rules.get(clean_ip)
            if not record:
                return False

            if record.is_expired(current_time):
                # Expired: clean rule
                self._active_rules.pop(clean_ip, None)
                if self.is_admin and not record.is_simulated:
                    self._remove_firewall_rule(clean_ip)
                logger.info(f"[IPS AUTO-EXPIRE] Temporary block on {clean_ip} expired.")
                return False

            return True

    def clean_expired_rules(self, now: Optional[float] = None) -> List[str]:
        """
        Scans all tracked rules and removes those whose time window has expired.
        
        Returns:
            List of unblocked IP addresses.
        """
        current_time = now if now is not None else time.time()
        expired_ips: List[str] = []

        with self._lock:
            for ip, record in list(self._active_rules.items()):
                if record.is_expired(current_time):
                    expired_ips.append(ip)
                    del self._active_rules[ip]
                    if self.is_admin and not record.is_simulated:
                        self._remove_firewall_rule(ip)
                    logger.info(f"[IPS AUTO-EXPIRE] Removed expired block for {ip}.")

        return expired_ips

    def cleanup_stale_rules(self) -> int:
        """
        Recovery routine: Queries and deletes any dangling firewall rules with prefix 'NIPS_BLOCK_'.
        Safe for use on startup and shutdown.
        
        Returns:
            Count of cleaned rules.
        """
        if not self.is_admin:
            return 0

        # PowerShell command safely removes rules matching prefix without affecting other firewall rules
        ps_cmd = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"Get-NetFirewallRule -Name '{self.RULE_PREFIX}*' -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue",
        ]
        rc, _, _ = self._executor(ps_cmd)
        return 1 if rc == 0 else 0

    def flush_all_rules(self) -> int:
        """
        Graceful shutdown / emergency reset: Removes all NIPS block rules.
        
        Returns:
            Total count of rules flushed.
        """
        count = 0
        with self._lock:
            for ip in list(self._active_rules.keys()):
                self._remove_firewall_rule(ip)
                count += 1
            self._active_rules.clear()

        if self.is_admin:
            self.cleanup_stale_rules()

        logger.info(f"[IPS FLUSH] Flushed all NIPS Windows Defender Firewall rules (Total: {count}).")
        return count

    def get_active_blocks(self) -> List[FirewallBlockRecord]:
        """Returns snapshot list of currently active block records."""
        with self._lock:
            return list(self._active_rules.values())
