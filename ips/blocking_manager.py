"""Comprehensive IPS Blocking Manager and Gateway Enforcement Subsystem."""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
import threading
import time
from typing import Callable, Dict, List, Optional, Set, Tuple

from ips.firewall_policy import (
    AllowlistDenylistManager,
    ClientSecurityPolicy,
    DynamicBlockManager,
    EmergencyKillswitch,
    FirewallRule,
    TemporaryBlock,
)
from ips.rate_limiter import RateLimiter
from ips.stateful_firewall import ConnectionState, FirewallAction, StatefulFirewall
from ips.windows_firewall_enforcer import WindowsFirewallEnforcer
from ips.windows_wfp_divert import WindowsFilteringStatus, WindowsWFPInvestigator
from models.alert_model import DecisionAction, DPIResult, IDSAlert, Severity
from models.packet_models import ParsedPacket

logger = logging.getLogger("dpi_ids_ips.ips.blocking_manager")


@dataclass
class IPSEnforcementResult:
    """Outcome of complete IPS enforcement for a packet."""
    decision: DecisionAction
    effective_action: str  # "ACTUAL_BLOCK", "SIMULATED_BLOCK", "ALLOW"
    is_forwarded: bool     # True if packet is physically forwarded/reinjected, False if dropped
    reason: str
    matched_rule: Optional[str] = None
    state: ConnectionState = ConnectionState.NEW
    dynamic_ban_issued: bool = False
    ban_seconds: float = 0.0
    enforcement_succeeded: bool = False


class BlockingManager:
    """
    Central Intrusion Prevention System (IPS) Manager.
    Coordinates Stateful Firewall, Policy Rules, Rate Limiting, Allowlists/Denylists,
    Dynamic Expirable Blocks, Windows Defender Firewall Enforcer, and Enforcement Paths.
    """

    def __init__(
        self,
        active_prevention: bool = False,
        default_ban_seconds: float = 60.0,
        enable_rate_limiting: bool = True,
        rate_limit_pps: float = 100.0,
        firewall_enforcer: Optional[WindowsFirewallEnforcer] = None,
    ) -> None:
        # Starts in Monitoring / Simulation mode by default
        self.active_prevention = active_prevention
        self.default_ban_seconds = default_ban_seconds

        # Windows Kernel / WFP / WinDivert Investigation
        self.wfp_status: WindowsFilteringStatus = WindowsWFPInvestigator.investigate()
        logger.info(
            f"IPS Enforcement Engine Initialized. Mode: {'ACTIVE_PREVENTION' if active_prevention else 'SIMULATION/MONITORING'}. "
            f"Mechanism: {self.wfp_status.selected_enforcement_mechanism}"
        )

        # Core Subsystems
        self.stateful_firewall = StatefulFirewall()
        self.allowlist_denylist = AllowlistDenylistManager()
        self.dynamic_blocks = DynamicBlockManager(default_ban_seconds=default_ban_seconds)
        self.rate_limiter = RateLimiter(default_pps_limit=rate_limit_pps)
        self.killswitch = EmergencyKillswitch()

        # Windows Defender Firewall / WFP Enforcer
        self.firewall_enforcer = firewall_enforcer or WindowsFirewallEnforcer(
            default_ban_seconds=default_ban_seconds
        )

        # Policies & Rules
        self.client_policies: Dict[str, ClientSecurityPolicy] = {}
        self.static_rules: List[FirewallRule] = []
        self._load_default_firewall_rules()

        # Strictly Distinguished Metrics (As mandated by Requirements)
        self.security_block_decisions: int = 0
        self.intercepted_packets: int = 0
        self.actual_dropped_packets: int = 0
        self.forwarded_or_reinjected_packets: int = 0
        self.simulated_blocks: int = 0
        self.allow_decisions: int = 0
        self.alert_decisions: int = 0

        # Optional external hook for physically forwarding or dropping packets
        self.on_packet_drop_hook: Optional[Callable[[ParsedPacket, str], None]] = None
        self.on_packet_forward_hook: Optional[Callable[[ParsedPacket], None]] = None

        # Background auto-expiration reaper
        self._reaper_stop = threading.Event()
        self._reaper_thread: Optional[threading.Thread] = None
        self._start_auto_reaper()

    def _load_default_firewall_rules(self) -> None:
        """Loads baseline protocol rules."""
        # Rule 1: Block cleartext Telnet
        self.static_rules.append(
            FirewallRule(
                rule_id="RULE_BLOCK_TELNET",
                action=DecisionAction.BLOCK,
                protocol="TCP",
                dst_ports={23},
                description="Block unencrypted Telnet port 23",
            )
        )
        # Rule 2: Block SMB from WAN
        self.static_rules.append(
            FirewallRule(
                rule_id="RULE_BLOCK_WAN_SMB",
                action=DecisionAction.BLOCK,
                protocol="TCP",
                dst_ports={445, 139},
                direction="INBOUND",
                description="Block incoming SMB file sharing",
            )
        )

    # --- Mode & Control APIs ---

    @property
    def actual_verified_drops(self) -> int:
        return self.actual_dropped_packets

    def is_allowlisted(self, packet: ParsedPacket) -> bool:
        """Determines if a packet is protected by the safety allowlist."""
        return self.allowlist_denylist.is_allowlisted(packet)

    def enable_active_prevention(self, force: bool = False) -> bool:
        """Enables active dropping of packets (after controlled verification)."""
        if not self.firewall_enforcer.is_admin and not force:
            logger.warning(
                "[!] Windows Administrator privileges NOT detected. "
                "Windows Defender Firewall rule creation is disabled on OS. "
                "Active prevention enabled in software hook mode."
            )
        self.active_prevention = True
        logger.warning("IPS ACTIVE PREVENTION ENABLED: Confirmed threat traffic will be dropped.")
        return True

    def disable_active_prevention(self) -> None:
        """Reverts to safe monitoring and simulation mode."""
        self.active_prevention = False
        logger.info("IPS reverted to MONITORING / SIMULATION mode. No packets will be physically dropped.")

    def _start_auto_reaper(self) -> None:
        """Starts background daemon to reap expired bans and release firewall rules."""
        def _reap_loop():
            while not self._reaper_stop.is_set():
                try:
                    self.clean_expired_bans()
                except Exception as e:
                    logger.debug(f"Auto-reaper background exception: {e}")
                time.sleep(1.0)

        self._reaper_thread = threading.Thread(
            target=_reap_loop,
            name="IPS-AutoReaper",
            daemon=True,
        )
        self._reaper_thread.start()

    def clean_expired_bans(self, now: Optional[float] = None) -> List[str]:
        """Scans dynamic blocks and firewall enforcer to clean up expired entries."""
        ts = now if now is not None else time.time()
        self.dynamic_blocks.clean_expired(ts)
        expired_fw = self.firewall_enforcer.clean_expired_rules(ts)
        return expired_fw

    def shutdown(self) -> None:
        """Gracefully shuts down reaper and flushes all Windows Firewall rules."""
        self._reaper_stop.set()
        if self._reaper_thread and self._reaper_thread.is_alive():
            self._reaper_thread.join(timeout=1.0)
        self.firewall_enforcer.flush_all_rules()

    def trigger_emergency_killswitch(self, reason: str = "Admin Override") -> None:
        """Instantly activates fail-open bypass, stopping all packet drops."""
        self.killswitch.activate(reason)
        self.active_prevention = False

    def reset_emergency_killswitch(self) -> None:
        """Deactivates killswitch, resuming configured IPS operation."""
        self.killswitch.deactivate()

    # --- Policy & Rule Management APIs ---

    def register_client_policy(self, policy: ClientSecurityPolicy) -> None:
        """Registers a dedicated security policy for a client IP."""
        self.client_policies[policy.client_ip] = policy
        logger.info(f"Registered custom security policy for client: {policy.client_ip}")

    def add_firewall_rule(self, rule: FirewallRule) -> None:
        """Adds a static or protocol-based firewall rule."""
        self.static_rules.append(rule)

    def add_allowlisted_ip(self, ip_or_cidr: str) -> None:
        self.allowlist_denylist.add_allowlist_ip(ip_or_cidr)

    def add_denylisted_ip(self, ip_or_cidr: str) -> None:
        self.allowlist_denylist.add_denylist_ip(ip_or_cidr)

    def add_temporary_block(self, ip_address: str, duration_seconds: float, reason: str) -> TemporaryBlock:
        return self.dynamic_blocks.add_block(ip_address, reason, duration_seconds=duration_seconds)

    def unblock_ip(self, ip_address: str) -> bool:
        return self.dynamic_blocks.unblock(ip_address)

    # --- Core Enforcement Pipeline ---

    def evaluate_and_enforce(
        self,
        packet: ParsedPacket,
        dpi_result: Optional[DPIResult] = None,
        alerts: Optional[List[IDSAlert]] = None,
        is_outbound: bool = True,
        client_ip: Optional[str] = None,
    ) -> IPSEnforcementResult:
        """
        Executes the full IPS policy evaluation pipeline.

        Distinguishes:
            - Intercepted packets
            - Security block decisions
            - Actual dropped packets
            - Forwarded / reinjected packets
        """
        self.intercepted_packets += 1
        now = packet.timestamp or time.time()
        length = packet.raw_length or len(packet.payload)

        src_ip = packet.ipv4.src_ip if packet.ipv4 else (packet.ipv6.src_ip if packet.ipv6 else "")
        dst_ip = packet.ipv4.dst_ip if packet.ipv4 else (packet.ipv6.dst_ip if packet.ipv6 else "")
        src_port = packet.tcp.src_port if packet.tcp else (packet.udp.src_port if packet.udp else 0)
        dst_port = packet.tcp.dst_port if packet.tcp else (packet.udp.dst_port if packet.udp else 0)
        proto = packet.transport_type if packet.transport_type != "None" else packet.network_type

        # 1. Emergency Killswitch (Fail-Open Bypass)
        if self.killswitch.is_active:
            self.allow_decisions += 1
            self.forwarded_or_reinjected_packets += 1
            if self.on_packet_forward_hook:
                self.on_packet_forward_hook(packet)
            return IPSEnforcementResult(
                decision=DecisionAction.ALLOW,
                effective_action="ALLOW",
                is_forwarded=True,
                reason=f"Bypass: Emergency Killswitch Active ({self.killswitch.trigger_reason})",
            )

        # 2. Safety Allowlist (Protects Gateway, DHCP, DNS, Loopback from blocks)
        if self.allowlist_denylist.is_allowlisted(packet):
            if alerts:
                self.alert_decisions += 1
            else:
                self.allow_decisions += 1
            self.forwarded_or_reinjected_packets += 1
            if self.on_packet_forward_hook:
                self.on_packet_forward_hook(packet)
            return IPSEnforcementResult(
                decision=DecisionAction.ALLOW,
                effective_action="ALLOW",
                is_forwarded=True,
                reason="Traffic protected by safety allowlist",
            )

        # 3. Static Denylist Check (Unconditional Instant Drop)
        is_denied, deny_reason = self.allowlist_denylist.is_denylisted(packet)
        if is_denied:
            return self._enforce_block(packet, deny_reason, matched_rule="STATIC_DENYLIST")

        # 4. Dynamic Expirable Bans Check
        is_dyn_blocked, dyn_ban = self.dynamic_blocks.is_blocked(src_ip, now)
        if is_dyn_blocked and dyn_ban:
            rem = dyn_ban.time_remaining(now)
            return self._enforce_block(
                packet,
                f"Source IP {src_ip} is under dynamic temporary block ({rem:.1f}s remaining): {dyn_ban.reason}",
                matched_rule="DYNAMIC_BLOCK",
            )

        # 5. Client Security Policy Enforcement
        effective_client_ip = client_ip or (src_ip if is_outbound else dst_ip)
        if effective_client_ip in self.client_policies:
            policy = self.client_policies[effective_client_ip]
            app_proto = dpi_result.protocol if dpi_result else ""
            pol_allowed, pol_reason = policy.evaluate(packet, app_proto)
            if not pol_allowed:
                return self._enforce_block(packet, pol_reason, matched_rule="CLIENT_SECURITY_POLICY")

        # 6. Rate Limiting Check (Token Bucket)
        rate_key = src_ip if is_outbound else dst_ip
        rate_ok, rate_reason = self.rate_limiter.check_rate_limit(rate_key, length, now)
        if not rate_ok:
            return self._enforce_block(packet, rate_reason, matched_rule="RATE_LIMITER")

        # 7. Static / Protocol-based Firewall Rules
        for rule in self.static_rules:
            if rule.matches(packet, is_outbound):
                if rule.action == DecisionAction.BLOCK:
                    return self._enforce_block(packet, rule.description or f"Rule {rule.rule_id}", matched_rule=rule.rule_id)

        # 8. Stateful Firewall Inspection (Connection States: NEW, ESTABLISHED, RELATED, INVALID)
        fw_res = self.stateful_firewall.evaluate_packet(packet, is_outbound_from_client=is_outbound)
        if fw_res.action == FirewallAction.DROP:
            return self._enforce_block(packet, fw_res.reason, matched_rule="STATEFUL_FIREWALL", state=fw_res.state)

        # 9. IDS Alerts & Dynamic Block Promotion
        active_alerts = alerts or []
        has_block_alert = any(
            a.recommended_action == DecisionAction.BLOCK or a.severity == Severity.CRITICAL
            for a in active_alerts
        )

        if has_block_alert:
            crit_alert = next(
                (a for a in active_alerts if a.recommended_action == DecisionAction.BLOCK or a.severity == Severity.CRITICAL),
                active_alerts[0],
            )
            # Automatic promotion of critical attack to temporary dynamic block
            ban = self.dynamic_blocks.add_block(
                ip_address=src_ip,
                reason=crit_alert.matched_rule,
                severity=crit_alert.severity,
                duration_seconds=self.default_ban_seconds,
                alert_id=crit_alert.alert_id,
            )
            # Mark flow in stateful firewall so subsequent packets fast-path drop
            self.stateful_firewall.block_connection(proto, src_ip, src_port, dst_ip, dst_port, crit_alert.matched_rule)

            return self._enforce_block(
                packet,
                f"IDS Decision BLOCK: {crit_alert.matched_rule} (Evidence: {crit_alert.evidence})",
                matched_rule=f"IDS_ALERT_{crit_alert.category.value}",
                dynamic_ban_issued=True,
                ban_seconds=ban.duration_seconds,
            )

        # 10. All checks passed -> Packet Allowed & Forwarded
        if active_alerts:
            self.alert_decisions += 1
        else:
            self.allow_decisions += 1
        self.forwarded_or_reinjected_packets += 1
        if self.on_packet_forward_hook:
            self.on_packet_forward_hook(packet)

        return IPSEnforcementResult(
            decision=DecisionAction.ALERT if active_alerts else DecisionAction.ALLOW,
            effective_action="ALERT" if active_alerts else "ALLOW",
            is_forwarded=True,
            reason="Traffic Permitted with Security Alert" if active_alerts else "Traffic Permitted",
            state=fw_res.state,
        )

    def _enforce_block(
        self,
        packet: ParsedPacket,
        reason: str,
        matched_rule: str,
        state: ConnectionState = ConnectionState.NEW,
        dynamic_ban_issued: bool = False,
        ban_seconds: float = 0.0,
    ) -> IPSEnforcementResult:
        """Applies the block decision adhering to Simulation vs Active Prevention mode."""
        self.security_block_decisions += 1
        src_ip = packet.ipv4.src_ip if packet.ipv4 else (packet.ipv6.src_ip if packet.ipv6 else "")

        if self.active_prevention:
            # Mode: ACTIVE PREVENTION
            fw_success = False
            if src_ip:
                fw_success = self.firewall_enforcer.block_ip(
                    ip=src_ip,
                    reason=reason,
                    duration_seconds=ban_seconds or self.default_ban_seconds,
                    now=packet.timestamp,
                )

            if fw_success:
                self.actual_dropped_packets += 1
                if self.on_packet_drop_hook:
                    self.on_packet_drop_hook(packet, reason)

                logger.warning(
                    f"[IPS ACTUAL BLOCK] Packet {packet.packet_id} DROPPED via OS Firewall rule. "
                    f"Rule: {matched_rule}. Reason: {reason}"
                )
                return IPSEnforcementResult(
                    decision=DecisionAction.BLOCK,
                    effective_action="ACTUAL_BLOCK",
                    is_forwarded=False,
                    reason=f"ACTUAL BLOCK (Packet Dropped): {reason}",
                    matched_rule=matched_rule,
                    state=state,
                    dynamic_ban_issued=dynamic_ban_issued,
                    ban_seconds=ban_seconds,
                    enforcement_succeeded=True,
                )
            else:
                # Firewall rule creation failed on OS
                logger.error(
                    f"[IPS ENFORCEMENT FAILED] Failed to apply OS firewall rule for {src_ip}. "
                    f"Rule: {matched_rule}. Reason: {reason}. Dropped in user-space software only."
                )
                if self.on_packet_drop_hook:
                    self.on_packet_drop_hook(packet, reason)

                return IPSEnforcementResult(
                    decision=DecisionAction.BLOCK,
                    effective_action="SOFTWARE_ONLY_BLOCK",
                    is_forwarded=False,
                    reason=f"SOFTWARE_ONLY_BLOCK (Firewall Rule Creation Failed): {reason}",
                    matched_rule=matched_rule,
                    state=state,
                    dynamic_ban_issued=dynamic_ban_issued,
                    ban_seconds=ban_seconds,
                    enforcement_succeeded=False,
                )
        else:
            # Mode: MONITORING / SIMULATION -> Decision is logged, but packet is NOT dropped
            self.simulated_blocks += 1
            self.forwarded_or_reinjected_packets += 1
            if self.on_packet_forward_hook:
                self.on_packet_forward_hook(packet)

            logger.info(f"[IPS SIMULATION] Packet {packet.packet_id} would be blocked. Rule: {matched_rule}. Reason: {reason}")
            return IPSEnforcementResult(
                decision=DecisionAction.BLOCK,
                effective_action="SIMULATED_BLOCK",
                is_forwarded=True,
                reason=f"SIMULATED BLOCK (Traffic Not Dropped): {reason}",
                matched_rule=matched_rule,
                state=state,
                dynamic_ban_issued=dynamic_ban_issued,
                ban_seconds=ban_seconds,
                enforcement_succeeded=False,
            )

    # Backward compatibility with existing Phase 2 handle_decision API
    def handle_decision(
        self,
        decision: DecisionAction,
        packet: ParsedPacket,
        alerts: Optional[List[IDSAlert]] = None,
    ) -> Tuple[DecisionAction, str]:
        """Provides backward-compatible interface for legacy worker loop."""
        if decision == DecisionAction.ALLOW:
            self.intercepted_packets += 1
            self.allow_decisions += 1
            self.forwarded_or_reinjected_packets += 1
            return DecisionAction.ALLOW, "Traffic Allowed"

        if decision == DecisionAction.ALERT:
            self.intercepted_packets += 1
            self.alert_decisions += 1
            self.forwarded_or_reinjected_packets += 1
            return DecisionAction.ALERT, "Traffic Allowed with Alert"

        if decision == DecisionAction.BLOCK:
            # 1. Safety Allowlist override check
            if self.is_allowlisted(packet):
                self.intercepted_packets += 1
                logger.info("Block decision overridden by safety allowlist.")
                self.alert_decisions += 1
                self.forwarded_or_reinjected_packets += 1
                return DecisionAction.ALERT, "Block Overridden by Allowlist"

            # 2. Emergency Killswitch bypass check
            if self.killswitch.is_active:
                self.intercepted_packets += 1
                self.security_block_decisions += 1
                self.simulated_blocks += 1
                self.forwarded_or_reinjected_packets += 1
                return DecisionAction.BLOCK, "SIMULATED BLOCK (Traffic Not Dropped)"

            # 3. Simulation Mode check
            if not self.active_prevention:
                self.intercepted_packets += 1
                self.security_block_decisions += 1
                self.simulated_blocks += 1
                self.forwarded_or_reinjected_packets += 1
                return DecisionAction.BLOCK, "SIMULATED BLOCK (Traffic Not Dropped)"

            # 4. Active Prevention Mode: invoke enforcement pipeline
            active_alerts = alerts or []
            has_block_alert = any(
                a.recommended_action == DecisionAction.BLOCK or a.severity == Severity.CRITICAL
                for a in active_alerts
            )
            if has_block_alert:
                res = self.evaluate_and_enforce(packet=packet, alerts=alerts)
                return res.decision, res.reason
            else:
                self.intercepted_packets += 1
                res = self._enforce_block(
                    packet=packet,
                    reason="Decision Engine BLOCK",
                    matched_rule="DECISION_ENGINE_BLOCK",
                )
                return res.decision, res.reason

        res = self.evaluate_and_enforce(packet=packet, alerts=alerts)
        return res.decision, res.reason
