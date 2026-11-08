"""Threat Intelligence and Reputation Engine for IP addresses and domain names."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Set

from models.alert_model import DecisionAction, DetectionCategory, IDSAlert, Severity

logger = logging.getLogger("dpi_ids_ips.ids.reputation")


@dataclass
class ThreatIndicator:
    """Represents a known malicious indicator (IP, CIDR, or domain)."""
    indicator: str
    category: str  # C2, SCANNER, PHISHING, MALWARE, TOR_EXIT, RECON
    threat_level: Severity
    description: str
    first_seen: float = field(default_factory=time.time)
    confidence: float = 1.0  # 0.0 to 1.0


class ReputationEngine:
    """Evaluates IP addresses and domain names against threat intelligence feeds."""

    def __init__(self, feed_path: Optional[str] = None) -> None:
        self.malicious_ips: Dict[str, ThreatIndicator] = {}
        self.malicious_subnets: List[Tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ThreatIndicator]] = []
        self.malicious_domains: Dict[str, ThreatIndicator] = {}
        self.suspicious_tlds: Set[str] = {".top", ".xyz", ".buzz", ".click", ".onion", ".tk", ".work"}

        # Built-in seed intelligence
        self._load_seed_intel()

        # Load external feed if present
        if feed_path and os.path.exists(feed_path):
            self.load_feed(feed_path)

        # Statistics
        self.total_ip_lookups = 0
        self.total_domain_lookups = 0
        self.total_reputation_matches = 0

    def _load_seed_intel(self) -> None:
        """Seeds known malicious indicators for testing and baseline protection."""
        # Known C2 / attack IPs
        seeds = [
            ("198.51.100.23", "C2", Severity.CRITICAL, "Known Cobalt Strike C2 server"),
            ("203.0.113.88", "SCANNER", Severity.HIGH, "Mirai botnet scanning node"),
            ("185.220.101.5", "TOR_EXIT", Severity.MEDIUM, "Tor exit node used in brute force"),
            ("45.154.255.99", "MALWARE", Severity.CRITICAL, "Emotet malware delivery host"),
            ("192.0.2.66", "RECON", Severity.HIGH, "Masscan / Shodan reconnaissance scanner"),
        ]
        for ip, cat, sev, desc in seeds:
            self.add_ip_indicator(ip, cat, sev, desc)

        # Known malicious domains
        domain_seeds = [
            ("evil-c2-server.com", "C2", Severity.CRITICAL, "Known ransomware C2 domain"),
            ("phishing-bank-login.xyz", "PHISHING", Severity.HIGH, "Credential harvesting portal"),
            ("crypto-miner-pool.top", "MALWARE", Severity.MEDIUM, "Cryptojacking mining pool"),
            ("malicious-payload-drop.buzz", "MALWARE", Severity.CRITICAL, "Trojan dropper URL domain"),
        ]
        for domain, cat, sev, desc in domain_seeds:
            self.add_domain_indicator(domain, cat, sev, desc)

    def add_ip_indicator(
        self,
        ip_or_cidr: str,
        category: str,
        severity: Severity,
        description: str,
        confidence: float = 1.0,
    ) -> None:
        """Adds an IP address or CIDR range to the reputation database."""
        indicator = ThreatIndicator(
            indicator=ip_or_cidr,
            category=category,
            threat_level=severity,
            description=description,
            confidence=confidence,
        )
        if "/" in ip_or_cidr:
            try:
                net = ipaddress.ip_network(ip_or_cidr, strict=False)
                self.malicious_subnets.append((net, indicator))
            except ValueError:
                logger.warning(f"Invalid CIDR in reputation feed: {ip_or_cidr}")
        else:
            self.malicious_ips[ip_or_cidr] = indicator

    def add_domain_indicator(
        self,
        domain: str,
        category: str,
        severity: Severity,
        description: str,
        confidence: float = 1.0,
    ) -> None:
        """Adds a domain to the reputation database."""
        norm_domain = domain.strip().lower().rstrip(".")
        self.malicious_domains[norm_domain] = ThreatIndicator(
            indicator=norm_domain,
            category=category,
            threat_level=severity,
            description=description,
            confidence=confidence,
        )

    def load_feed(self, feed_path: str) -> None:
        """Loads reputation feed from JSON file."""
        try:
            with open(feed_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for item in data.get("ips", []):
                sev = Severity[item.get("severity", "HIGH")]
                self.add_ip_indicator(
                    item["ip"],
                    item.get("category", "MALWARE"),
                    sev,
                    item.get("description", "Malicious IP"),
                )
            for item in data.get("domains", []):
                sev = Severity[item.get("severity", "HIGH")]
                self.add_domain_indicator(
                    item["domain"],
                    item.get("category", "MALWARE"),
                    sev,
                    item.get("description", "Malicious Domain"),
                )
            logger.info(f"Loaded threat intelligence feed from '{feed_path}'")
        except Exception as e:
            logger.error(f"Failed loading threat feed from {feed_path}: {e}")

    def check_ip(self, ip_str: str) -> Optional[ThreatIndicator]:
        """Checks an IP address against the reputation database."""
        self.total_ip_lookups += 1
        if not ip_str or ip_str in ("0.0.0.0", "127.0.0.1", "::1"):
            return None

        # 1. Exact IP match O(1)
        if ip_str in self.malicious_ips:
            self.total_reputation_matches += 1
            return self.malicious_ips[ip_str]

        # 2. Subnet CIDR match
        try:
            addr = ipaddress.ip_address(ip_str)
            for net, indicator in self.malicious_subnets:
                if addr in net:
                    self.total_reputation_matches += 1
                    return indicator
        except ValueError:
            pass

        return None

    def check_domain(self, domain_name: str) -> Optional[ThreatIndicator]:
        """Checks a domain name and its parent domains against the reputation database."""
        self.total_domain_lookups += 1
        if not domain_name:
            return None

        clean = domain_name.strip().lower().rstrip(".")
        parts = clean.split(".")

        # Check exact domain and parent hierarchy (e.g. sub.evil-c2-server.com -> evil-c2-server.com)
        for i in range(len(parts) - 1):
            sub = ".".join(parts[i:])
            if sub in self.malicious_domains:
                self.total_reputation_matches += 1
                return self.malicious_domains[sub]

        # Check suspicious TLD
        for tld in self.suspicious_tlds:
            if clean.endswith(tld):
                return ThreatIndicator(
                    indicator=clean,
                    category="SUSPICIOUS_TLD",
                    threat_level=Severity.LOW,
                    description=f"Domain uses high-abuse top-level domain '{tld}'",
                    confidence=0.6,
                )

        return None

