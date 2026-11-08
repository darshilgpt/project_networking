"""WireGuard Server and Client configuration generator and peer manager."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import ipaddress
import json
import logging
import os
import socket
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

logger = logging.getLogger("dpi_ids_ips.server.wireguard")


def generate_keypair() -> Tuple[str, str]:
    """
    Generates a cryptographically valid Curve25519 keypair for WireGuard.

    Returns:
        Tuple of (base64_private_key, base64_public_key)
    """
    priv_key = X25519PrivateKey.generate()
    priv_bytes = priv_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    pub_bytes = priv_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    priv_b64 = base64.b64encode(priv_bytes).decode("ascii")
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")
    return priv_b64, pub_b64


def generate_preshared_key() -> str:
    """Generates a random 32-byte pre-shared key for post-quantum resistance."""
    return base64.b64encode(os.urandom(32)).decode("ascii")


def detect_server_lan_ip() -> str:
    """Detects the primary outbound LAN IPv4 address of the Windows server."""
    try:
        # Probe using standard UDP socket (does not transmit packets)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


@dataclass
class WireGuardPeer:
    """Metadata and keys for an authenticated WireGuard client peer (e.g. laptop)."""
    peer_name: str
    private_key: str
    public_key: str
    assigned_ip: str
    allowed_ips: str = "0.0.0.0/0, ::/0"  # Full tunnel default
    dns_servers: str = "1.1.1.1, 8.8.8.8"
    preshared_key: Optional[str] = None
    persistent_keepalive: int = 25

    def to_client_conf(self, server_public_key: str, server_endpoint: str) -> str:
        """Renders the client .conf file for this peer."""
        lines = [
            "# ===========================================================",
            f"# WireGuard Client Configuration for: {self.peer_name}",
            "# Import this configuration into WireGuard on the client laptop",
            "# ===========================================================",
            "[Interface]",
            f"PrivateKey = {self.private_key}",
            f"Address = {self.assigned_ip}/24",
            f"DNS = {self.dns_servers}",
            "",
            "[Peer]",
            f"PublicKey = {server_public_key}",
            f"Endpoint = {server_endpoint}",
            f"AllowedIPs = {self.allowed_ips}",
            f"PersistentKeepalive = {self.persistent_keepalive}",
        ]
        if self.preshared_key:
            lines.append(f"PresharedKey = {self.preshared_key}")
        lines.append("")
        return "\n".join(lines)


@dataclass
class WireGuardServerConfig:
    """Encapsulates WireGuard server endpoint configuration and registered peers."""
    server_private_key: str
    server_public_key: str
    listen_port: int = 51820
    server_ip: str = "10.8.0.1"
    subnet_cidr: str = "10.8.0.0/24"
    endpoint_host: str = ""
    peers: List[WireGuardPeer] = field(default_factory=list)

    def to_server_conf(self) -> str:
        """Renders the Windows server wg0.conf configuration."""
        lines = [
            "# ===========================================================",
            "# Central Windows WireGuard Security Server Endpoint Configuration",
            "# ===========================================================",
            "[Interface]",
            f"PrivateKey = {self.server_private_key}",
            f"Address = {self.server_ip}/24",
            f"ListenPort = {self.listen_port}",
            "",
        ]

        for peer in self.peers:
            lines.append(f"# Peer: {peer.peer_name}")
            lines.append("[Peer]")
            lines.append(f"PublicKey = {peer.public_key}")
            lines.append(f"AllowedIPs = {peer.assigned_ip}/32")
            if peer.preshared_key:
                lines.append(f"PresharedKey = {peer.preshared_key}")
            lines.append("")

        return "\n".join(lines)


class WireGuardManager:
    """Manages WireGuard configuration lifecycle, peer provisioning, and key management."""

    def __init__(
        self,
        config_dir: str = "wireguard_config",
        subnet_cidr: str = "10.8.0.0/24",
        listen_port: int = 51820,
        server_endpoint: Optional[str] = None,
    ) -> None:
        self.config_dir = config_dir
        self.subnet_cidr = subnet_cidr
        self.listen_port = listen_port
        self.server_endpoint = server_endpoint or f"{detect_server_lan_ip()}:{listen_port}"
        self.server_config: Optional[WireGuardServerConfig] = None

    def initialize_server(
        self,
        peer_names: Optional[List[str]] = None,
        use_preshared_keys: bool = False,
    ) -> WireGuardServerConfig:
        """
        Provisions a complete WireGuard server configuration with multiple authenticated client peers.

        Args:
            peer_names: Names/labels for client laptops (default: ['Laptop-1', 'Laptop-2', 'Laptop-3']).
            use_preshared_keys: Whether to generate pre-shared symmetric keys.

        Returns:
            Populated WireGuardServerConfig.
        """
        if not peer_names:
            peer_names = ["Laptop-1", "Laptop-2", "Laptop-3"]

        s_priv, s_pub = generate_keypair()
        net = ipaddress.ip_network(self.subnet_cidr, strict=False)
        hosts = list(net.hosts())

        server_ip = str(hosts[0])  # e.g. 10.8.0.1

        server_cfg = WireGuardServerConfig(
            server_private_key=s_priv,
            server_public_key=s_pub,
            listen_port=self.listen_port,
            server_ip=server_ip,
            subnet_cidr=self.subnet_cidr,
            endpoint_host=self.server_endpoint,
        )

        # Allocate unique consecutive VPN IPs to peers
        for idx, name in enumerate(peer_names, start=1):
            if idx >= len(hosts):
                raise ValueError(f"Subnet {self.subnet_cidr} has exhausted available host IPs.")
            c_priv, c_pub = generate_keypair()
            psk = generate_preshared_key() if use_preshared_keys else None
            client_ip = str(hosts[idx])  # 10.8.0.2, 10.8.0.3, ...

            peer = WireGuardPeer(
                peer_name=name,
                private_key=c_priv,
                public_key=c_pub,
                assigned_ip=client_ip,
                preshared_key=psk,
            )
            server_cfg.peers.append(peer)

        self.server_config = server_cfg
        return server_cfg

    def save_configs(self) -> Dict[str, str]:
        """
        Writes all server and client .conf files to disk in config_dir.

        Returns:
            Dictionary mapping filename to absolute path.
        """
        if not self.server_config:
            raise RuntimeError("Server configuration not initialized. Call initialize_server() first.")

        os.makedirs(self.config_dir, exist_ok=True)
        clients_dir = os.path.join(self.config_dir, "clients")
        os.makedirs(clients_dir, exist_ok=True)

        written_files = {}

        # 1. Server config: wg0_server.conf
        server_conf_path = os.path.join(self.config_dir, "wg0.conf")
        with open(server_conf_path, "w", encoding="utf-8") as f:
            f.write(self.server_config.to_server_conf())
        written_files["server_conf"] = os.path.abspath(server_conf_path)

        # 2. Client configs: clients/<peer_name>.conf
        for peer in self.server_config.peers:
            filename = f"{peer.peer_name.lower().replace(' ', '_')}.conf"
            client_path = os.path.join(clients_dir, filename)
            client_text = peer.to_client_conf(
                server_public_key=self.server_config.server_public_key,
                server_endpoint=self.server_config.endpoint_host,
            )
            with open(client_path, "w", encoding="utf-8") as f:
                f.write(client_text)
            written_files[peer.peer_name] = os.path.abspath(client_path)

        # 3. JSON summary mapping for easy automation and client manager registration
        summary_path = os.path.join(self.config_dir, "wireguard_peers.json")
        summary_data = {
            "server": {
                "server_ip": self.server_config.server_ip,
                "subnet": self.server_config.subnet_cidr,
                "listen_port": self.server_config.listen_port,
                "endpoint": self.server_config.endpoint_host,
                "public_key": self.server_config.server_public_key,
            },
            "peers": [
                {
                    "name": p.peer_name,
                    "vpn_ip": p.assigned_ip,
                    "public_key": p.public_key,
                    "conf_file": os.path.join("clients", f"{p.peer_name.lower().replace(' ', '_')}.conf"),
                }
                for p in self.server_config.peers
            ],
        }
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=2)
        written_files["peers_json"] = os.path.abspath(summary_path)

        logger.info(f"Saved WireGuard configs to {self.config_dir} ({len(self.server_config.peers)} client profiles)")
        return written_files

    @staticmethod
    def load_peers_mapping(json_path: str) -> Dict[str, str]:
        """Loads {vpn_ip: peer_name} from a wireguard_peers.json file."""
        if not os.path.exists(json_path):
            return {}
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return {p["vpn_ip"]: p["name"] for p in data.get("peers", [])}
        except Exception as e:
            logger.warning(f"Could not load peers from {json_path}: {e}")
            return {}

