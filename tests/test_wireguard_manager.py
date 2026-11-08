"""Unit tests for WireGuard configuration generator and peer manager."""

import os
import tempfile

from server.wireguard_manager import WireGuardManager, generate_keypair, generate_preshared_key


def test_generate_keypair():
    """Verifies that generated Curve25519 keys are valid base64 strings."""
    priv, pub = generate_keypair()
    assert len(priv) == 44
    assert len(pub) == 44
    assert priv != pub


def test_generate_preshared_key():
    """Verifies that generated PSK is a 32-byte base64 string."""
    psk = generate_preshared_key()
    assert len(psk) == 44


def test_initialize_server_multi_peer_unique_ips():
    """Verifies server initialization with multiple peers assigning unique consecutive VPN IPs."""
    manager = WireGuardManager(subnet_cidr="10.8.0.0/24", listen_port=51820)
    peers = ["Laptop-A", "Laptop-B", "Laptop-C"]
    cfg = manager.initialize_server(peer_names=peers)

    assert cfg.server_ip == "10.8.0.1"
    assert len(cfg.peers) == 3

    ips = [p.assigned_ip for p in cfg.peers]
    assert ips == ["10.8.0.2", "10.8.0.3", "10.8.0.4"]
    # All IPs are unique
    assert len(set(ips)) == 3

    # Check full-tunnel routing configuration
    for p in cfg.peers:
        conf_text = p.to_client_conf(server_public_key=cfg.server_public_key, server_endpoint="1.2.3.4:51820")
        assert "AllowedIPs = 0.0.0.0/0, ::/0" in conf_text
        assert f"Address = {p.assigned_ip}/24" in conf_text
        assert "Endpoint = 1.2.3.4:51820" in conf_text


def test_save_and_load_peers_mapping():
    """Verifies saving server and client configs to disk and loading peer mapping."""
    with tempfile.TemporaryDirectory() as tmpdir:
        manager = WireGuardManager(config_dir=tmpdir, subnet_cidr="10.8.0.0/24")
        manager.initialize_server(peer_names=["Alice", "Bob"])
        files = manager.save_configs()

        assert os.path.exists(files["server_conf"])
        assert os.path.exists(files["peers_json"])

        mapping = WireGuardManager.load_peers_mapping(files["peers_json"])
        assert mapping["10.8.0.2"] == "Alice"
        assert mapping["10.8.0.3"] == "Bob"

