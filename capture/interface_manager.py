"""Network Interface Manager for discovering, displaying, and selecting capture interfaces."""

from __future__ import annotations

import logging
import re
import sys
from typing import List, Optional

from scapy.all import conf
from scapy.arch.windows import get_windows_if_list

from models.packet_models import InterfaceInfo

logger = logging.getLogger("dpi_ids_ips.capture.interface_manager")


class InterfaceManager:
    """Discovers and manages network interfaces for live packet capture."""

    @staticmethod
    def _is_wifi(name: str, desc: str, if_type: int = 0) -> bool:
        """Determines if the interface is likely a Wi-Fi adapter."""
        target = f"{name} {desc}".lower()
        if if_type == 71:  # IF_TYPE_IEEE80211
            return True
        keywords = ["wi-fi", "wifi", "802.11", "wireless", "wlan"]
        return any(kw in target for kw in keywords)

    @staticmethod
    def _is_wireguard(name: str, desc: str) -> tuple[bool, Optional[str]]:
        """Determines if the interface is a WireGuard or Wintun virtual tunnel adapter."""
        target = f"{name} {desc}".lower()
        if "wireguard" in target:
            return True, "WireGuard"
        if "wintun" in target:
            return True, "Wintun"
        # Match standalone 'wg' or 'wg0', 'wg1'
        if re.search(r"\bwg\d*\b", target):
            return True, "WireGuard"
        if "tunnel" in target or "tun" in target.split():
            return True, "Tunnel"
        return False, None

    @classmethod
    def get_interfaces(cls) -> List[InterfaceInfo]:
        """
        Enumerates valid network interfaces available for packet capture on Windows.

        Returns:
            List of InterfaceInfo objects.
        """
        interfaces: List[InterfaceInfo] = []

        # Query Windows network interface list
        win_if_map = {}
        try:
            for item in get_windows_if_list():
                # Filter out filter driver clones (e.g., -0000)
                name = item.get("name", "")
                if "-0000" in name:
                    continue
                guid = item.get("guid", "").strip("{}").lower()
                win_if_map[guid] = item
                win_if_map[name.lower()] = item
        except Exception as e:
            logger.warning(f"Could not retrieve Windows native interface list: {e}")

        # Query Scapy's registered interfaces
        scapy_ifaces = list(conf.ifaces.values())

        # If Scapy has registered interfaces, prioritize those that Npcap can capture on
        index = 1
        seen_names = set()
        seen_guids = set()

        for s_iface in scapy_ifaces:
            guid = getattr(s_iface, "guid", "") or ""
            norm_guid = guid.strip("{}").lower()
            name = getattr(s_iface, "name", "") or "Unnamed"
            desc = getattr(s_iface, "description", "") or name
            mac = getattr(s_iface, "mac", "") or ""

            if name in seen_names or (norm_guid and norm_guid in seen_guids):
                continue

            # Check matching windows metadata
            win_meta = win_if_map.get(norm_guid) or win_if_map.get(name.lower(), {})
            if_type = win_meta.get("type", 0)

            # Extract IP addresses
            ipv4_list: List[str] = []
            ipv6_list: List[str] = []

            # Check Scapy IPs
            ips_raw = getattr(s_iface, "ips", None)
            if isinstance(ips_raw, dict):
                ipv4_list.extend(ips_raw.get(4, []))
                ipv6_list.extend(ips_raw.get(6, []))
            elif isinstance(ips_raw, list):
                for ip in ips_raw:
                    if ":" in ip:
                        ipv6_list.append(ip)
                    else:
                        ipv4_list.append(ip)

            # Fall back to Windows metadata IPs if not present
            if not ipv4_list and not ipv6_list and "ips" in win_meta:
                for ip in win_meta.get("ips", []):
                    if ":" in ip:
                        ipv6_list.append(ip)
                    else:
                        ipv4_list.append(ip)

            # Fallback to single ip attribute
            single_ip = getattr(s_iface, "ip", None)
            if single_ip and single_ip not in ipv4_list:
                ipv4_list.append(single_ip)

            is_wifi_dev = cls._is_wifi(name, desc, if_type)
            is_tunnel_dev, tunnel_kind = cls._is_wireguard(name, desc)

            info = InterfaceInfo(
                index=index,
                name=name,
                description=desc,
                guid=guid,
                mac=mac or win_meta.get("mac", ""),
                ipv4_addrs=ipv4_list,
                ipv6_addrs=ipv6_list,
                is_wifi=is_wifi_dev,
                is_tunnel=is_tunnel_dev,
                tunnel_type=tunnel_kind,
                scapy_name=getattr(s_iface, "pcap_name", None) or getattr(s_iface, "network_name", None) or name,
                scapy_iface=s_iface,
            )
            interfaces.append(info)
            seen_names.add(name)
            if norm_guid:
                seen_guids.add(norm_guid)
            index += 1

        # If Scapy found nothing, fall back to native Windows interfaces
        if not interfaces:
            for item in get_windows_if_list():
                name = item.get("name", "")
                if "-0000" in name or name in seen_names:
                    continue
                guid = item.get("guid", "")
                norm_guid = guid.strip("{}").lower()
                desc = item.get("description", "")
                mac = item.get("mac", "")
                ips = item.get("ips", [])
                ipv4_list = [ip for ip in ips if ":" not in ip]
                ipv6_list = [ip for ip in ips if ":" in ip]
                is_wifi_dev = cls._is_wifi(name, desc, item.get("type", 0))
                is_tunnel_dev, tunnel_kind = cls._is_wireguard(name, desc)

                info = InterfaceInfo(
                    index=index,
                    name=name,
                    description=desc,
                    guid=guid,
                    mac=mac,
                    ipv4_addrs=ipv4_list,
                    ipv6_addrs=ipv6_list,
                    is_wifi=is_wifi_dev,
                    is_tunnel=is_tunnel_dev,
                    tunnel_type=tunnel_kind,
                    scapy_name=name,
                    scapy_iface=name,
                )
                interfaces.append(info)
                seen_names.add(name)
                index += 1

        # Sort interfaces so active Wi-Fi and interfaces with IPv4 are presented first
        def sort_key(i: InterfaceInfo) -> tuple:
            # 0: Active Wi-Fi with valid IPv4
            # 1: Wi-Fi
            # 2: Other interface with valid IPv4
            # 3: Loopback
            # 4: Everything else
            has_ip = bool(i.ipv4_addrs and not any(ip.startswith("169.254") for ip in i.ipv4_addrs))
            if i.is_wifi and has_ip:
                return (0, i.name)
            if i.is_wifi:
                return (1, i.name)
            if has_ip and "loopback" not in i.name.lower():
                return (2, i.name)
            if "loopback" in i.name.lower():
                return (3, i.name)
            return (4, i.name)

        interfaces.sort(key=sort_key)
        for idx, iface in enumerate(interfaces, 1):
            iface.index = idx

        return interfaces

    @classmethod
    def display_interfaces(cls, interfaces: List[InterfaceInfo]) -> None:
        """Prints a human-readable list of available interfaces."""
        print("=" * 80)
        print("AVAILABLE NETWORK INTERFACES")
        print("=" * 80)

        if not interfaces:
            print("No network interfaces detected. Ensure Npcap is installed and running.")
            print("=" * 80)
            return

        for iface in interfaces:
            wifi_tag = " [Wi-Fi Adapter]" if iface.is_wifi else ""
            tunnel_tag = f" [{iface.tunnel_type or 'Tunnel'} Adapter]" if iface.is_tunnel else ""
            ip_str = ", ".join(iface.ipv4_addrs) if iface.ipv4_addrs else "No IPv4"
            mac_str = iface.mac if iface.mac else "N/A"

            print(f"[{iface.index}] {iface.name}{wifi_tag}{tunnel_tag}")
            print(f"    Description : {iface.description}")
            print(f"    MAC Address : {mac_str}")
            print(f"    IPv4 Address: {ip_str}")
            if iface.ipv6_addrs:
                print(f"    IPv6 Address: {iface.ipv6_addrs[0]}...")
            print("-" * 80)

    @classmethod
    def find_tunnel_interface(cls, interfaces: List[InterfaceInfo]) -> Optional[InterfaceInfo]:
        """Finds a WireGuard or virtual tunnel interface if present."""
        candidates = [i for i in interfaces if i.is_tunnel]
        return candidates[0] if candidates else None

    @classmethod
    def find_wifi_interface(cls, interfaces: List[InterfaceInfo]) -> Optional[InterfaceInfo]:
        """Finds the primary active Wi-Fi interface if present."""
        wifi_candidates = [i for i in interfaces if i.is_wifi]
        if not wifi_candidates:
            return None

        # Prefer Wi-Fi adapter with active IPv4 assignment
        for c in wifi_candidates:
            if c.ipv4_addrs and not any(ip.startswith("169.254") for ip in c.ipv4_addrs):
                return c

        return wifi_candidates[0]

    @classmethod
    def select_interface(
        cls, interfaces: List[InterfaceInfo], choice_input: Optional[str] = None
    ) -> InterfaceInfo:
        """
        Prompts user to select an interface or validates a provided choice string/index.

        Args:
            interfaces: List of available InterfaceInfo objects.
            choice_input: Optional pre-selected choice (index or name).

        Returns:
            The selected InterfaceInfo object.

        Raises:
            ValueError: If the selection is invalid and non-interactive.
        """
        if not interfaces:
            raise RuntimeError("Cannot select interface: No network interfaces available.")

        wifi_default = cls.find_wifi_interface(interfaces)
        default_index = wifi_default.index if wifi_default else 1

        # Programmatic / CLI argument selection
        if choice_input is not None:
            choice_clean = choice_input.strip()

            # By index
            if choice_clean.isdigit():
                idx = int(choice_clean)
                for iface in interfaces:
                    if iface.index == idx:
                        return iface
                raise ValueError(f"Interface index {idx} out of range [1-{len(interfaces)}].")

            # By name / description match
            choice_lower = choice_clean.lower()
            for iface in interfaces:
                if (
                    choice_lower == iface.name.lower()
                    or choice_lower in iface.description.lower()
                    or choice_lower == iface.guid.lower()
                ):
                    return iface

            raise ValueError(f"No interface matching '{choice_input}' found.")

        # Interactive selection
        cls.display_interfaces(interfaces)
        prompt_text = f"Select interface [1-{len(interfaces)}] (Default: {default_index} - {interfaces[default_index-1].name}): "

        while True:
            try:
                user_val = input(prompt_text).strip()
            except (EOFError, KeyboardInterrupt):
                print("\nSelection aborted.")
                sys.exit(0)

            if not user_val:
                # User pressed Enter, choose default
                return interfaces[default_index - 1]

            if user_val.isdigit():
                idx = int(user_val)
                if 1 <= idx <= len(interfaces):
                    return interfaces[idx - 1]
                print(f"Error: Selection {idx} is out of range. Enter a number between 1 and {len(interfaces)}.")
                continue

            # Check if name was typed
            val_lower = user_val.lower()
            matched = [
                i for i in interfaces if val_lower in i.name.lower() or val_lower in i.description.lower()
            ]
            if len(matched) == 1:
                return matched[0]
            elif len(matched) > 1:
                print(f"Multiple interfaces match '{user_val}'. Please select by number:")
                for m in matched:
                    print(f"  [{m.index}] {m.name} ({m.description})")
                continue

            print(f"Error: Invalid selection '{user_val}'. Please enter a valid interface number.")
