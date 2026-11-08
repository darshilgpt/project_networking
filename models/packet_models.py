"""Packet models and structured dataclasses for network protocol dissection."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, List, Optional


@dataclass
class EthernetHeader:
    """Represents an Ethernet II frame header."""
    src_mac: str
    dst_mac: str
    ethertype_code: int
    ethertype_name: str
    vlan_id: Optional[int] = None
    vlan_pcp: Optional[int] = None
    raw_header: bytes = b""

    def __str__(self) -> str:
        vlan_info = f" [VLAN {self.vlan_id}]" if self.vlan_id is not None else ""
        return f"{self.src_mac} -> {self.dst_mac} | Type: {self.ethertype_name} (0x{self.ethertype_code:04X}){vlan_info}"


@dataclass
class IPv4Header:
    """Represents an IPv4 packet header."""
    version: int
    ihl: int  # Header length in 32-bit words (5 = 20 bytes)
    header_length: int  # Header length in bytes (ihl * 4)
    dscp: int
    ecn: int
    total_length: int  # Total packet length in bytes
    identification: int
    flags_raw: int
    flag_df: bool  # Don't fragment
    flag_mf: bool  # More fragments
    fragment_offset: int  # Offset in bytes (raw 13-bit offset * 8)
    ttl: int
    protocol_code: int
    protocol_name: str
    checksum: int
    checksum_valid: Optional[bool]
    src_ip: str
    dst_ip: str
    options: bytes = b""
    raw_header: bytes = b""

    @property
    def is_fragmented(self) -> bool:
        """Indicates if packet is a fragment (either MF set or offset > 0)."""
        return self.flag_mf or self.fragment_offset > 0

    @property
    def flags_str(self) -> str:
        flags: List[str] = []
        if self.flag_df:
            flags.append("DF")
        if self.flag_mf:
            flags.append("MF")
        return ", ".join(flags) if flags else "None"


@dataclass
class IPv6ExtensionHeader:
    """Represents an IPv6 extension header."""
    next_header_code: int
    next_header_name: str
    header_length: int
    data: bytes = b""


@dataclass
class IPv6Header:
    """Represents an IPv6 packet header with potential extension headers."""
    version: int
    traffic_class: int
    flow_label: int
    payload_length: int
    next_header_code: int
    next_header_name: str
    hop_limit: int
    src_ip: str
    dst_ip: str
    extension_headers: List[IPv6ExtensionHeader] = field(default_factory=list)
    upper_protocol_code: int = 0
    upper_protocol_name: str = ""
    raw_header: bytes = b""


@dataclass
class TCPFlags:
    """Decoded TCP control flags."""
    cwr: bool = False
    ece: bool = False
    urg: bool = False
    ack: bool = False
    psh: bool = False
    rst: bool = False
    syn: bool = False
    fin: bool = False
    raw_value: int = 0

    def summary(self) -> str:
        """Returns comma-separated active flag names."""
        active: List[str] = []
        if self.syn and self.ack:
            # Common combined notation check or individual
            pass
        if self.syn:
            active.append("SYN")
        if self.ack:
            active.append("ACK")
        if self.fin:
            active.append("FIN")
        if self.rst:
            active.append("RST")
        if self.psh:
            active.append("PSH")
        if self.urg:
            active.append("URG")
        if self.ece:
            active.append("ECE")
        if self.cwr:
            active.append("CWR")
        return ", ".join(active) if active else "NONE"


@dataclass
class TCPOption:
    """Parsed TCP option entry."""
    kind: int
    name: str
    length: int
    data: bytes = b""
    decoded: Any = None


@dataclass
class TCPHeader:
    """Represents a TCP segment header."""
    src_port: int
    dst_port: int
    seq_num: int
    ack_num: int
    data_offset: int  # In 32-bit words
    header_length: int  # In bytes (data_offset * 4)
    flags: TCPFlags
    window_size: int
    checksum: int
    urgent_pointer: int
    options: List[TCPOption] = field(default_factory=list)
    payload_length: int = 0
    raw_header: bytes = b""


@dataclass
class UDPHeader:
    """Represents a UDP datagram header."""
    src_port: int
    dst_port: int
    length: int  # Header + payload
    checksum: int
    payload_length: int = 0
    raw_header: bytes = b""


@dataclass
class ICMPHeader:
    """Represents an ICMP or ICMPv6 message header."""
    icmp_type: int
    type_name: str
    code: int
    code_name: str
    checksum: int
    rest_of_header: bytes = b""
    raw_header: bytes = b""
    is_ipv6: bool = False


@dataclass
class ParsedPacket:
    """Composite structured packet representation returned by the packet dispatcher."""
    packet_id: int
    timestamp: float
    datetime_str: str
    raw_length: int

    # Layer 2
    ethernet: Optional[EthernetHeader] = None

    # Layer 3
    network_type: str = "None"
    ipv4: Optional[IPv4Header] = None
    ipv6: Optional[IPv6Header] = None

    # Layer 4
    transport_type: str = "None"
    tcp: Optional[TCPHeader] = None
    udp: Optional[UDPHeader] = None
    icmp: Optional[ICMPHeader] = None

    # Payload & diagnostics
    payload: bytes = b""
    payload_length: int = 0
    parse_errors: List[str] = field(default_factory=list)
    is_malformed: bool = False

    @property
    def summary_line(self) -> str:
        """Generates a concise one-line summary for compact monitor mode."""
        l3 = self.network_type
        l4 = self.transport_type
        src = ""
        dst = ""
        details = ""

        if self.ipv4:
            src = self.ipv4.src_ip
            dst = self.ipv4.dst_ip
        elif self.ipv6:
            src = self.ipv6.src_ip
            dst = self.ipv6.dst_ip
        elif self.ethernet:
            src = self.ethernet.src_mac
            dst = self.ethernet.dst_mac

        if self.tcp:
            src = f"{src}:{self.tcp.src_port}"
            dst = f"{dst}:{self.tcp.dst_port}"
            details = f"[{self.tcp.flags.summary()}] Seq={self.tcp.seq_num} Ack={self.tcp.ack_num} Win={self.tcp.window_size} Len={self.payload_length}"
        elif self.udp:
            src = f"{src}:{self.udp.src_port}"
            dst = f"{dst}:{self.udp.dst_port}"
            details = f"Len={self.udp.length} PayloadLen={self.payload_length}"
        elif self.icmp:
            details = f"{self.icmp.type_name} (code {self.icmp.code}: {self.icmp.code_name})"
        else:
            details = f"PayloadLen={self.payload_length}"

        return f"#{self.packet_id} [{self.datetime_str}] {l3}/{l4} {src} -> {dst} {details}"


@dataclass
class InterfaceInfo:
    """Network interface metadata."""
    index: int
    name: str
    description: str
    guid: str
    mac: str
    ipv4_addrs: List[str] = field(default_factory=list)
    ipv6_addrs: List[str] = field(default_factory=list)
    is_wifi: bool = False
    is_tunnel: bool = False
    tunnel_type: Optional[str] = None
    scapy_name: str = ""
    scapy_iface: Any = None

    def display_name(self) -> str:
        return f"{self.name} ({self.description})" if self.name != self.description else self.name


@dataclass
class CaptureStats:
    """Statistics for the current capture session."""
    total_captured: int = 0
    total_parsed: int = 0
    total_errors: int = 0
    ipv4_count: int = 0
    ipv6_count: int = 0
    tcp_count: int = 0
    udp_count: int = 0
    icmp_count: int = 0
    other_l3_count: int = 0
    other_l4_count: int = 0
    bytes_captured: int = 0
    start_time: float = field(default_factory=lambda: datetime.now().timestamp())
    last_packet_time: float = 0.0

    def record_packet(self, packet: ParsedPacket) -> None:
        """Updates statistics with information from a parsed packet."""
        self.total_captured += 1
        self.bytes_captured += packet.raw_length
        self.last_packet_time = packet.timestamp

        if packet.is_malformed or packet.parse_errors:
            self.total_errors += 1
        else:
            self.total_parsed += 1

        if packet.ipv4:
            self.ipv4_count += 1
        elif packet.ipv6:
            self.ipv6_count += 1
        else:
            self.other_l3_count += 1

        if packet.tcp:
            self.tcp_count += 1
        elif packet.udp:
            self.udp_count += 1
        elif packet.icmp:
            self.icmp_count += 1
        else:
            self.other_l4_count += 1

