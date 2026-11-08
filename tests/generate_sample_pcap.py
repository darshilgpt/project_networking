"""Generates a rich sample PCAP with multi-client VPN traffic and security events."""

from __future__ import annotations

import os
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


def generate_pcap(filepath: str = "sample_vpn_traffic.pcap") -> str:
    pkts = []

    # Client A: 10.8.0.2 (Web browsing)
    pkts.append(
        Ether() / IP(src="10.8.0.2", dst="142.250.190.46") / TCP(sport=49152, dport=80, flags="PA", seq=100, ack=200)
        / b"GET /index.html HTTP/1.1\r\nHost: www.google.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    )
    pkts.append(
        Ether() / IP(src="142.250.190.46", dst="10.8.0.2") / TCP(sport=80, dport=49152, flags="PA", seq=200, ack=180)
        / b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\n<h1>Hello</h1>"
    )

    # Client B: 10.8.0.3 (DNS queries & malicious DNS tunneling attempt)
    pkts.append(
        Ether() / IP(src="10.8.0.3", dst="8.8.8.8") / UDP(sport=53001, dport=53)
        / b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06github\x03com\x00\x00\x01\x00\x01"
    )
    # DNS Tunneling query matching rule 1006
    pkts.append(
        Ether() / IP(src="10.8.0.3", dst="8.8.8.8") / UDP(sport=53002, dport=53)
        / b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07payload\x06tunnel\x04evil\x03com\x00\x00\x01\x00\x01"
    )

    # Client C: 10.8.0.4 (Security scanner probes & SQLi)
    # Attack 1: /.env file exfiltration (Rule 1002 - BLOCK)
    pkts.append(
        Ether() / IP(src="10.8.0.4", dst="192.168.1.10") / TCP(sport=55001, dport=80, flags="PA", seq=500, ack=600)
        / b"GET /.env HTTP/1.1\r\nHost: target-server.local\r\n\r\n"
    )
    # Attack 2: Path Traversal (Rule 1003 - BLOCK)
    pkts.append(
        Ether() / IP(src="10.8.0.4", dst="192.168.1.10") / TCP(sport=55002, dport=80, flags="PA", seq=600, ack=700)
        / b"GET /../../windows/win.ini HTTP/1.1\r\nHost: target-server.local\r\n\r\n"
    )
    # Attack 3: SQL Injection (Rule 1004 - ALERT)
    pkts.append(
        Ether() / IP(src="10.8.0.4", dst="192.168.1.10") / TCP(sport=55003, dport=80, flags="PA", seq=700, ack=800)
        / b"GET /search?q=test' union select 1,2,3-- HTTP/1.1\r\nHost: target-server.local\r\n\r\n"
    )

    wrpcap(filepath, pkts)
    print(f"Generated test PCAP with {len(pkts)} packets at {filepath}")
    return filepath


if __name__ == "__main__":
    generate_pcap()

