"""DNS Protocol Inspector for decoding queries, answers, and suspicious domain heuristics."""

from __future__ import annotations

import math
import socket
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

DNS_QTYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}

DNS_RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


@dataclass
class DNSQuestion:
    """DNS query question."""
    name: str
    qtype_code: int
    qtype_name: str
    qclass: int


@dataclass
class DNSAnswer:
    """DNS response record."""
    name: str
    rtype_code: int
    rtype_name: str
    ttl: int
    rdata: str


@dataclass
class DNSMetadata:
    """Extracted DNS message fields."""
    tx_id: int
    is_response: bool
    opcode: int
    rcode_code: int
    rcode_name: str
    questions: List[DNSQuestion] = field(default_factory=list)
    answers: List[DNSAnswer] = field(default_factory=list)
    is_suspicious_domain: bool = False
    suspicious_reasons: List[str] = field(default_factory=list)
    is_dns_tunneling: bool = False
    tunneling_indicators: List[str] = field(default_factory=list)
    rtt_ms: Optional[float] = None

    @property
    def query_name(self) -> str:
        return self.questions[0].name if self.questions else ""


class DNSTransactionTracker:
    """Tracks in-flight DNS query transaction IDs and measures query-response latency."""

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout
        # (tx_id, client_ip) -> query_timestamp
        self._in_flight: Dict[Tuple[int, str], float] = {}

    def record_query(self, tx_id: int, client_ip: str, timestamp: float) -> None:
        self._expire(timestamp)
        self._in_flight[(tx_id, client_ip)] = timestamp

    def record_response(self, tx_id: int, client_ip: str, timestamp: float) -> Tuple[Optional[float], bool]:
        """
        Calculates RTT latency.

        Returns:
            Tuple of (Optional[rtt_ms], is_unsolicited_response)
        """
        self._expire(timestamp)
        key = (tx_id, client_ip)
        if key in self._in_flight:
            q_time = self._in_flight.pop(key)
            rtt = max(0.0, (timestamp - q_time) * 1000.0)
            return round(rtt, 2), False
        return None, True

    def _expire(self, now: float) -> None:
        expired = [k for k, t in self._in_flight.items() if now - t > self.timeout]
        for k in expired:
            del self._in_flight[k]


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy for domain randomness/DGA detection."""
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class DNSInspector:
    """Inspects and decodes DNS packets (RFC 1035)."""

    HEADER_LEN = 12

    @classmethod
    def is_dns(cls, payload: bytes, is_udp: bool = True, src_port: int = 0, dst_port: int = 0) -> bool:
        """Determines if the payload matches standard DNS structure."""
        if len(payload) < cls.HEADER_LEN:
            return False

        # If on standard DNS ports (53, 5353, 5355), high confidence
        if src_port in (53, 5353, 5355) or dst_port in (53, 5353, 5355):
            return True

        # Otherwise validate DNS header sanity
        flags, qdcount, ancount, _, _ = struct.unpack("!HHHHH", payload[2:12])
        opcode = (flags >> 11) & 0x0F
        if opcode in (0, 1, 2) and qdcount in range(1, 10):
            return True

        return False

    @classmethod
    def _parse_name(cls, data: bytes, offset: int, depth: int = 0) -> Tuple[str, int]:
        """Parses DNS wire format domain labels with pointer compression support."""
        if depth > 10:  # Prevent recursion loops
            return "<loop>", offset

        labels = []
        orig_offset = offset
        jumped = False

        while offset < len(data):
            length = data[offset]

            if length == 0:
                offset += 1
                break

            # Compression pointer (2 MSBs set: 0xC0)
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(data):
                    break
                pointer = struct.unpack("!H", data[offset : offset + 2])[0] & 0x3FFF
                if not jumped:
                    orig_offset = offset + 2
                    jumped = True
                pointed_name, _ = cls._parse_name(data, pointer, depth + 1)
                labels.append(pointed_name)
                break
            else:
                offset += 1
                if offset + length > len(data):
                    break
                label = data[offset : offset + length].decode("ascii", errors="ignore")
                labels.append(label)
                offset += length

        name = ".".join(filter(None, labels))
        return name, (orig_offset if jumped else offset)

    @classmethod
    def inspect(cls, payload: bytes, is_udp: bool = True) -> Optional[DNSMetadata]:
        """
        Parses a DNS payload and extracts questions, answers, and heuristic indicators.

        Args:
            payload: Raw transport payload.

        Returns:
            DNSMetadata dataclass or None if invalid.
        """
        # If TCP, payload may have a 2-byte prefix indicating length
        data = payload
        if not is_udp and len(payload) >= 2:
            tcp_len = struct.unpack("!H", payload[:2])[0]
            if len(payload) >= tcp_len + 2:
                data = payload[2 : tcp_len + 2]

        if len(data) < cls.HEADER_LEN:
            return None

        try:
            tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:cls.HEADER_LEN])
        except struct.error:
            return None

        is_response = bool((flags >> 15) & 0x01)
        opcode = (flags >> 11) & 0x0F
        rcode = flags & 0x0F
        rcode_name = DNS_RCODES.get(rcode, f"RCODE_{rcode}")

        offset = cls.HEADER_LEN
        questions: List[DNSQuestion] = []
        suspicious_reasons: List[str] = []
        is_suspicious = False

        # Parse Questions
        for _ in range(min(qdcount, 20)):
            if offset >= len(data):
                break
            qname, offset = cls._parse_name(data, offset)
            if offset + 4 > len(data):
                break
            qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
            offset += 4

            qtype_name = DNS_QTYPES.get(qtype, f"TYPE_{qtype}")
            questions.append(DNSQuestion(name=qname, qtype_code=qtype, qtype_name=qtype_name, qclass=qclass))

            # Heuristic checks on domain name
            is_tunneling = False
            tunneling_indicators: List[str] = []

            if qname:
                entropy = calculate_entropy(qname)
                # DGA / Tunneling heuristic
                if entropy > 4.2 and len(qname) > 18:
                    is_suspicious = True
                    suspicious_reasons.append(f"High domain entropy ({entropy:.2f}) suggesting DGA or DNS tunneling")

                if entropy > 3.8 and len(qname) > 35:
                    is_tunneling = True
                    tunneling_indicators.append(f"High entropy payload ({entropy:.2f}) in long query ({len(qname)} chars)")

                if len(qname) > 70:
                    is_suspicious = True
                    is_tunneling = True
                    suspicious_reasons.append(f"Excessive domain length ({len(qname)} chars)")
                    tunneling_indicators.append(f"Abnormally long domain ({len(qname)} chars)")

                subdomains = qname.split(".")
                if len(subdomains) > 6:
                    is_suspicious = True
                    suspicious_reasons.append(f"Excessive subdomain depth ({len(subdomains)} levels)")

                # Check for base32 / hex encoded tunneling subdomains
                for sub in subdomains:
                    if len(sub) > 40:
                        is_tunneling = True
                        tunneling_indicators.append(f"Abnormally long subdomain label ({len(sub)} chars)")
                    # Hex encoding test
                    if len(sub) > 20 and all(c in "0123456789abcdefABCDEF" for c in sub):
                        is_tunneling = True
                        tunneling_indicators.append(f"Hex-encoded data in subdomain label ({sub[:15]}...)")

        # Parse Answers
        answers: List[DNSAnswer] = []
        for _ in range(min(ancount, 30)):
            if offset >= len(data):
                break
            aname, offset = cls._parse_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
            offset += 10

            if offset + rdlength > len(data):
                break
            rdata_bytes = data[offset : offset + rdlength]
            offset += rdlength

            rtype_name = DNS_QTYPES.get(rtype, f"TYPE_{rtype}")
            rdata_str = ""

            if rtype == 1 and rdlength == 4:  # A (IPv4)
                rdata_str = socket.inet_ntoa(rdata_bytes)
            elif rtype == 28 and rdlength == 16:  # AAAA (IPv6)
                rdata_str = socket.inet_ntop(socket.AF_INET6, rdata_bytes)
            elif rtype == 5:  # CNAME
                cname, _ = cls._parse_name(data, offset - rdlength)
                rdata_str = cname
            elif rtype == 12:  # PTR
                ptr_name, _ = cls._parse_name(data, offset - rdlength)
                rdata_str = ptr_name
            elif rtype == 16:  # TXT
                # Character string formatted: 1-byte length followed by string data
                txt_chunks = []
                t_off = 0
                while t_off < len(rdata_bytes):
                    t_len = rdata_bytes[t_off]
                    t_chunk = rdata_bytes[t_off + 1 : t_off + 1 + t_len].decode("utf-8", errors="replace")
                    txt_chunks.append(t_chunk)
                    t_off += 1 + t_len
                rdata_str = " ".join(txt_chunks)
                if len(rdata_str) > 100:
                    is_tunneling = True
                    tunneling_indicators.append(f"Large TXT payload ({len(rdata_str)} chars) in DNS response")
            elif rtype == 15 and rdlength >= 2:  # MX
                pref = struct.unpack("!H", rdata_bytes[:2])[0]
                mx_name, _ = cls._parse_name(data, offset - rdlength + 2)
                rdata_str = f"{pref} {mx_name}"
            else:
                rdata_str = f"[{rdlength} bytes]"

            answers.append(DNSAnswer(name=aname, rtype_code=rtype, rtype_name=rtype_name, ttl=ttl, rdata=rdata_str))

        return DNSMetadata(
            tx_id=tx_id,
            is_response=is_response,
            opcode=opcode,
            rcode_code=rcode,
            rcode_name=rcode_name,
            questions=questions,
            answers=answers,
            is_suspicious_domain=is_suspicious,
            suspicious_reasons=suspicious_reasons,
            is_dns_tunneling=is_tunneling,
            tunneling_indicators=tunneling_indicators,
        )

