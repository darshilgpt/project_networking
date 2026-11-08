"""Unit tests for DNS Inspector."""

from scapy.layers.dns import DNS, DNSQR, DNSRR
from dpi.dns_inspector import DNSInspector, calculate_entropy


def test_dns_query_parsing():
    """Tests parsing a standard DNS query for google.com."""
    scapy_dns = DNS(id=0x1234, rd=1, qd=DNSQR(qname="google.com", qtype="A"))
    raw_bytes = bytes(scapy_dns)

    meta = DNSInspector.inspect(raw_bytes, is_udp=True)

    assert meta is not None
    assert meta.tx_id == 0x1234
    assert meta.is_response is False
    assert len(meta.questions) == 1
    assert meta.questions[0].name == "google.com"
    assert meta.questions[0].qtype_name == "A"
    assert meta.is_suspicious_domain is False


def test_dns_response_parsing():
    """Tests parsing a DNS response with A record answer."""
    scapy_dns = DNS(
        id=0x5678,
        qr=1,
        qd=DNSQR(qname="example.com", qtype="A"),
        an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34", ttl=300),
    )
    raw_bytes = bytes(scapy_dns)

    meta = DNSInspector.inspect(raw_bytes, is_udp=True)

    assert meta is not None
    assert meta.tx_id == 0x5678
    assert meta.is_response is True
    assert meta.rcode_name == "NOERROR"
    assert len(meta.answers) == 1
    assert meta.answers[0].name == "example.com"
    assert meta.answers[0].rdata == "93.184.216.34"
    assert meta.answers[0].ttl == 300


def test_suspicious_dga_domain_detection():
    """Tests heuristic detection of high-entropy DGA/tunneling domain names."""
    # High entropy randomized domain
    random_domain = "x7k9mqz8v1p4l2a0b8c.malicious-c2.net"
    scapy_dns = DNS(id=0x9999, qd=DNSQR(qname=random_domain, qtype="TXT"))
    raw_bytes = bytes(scapy_dns)

    meta = DNSInspector.inspect(raw_bytes, is_udp=True)

    assert meta is not None
    assert meta.is_suspicious_domain is True
    assert any("entropy" in r for r in meta.suspicious_reasons)


def test_entropy_calculation():
    """Tests Shannon entropy calculator."""
    # Low entropy (repetitive)
    low = calculate_entropy("aaaaaa")
    assert low == 0.0

    # High entropy (diverse)
    high = calculate_entropy("abcdefghijklmnopqrstuvwxyz0123456789")
    assert high > 4.5

