"""Unit tests for TCP stream reassembly."""

import pytest
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

from parser.packet_dispatcher import PacketDispatcher
from reassembly.tcp_reassembler import TCPReassembler, DirectionalTCPStream
from models.packet_models import TCPFlags


@pytest.fixture
def dispatcher():
    return PacketDispatcher()


@pytest.fixture
def reassembler():
    return TCPReassembler()


def test_in_order_tcp_reassembly(dispatcher, reassembler):
    """Tests normal sequential multi-segment TCP stream reassembly."""
    # Segment 1: "Hello "
    p1 = bytes(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=5000, dport=80, flags="A", seq=1000) / b"Hello ")
    pkt1 = dispatcher.dispatch(p1, timestamp=10.0)
    chunk1, full1 = reassembler.process_packet(pkt1)
    assert chunk1 == b"Hello "
    assert full1 == b"Hello "

    # Segment 2: "World!"
    p2 = bytes(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=5000, dport=80, flags="A", seq=1006) / b"World!")
    pkt2 = dispatcher.dispatch(p2, timestamp=10.1)
    chunk2, full2 = reassembler.process_packet(pkt2)
    assert chunk2 == b"World!"
    assert full2 == b"Hello World!"


def test_out_of_order_tcp_segments(dispatcher, reassembler):
    """Tests that out-of-order segments are buffered until missing segment arrives."""
    # First: Establish baseline with SYN
    syn_pkt = bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=80, flags="S", seq=100))
    reassembler.process_packet(dispatcher.dispatch(syn_pkt, timestamp=1.0))

    # Send Segment 2 first (seq 111, length 10: "PART_TWO__"): expected_seq is 101, so this is OUT-OF-ORDER
    p2 = bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=80, flags="A", seq=111) / b"PART_TWO__")
    chunk2, full2 = reassembler.process_packet(dispatcher.dispatch(p2, timestamp=1.1))
    # Should not reassemble yet because segment 1 (seq 101..110) is missing!
    assert chunk2 == b""
    assert full2 == b""

    # Now send Segment 1 (seq 101, length 10: "PART_ONE__")
    p1 = bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=80, flags="A", seq=101) / b"PART_ONE__")
    chunk1, full1 = reassembler.process_packet(dispatcher.dispatch(p1, timestamp=1.2))

    # Both segment 1 and buffered segment 2 should now be drained!
    assert chunk1 == b"PART_ONE__PART_TWO__"
    assert full1 == b"PART_ONE__PART_TWO__"


def test_duplicate_and_retransmission():
    """Tests duplicate detection and overlapping retransmissions."""
    stream = DirectionalTCPStream()
    flags = TCPFlags(ack=True)

    # 1. Base segment: seq 1000, "ABCDE" (len 5)
    c1 = stream.push_segment(seq=1000, payload=b"ABCDE", flags=flags, timestamp=1.0)
    assert c1 == b"ABCDE"
    assert stream.expected_seq == 1005

    # 2. Exact duplicate retransmission: seq 1000, "ABCDE"
    c2 = stream.push_segment(seq=1000, payload=b"ABCDE", flags=flags, timestamp=1.1)
    assert c2 == b""  # Ignored
    assert stream.duplicate_segments == 1
    assert stream.retransmitted_segments == 1

    # 3. Partial overlap retransmission: seq 1003, "DEFG" (len 4, "DE" overlaps, "FG" is new)
    c3 = stream.push_segment(seq=1003, payload=b"DEFG", flags=flags, timestamp=1.2)
    assert c3 == b"FG"  # Only new bytes after 1005 ("FG") attached
    assert stream.get_stream_bytes() == b"ABCDEFG"


def test_missing_segment_gap(dispatcher, reassembler):
    """Tests that a missing gap is retained and does not corrupt the stream."""
    # Send seq 1000 ("AAA")
    p1 = bytes(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=8080, dport=80, flags="A", seq=1000) / b"AAA")
    reassembler.process_packet(dispatcher.dispatch(p1))

    # Send seq 2000 ("BBB") -> large gap
    p2 = bytes(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=8080, dport=80, flags="A", seq=2000) / b"BBB")
    chunk, full = reassembler.process_packet(dispatcher.dispatch(p2))

    assert chunk == b""
    assert full == b"AAA"


def test_bidirectional_tcp_reassembly(dispatcher, reassembler):
    """Tests independent reassembly for client->server and server->client streams."""
    # Client sends request
    p_req = bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5555, dport=80, flags="PA", seq=100) / b"GET / HTTP/1.1\r\n")
    c_req, _ = reassembler.process_packet(dispatcher.dispatch(p_req))
    assert c_req == b"GET / HTTP/1.1\r\n"

    # Server sends response
    p_resp = bytes(Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=5555, flags="PA", seq=500) / b"HTTP/1.1 200 OK\r\n")
    c_resp, _ = reassembler.process_packet(dispatcher.dispatch(p_resp))
    assert c_resp == b"HTTP/1.1 200 OK\r\n"
