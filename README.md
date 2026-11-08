# Real-Time Deep Packet Inspection (DPI) & Intrusion Detection / Prevention System (IDS/IPS)

A modular, high-performance Network Security and Deep Packet Inspection (DPI) engine built entirely in Python 3.11+ for Windows 11 using Npcap.

The system captures real-time packets from active network interfaces (including Wi-Fi), dissects protocol headers from first principles, maintains stateful bidirectional flow tracking, reassembles TCP streams, extracts Layer 7 application metadata (HTTP, DNS, TLS SNI), evaluates signature and behavioural intrusion detection rules, and executes an automated decision engine (ALLOW / ALERT / BLOCK) with safe IPS simulation.

---

## 1. System Architecture

```
[ Wi-Fi Adapter (Npcap) ]
            │ (Raw frame bytes)
[ Phase 1 Packet Dispatcher ]
            │ (ParsedPacket with raw L7 payload)
========================= PHASE 2 PIPELINE =========================
            ▼
    [ Flow Tracker ] ─────────► Bidirectional 5-tuple state & metrics
            │
            ├─► [ TCP Stream Reassembler ] (Out-of-order, duplicates, retransmissions)
            │
            ▼
    [ DPI Engine ]
        ├── Protocol Detector (HTTP / DNS / TLS payload signatures)
        ├── HTTP Inspector (Methods, URIs, Headers, Status codes, Body)
        ├── DNS Inspector (Queries, Types, Answers, DGA & entropy heuristics)
        ├── TLS Inspector (ClientHello, SNI, Ciphers, Handshake metadata)
        └── Signature Matcher (rules/dpi_rules.json)
            │
            ▼
    [ Intrusion Detection System (IDS) ]
        ├── Signature-Based Detection (DPI rule alerts)
        └── Behaviour-Based Detection (Port scans, SYN floods, DNS anomalies, Failures)
            │
            ▼
    [ Decision Engine ]
        └── Evaluation: ALLOW | ALERT | BLOCK
            │
            ▼
    [ IPS Module ]
        ├── Mode 1: Monitoring / Simulation (Default - Safe, no dropped packets)
        └── Mode 2: Active Prevention (WinDivert/PyDivert with allowlist guards)
            │
            ▼
    [ Real-Time Terminal Monitor & Session Statistics ]
```

---

## 2. Project Layout

```
project_networking/
│
├── main.py                     # Application CLI controller & pipeline loop
│
├── capture/                    # Packet acquisition subsystem (Phase 1)
│   ├── __init__.py
│   ├── interface_manager.py    # Discovers, filters, and selects adapters
│   └── packet_capture.py       # Scapy / Npcap continuous capture engine
│
├── parser/                     # Custom binary parsing subsystem (Phase 1)
│   ├── __init__.py
│   ├── ethernet_parser.py      # Ethernet II & 802.1Q VLAN dissection
│   ├── ipv4_parser.py          # IPv4 header & checksum verification
│   ├── ipv6_parser.py          # IPv6 header & extension header traversal
│   ├── tcp_parser.py           # TCP segment, flags bitmask & options parsing
│   ├── udp_parser.py           # UDP datagram length validation & extraction
│   ├── icmp_parser.py          # ICMP & ICMPv6 message parsing
│   └── packet_dispatcher.py    # Layer 2 -> 3 -> 4 pipeline coordinator
│
├── models/                     # Strongly-typed data models
│   ├── __init__.py
│   ├── packet_models.py        # Protocol headers & capture statistics
│   ├── flow_model.py           # 5-tuple FlowKey, Flow, FlowStats, TCPState
│   └── alert_model.py          # IDSAlert, Severity, DPIResult, DecisionAction
│
├── flow/                       # Flow tracking subsystem (Phase 2)
│   ├── __init__.py
│   ├── flow_tracker.py         # Bidirectional 5-tuple flow identification & state
│   └── flow_manager.py         # Flow expiration, timeouts, memory bounds
│
├── reassembly/                 # TCP stream reassembly subsystem (Phase 2)
│   ├── __init__.py
│   └── tcp_reassembler.py      # Sequence tracking, retransmissions, out-of-order buffer
│
├── dpi/                        # Deep Packet Inspection subsystem (Phase 2)
│   ├── __init__.py
│   ├── protocol_detector.py    # Payload-based protocol identification
│   ├── http_inspector.py       # HTTP request/response parser & metadata extraction
│   ├── dns_inspector.py        # DNS query/response decoder & domain checks
│   ├── tls_inspector.py        # TLS ClientHello SNI extractor & metadata
│   ├── signature_matcher.py    # Configurable rule matcher (exact, substring, regex)
│   └── dpi_engine.py           # Main DPI coordinator
│
├── ids/                        # Intrusion Detection subsystem (Phase 2)
│   ├── __init__.py
│   ├── signature_detector.py   # Signature alert generation
│   ├── behaviour_detector.py   # Port scan, SYN flood, failure rate detectors
│   └── ids_engine.py           # Central IDS engine
│
├── ips/                        # Intrusion Prevention subsystem (Phase 2)
│   ├── __init__.py
│   ├── decision_engine.py      # Rule-based policy arbiter (ALLOW/ALERT/BLOCK)
│   ├── blocking_manager.py     # Simulation tracking & allowlist safety guards
│   └── packet_interceptor.py   # Optional WinDivert integration with killswitch
│
├── rules/                      # External configuration rules
│   ├── dpi_rules.json          # Configurable DPI signature rules
│   └── ids_rules.json          # Behavioural thresholds & policies
│
├── utils/                      # Formatting & diagnostics
│   ├── __init__.py
│   ├── logger.py               # Structured application logger
│   └── formatter.py            # Terminal cards & summary formatter
│
├── tests/                      # Automated unit test suite (68 tests)
│   ├── test_ethernet.py
│   ├── test_ipv4.py
│   ├── test_ipv6.py
│   ├── test_tcp.py
│   ├── test_udp.py
│   ├── test_icmp.py
│   ├── test_dispatcher.py
│   ├── test_flow_tracker.py
│   ├── test_tcp_reassembly.py
│   ├── test_http_inspection.py
│   ├── test_dns_inspection.py
│   ├── test_tls_inspection.py
│   ├── test_ids.py
│   └── test_ips.py
│
├── requirements.txt
└── README.md
```

---

## 3. Key Capabilities

### Flow Tracking
- **Bidirectional 5-Tuple**: Normalizes `(src_ip, src_port, dst_ip, dst_port, proto)` so both directions map to the same `Flow` instance.
- **TCP State Machine**: Tracks transitions across `SYN_SENT`, `SYN_RECEIVED`, `ESTABLISHED`, `FIN_WAIT`, `CLOSED`, and `RESET`.
- **Memory Bound & Expiration**: Configurable idle timeouts and LRU eviction of oldest flows when `max_flows` is reached.

### TCP Stream Reassembly
- **Sequence Number Tracking**: Maintains expected sequence boundaries.
- **Out-of-Order Handling**: Buffers non-contiguous segments until the missing sequence hole arrives, then seamlessly drains.
- **Retransmissions & Duplicates**: Discards exact duplicates and trims partial overlapping retransmissions.
- **Stream Expiration**: Frees memory on connection termination (`FIN` / `RST`) or timeout.

### Application Layer Protocol Detection & DPI
- **HTTP**: Parses request methods (`GET`, `POST`, etc.), URIs, HTTP versions, `Host`, `User-Agent`, `Content-Type`, `Content-Length`, status codes, and body previews.
- **DNS**: Unpacks queries and answers (A, AAAA, CNAME), decodes compressed domain label pointers, and calculates Shannon entropy to detect DGA (Domain Generation Algorithms) and DNS tunneling.
- **TLS**: Decodes unencrypted TLS handshake records (`ClientHello`), parses extension fields, and extracts the **Server Name Indication (SNI)** hostname without decrypting HTTPS traffic.
- **Signature Matcher**: Evaluates external rules from `rules/dpi_rules.json` supporting `exact`, `case_insensitive`, `substring`, and `regex` matching.

### Intrusion Detection & Prevention
- **Port Scanning**: Detects single sources probing > 15 distinct ports within a 5-second window.
- **SYN Flood**: Detects rapid bursts exceeding 25 SYNs in 2 seconds.
- **DNS Anomalies**: Flags DGA patterns, query floods, and NXDOMAIN bursts.
- **Decision Engine**: Classifies traffic as `ALLOW`, `ALERT`, or `BLOCK`.
- **IPS Modes**:
  - *Mode 1 (Monitoring / Simulation)*: Records simulated blocking decisions without dropping traffic.
  - *Mode 2 (Active Prevention)*: Optional WinDivert integration with safety allowlists (loopback, DHCP, DNS management protection) and an emergency killswitch.

---

## 4. Running the Application

### 1. Default Interactive Mode (Wi-Fi Capture & DPI)
```bash
python main.py
```

### 2. Specific Interface Selection
```bash
# Capture on Wi-Fi interface by index
python main.py -i 1

# Capture 50 packets and exit
python main.py -i 1 --count 50
```

### 3. Display Modes
```bash
# Compact mode (single line summary per packet)
python main.py -i 1 --verbosity compact

# Detailed mode (expanded headers, user-agents, and evidence)
python main.py -i 1 --verbosity detailed
```

### 4. Running Tests
Run the automated test suite (83 unit and integration tests):
```bash
python -m pytest -v
```

---

## 5. Centralised Windows Network Security Server

The centralized security server mode transforms the DPI engine into a multi-client security hub designed for central inspection of VPN and tunnel traffic.

### Server Architecture
- **Modular Packet Ingestion**: Support for physical/Wi-Fi adapters, WireGuard/Wintun tunnel interfaces (including raw Layer 3 IP parsing), and PCAP/PCAPNG replay for offline analysis and testing.
- **Multi-Client VPN Identification**: Detects and maps traffic to distinct clients based on VPN client CIDR subnets (e.g. `10.8.0.0/24`) and IP direction.
- **Per-Client State Isolation**: Dedicated `FlowManager` and `TCPReassembler` instances per client ensure 5-tuple tables, reassembly buffers, and metrics remain completely isolated.
- **Bounded Queue & Worker Pool**: Multi-threaded worker pool consuming from a bounded queue (`queue.Queue`) to safeguard against buffer exhaustion under traffic bursts.
- **Live Terminal Dashboard**: Interactive `rich` dashboard rendering server telemetry, active VPN clients, DPI classifications, and real-time security alerts.
- **Structured Logging & Graceful Termination**: Non-blocking `SIGINT` / `SIGTERM` handlers cleanly stop ingestion, drain queues, join workers, and print a final session summary.

### Server Commands

#### 1. Launch Central Server on Live Interface / Interactive Selection
```bash
python server_main.py
```

#### 2. Replay PCAP Trace (Burst or Real-Time)
```bash
# Replay at maximum throughput
python server_main.py -p sample_vpn_traffic.pcap

# Replay with inter-packet delay pacing
python server_main.py -p sample_vpn_traffic.pcap --pcap-rate realtime
```

#### 3. Capture on WireGuard / Wintun Virtual Tunnel Adapter
```bash
# Auto-discover and capture on WireGuard tunnel interface
python server_main.py --tunnel --vpn-subnet 10.8.0.0/24
```

#### 4. Headless / Background Service Mode
```bash
python server_main.py -i 1 --no-dashboard --log-file security_server.log
```

#### 5. List Interfaces with WireGuard & Wi-Fi Highlighting
```bash
python server_main.py -l
```

---

Press `Ctrl+C` cleanly at any time to halt capture and view the comprehensive session report.
