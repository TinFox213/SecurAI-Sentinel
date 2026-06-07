# Logical Data Flow and Signal Parsing

This document details how SecurAI Sentinel ingests raw signal data, parses it, applies detection rules, and coordinates the flow of information from multi-protocol auditing modules to the user interface.

## Logical Data Pipeline Overview

The system processes security signals through a multi-stage pipeline:

1. Data Ingestion: Raw packet captures, network logs, configuration text, or honey token hits are captured by the backend server or uploaded from the user interface.
2. Signal Parsing: The backend processes the input data (decoding binary headers or applying expression filters to configuration text).
3. Rule-Based Analysis: Programmatic checks evaluate the parsed fields against signature rules (such as blocklists, port lists, and flag state checks).
4. AI Enrichment: Normalized summaries and flagged items are forwarded to an AI provider model to obtain descriptive summaries, risk assessments, and mitigation guides.
5. Storage and Timeline: The results are returned to the client browser, persisted in local IndexedDB tables, and appended to the centralized Forensics Timeline.
6. Real-Time UI Broadcast: WebSocket channels send immediate threat warnings to active dashboards.

---

## Signal Ingestion and Binary Parsing

The application ingests raw signals from multiple protocols, including network socket connections, file uploads, and tracking pixel requests.

### Packet Capture Manual Binary Parsing
When a user uploads a PCAP or PCAPNG packet capture file, the backend verifies the data format manually by reading raw binary buffers without requiring external system dependencies.

- Magic Byte Validation:
  - The parser examines the initial four bytes of the file buffer to verify the capture format.
  - PCAP Little-Endian: Indicated by magic numbers 0xd4c3b2a1 or 0x4d3cb2a1.
  - PCAP Big-Endian: Indicated by magic numbers 0xa1b2c3d4 or 0xa1b23c4d.
  - PCAPNG: Indicated by the block magic number 0x0a0d0d0a.
- Byte Order Resolution:
  - Based on the identified magic bytes, the parser sets its endianness flag (Little-Endian or Big-Endian) and resolution scale (microseconds or nanoseconds) for reading subsequent multi-byte integers.
- Frame and Block Traversal:
  - For standard PCAP files, the parser skips the twenty-four byte global header and loops through the packet records. It reads each packet header (sixteen bytes containing timestamp seconds, timestamp subseconds, and captured data length), extracts the payload slice, and advances the buffer offset.
  - For PCAPNG files, the parser traverses block structures. It reads the block type and block total length, tracks interface descriptions to resolve link layers, and extracts packet payloads from Enhanced Packet Blocks or Simple Packet Blocks.

### Protocol Layer Extraction
Once a packet payload slice is isolated, the parser unpacks its network headers:

- Link Layer: Reads the Ethernet frame header (fourteen bytes). It formats the destination and source MAC addresses (six octets each) and reads the two-byte ethertype. If the ethertype is 0x0806, the packet is flagged as ARP. If it is 0x0800, it is processed as IPv4.
- Network Layer: For IPv4 packets, the parser reads the Internet Header Length (IHL) byte to determine the start of the transport layer. It extracts the protocol field number and decodes the source and destination IPv4 addresses.
- Transport Layer:
  - TCP (Protocol Number 6): Reads the source and destination port numbers. It extracts the flag byte and decodes individual bit states to identify Active Flags (such as Synchronization, Acknowledgment, Reset, Push, and Finish).
  - UDP (Protocol Number 17): Extracts the source and destination port numbers and maps common destinations to known service names.
  - ICMP (Protocol Number 1): Recognizes the control message protocol.

---

## Config and Log Rules Parsing

For text-based signal sources (such as system logs and software configurations), the backend uses string matchers and regular expressions to parse content.

- Firewall Rules Analysis: Inspects iptables configuration scripts line-by-line, verifying syntax validity, checking policies, and alerting on open traffic access.
- Web Configuration Audits: Inspects configuration files (such as Nginx files) to check for missing security headers (such as Content Security Policy, X-Frame-Options, and Strict-Transport-Security) and verifies that control braces are properly balanced.
- Content Security Policy (CSP) Analysis: Validates CSP headers by verifying directive separation, checking for permissive source declarations, and flags configurations that lack default fallback restrictions.
- Log Traversal: Scans authentication and system log entries to parse timestamps, program identifiers, source IP addresses, and event strings.

---

## Vulnerability Flagging and Rule Logic

The system combines algorithmic checks and AI classification to identify threat markers.

### Programmatic Detection Heuristics
- Port Risk Rules: The parser compares TCP and UDP port values against a blocklist of high-risk services (such as FTP, Telnet, SMB, and RDP). Traffic observed on these ports is instantly flagged.
- Protocol Anomalies: Flagged when TCP Reset (RST) flags are observed in high volumes (indicating scanning or connection rejection) or when unusual Ethertype values appear.
- Gateway Protection: The ARP watchdog compares gateway IP-to-MAC associations. If the MAC address of the default gateway changes from its established trusted value, the system triggers an ARP Spoofing alert.
- Honey Token Breaches: The system generates Canary files containing unique tracking pixel URLs. When a trap file is opened, the target attempts to load the transparent image from the backend. The backend captures the query token, source IP, user agent, and referrer headers, logging a Critical breach alert.

### AI Threat and Script Generation
- Contextual Analysis: Flagged issues and summaries are packed into system instructions. The AI maps the findings to MITRE ATT&CK categories, determines an overall threat level, and provides mitigation advice.
- Actionable Script Generation: Based on the findings, the backend prompts the AI model to output a remediation script (such as a Bash or Python script). The system strips markdown fences to deliver a raw, deployable script containing safety checks and error-handling steps.

---

## Threat Communication and UI Display

When the backend flags an alert (via honeypot triggers, ghost port attempts, or ARP changes):

1. The notification engine broadcasts an alert payload containing the timestamp, source IP, message details, and severity level.
2. The WebSocket server pushes this JSON payload to all active client connections.
3. The frontend displays a real-time toast notification, updates the live alert logs, and highlights affected modules on the dashboard.
4. The client adds the event to its browser IndexedDB forensics log, making it available on the Forensics Timeline.
