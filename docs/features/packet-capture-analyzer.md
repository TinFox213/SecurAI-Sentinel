# Packet Capture Analyzer

## Purpose

Packet Capture Analyzer inspects PCAP/PCAPNG files for conversations, protocols, anomalies, IOCs, and AI-assisted network forensics.

## Source Files

- `src/components/PacketCaptureAnalyzer.tsx`
- `server/index.js` (`POST /pcap/analyze`, `/pcap/ai-analyze`, `/pcap/protocols`, `/pcap/ip-reputation`)
- `src/services/db.ts`

## What It Does Today

- Accepts PCAP and PCAPNG uploads up to 50 MB.
- Includes a synthetic sample capture builder for testing.
- Sends captures as multipart form data to `/pcap/analyze`.
- Backend detects capture format by magic bytes and parses with `pcap-parser` or manual fallback parsers.
- Extracts packet summaries, conversations, protocol statistics, top talkers, suspicious ports, RST flags, beaconing, scans, large transfers, unusual protocols, and DNS tunneling candidates.
- Runs `/pcap/protocols` for protocol and TCP flag distributions.
- Optionally runs `/pcap/ai-analyze` for deep AI network-forensics interpretation.
- Exports packets as CSV, copies IOCs, and can send findings to Forensics Timeline or ATT&CK Mapper.

## Data and API Dependencies

- IndexedDB: `forensicsEvents`, `settings`
- Backend: `/pcap/analyze`, `/pcap/ai-analyze`, `/pcap/protocols`, `/pcap/ip-reputation`

## Limitations

- Manual parsers are useful but not a replacement for Wireshark/TShark, Zeek, or Suricata.
- Large captures and encrypted traffic will need deeper tooling.
- IP reputation requires configured AbuseIPDB for real scoring.

## Real-Tool Upgrade Path

Use TShark for packet-level extraction, Zeek for metadata logs, Suricata for signature events, and Arkime or a similar packet index for larger environments.

