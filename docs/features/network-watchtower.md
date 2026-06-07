# Network Watchtower

## Purpose

Network Watchtower monitors local network devices, rogue devices, ghost port triggers, ARP anomalies, and basic port exposure.

## Source Files

- `src/modules/watchtower/NetworkWatchtower.tsx`
- `src/modules/watchtower/NetworkGraph.tsx`
- `server/index.js` (`GET /scan`, `POST /scan`, `POST /scan-ports`, `/network/arp-status`, `/network/arp-reset`, `/alerts`, WebSocket, ghost ports)
- `src/services/db.ts`

## What It Does Today

- Checks backend health.
- Scans local devices through `/scan`.
- Saves devices to `knownDevices`.
- Lets users mark devices as known or delete tracked devices.
- Supports Night Mode, which rescans periodically and alerts on unknown devices.
- Polls `/network/arp-status` every five seconds for ARP guard status.
- Plays a browser siren on intruder/ARP spoof alerts.
- Connects to backend WebSocket for live ghost-port alerts.
- Can scan a device's selected ports through `/scan-ports`.
- Can generate firewall mitigation commands through `/remediate/firewall`.
- Shows either list or ReactFlow graph view.
- Logs ghost-port triggers, unknown devices, and ARP spoofing into Forensics Timeline.

## Data and API Dependencies

- IndexedDB: `knownDevices`, `settings`, `forensicsEvents`
- Backend: `/health`, `/scan`, `/scan-ports`, `/network/arp-status`, `/network/arp-reset`, `/alerts`, WebSocket
- Backend ghost ports: `8080`, `8443`

## Limitations

- Discovery depends on local network visibility and the backend running with enough OS permissions.
- Port scanning is a small built-in probe set, not Nmap.
- ARP mitigation outputs scripts/commands; it does not automatically reconfigure the host.
- Some visible text in this module contains encoding artifacts.

## Real-Tool Upgrade Path

Use Nmap for device/service discovery, arp-scan where available, Zeek/Suricata for network detection, and Wazuh/osquery for endpoint inventory.

