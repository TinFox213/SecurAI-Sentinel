# Forensics Timeline

## Purpose

Forensics Timeline correlates security events from multiple modules into an investigation trail.

## Source Files

- `src/modules/forensics/ForensicsTimeline.tsx`
- `src/utils/forensicsLogger.ts`
- `src/services/db.ts`

## What It Does Today

- Loads `forensicsEvents` from IndexedDB.
- Supports event types including port scans, vulnerabilities, phishing, malware, canary triggers, ghost ports, ARP spoofing, new devices, breaches, CVEs, ATT&CK classifications, SSL issues, DNS anomalies, log anomalies, and custom events.
- Filters by date range, severity, module, event type, search text, and sort order.
- Displays a vertical timeline and a Gantt-like SVG view.
- Supports bookmark, tags, manual custom events, event drawer, delete, clear all, and seed test events.
- Exports JSON and CSV.
- Reconstructs selected chains over a recent time window.

## Data and API Dependencies

- IndexedDB: `forensicsEvents`
- Helper: `logForensicsEvent`

## Limitations

- Events are browser-local and not immutable.
- There is no evidence hash, chain-of-custody model, or external case ID yet.
- Imported evidence from tools is not yet normalized into this timeline.

## Real-Tool Upgrade Path

Import Wazuh alerts, Suricata EVE JSON, Zeek logs, Plaso timelines, osquery events, TheHive case events, and Red Team tool runs. Store raw artifact references and hashes for auditability.

