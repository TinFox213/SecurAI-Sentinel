# MITRE ATT&CK Mapper

## Purpose

MITRE ATT&CK Mapper maps findings to ATT&CK techniques, tactics, detections, mitigations, and ATT&CK Navigator output.

## Source Files

- `src/modules/mitre/MitreMapper.tsx`
- `server/index.js` (`POST /attack/classify`, `GET /attack/technique/:id`)
- `src/services/db.ts`

## What It Does Today

- Accepts pasted findings or selected scan history.
- Loads prefill data from `mitre_prefill_payload`.
- Sends evidence to `/attack/classify`.
- Displays tactic coverage, technique matrix, confidence, evidence, mitigation, and detection guidance.
- Opens a drawer for individual technique details from `/attack/technique/:id`.
- Exports an ATT&CK Navigator layer JSON file.
- Copies summaries and logs classified attacks to Forensics Timeline.

## Data and API Dependencies

- IndexedDB: `scanHistory`, `settings`, `forensicsEvents`
- Backend: `/attack/classify`, `/attack/technique/:id`

## Limitations

- Technique matching is AI-assisted and backed by a limited static technique map in the backend.
- It does not currently ingest full ATT&CK STIX data.

## Real-Tool Upgrade Path

Use the official ATT&CK STIX dataset, Sigma rules, Suricata/Zeek/Wazuh detections, and tool outputs to map evidence deterministically where possible. AI should assist with ambiguous mapping and narrative reporting.

