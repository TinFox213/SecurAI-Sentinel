# Incident Response Playbook

## Purpose

Incident Response Playbook generates and tracks incident response steps from user-provided or prefilled incident context.

## Source Files

- `src/components/IncidentResponsePlaybook.tsx`
- `server/index.js` (`POST /ir/generate`, `POST /ir/update-step`)
- `src/services/db.ts`

## What It Does Today

- Collects incident type, severity, affected systems, findings, and organization context.
- Can load context from scan history, saved settings, or prefill payloads.
- Sends incident context to `/ir/generate`.
- Receives a structured playbook with phases, steps, owner roles, timelines, commands, communication plans, IOCs, lessons learned, and references.
- Tracks step status and notes.
- Sends step updates to `/ir/update-step`.
- Saves generated playbooks locally.
- Can copy commands/IOCs and log playbook generation into Forensics Timeline.

## Data and API Dependencies

- IndexedDB: `settings`, `scanHistory`, `forensicsEvents`
- Backend: `/ir/generate`, `/ir/update-step`

## Limitations

- Playbooks are AI-generated and should be reviewed against organizational IR policy.
- There is no external case-management system yet.
- Step updates are local/user-driven, not connected to ticketing or SOAR.

## Real-Tool Upgrade Path

Integrate TheHive for case creation and task tracking, Cortex analyzers/responders where appropriate, Wazuh/Velociraptor for evidence collection, and MISP for IOC sharing.

