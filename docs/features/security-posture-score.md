# Security Posture Score

## Purpose

Security Posture Score turns historical app activity into an executive posture report across network, web, endpoint, data protection, threat intelligence, and incident readiness.

## Source Files

- `src/modules/posture/SecurityPostureScore.tsx`
- `server/index.js` (`POST /posture/analyze`)
- `src/services/db.ts`

## What It Does Today

- Loads scan history, dark web scans, posture history, and saved AI Red Team reports.
- Sends aggregated evidence to `/posture/analyze`.
- Renders an overall score, grade, trend, category scores, critical findings, strengths, recommendations, compliance hints, and scan-coverage signals.
- Stores generated posture reports in local posture history.
- Gives navigation recommendations for missing or stale scans.
- Adds a small score boost when a recent AI Red Team report exists.

## Data and API Dependencies

- IndexedDB: `scanHistory`, `darkwebScans`, `postureHistory`, `settings`
- Backend: `POST http://localhost:3001/posture/analyze`

## Limitations

- The final scoring logic is AI-generated, not a deterministic framework mapping.
- Compliance hints are advisory and not backed by a full CIS, ISO 27001, GDPR, SOC 2, or NIST evidence model.
- Real tool coverage depends on other modules producing reliable structured evidence.

## Real-Tool Upgrade Path

Use real evidence from Nmap, ZAP, Nuclei, Trivy, Semgrep, Wazuh, osquery, Suricata, Zeek, and TheHive. Build a deterministic scoring layer first, then use AI only to explain trends and improvement priorities.

