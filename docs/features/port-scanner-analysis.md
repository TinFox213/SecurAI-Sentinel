# Port Scanner Analysis

## Purpose

Port Scanner Analysis is a legacy AI analyzer that interprets pasted port scan data, identifies risky exposed services, and recommends remediation.

## Source Files

- `App.tsx`
- `src/modules/analysis/AnalysisResult.tsx`
- `src/modules/analysis/AttackGraph.tsx`
- `src/modules/analysis/RiskGauge.tsx`
- `src/services/geminiService.ts`
- `server/index.js` (`POST /api/analyze`, `POST /api/generate-script`, `POST /remediate/firewall`)

## What It Does Today

- Provides sample port scan data.
- Validates that input resembles port/service output.
- Encrypts the pasted content and sends it to `/api/analyze`.
- Saves AI analysis to `scanHistory`.
- Displays threat level, risk gauge, summary, recommendations, detailed analysis, and optional attack graph.
- Parses ports from AI text and raw input for display and Zero Trust handoff.
- Can generate a remediation script through `/api/generate-script`.
- Can request firewall mitigation commands through `/remediate/firewall`.
- Can prefill Zero Trust Builder with open and dangerous ports.

## Data and API Dependencies

- IndexedDB: `scanHistory`, `settings`, `forensicsEvents`
- Backend: `/api/analyze`, `/api/generate-script`, `/remediate/firewall`

## Limitations

- This module analyzes pasted data; it does not run Nmap itself.
- Port parsing is heuristic and depends on text patterns.
- Firewall mitigation output is a generated command, not automatically applied.

## Real-Tool Upgrade Path

Run Nmap from the backend with XML output. Parse service/version data deterministically, map services to CVEs and risky defaults, then use AI only to summarize risk and create action plans.

