# Keylogger Detection

## Purpose

Keylogger Detection analyzes process, hook, and credential-theft evidence for possible keylogging behavior.

## Source Files

- `App.tsx`
- `src/modules/analysis/AnalysisResult.tsx`
- `src/services/geminiService.ts`

## What It Does Today

- Provides sample keylogger-like evidence.
- Validates input for hooks, keyboard events, processes, registry, or suspicious capture terms.
- Sends encrypted content to `/api/analyze`.
- Saves results to scan history.
- Can be correlated later through Forensics Timeline if logged as part of a broader incident.

## Data and API Dependencies

- IndexedDB: `scanHistory`
- Backend: `/api/analyze`

## Limitations

- It does not collect endpoint telemetry directly.
- It does not inspect kernel hooks, browser extensions, startup persistence, or real process trees.

## Real-Tool Upgrade Path

Use osquery, Wazuh, Velociraptor, Sysmon logs, Sigma rules, YARA, and Volatility 3 to collect and analyze real endpoint evidence. Use AI to explain whether the evidence indicates credential theft and what containment is needed.

