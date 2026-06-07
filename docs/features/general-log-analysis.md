# General Log Analysis

## Purpose

General Log Analysis turns raw pasted logs into security findings, anomalies, and remediation guidance.

## Source Files

- `App.tsx`
- `src/modules/analysis/AnalysisResult.tsx`
- `src/services/geminiService.ts`

## What It Does Today

- Provides sample log content.
- Performs light input validation for timestamps, IPs, HTTP verbs, errors, warnings, or auth events.
- Sends encrypted payloads to `/api/analyze`.
- Saves results to scan history.
- Displays threat level, summary, detailed analysis, and recommendations.

## Data and API Dependencies

- IndexedDB: `scanHistory`
- Backend: `/api/analyze`

## Limitations

- It does not parse logs with a schema.
- It does not run Sigma, YARA-L, SIEM query conversion, or anomaly models.
- It can miss issues if the input is too ambiguous or too large.

## Real-Tool Upgrade Path

Add parsers for Windows Event Logs, Sysmon, Apache/Nginx, auth logs, Suricata EVE JSON, Zeek logs, and Wazuh alerts. Add Sigma/pySigma conversion and SIEM export.

