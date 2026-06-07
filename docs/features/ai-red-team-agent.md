# AI Red Team Agent

## Purpose

The AI Red Team Agent plans and executes guided security assessment missions against authorized targets.

## Source Files

- `src/components/AIRedTeamAgent.tsx`
- `src/hooks/useAgentMission.ts`
- `server/index.js` (`/agent/*`, `/scan`, `/scan-ports`, `/web/*`, `/osint/*`, `/cve/*`, `/attack/*`, `/ir/*`, `/vuln/*`)

## What It Does Today

- Accepts target, objectives, mode, permission checkbox, max steps, timeout, auto-IR option, and forensics logging option.
- Supports `passive`, `active`, and `full` mission modes.
- Requests an AI plan from `/agent/plan`, with frontend fallback planning when needed.
- Executes internal backend tools such as port scan, SSL check, header check, DNS check, subdomain enum, CVE search, dark-web domain lookup, ATT&CK classification, IP reputation, vulnerability analysis, and IR generation.
- Requests AI step interpretation from `/agent/interpret`.
- Requests final AI synthesis from `/agent/synthesize`.
- Exports/saves the report and can hand off findings to ATT&CK Mapper, IR Playbook, Forensics Timeline, and saved settings.

## Data and API Dependencies

- Settings: `agent_prefill_payload`, saved agent reports
- Forensics events when enabled
- Backend endpoints used through `useAgentMission`

## Limitations

- The "tools" are currently internal backend checks, API calls, or AI analyses, not external offensive CLIs.
- Target authorization is UI-level, not enforced through a full backend scope manager.
- The current active scan is a small TCP port probe, not a full Nmap/Nuclei/ZAP workflow.

## Real-Tool Upgrade Path

Replace the internal tool switch with a backend tool registry. The agent should choose from approved tool adapters such as Nmap, Subfinder, httpx, ZAP, Nuclei, AbuseIPDB, NVD, Greenbone, and Metasploit lab-mode modules. AI should plan and interpret, but the tool runner should produce primary evidence.

