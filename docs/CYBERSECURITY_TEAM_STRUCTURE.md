# Cybersecurity Team-Based Application Structure

The current application groups features by broad UI type: Home, Analysis, and Operations. For a cybersecurity product, the navigation will be clearer if modules are grouped by team function and workflow ownership.

## Proposed Sidebar Groups

| New Group | Purpose | Modules |
| --- | --- | --- |
| Command Center | Executive and operator overview | Home, Security Posture Score, Scan History and Reports, AI Provider Status |
| Red Team | Authorized offensive assessment and attack-surface discovery | AI Red Team Agent, Port Scanner, Vulnerability Analysis, CVE Intel Hub, WebSec Ops, MITRE ATT&CK Mapper, Packet Capture Analyzer, Cyber Dojo Auto-Pentest |
| Blue Team / SOC | Monitoring, detection, endpoint triage, and alert handling | Network Watchtower, Fleet EDR, General Log Analysis, Packet Capture Analyzer, Live Alerts, Forensics Timeline |
| Threat Intelligence | External exposure and vulnerability intelligence | CVE Intel Hub, Dark Web Monitor, OSINT threat intel, IP reputation, breach/paste checks |
| DFIR | Incident response, evidence handling, and timeline reconstruction | Incident Response Playbook, Forensics Timeline, Packet Capture Analyzer, CryptoVault, Malware Analysis, Keylogger Detection |
| Deception Engineering | Canary tokens, trap files, ghost ports, and early-warning tripwires | Canary Factory, Network Watchtower Ghost Ports, Live Alerts |
| AppSec / DevSecOps | Application, code, container, and infrastructure security | WebSec Ops, CryptoVault Code Analysis, Vulnerability Analysis, Zero Trust Policy Builder, CVE IaC Patching |
| Governance and Resilience | Risk, control mapping, compliance hints, and hardening plans | Security Posture Score, Zero Trust Policy Builder, Reports, IR Playbook |
| Training Lab | Practice and education | Cyber Dojo, Teaching Mode |
| Utility Bench | Small analyst tools that do not belong to a mission flow | Utility Belt, EXIF Cleaner, Decoder |

## Current-to-New Mapping

| Current Module | Proposed Primary Team | Secondary Teams |
| --- | --- | --- |
| Home | Command Center | Governance |
| Posture Score | Command Center | Governance, Blue Team |
| Red Team Agent | Red Team | Purple Team, Threat Intelligence |
| Port Scanner | Red Team | Blue Team, Zero Trust |
| Vulnerability | Red Team | AppSec, Governance |
| ATT&CK Mapper | Purple Team | Blue Team, Red Team, DFIR |
| CVE Intel Hub | Threat Intelligence | AppSec, Red Team |
| Phishing Detect | Blue Team / SOC | Training, DFIR |
| Dark Web Monitor | Threat Intelligence | Command Center, DFIR |
| Malware Analysis | DFIR | Blue Team / SOC |
| Keylogger Detect | DFIR | Endpoint Security |
| General Logs | Blue Team / SOC | DFIR |
| Packet Analyzer | DFIR | Blue Team, Red Team |
| CryptoVault | DFIR | AppSec, Utility Bench |
| Cyber Dojo | Training Lab | Purple Team |
| IR Playbook | DFIR | Command Center, Governance |
| Canary Factory | Deception Engineering | Blue Team |
| Network Watchtower | Blue Team / SOC | Deception, Network Security |
| Forensics Timeline | DFIR | Blue Team, Command Center |
| WebSec Ops | AppSec / DevSecOps | Red Team, Threat Intelligence |
| Zero Trust Builder | Governance and Resilience | AppSec, Blue Team |
| Utility Belt | Utility Bench | AppSec, DFIR |
| Fleet EDR | Blue Team / SOC | DFIR, Endpoint Security |
| AI Chat Assistant | Global Assistant | All teams |
| Live Alerts | Global Alerts | Blue Team, Deception |

## Purple Team View

Purple Team does not need to be a separate sidebar group unless you want a dedicated collaboration workspace. It can be a cross-team workflow that stitches these modules together:

1. Red Team Agent runs a scoped mission.
2. ATT&CK Mapper converts findings into tactics and techniques.
3. Blue Team validates detections through Forensics Timeline, General Logs, Fleet EDR, Packet Analyzer, and Network Watchtower.
4. Incident Response Playbook generates response steps.
5. Zero Trust Builder generates hardening controls.
6. Posture Score measures the improved state.

## Recommended UI Changes

1. Change `ModuleGroup` in `src/config/modules.ts` from `home | analysis | operations` to team groups such as `command | red | blue | threatIntel | dfir | deception | appsec | governance | training | utility`.
2. Let a module appear in one primary group but expose secondary labels in search/command palette.
3. Keep the command palette flat so users can still jump directly to any tool.
4. Add a "Workflow" strip at the top of major modules with suggested next modules, such as WebSec Ops -> Red Team Agent -> Zero Trust Builder -> Posture Score.
5. Rename "Analysis Modules" to team-specific language. Analysts should not need to decide whether a feature is "analysis" or "operations"; they should recognize their team task.

## Suggested Navigation Order

1. Command Center
2. Red Team
3. Blue Team / SOC
4. Threat Intelligence
5. DFIR
6. Deception Engineering
7. AppSec / DevSecOps
8. Governance and Resilience
9. Training Lab
10. Utility Bench

## Why This Fits the Product

The application already has strong cross-module handoffs: WebSec Ops can prefill the Red Team Agent and Zero Trust Builder, Packet Analyzer can open ATT&CK Mapper, Red Team Agent can trigger IR workflows, and multiple modules log into Forensics Timeline. Team-based navigation makes those workflows feel intentional instead of scattered.

