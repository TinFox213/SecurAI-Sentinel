# SecurAI Sentinel Application Features

SecurAI Sentinel is a local-first cybersecurity operations dashboard. It combines AI-assisted analysis, browser persistence, backend security utilities, live alerts, reports, training modules, forensics, and planned real-tool orchestration.

## Current Feature Inventory

| Feature | Current Navigation | Primary Role | Detailed Doc |
| --- | --- | --- | --- |
| Home Command Center | Home Dashboard | Landing dashboard, AI provider status, featured modules | [home-command-center.md](features/home-command-center.md) |
| Security Posture Score | Home Dashboard | Organization-level posture scoring and trends | [security-posture-score.md](features/security-posture-score.md) |
| AI Red Team Agent | Home Dashboard | Guided assessment mission planner/executor | [ai-red-team-agent.md](features/ai-red-team-agent.md) |
| Port Scanner Analysis | Analysis Modules | AI interpretation of port scan data | [port-scanner-analysis.md](features/port-scanner-analysis.md) |
| Vulnerability Analysis | Analysis Modules | AI interpretation of vulnerability scan output | [vulnerability-analysis.md](features/vulnerability-analysis.md) |
| MITRE ATT&CK Mapper | Analysis Modules | Map findings to ATT&CK tactics and techniques | [mitre-attack-mapper.md](features/mitre-attack-mapper.md) |
| CVE Intelligence Hub | Analysis Modules | NVD CVE search, AI context, watchlist, IaC patching | [cve-intelligence-hub.md](features/cve-intelligence-hub.md) |
| Phishing Detection | Analysis Modules | AI inspection of suspicious messages | [phishing-detection.md](features/phishing-detection.md) |
| Dark Web Monitor | Analysis Modules | HIBP/AbuseIPDB-backed exposure checks with AI risk summary | [dark-web-monitor.md](features/dark-web-monitor.md) |
| Malware Analysis | Analysis Modules | AI inspection of malware indicators and process traces | [malware-analysis.md](features/malware-analysis.md) |
| Keylogger Detection | Analysis Modules | AI inspection of hook/process/credential theft evidence | [keylogger-detection.md](features/keylogger-detection.md) |
| General Log Analysis | Analysis Modules | AI anomaly detection over pasted logs | [general-log-analysis.md](features/general-log-analysis.md) |
| Packet Capture Analyzer | Analysis Modules | PCAP/PCAPNG parsing, anomaly detection, AI network forensics | [packet-capture-analyzer.md](features/packet-capture-analyzer.md) |
| CryptoVault | Operations | File encryption, code scan, code patch output | [cryptovault.md](features/cryptovault.md) |
| Cyber Dojo | Operations | Interactive security training games | [cyber-dojo.md](features/cyber-dojo.md) |
| Incident Response Playbook | Operations | AI-generated and trackable IR playbooks | [incident-response-playbook.md](features/incident-response-playbook.md) |
| Canary Factory | Operations | Honey token generation, trap files, tracking alerts | [canary-factory.md](features/canary-factory.md) |
| Network Watchtower | Operations | Local network inventory, ARP guard, ghost port alerts | [network-watchtower.md](features/network-watchtower.md) |
| Forensics Timeline | Operations | Cross-module event correlation and reconstruction | [forensics-timeline.md](features/forensics-timeline.md) |
| WebSec Ops | Operations | Subdomains, SSL, headers, DNS integrity checks | [websec-ops.md](features/websec-ops.md) |
| Zero Trust Policy Builder | Operations | AI-generated policy packages and validation | [zero-trust-policy-builder.md](features/zero-trust-policy-builder.md) |
| Utility Belt | Operations | Web3 audit, EXIF cleaner, breach radar, decoder | [utility-belt.md](features/utility-belt.md) |
| Fleet EDR | Operations | Endpoint telemetry dashboard and isolation script generator | [fleet-edr.md](features/fleet-edr.md) |
| AI Chat Assistant | Global Overlay | Contextual chat over latest analysis | [ai-chat-assistant.md](features/ai-chat-assistant.md) |
| Live Alerts | Global Overlay | Canary and ghost-port alert notifications | [live-alerts.md](features/live-alerts.md) |
| Scan History and Reports | Sidebar / Result Views | Historical scans, PDF exports, cross-module prefill | [scan-history-and-reporting.md](features/scan-history-and-reporting.md) |

## Current Navigation Model

The current sidebar groups modules as:

| Current Group | Modules |
| --- | --- |
| Home Dashboard | Home, Posture Score, Red Team Agent |
| Analysis Modules | Port Scanner, Vulnerability, ATT&CK Mapper, CVE Intel Hub, Phishing Detect, Dark Web Monitor, Malware Analysis, Keylogger Detect, General Logs, Packet Analyzer |
| Operations | CryptoVault, Cyber Dojo, IR Playbook, Canary Factory, Network Watchtower, Forensics Timeline, WebSec Ops, Zero Trust Builder, Utility Belt, Fleet EDR |

This grouping is functional, but it does not match how cybersecurity teams normally work. A team-oriented proposal is documented in [CYBERSECURITY_TEAM_STRUCTURE.md](CYBERSECURITY_TEAM_STRUCTURE.md).

## Major Cross-Feature Workflows

1. A user can paste data into a legacy analyzer, run AI analysis, export a PDF, save scan history, and send port findings into Zero Trust Builder.
2. WebSec Ops can save missing-header context and open either AI Red Team Agent or Zero Trust Builder with prefilled target data.
3. Packet Capture Analyzer can parse captures, detect anomalies, export IOCs, log forensics events, and send attack evidence into the MITRE ATT&CK Mapper.
4. CVE Intel Hub can search NVD, request AI interpretation, save CVEs to a watchlist, and generate IaC remediation patches for high-risk items.
5. Dark Web Monitor can use HIBP and AbuseIPDB when keys exist, fallback to demo data when keys are missing, save local scan history, and log breach events.
6. Network Watchtower logs ARP spoofing, ghost-port triggers, and unknown devices into the Forensics Timeline.
7. AI Red Team Agent can orchestrate internal backend tools, generate a final report, save it, log a mission, map findings to ATT&CK, or start an IR playbook.
8. Security Posture Score aggregates historical scans, dark-web scans, agent reports, and posture history into a scored view.

## Main Implementation Boundaries

| Area | Today |
| --- | --- |
| AI analysis | Central to many modules; backend supports multiple AI providers. |
| Real tools | Some checks are real API/system checks, but most offensive/security tooling is not yet external CLI integration. |
| Endpoint monitoring | Fleet EDR is currently simulated in the frontend, with a basic backend telemetry receiver and isolation-command generator. |
| Training | Cyber Dojo is intentionally simulated and educational. |
| Deception | Trap-file tracking is functional through tracking pixels; honey token use is generated but not externally registered. |
| Chat | Frontend exists, backend /api/chat route is missing. |

## Recommended Next Direction

Move from "AI first" to "tool result first, AI second":

1. Run trusted tools in a controlled backend runner.
2. Parse results into a normalized finding schema.
3. Store evidence and raw artifacts.
4. Let AI explain, prioritize, summarize, and generate remediation from the tool evidence.
5. Keep all active scanning behind target authorization, rate limits, and audit logs.

The detailed implementation plan is in [REAL_TOOL_INTEGRATION_PLAN.md](REAL_TOOL_INTEGRATION_PLAN.md).

