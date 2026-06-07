# Repository and Platform Map

This document records the application-level reading pass for SecurAI Sentinel. Dependency and build-output folders such as node_modules and dist are third-party or generated artifacts, so the feature documentation is based on authored source, backend, config, scripts, and existing docs.

## Top-Level Structure

| Path | Purpose |
| --- | --- |
| App.tsx | Main application controller, module routing, legacy AI analyzer workflow, PDF export, command palette, global overlays. |
| src/config/modules.ts | Navigation registry and current grouping into Home, Analysis, and Operations. |
| src/types/types.ts | Shared enums and TypeScript data contracts for scans, CVEs, dark web reports, posture, MITRE, PCAP, IR, red-team agent, and Zero Trust policies. |
| src/services/db.ts | Browser IndexedDB persistence via Dexie. |
| src/services/geminiService.ts | Frontend AI service wrapper for encrypted /api/analyze and dojo challenge generation. |
| server/index.js | Express backend, auth gate, AI provider routing, network/web/OSINT/CVE/PCAP/IR/agent/Zero Trust endpoints, WebSocket alerts, ghost ports, ARP guard. |
| docs/ | Existing and generated product documentation. |
| start-app.ps1 | Windows quick launcher for backend and frontend. |
| test-websec-ops.ps1 | Manual PowerShell endpoint checks for WebSec Ops. |

## Runtime Stack

The frontend is a React + TypeScript + Vite application with Tailwind CSS, Framer Motion, Lucide icons, ReactFlow graphs, Recharts, jsPDF, Dexie, CryptoJS, EXIF parsing, and toast notifications.

The backend is an Express server on port 3001. It supports local-only unauthenticated mode by default, or token-protected mode through INTERNAL_API_TOKEN. It also restricts CORS to local frontend origins unless CORS_ALLOWED_ORIGINS is configured.

## AI Provider Routing

The backend can route AI calls to:

| Provider | Environment Variables |
| --- | --- |
| Gemini | GEMINI_API_KEY, GEMINI_MODEL |
| OpenRouter | OPENROUTER_API_KEY, OPENROUTER_MODEL, OPENROUTER_BASE_URL, OPENROUTER_SITE_URL, OPENROUTER_APP_NAME |
| NVIDIA | NVIDIA_API_KEY, NVIDIA_MODEL, NVIDIA_BASE_URL |

Routing is controlled by AI_PROVIDER, AI_PROVIDER_ORDER, and AI_REQUEST_TIMEOUT_MS. The Home page and Sidebar poll /api/ai-providers to show routing health.

## Persistence

The app stores local browser data in IndexedDB through SecurAIDatabase.

| Store | Used For |
| --- | --- |
| scanHistory | Legacy AI scan results and reloadable historical analyses. |
| knownDevices | Network Watchtower discovered devices and known/unknown device state. |
| settings | Cross-module prefill payloads, saved reports, watchlists, dismissals, and saved playbooks. |
| edrTelemetry | Fleet EDR simulated endpoint telemetry. |
| darkwebScans | Dark Web Monitor scan history. |
| postureHistory | Security posture score trend data. |
| forensicsEvents | Shared investigation timeline events. |

## Backend Security Notes

The backend loads .env.local first and .env second. The current .env.example includes API variable names for AI providers, HIBP, and AbuseIPDB. Secrets should be kept out of committed example files and rotated if a real key was ever committed.

The frontend encrypts legacy AI analysis payloads before sending them to /api/analyze, but both frontend and backend currently have a fallback shared key. For production, use a per-install secret with rotation and never rely on a compiled fallback.

Several middleware packages are installed in server/package.json, but only CORS and JSON parsing are clearly wired into server/index.js. Production hardening should explicitly add security headers, request limits, audit logging, and CSRF/origin protections where needed.

## Current Integration Shape

The product already mixes four execution styles:

1. Real local/network checks: network discovery, basic port probes, ARP inspection, SSL checks, HTTP header fetches, DNS comparison, PCAP parsing, HIBP/NVD/AbuseIPDB/Shodan InternetDB lookups where configured.
2. AI analysis: legacy scan interpretation, CVE explanation, posture scoring, IR playbook generation, red-team planning and synthesis, dark web risk summarization, Zero Trust policy generation, Web3 audit, breach radar.
3. Simulated training or telemetry: Cyber Dojo games, Fleet EDR agent telemetry, demo dark-web data, generated canary tokens.
4. UI-only or partially wired surfaces: AI chat overlay calls /api/chat, but the backend route is not currently implemented.
