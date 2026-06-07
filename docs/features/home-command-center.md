# Home Command Center

## Purpose

The Home Command Center is the first-screen mission dashboard. It gives the user quick access to posture scoring, the AI Red Team Agent, featured mission modules, and AI provider health.

## Source Files

- `src/modules/home/HomePage.tsx`
- `src/config/modules.ts`
- `src/hooks/useAiProviders.ts`
- `src/services/aiProviderService.ts`

## What It Does Today

- Displays the SecurAI Sentinel command surface and product positioning.
- Shows counts for analysis modules, operations consoles, configured AI providers, and security mode.
- Highlights Posture Score and Red Team Agent as primary actions.
- Shows pinned/featured modules from `featuredModules`.
- Polls `/api/ai-providers` every 45 seconds through `useAiProviders`.
- Allows direct navigation into featured modules.

## Data and API Dependencies

- `GET http://localhost:3001/api/ai-providers`
- `moduleRegistry`, `analysisModules`, `operationsModules`, and `featuredModules`

## Limitations

- It is mostly a navigation/status screen; it does not aggregate live alerts, open cases, or tool-run status yet.
- AI provider health is backend-reported only; it does not run a live test prompt.

## Real-Tool Upgrade Path

Add mission status widgets fed by real tool jobs: running scans, recent findings, open cases, endpoint health, and high-priority alerts. This should become the command-center view for Red Team, Blue Team, DFIR, and Governance users.

