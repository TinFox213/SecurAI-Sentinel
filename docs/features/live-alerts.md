# Live Alerts

## Purpose

Live Alerts shows global toast notifications when canary traps or alert streams produce new events.

## Source Files

- `src/components/common/LiveAlertToast.tsx`
- `server/index.js` (`/canary-alerts`, WebSocket alert broadcasting, ghost ports, tracking pixel endpoints)
- `src/modules/canary/CanaryFactory.tsx`
- `src/modules/watchtower/NetworkWatchtower.tsx`

## What It Does Today

- Polls `GET /canary-alerts` every two seconds.
- Compares alert count to detect new canary alerts.
- Displays temporary toast notifications with IP, token, and timestamp.
- Lets the user dismiss visible alert toasts.
- Network Watchtower separately connects to WebSocket for ghost-port alerts.

## Data and API Dependencies

- Backend: `/canary-alerts`, WebSocket, `/track/alerts`

## Limitations

- LiveAlertToast uses the legacy canary alert endpoint, while Canary Factory's newer monitor uses `/track/alerts`.
- It does not authenticate requests from the frontend with a token today.
- Alert state is not unified across all modules.

## Real-Tool Upgrade Path

Create a single alert event bus and normalized alert store. Feed it with canary triggers, Wazuh alerts, Suricata events, Zeek notices, Nuclei critical findings, tool-job failures, and user-defined notifications.

