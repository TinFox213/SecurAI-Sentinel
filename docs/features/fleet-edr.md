# Fleet EDR

## Purpose

Fleet EDR is an endpoint telemetry dashboard for monitored machines, processes, network connections, alerts, and isolation actions.

## Source Files

- `src/modules/fleet/FleetEDR.tsx`
- `server/index.js` (`POST /edr/telemetry`, `POST /edr/isolate`)
- `src/services/db.ts`

## What It Does Today

- Loads endpoint telemetry from local IndexedDB every five seconds.
- Can simulate an endpoint agent with hostname, OS, health, CPU, memory, process list, network connections, and optional suspicious alert.
- Displays monitored endpoints in a sidebar.
- Shows selected endpoint details, process table, network table, and active alerts.
- Requests isolation commands from `/edr/isolate`.
- Displays Windows `netsh` or Linux `iptables` containment commands for manual deployment.

## Data and API Dependencies

- IndexedDB: `edrTelemetry`
- Backend: `/edr/telemetry`, `/edr/isolate`

## Limitations

- The UI currently simulates agent telemetry; it does not consume real agent data automatically.
- `/edr/telemetry` acknowledges events but does not persist them server-side.
- Isolation commands are copied manually and not pushed to endpoints.
- Some UI separators show encoding artifacts in rendered text.

## Real-Tool Upgrade Path

Use osquery or Wazuh agents for telemetry, Velociraptor for hunts and collection, and a secured response channel for isolation. Store endpoint alerts as normalized findings and forensics events.

