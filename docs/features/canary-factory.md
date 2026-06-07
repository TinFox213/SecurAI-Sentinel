# Canary Factory

## Purpose

Canary Factory creates deception artifacts and monitors trap triggers.

## Source Files

- `src/modules/canary/CanaryFactory.tsx`
- `server/index.js` (`/track/*`, `/canary-alerts`, `/tracking_pixel.png`)
- `src/components/common/LiveAlertToast.tsx`
- `src/services/db.ts`

## What It Does Today

- Generates realistic-looking honey tokens for AWS, GitHub, Stripe, and OpenAI.
- Provides deployment strategy guidance for tokens.
- Generates trap files with embedded tracking pixel URLs.
- Creates PDF traps with jsPDF and simpler text/CSV-style fallback content for other formats.
- Polls `/track/alerts` for trap-file triggers.
- Logs new trap triggers into Forensics Timeline.
- Supports alert archive and deletion through backend tracking endpoints.
- Global Live Alerts also poll the legacy `/canary-alerts` endpoint.

## Data and API Dependencies

- Backend: `/track/pixel.png`, `/track/alerts`, `DELETE /track/alerts`, `/canary-alerts`, `/tracking_pixel.png`
- IndexedDB: `forensicsEvents`

## Limitations

- Generated honey tokens are not registered with a real canary-token service, so token use is not actually monitored unless deployed through an external platform.
- Trap-file tracking relies on the target opening content that loads the tracking pixel and can reach the local backend.
- There are two related canary alert systems in the backend: legacy `/canary-alerts` and newer `/track/alerts`.

## Real-Tool Upgrade Path

Integrate OpenCanary or a Canarytokens-compatible API. Store registered token metadata, ingest real triggers, and connect high-confidence events to TheHive and Forensics Timeline.

