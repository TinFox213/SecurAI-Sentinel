# Dark Web Monitor

## Purpose

Dark Web Monitor checks exposed emails, domains, IPs, and usernames for breach and abuse-risk context.

## Source Files

- `src/modules/darkweb/DarkWebMonitor.tsx`
- `server/index.js` (`/darkweb/*`, `/pcap/ip-reputation`)
- `src/services/db.ts`

## What It Does Today

- Supports query types: email, domain, IP, and username.
- Uses Have I Been Pwned for email/domain breach and paste checks when `HIBP_API_KEY` exists.
- Uses AbuseIPDB for IP reputation when `ABUSEIPDB_API_KEY` exists.
- Falls back to AI-generated demo data when required dark-web API keys are missing.
- Sends exposure data to `/darkweb/analyze` for AI risk scoring and recommendations.
- Saves scan history locally.
- Logs breach/paste exposure into Forensics Timeline.
- Displays risk score, breach cards, exposed data classes, paste exposures, IP reputation, immediate actions, and long-term recommendations.

## Data and API Dependencies

- IndexedDB: `darkwebScans`, `forensicsEvents`
- External: Have I Been Pwned, AbuseIPDB
- Backend: `/darkweb/breach`, `/darkweb/analyze`, `/darkweb/demo-data`, `/darkweb/pastes`, `/darkweb/domain`, `/pcap/ip-reputation`

## Limitations

- "Dark web" visibility is actually breach/paste/IP-reputation API visibility; it is not a crawler of hidden services.
- Demo mode can look realistic but is not evidence.
- Username checks are currently weaker than email/domain/IP checks.

## Real-Tool Upgrade Path

Integrate MISP for internal threat intel, HIBP for breach evidence, AbuseIPDB/VirusTotal/OTX for reputation, and case creation in TheHive for high-risk exposures.

