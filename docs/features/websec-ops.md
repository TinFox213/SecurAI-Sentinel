# WebSec Ops

## Purpose

WebSec Ops assesses web exposure through subdomain enumeration, SSL checks, security header grading, and DNS integrity checks.

## Source Files

- `src/modules/websec/WebSecOps.tsx`
- `server/index.js` (`POST /web/ssl`, `/web/headers`, `/web/dns`, `/osint/subdomains`)
- `src/services/db.ts`

## What It Does Today

- Recon-X enumerates subdomains through `/osint/subdomains`, backed by crt.sh in the backend.
- SSL Sentinel checks certificate validity, issuer, dates, and days remaining through `/web/ssl`.
- Header Grader fetches headers through `/web/headers` and grades HSTS, CSP, X-Frame-Options, and X-Content-Type-Options.
- DNS Integrity compares system DNS answers with Google resolver answers through `/web/dns`.
- Logs expired/near-expired SSL and DNS mismatch events into Forensics Timeline.
- Saves latest header result as `websec_latest_result`.
- Can prefill Red Team Agent and Zero Trust Builder with target context.

## Data and API Dependencies

- IndexedDB: `settings`, `forensicsEvents`
- External: crt.sh, DNS resolvers
- Backend: `/osint/subdomains`, `/web/ssl`, `/web/headers`, `/web/dns`

## Limitations

- Backend defines some web endpoints twice; Express will usually satisfy the first matching route, leaving later duplicates effectively shadowed.
- Header grading is simple and checks only a small set of controls.
- Subdomain enumeration depends on crt.sh availability.

## Real-Tool Upgrade Path

Add Subfinder, Amass, httpx, OWASP ZAP passive scan, SSLyze/testssl.sh, and Nuclei web templates. Store raw outputs and expose the same user-friendly grades from deterministic evidence.

