# Phishing Detection

## Purpose

Phishing Detection analyzes suspicious email or message content and explains phishing indicators.

## Source Files

- `App.tsx`
- `src/modules/analysis/AnalysisResult.tsx`
- `src/services/geminiService.ts`

## What It Does Today

- Provides a sample phishing email.
- Validates input for sender, subject, link, urgency, login, password, or security-alert language.
- Sends encrypted text to `/api/analyze`.
- Saves results to scan history.
- Logs a forensics event for high-risk phishing output.
- Displays risk, summary, recommendations, and detailed analysis.

## Data and API Dependencies

- IndexedDB: `scanHistory`, `forensicsEvents`
- Backend: `/api/analyze`

## Limitations

- It does not parse `.eml` files, headers, SPF/DKIM/DMARC, attachment hashes, or URL reputation.
- It is AI-only today.

## Real-Tool Upgrade Path

Add email-header parsing, URL expansion, DNS/SPF/DKIM/DMARC checks, attachment hashing, YARA scans, sandbox verdict imports, and threat-intel lookups. AI can then explain the indicators and draft response guidance.

