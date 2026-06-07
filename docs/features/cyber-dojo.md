# Cyber Dojo

## Purpose

Cyber Dojo is a training lab for practicing common cybersecurity recognition and response skills.

## Source Files

- `src/modules/dojo/CyberDojo.tsx`
- `src/modules/dojo/TeachingMode.tsx`
- `src/services/dojoService.ts`
- `src/services/geminiService.ts`
- `server/index.js` (`POST /api/generate-challenge`)

## What It Does Today

- Provides five games: Phishing Detective, SQL Injection Playground, Crypto Cracker, Log Hunter, and Auto-Pentest Staging.
- Generates AI challenges where available and uses local fallbacks when the backend or AI provider fails.
- Tracks scores in component state.
- Teaching Mode explains each challenge category.
- Phishing Detective asks users to select suspicious email elements.
- SQLi Playground matches common SQL injection payload patterns.
- Crypto Cracker decodes Base64, hex, or ROT13-like challenges.
- Log Hunter hides one malicious Apache log line among normal lines.
- Auto-Pentest simulates terminal execution of a generated exploit flow.

## Data and API Dependencies

- Backend: `/api/generate-challenge`
- Local component state only for scoring

## Limitations

- Scores are not persisted.
- The pentest module is simulated and does not run containers or exploits.
- Training content includes some mojibake characters from encoding issues in UI text.

## Real-Tool Upgrade Path

Add lab containers such as OWASP Juice Shop, DVWA, deliberately vulnerable services, and safe CTF-style targets. Keep exploit execution isolated from the host and production networks.

