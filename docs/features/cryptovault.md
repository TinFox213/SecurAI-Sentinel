# CryptoVault

## Purpose

CryptoVault protects files with client-side AES encryption and can scan code/text content for AI-assisted security issues before export.

## Source Files

- `src/modules/crypto/CryptoVault.tsx`
- `src/services/cryptoVaultService.ts`
- `server/index.js` (`POST /api/analyze-code`, `POST /remediate/iac`)

## What It Does Today

- Supports encrypt and decrypt modes.
- Reads selected files in the browser.
- Encrypts file data with CryptoJS AES using a user-provided key and downloads a `.encrypted` file.
- Decrypts encrypted data back into the original file.
- Sends code/text files to `/api/analyze-code` for AI vulnerability analysis.
- Displays vulnerable code analysis and can offer patched output.
- Can request IaC patch generation for high/critical code findings.

## Data and API Dependencies

- Browser FileReader and Blob APIs
- Backend: `/api/analyze-code`, `/remediate/iac`

## Limitations

- The module name and registry description mention sanitization/metadata stripping, but this component currently focuses on encryption plus code analysis. Image metadata stripping is implemented in Utility Belt's EXIF cleaner, not here.
- Code analysis is AI-generated, not Semgrep/SAST evidence.
- Key management is fully user-managed; lost keys cannot be recovered.

## Real-Tool Upgrade Path

Add Semgrep, Gitleaks, Trivy filesystem scanning, YARA, and metadata sanitization tooling. Keep encryption local, but store scan reports as structured artifacts.

