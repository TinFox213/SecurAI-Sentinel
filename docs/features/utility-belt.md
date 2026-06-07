# Utility Belt

## Purpose

Utility Belt is a collection of small security utilities for quick analyst tasks.

## Source Files

- `src/modules/utility/UtilityBelt.tsx`
- `src/services/geminiService.ts`

## What It Does Today

- Web3 Smart Contract Auditor sends Solidity code to AI and parses a JSON audit report.
- EXIF Ghost Cleaner extracts EXIF data from uploaded images using `exif-js`, shows camera/GPS metadata when present, and redraws the image through canvas to download a sanitized JPEG.
- Breach Radar sends a domain/email prompt to AI for general breach-risk context.
- Payload Decoder supports Base64 encode/decode, hex encode/decode, URL encode/decode, ROT13, copy, and swap.

## Data and API Dependencies

- Browser FileReader, canvas, and clipboard APIs
- `analyzeSecurityData(ScanType.GENERAL_LOG, prompt)`
- Backend: `/api/analyze` indirectly through `geminiService`

## Limitations

- Web3 audit and Breach Radar are AI-only.
- EXIF sanitization outputs JPEG and may change image format/quality.
- Decoder operations are simple transformations, not full CyberChef functionality.

## Real-Tool Upgrade Path

Add Slither/Mythril for Solidity, Gitleaks/Semgrep for code snippets, ExifTool for robust metadata handling, CyberChef-style recipes, and HIBP/MISP-backed breach lookups.

