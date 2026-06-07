# Zero Trust Policy Builder

## Purpose

Zero Trust Policy Builder turns scan context into policy packages, deployment steps, and hardening configurations.

## Source Files

- `src/components/ZeroTrustPolicyBuilder.tsx`
- `server/index.js` (`POST /zerotrust/generate`, `POST /zerotrust/validate`)
- `src/services/db.ts`

## What It Does Today

- Accepts manual context or loads latest findings from other modules.
- Loads prefill data from `zerotrust_prefill_payload`.
- Supports target environments such as Linux server, Nginx, Apache, AWS, Docker, and Windows.
- Offers templates including hardened SSH, common attack-port blocking, security headers, strict CSP, rate limiting, and Docker isolation.
- Generates AI policy output through `/zerotrust/generate`.
- Displays policy title, risk reduction, security rules, configs, deployment checklist, and test commands.
- Validates config snippets through `/zerotrust/validate`.
- Exports CSV, downloads configs, copies commands, creates installer scripts, exports PDF, and logs to Forensics Timeline.

## Data and API Dependencies

- IndexedDB: `settings`, `scanHistory`, `forensicsEvents`
- Backend: `/zerotrust/generate`, `/zerotrust/validate`

## Limitations

- Policy generation is AI-authored and must be reviewed.
- Validation is lightweight syntax checking for a few config types, not real deployment verification.
- It does not yet use actual cloud/firewall state.

## Real-Tool Upgrade Path

Use real findings from Nmap, ZAP, Nuclei, Wazuh, Trivy, and cloud scanners. Add config validation with `nginx -t`, `iptables-restore --test`, Terraform validation, Kubernetes schema validation, and cloud-policy simulators where available.

