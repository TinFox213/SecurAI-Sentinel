import { ScanType, SecurityAnalysis, ThreatLevel } from "../types/types";

import { encryptPayload } from '../utils/crypto';

type RawFinding = {
  title?: string;
  description?: string;
  severity?: string;
  mitigation?: string;
};

type RawAnalysisResponse = {
  threat_level?: string;
  threatLevel?: string;
  risk_score?: number | string;
  riskScore?: number | string;
  summary?: string;
  detailed_analysis?: string;
  detailedAnalysis?: string;
  additional_notes?: string;
  additionalNotes?: string;
  attackVector?: string;
  exploitationVector?: string;
  recommendations?: string[];
  findings?: RawFinding[];
};

const normalizeThreatLevel = (value: unknown): ThreatLevel => {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'critical') return ThreatLevel.CRITICAL;
  if (normalized === 'high') return ThreatLevel.HIGH;
  if (normalized === 'medium') return ThreatLevel.MEDIUM;
  if (normalized === 'low') return ThreatLevel.LOW;
  if (normalized === 'safe') return ThreatLevel.LOW;
  return ThreatLevel.MEDIUM;
};

const clampRiskScore = (value: unknown): number => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return 0;
  return Math.max(0, Math.min(100, Math.round(parsed)));
};

const riskFromThreat = (level: ThreatLevel): number => {
  if (level === ThreatLevel.CRITICAL) return 90;
  if (level === ThreatLevel.HIGH) return 75;
  if (level === ThreatLevel.MEDIUM) return 50;
  return 20;
};

const normalizeAnalysisResponse = (raw: RawAnalysisResponse): SecurityAnalysis => {
  const threatLevel = normalizeThreatLevel(raw.threat_level ?? raw.threatLevel);
  const findings = Array.isArray(raw.findings) ? raw.findings : [];

  const summary = String(raw.summary || '').trim() || 'Analysis completed. No summary was provided by the model.';

  const detailedFromFindings = findings.length > 0
    ? findings
        .map((f, idx) => {
          const title = String(f.title || `Finding ${idx + 1}`);
          const severity = String(f.severity || 'Unknown');
          const description = String(f.description || 'No description provided.');
          return `${idx + 1}. [${severity}] ${title}\n${description}`;
        })
        .join('\n\n')
    : '';

  const detailedAnalysis = String(raw.detailed_analysis || raw.detailedAnalysis || detailedFromFindings).trim() || 'Detailed analysis is unavailable.';

  const recommendations = Array.isArray(raw.recommendations) && raw.recommendations.length > 0
    ? raw.recommendations.filter((item) => typeof item === 'string' && item.trim().length > 0)
    : findings
        .map((f) => String(f.mitigation || '').trim())
        .filter((item) => item.length > 0);

  const additionalNotes = String(
    raw.additional_notes || raw.additionalNotes || raw.attackVector || raw.exploitationVector || ''
  ).trim() || 'No exploitation vector details were returned.';

  const scoreCandidate = raw.risk_score ?? raw.riskScore;
  const computedRisk = clampRiskScore(scoreCandidate);

  return {
    threat_level: threatLevel,
    risk_score: computedRisk > 0 ? computedRisk : riskFromThreat(threatLevel),
    summary,
    detailed_analysis: detailedAnalysis,
    recommendations: recommendations.length > 0 ? recommendations : ['Data unavailable: no remediation recommendations were returned.'],
    additional_notes: additionalNotes
  };
};

export const analyzeSecurityData = async (
  scanType: ScanType,
  inputData: string
): Promise<SecurityAnalysis> => {
  // Use backend proxy instead of direct API call (secure - no exposed keys)
  try {
    const encryptedBody = encryptPayload({ scanType, inputData });

    const response = await fetch('http://localhost:3001/api/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ payload: encryptedBody })
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ message: 'Analysis failed' }));
      // Build a detailed error message from backend response
      let errorMsg = errorData.message || 'AI analysis request failed';
      if (errorData.details) {
        errorMsg += ` | ${errorData.details}`;
      }
      if (errorData.type) {
        errorMsg = `[${errorData.type}] ${errorMsg}`;
      }
      console.error('Backend Error Response:', errorData);
      throw new Error(errorMsg);
    }

    const rawAnalysis = await response.json() as RawAnalysisResponse;
    return normalizeAnalysisResponse(rawAnalysis);
    
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Failed to analyze security data';
    console.error('AI Analysis Error:', error);
    throw new Error(message);
  }
};

// ==================== CYBER DOJO CHALLENGE GENERATOR ====================

export type DojoGameType = 'phishing' | 'sqli' | 'crypto' | 'log' | 'pentest';

// Challenge response types
export interface PhishingChallenge {
  sender: string;
  subject: string;
  body: string;
  indicators: Array<{
    text: string;
    reason: string;
    type: 'domain' | 'urgency' | 'grammar' | 'request';
  }>;
  theme: string;
}

export interface SQLiChallenge {
  context: string;
  hint: string;
  vulnerability_type: string;
  target_table: string;
  difficulty: 'easy' | 'medium' | 'hard';
}

export interface CryptoChallenge {
  encrypted_string: string;
  clear_text: string;
  encoding_type: 'base64' | 'hex' | 'rot13';
  difficulty_hint: string;
}

export interface LogHunterChallenge {
  log_block: string;
  malicious_line_index: number;
  attack_type: string;
  explanation: string;
}

export interface PentestChallenge {
  targetEnvironment: string;
  vulnerability: string;
  exploitScript: string;
  mitigationSteps: string[];
  difficulty: 'easy' | 'medium' | 'hard';
}

// Unified challenge generator
export const generateDojoChallenge = async (
  gameType: DojoGameType,
  previousThemes: string[] = []
): Promise<PhishingChallenge | SQLiChallenge | CryptoChallenge | LogHunterChallenge | PentestChallenge> => {
  const timestamp = Date.now();
  const randomSeed = Math.floor(Math.random() * 10000);

  let prompt = '';
  let fallback: PhishingChallenge | SQLiChallenge | CryptoChallenge | LogHunterChallenge | PentestChallenge;

  switch (gameType) {
    case 'phishing':
      const themes = ['Banking', 'Netflix', 'HR Department', 'Cryptocurrency Exchange', 'Social Media', 'Cloud Storage', 'Package Delivery', 'Tax Authority'];
      const availableThemes = previousThemes.length > 0 
        ? themes.filter(t => !previousThemes.includes(t)) 
        : themes;
      const selectedTheme = availableThemes[Math.floor(Math.random() * availableThemes.length)] || themes[0];

      prompt = `Generate a UNIQUE realistic phishing email about "${selectedTheme}".

CRITICAL: This must be COMPLETELY DIFFERENT from any previous emails. Use unique wording, different tactics, and varied suspicious elements.

Requirements:
1. Create a believable but fake email that impersonates ${selectedTheme}
2. Include 3-5 suspicious indicators (mix obvious and subtle)
3. Make it look somewhat legitimate but with clear red flags
4. Use urgency triggers, typos, suspicious domains, or unusual requests
5. Body should be 3-6 sentences
6. Timestamp for uniqueness: ${timestamp}, Seed: ${randomSeed}

Return JSON with:
- sender: email address (make it subtly wrong, e.g., paypa1.com, amaz0n.com)
- subject: email subject line
- body: email body text
- indicators: array of suspicious elements [{text, reason, type}]
- theme: "${selectedTheme}"

Type must be: domain, urgency, grammar, or request`;
      fallback = {
        sender: 'security-alert@paypa1-verify.com',
        subject: 'URGENT: Verify Your Account Within 24 Hours',
        body: 'Your account has been flagged for unusual activity. Click here to verify your identity immediately or your account will be permanently suspended. We detected a login attempt from an unrecognized device in Nigeria.',
        indicators: [
          { text: 'paypa1-verify.com', reason: 'Fake domain using number "1" instead of letter "l"', type: 'domain' },
          { text: 'Within 24 Hours', reason: 'Creates false urgency pressure', type: 'urgency' },
          { text: 'permanently suspended', reason: 'Threatening language to force quick action', type: 'urgency' },
          { text: 'Click here', reason: 'Vague link without showing actual URL', type: 'request' }
        ],
        theme: 'Banking'
      };
      break;

    case 'sqli':
      prompt = `Generate a SQL Injection training scenario.

Create a UNIQUE vulnerability scenario with:
1. A realistic context (e.g., "E-commerce Search", "Admin Login", "User Profile Lookup")
2. A helpful hint about the database structure
3. Specify the vulnerability type (authentication bypass, data extraction, blind SQLi)
4. Name the target table
5. Set difficulty level (easy/medium/hard)

Timestamp: ${timestamp}, Seed: ${randomSeed}

Return JSON matching this structure exactly.`;
      fallback = {
        context: 'Online Banking Login Portal',
        hint: 'The database uses a table named "accounts" with columns: username, password, balance',
        vulnerability_type: 'Authentication Bypass',
        target_table: 'accounts',
        difficulty: 'easy'
      };
      break;

    case 'crypto':
      prompt = `Generate a cryptography decoding challenge.

Create a UNIQUE encoded message with:
1. A flag or secret message (e.g., "FLAG{CYBER_MASTER_2026}", "SECRET{ELITE_HACKER}")
2. Encode it using Base64, Hex, or ROT13
3. Provide the encrypted string
4. Provide the clear text answer
5. Give a subtle hint about the encoding method

Timestamp: ${timestamp}, Seed: ${randomSeed}

Return JSON with: encrypted_string, clear_text, encoding_type, difficulty_hint`;
      fallback = {
        encrypted_string: 'RkxBR3tDWUJFUl9NQVNURVJfMjAyNn0=',
        clear_text: 'FLAG{CYBER_MASTER_2026}',
        encoding_type: 'base64',
        difficulty_hint: 'Look for the padding characters at the end'
      };
      break;

    case 'log':
      prompt = `Generate a realistic server log analysis challenge.

Create 12-15 lines of realistic Apache/Nginx access logs. EXACTLY ONE line must be malicious (SQL injection, XSS, directory traversal, or scanner activity).

Requirements:
1. Normal logs should show typical traffic (GET/POST requests, 200/304 status codes, common user agents)
2. The malicious line should contain clear attack patterns (e.g., ' OR 1=1--, ../../../etc/passwd, <script>, sqlmap)
3. Mix the malicious line randomly (not at the end!)
4. Use realistic timestamps, IPs, and paths

Timestamp: ${timestamp}, Seed: ${randomSeed}

Return JSON with:
- log_block: complete log text (all lines as one string, separated by \\n)
- malicious_line_index: the line number (0-indexed) of the malicious entry
- attack_type: type of attack (e.g., "SQL Injection", "Directory Traversal")
- explanation: brief explanation of why it's malicious`;
      fallback = {
        log_block: `192.168.1.45 - - [12/Jan/2026:10:23:15 +0000] "GET /index.html HTTP/1.1" 200 4523 "-" "Mozilla/5.0"
10.0.0.12 - - [12/Jan/2026:10:23:18 +0000] "GET /assets/style.css HTTP/1.1" 200 12456 "-" "Mozilla/5.0"
192.168.1.78 - - [12/Jan/2026:10:23:22 +0000] "POST /api/login HTTP/1.1" 200 245 "-" "Chrome/120.0"
203.0.113.45 - - [12/Jan/2026:10:23:28 +0000] "GET /admin.php?id=1' OR 1=1-- HTTP/1.1" 404 0 "-" "sqlmap/1.7.2"
172.16.0.5 - - [12/Jan/2026:10:23:25 +0000] "GET /dashboard HTTP/1.1" 200 8934 "-" "Firefox/121.0"
192.168.1.45 - - [12/Jan/2026:10:23:30 +0000] "GET /about.html HTTP/1.1" 200 3421 "-" "Safari/17.0"`,
        malicious_line_index: 3,
        attack_type: 'SQL Injection',
        explanation: 'Contains SQL injection payload (\' OR 1=1--) and suspicious user agent (sqlmap)'
      };
      break;

    case 'pentest':
      prompt = `Generate a realistic penetration testing challenge.

Create a simulated scenario where a specific vulnerability is present in a target environment, and provide a containerized exploit script (e.g. bash or python script) that an attacker would use to exploit it.

Requirements:
1. "targetEnvironment": A description of the simulated vulnerable server (e.g., "Kubernetes Pod running vulnerable Redis", "Apache Struts on Linux").
2. "vulnerability": The specific CVE or vulnerability description.
3. "exploitScript": The raw code of the exploit script (e.g. python or bash) that WOULD exploit this.
4. "mitigationSteps": An array of 2-3 precise steps to patch it.
5. "difficulty": 'easy', 'medium', or 'hard'.

Timestamp: ${timestamp}, Seed: ${randomSeed}

Return JSON with: targetEnvironment, vulnerability, exploitScript, mitigationSteps, difficulty`;
      fallback = {
        targetEnvironment: "Docker Desktop container running Redis 4.x.x unauthenticated",
        vulnerability: "Redis Unauthenticated RCE (CVE-2022-0543)",
        exploitScript: "#!/bin/bash\necho 'Connecting to rogue Redis server...'\nredis-cli -h TARGET_IP -p 6379 eval 'local io_l = package.loadlib(\"/usr/lib/x86_64-linux-gnu/liblua5.1.so.0\", \"luaopen_io\"); local io = io_l(); local f = io.popen(\"id\", \"r\"); local res = f:read(\"*a\"); f:close(); return res' 0\n",
        mitigationSteps: ["Require authentication by setting requirepass in redis.conf", "Bind Redis to localhost (127.0.0.1) instead of 0.0.0.0", "Upgrade Redis to a patched version > 5.x.x"],
        difficulty: "medium"
      };
      break;

    default:
      throw new Error(`Unknown game type: ${gameType}`);
  }

  try {
    const response = await fetch('http://localhost:3001/api/generate-challenge', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        gameType,
        prompt,
        timestamp,
        randomSeed
      })
    });

    if (!response.ok) {
      console.warn('Challenge generation failed, using fallback');
      return fallback;
    }

    const challenge = await response.json();
    return challenge;
  } catch (error) {
    console.error('Dojo Challenge Generation Error:', error);
    console.warn('Using fallback challenge');
    return fallback;
  }
};