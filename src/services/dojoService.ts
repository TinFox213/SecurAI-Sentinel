import { Type, Schema } from '@google/genai';

// Schema for Phishing Email generation
const phishingEmailSchema: Schema = {
  type: Type.OBJECT,
  properties: {
    subject: { type: Type.STRING },
    sender: { type: Type.STRING },
    body: { type: Type.STRING },
    suspicious_elements: {
      type: Type.ARRAY,
      items: {
        type: Type.OBJECT,
        properties: {
          text: { type: Type.STRING },
          reason: { type: Type.STRING },
          type: { 
            type: Type.STRING,
            enum: ['domain', 'urgency', 'grammar', 'request']
          }
        },
        required: ['text', 'reason', 'type']
      }
    }
  },
  required: ['subject', 'sender', 'body', 'suspicious_elements']
};

export interface PhishingEmail {
  subject: string;
  sender: string;
  body: string;
  suspicious_elements: Array<{
    text: string;
    reason: string;
    type: 'domain' | 'urgency' | 'grammar' | 'request';
  }>;
}

// Generate realistic phishing email with dynamic variation
export async function generatePhishingEmail(): Promise<PhishingEmail> {
  // Add randomization for unique challenges each time
  const themes = [
    'PayPal account verification',
    'Amazon delivery issue',
    'Microsoft security alert',
    'Bank fraud detection',
    'Netflix subscription expiring',
    'IRS tax refund pending',
    'LinkedIn connection request',
    'Apple iCloud storage full'
  ];
  
  const selectedTheme = themes[Math.floor(Math.random() * themes.length)];
  const timestamp = Date.now();
  
  const prompt = `Generate a UNIQUE realistic phishing email about "${selectedTheme}".

IMPORTANT: Create a NEW and DIFFERENT email than any previous ones. Use unique wording, different suspicious elements, and varied tactics.

Requirements:
1. Include 3-5 suspicious elements that users should identify
2. Mix obvious and subtle red flags
3. Make it look somewhat legitimate but with security issues
4. Include urgency triggers, typos, suspicious domains, or unusual requests
5. Keep the body concise (3-5 sentences)
6. Add variation - don't repeat common phrases
7. Timestamp for uniqueness: ${timestamp}

Return a JSON object with: subject, sender email, body text, and an array of suspicious_elements.
Each suspicious_element should have: text (exact phrase from email), reason (why it's suspicious), and type (domain/urgency/grammar/request).`;

  try {
    const response = await fetch('http://localhost:3001/api/generate-challenge', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        gameType: 'phishing',
        prompt,
        timestamp,
        randomSeed: Math.floor(Math.random() * 10000)
      })
    });

    if (!response.ok) {
      throw new Error('No response from AI');
    }

    const data = await response.json();
    return data as PhishingEmail;
  } catch (error) {
    console.error('Phishing email generation error:', error);
    // Return fallback example
    return {
      subject: 'Urgent: Account Verification Required',
      sender: 'support@paypa1-secure.com',
      body: 'Your PayPal account has been temporarily suspended. Please click here to verify your identity within 24 hours or your account will be permanently closed. Act now to avoid service disruption.',
      suspicious_elements: [
        { text: 'paypa1-secure.com', reason: 'Suspicious domain with number "1" instead of letter "l"', type: 'domain' },
        { text: 'within 24 hours', reason: 'Creates false urgency pressure', type: 'urgency' },
        { text: 'permanently closed', reason: 'Threatening language to force action', type: 'urgency' }
      ]
    };
  }
}

// Generate Apache logs with one malicious entry
export function generateApacheLogs(): { logs: string[]; maliciousIndex: number } {
  const normalLogs = [
    '192.168.1.45 - - [12/Jan/2026:10:23:15 +0000] "GET /index.html HTTP/1.1" 200 4523 "-" "Mozilla/5.0"',
    '10.0.0.12 - - [12/Jan/2026:10:23:18 +0000] "GET /assets/style.css HTTP/1.1" 200 12456 "-" "Mozilla/5.0"',
    '192.168.1.78 - - [12/Jan/2026:10:23:22 +0000] "POST /api/login HTTP/1.1" 200 245 "-" "Chrome/120.0"',
    '172.16.0.5 - - [12/Jan/2026:10:23:25 +0000] "GET /dashboard HTTP/1.1" 200 8934 "-" "Firefox/121.0"',
    '192.168.1.45 - - [12/Jan/2026:10:23:30 +0000] "GET /about.html HTTP/1.1" 200 3421 "-" "Safari/17.0"',
    '10.0.0.33 - - [12/Jan/2026:10:23:35 +0000] "GET /products HTTP/1.1" 200 15678 "-" "Edge/120.0"',
    '192.168.1.12 - - [12/Jan/2026:10:23:40 +0000] "GET /contact HTTP/1.1" 200 2345 "-" "Opera/105.0"',
    '172.16.0.8 - - [12/Jan/2026:10:23:45 +0000] "POST /api/search HTTP/1.1" 200 456 "-" "Mozilla/5.0"',
  ];

  const maliciousLogs = [
    '203.0.113.45 - - [12/Jan/2026:10:23:28 +0000] "GET /admin.php HTTP/1.1" 404 0 "-" "sqlmap/1.7.2"',
    '198.51.100.23 - - [12/Jan/2026:10:23:33 +0000] "POST /login?id=1\' OR 1=1-- HTTP/1.1" 500 0 "-" "Python-urllib/3.11"',
    '192.0.2.67 - - [12/Jan/2026:10:23:38 +0000] "GET /../../../etc/passwd HTTP/1.1" 404 0 "-" "curl/7.68.0"',
  ];

  // Randomly select one malicious log
  const maliciousLog = maliciousLogs[Math.floor(Math.random() * maliciousLogs.length)];
  
  // Insert at random position
  const maliciousIndex = Math.floor(Math.random() * (normalLogs.length - 1)) + 1;
  normalLogs.splice(maliciousIndex, 0, maliciousLog);

  return { logs: normalLogs, maliciousIndex };
}

// Generate crypto challenge
export function generateCryptoChallenge(): { encrypted: string; answer: string; type: 'base64' | 'hex' } {
  const flags = [
    'FLAG{DOJO_MASTER_2026}',
    'SECRET{YOU_ARE_ELITE}',
    'KEY{CRYPTO_WARRIOR}',
    'TOKEN{DECODE_CHAMPION}'
  ];

  const flag = flags[Math.floor(Math.random() * flags.length)];
  const type = Math.random() > 0.5 ? 'base64' : 'hex';

  let encrypted: string;
  if (type === 'base64') {
    encrypted = btoa(flag);
  } else {
    encrypted = Array.from(flag)
      .map(char => char.charCodeAt(0).toString(16).padStart(2, '0'))
      .join('');
  }

  return { encrypted, answer: flag, type };
}
