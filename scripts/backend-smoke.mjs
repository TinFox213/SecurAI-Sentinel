import { spawn } from 'node:child_process';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import CryptoJS from 'crypto-js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, '..');
const serverDir = path.join(rootDir, 'server');
const baseUrl = 'http://127.0.0.1:3001';
const sharedKey = process.env.VITE_E2EE_KEY || 'SECURAI_ENTERPRISE_E2EE_V1_SECRET_KEY';

const results = [];
const serverLogs = [];

function rememberLog(chunk) {
  const text = chunk.toString();
  serverLogs.push(...text.split(/\r?\n/).filter(Boolean));
  if (serverLogs.length > 80) serverLogs.splice(0, serverLogs.length - 80);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function request(method, route, body, timeoutMs) {
  const headers = {};
  const options = { method, headers };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(body);
  }

  const response = await fetchWithTimeout(`${baseUrl}${route}`, options, timeoutMs);
  const contentType = response.headers.get('content-type') || '';
  const payload = contentType.includes('application/json')
    ? await response.json().catch(() => null)
    : await response.text().catch(() => '');

  return { status: response.status, ok: response.ok, payload, contentType };
}

async function multipartRequest(route, fields, files, timeoutMs) {
  const form = new FormData();
  Object.entries(fields || {}).forEach(([key, value]) => form.append(key, value));
  Object.entries(files || {}).forEach(([key, file]) => form.append(key, file.blob, file.name));

  const response = await fetchWithTimeout(`${baseUrl}${route}`, { method: 'POST', body: form }, timeoutMs);
  const payload = await response.json().catch(() => null);
  return { status: response.status, ok: response.ok, payload, contentType: response.headers.get('content-type') || '' };
}

function encryptedPayload(value) {
  return CryptoJS.AES.encrypt(JSON.stringify(value), sharedKey).toString();
}

function buildSamplePcap() {
  const globalHeader = Buffer.alloc(24);
  globalHeader.writeUInt32LE(0xa1b2c3d4, 0);
  globalHeader.writeUInt16LE(2, 4);
  globalHeader.writeUInt16LE(4, 6);
  globalHeader.writeInt32LE(0, 8);
  globalHeader.writeUInt32LE(0, 12);
  globalHeader.writeUInt32LE(65535, 16);
  globalHeader.writeUInt32LE(1, 20);

  const packet = Buffer.alloc(54);
  Buffer.from('001122334455', 'hex').copy(packet, 0);
  Buffer.from('66778899aabb', 'hex').copy(packet, 6);
  packet.writeUInt16BE(0x0800, 12);
  packet[14] = 0x45;
  packet[15] = 0x00;
  packet.writeUInt16BE(40, 16);
  packet.writeUInt16BE(1, 18);
  packet.writeUInt16BE(0x4000, 20);
  packet[22] = 64;
  packet[23] = 6;
  packet.writeUInt16BE(0, 24);
  Buffer.from([192, 168, 1, 10]).copy(packet, 26);
  Buffer.from([93, 184, 216, 34]).copy(packet, 30);
  packet.writeUInt16BE(49152, 34);
  packet.writeUInt16BE(4444, 36);
  packet.writeUInt32BE(1, 38);
  packet.writeUInt32BE(0, 42);
  packet[46] = 0x50;
  packet[47] = 0x02;
  packet.writeUInt16BE(64240, 48);
  packet.writeUInt16BE(0, 50);
  packet.writeUInt16BE(0, 52);

  const packetHeader = Buffer.alloc(16);
  packetHeader.writeUInt32LE(Math.floor(Date.now() / 1000), 0);
  packetHeader.writeUInt32LE(0, 4);
  packetHeader.writeUInt32LE(packet.length, 8);
  packetHeader.writeUInt32LE(packet.length, 12);

  return Buffer.concat([globalHeader, packetHeader, packet]);
}

function hasKeys(obj, keys) {
  return obj && keys.every((key) => Object.prototype.hasOwnProperty.call(obj, key));
}

async function check(name, fn, expect) {
  const started = Date.now();
  try {
    const response = await fn();
    const verdict = expect(response);
    results.push({
      name,
      status: verdict.status,
      httpStatus: response.status,
      ms: Date.now() - started,
      message: verdict.message || ''
    });
  } catch (error) {
    results.push({
      name,
      status: 'FAIL',
      httpStatus: 0,
      ms: Date.now() - started,
      message: error?.name === 'AbortError' ? 'Timed out' : String(error?.message || error)
    });
  }
}

const okJson = (keys = []) => (response) => {
  if (!response.ok) return { status: 'FAIL', message: JSON.stringify(response.payload).slice(0, 240) };
  if (keys.length && !hasKeys(response.payload, keys)) {
    return { status: 'FAIL', message: `Missing keys: ${keys.filter((key) => !(key in (response.payload || {}))).join(', ')}` };
  }
  return { status: 'PASS' };
};

const allowExternalSkip = (keys = []) => (response) => {
  if (response.ok) {
    if (keys.length && !hasKeys(response.payload, keys)) {
      return { status: 'FAIL', message: `Missing keys: ${keys.filter((key) => !(key in (response.payload || {}))).join(', ')}` };
    }
    return { status: 'PASS' };
  }
  const code = response.payload?.error || response.payload?.message || '';
  if ([401, 429, 502, 503, 504].includes(response.status) || /API_KEY|provider|network|timeout|configured/i.test(code)) {
    return { status: 'SKIP', message: String(code).slice(0, 180) || `External dependency returned ${response.status}` };
  }
  return { status: 'FAIL', message: JSON.stringify(response.payload).slice(0, 240) };
};

async function waitForHealth(child) {
  for (let i = 0; i < 40; i += 1) {
    if (child.exitCode !== null) break;
    try {
      const response = await request('GET', '/health', undefined, 1500);
      if (response.ok) return true;
    } catch {
      await sleep(500);
    }
  }
  return false;
}

async function withLocalHttpServer(fn) {
  const server = http.createServer((req, res) => {
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.statusCode = 200;
    res.end(req.method === 'HEAD' ? undefined : 'ok');
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  try {
    return await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

async function main() {
  const child = spawn(process.execPath, ['index.js'], {
    cwd: serverDir,
    env: {
      ...process.env,
      GEMINI_API_KEY: '',
      VITE_GEMINI_API_KEY: '',
      OPENROUTER_API_KEY: '',
      VITE_OPENROUTER_API_KEY: '',
      NVIDIA_API_KEY: '',
      VITE_NVIDIA_API_KEY: '',
      HIBP_API_KEY: '',
      ABUSEIPDB_API_KEY: '',
      AI_REQUEST_TIMEOUT_MS: '5000',
      ALLOW_UNAUTH_LOCAL: 'true'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  child.stdout.on('data', rememberLog);
  child.stderr.on('data', rememberLog);

  try {
    if (!(await waitForHealth(child))) {
      console.error('Backend did not become healthy.');
      console.error(serverLogs.join('\n'));
      process.exitCode = 1;
      return;
    }

    await withLocalHttpServer(async (localUrl) => {
      await check('Root API metadata', () => request('GET', '/', undefined, 4000), okJson(['app', 'status']));
      await check('Health check', () => request('GET', '/health', undefined, 4000), okJson(['status', 'timestamp', 'ghostPorts']));
      await check('AI provider status', () => request('GET', '/api/ai-providers', undefined, 4000), okJson(['mode', 'providers', 'healthy']));
      await check('Encrypted core analysis', () => request('POST', '/api/analyze', {
        payload: encryptedPayload({
          scanType: 'Port Scan',
          inputData: 'Open ports: 22/tcp OpenSSH 7.2, 80/tcp Apache 2.4, 21/tcp FTP'
        })
      }, 7000), allowExternalSkip(['summary', 'threat_level', 'risk_score']));
      await check('AI chat assistant', () => request('POST', '/api/chat', {
        message: 'Summarize the risk of exposed FTP.',
        context: { threat_level: 'High', risk_score: 75, summary: 'FTP exposed' }
      }, 7000), allowExternalSkip(['response']));
      await check('Remediation script generator', () => request('POST', '/api/generate-script', {
        threatLevel: 'High',
        summary: 'FTP is exposed',
        recommendations: ['Disable FTP or restrict source IPs']
      }, 7000), allowExternalSkip(['script']));
      await check('Cyber Dojo challenge generation', () => request('POST', '/api/generate-challenge', {
        gameType: 'crypto',
        prompt: 'Return JSON for a base64 challenge.'
      }, 7000), allowExternalSkip());
      await check('CryptoVault code analyzer', () => request('POST', '/api/analyze-code', {
        fileName: 'sample.js',
        fileContent: 'const password = "hardcoded"; eval(userInput);'
      }, 7000), allowExternalSkip());

      await check('Network targeted scan wrapper', () => request('POST', '/scan', { ip: '127.0.0.1' }, 7000), okJson(['success', 'openPorts', 'totalOpen']));
      await check('Network port scanner', () => request('POST', '/scan-ports', { ip: '127.0.0.1' }, 7000), okJson(['success', 'openPorts', 'totalOpen']));
      await check('Network ARP status', () => request('GET', '/network/arp-status', undefined, 4000), okJson(['success', 'status', 'monitoring']));
      await check('Ghost alert clear', () => request('POST', '/alerts/clear', {}, 4000), okJson(['success']));
      await check('Ghost alert list', () => request('GET', '/alerts', undefined, 4000), okJson(['success', 'alerts', 'count']));
      await check('Canary tracking pixel', () => request('GET', '/tracking_pixel.png?token=audit', undefined, 4000), (response) => (
        response.status === 200 && response.contentType.includes('image/png')
          ? { status: 'PASS' }
          : { status: 'FAIL', message: `Expected PNG, got ${response.status} ${response.contentType}` }
      ));
      await check('Canary alert list', () => request('GET', '/canary-alerts', undefined, 4000), okJson(['success', 'alerts', 'count']));
      await check('Canary alert clear', () => request('POST', '/canary-alerts/clear', {}, 4000), okJson(['success']));
      await check('Trap pixel endpoint', () => request('GET', '/track/pixel.png?token=audit', undefined, 4000), (response) => (
        response.status === 200 && response.contentType.includes('image/png')
          ? { status: 'PASS' }
          : { status: 'FAIL', message: `Expected PNG, got ${response.status} ${response.contentType}` }
      ));
      await check('Trap alert list', () => request('GET', '/track/alerts', undefined, 4000), okJson(['count', 'alerts']));
      await check('Trap alert clear', () => request('DELETE', '/track/alerts', undefined, 4000), okJson(['success']));

      await check('Web headers checker', () => request('POST', '/web/headers', { url: localUrl }, 7000), okJson(['url', 'status', 'headers']));
      await check('Web DNS checker', () => request('POST', '/web/dns', { domain: 'localhost' }, 7000), allowExternalSkip(['domain', 'status']));
      await check('Web SSL checker', () => request('POST', '/web/ssl', { domain: 'localhost' }, 7000), allowExternalSkip(['domain']));
      await check('Subdomain recon', () => request('POST', '/osint/subdomains', { domain: 'example.com' }, 7000), allowExternalSkip(['domain', 'subdomains']));

      await check('CVE search', () => request('POST', '/cve/search', { query: 'CVE-2024-6387' }, 7000), allowExternalSkip());
      await check('CVE AI analysis', () => request('POST', '/cve/analyze', {
        cveId: 'CVE-2024-6387',
        description: 'OpenSSH regreSSHion remote unauthenticated code execution issue.',
        cvssScore: 8.1,
        affectedProducts: ['OpenSSH']
      }, 7000), allowExternalSkip(['plainEnglish', 'remediationSteps']));
      await check('Threat intel static feed', () => request('GET', '/osint/threat-intel', undefined, 4000), okJson(['globalCampaigns', 'timestamp']));

      await check('EDR telemetry ingest', () => request('POST', '/edr/telemetry', {
        endpointId: 'audit-endpoint',
        hostname: 'audit-host',
        os: 'windows',
        events: [{ type: 'process', name: 'powershell.exe' }]
      }, 4000), okJson(['success']));
      await check('EDR isolate command', () => request('POST', '/edr/isolate', {
        endpointId: 'audit-endpoint',
        os: 'windows',
        reason: 'Smoke test'
      }, 4000), okJson(['success', 'command']));
      await check('Firewall remediation command', () => request('POST', '/remediate/firewall', {
        port: 21,
        protocol: 'tcp',
        os: 'linux'
      }, 4000), okJson(['success', 'command']));
      await check('IaC remediation generator', () => request('POST', '/remediate/iac', {
        cveId: 'CVE-2024-6387',
        description: 'Restrict exposed SSH while patching.',
        format: 'terraform'
      }, 7000), allowExternalSkip(['patch']));

      const pcapBlob = new Blob([buildSamplePcap()], { type: 'application/vnd.tcpdump.pcap' });
      await check('PCAP parser', () => multipartRequest('/pcap/analyze', { analysisDepth: 'quick' }, {
        file: { blob: pcapBlob, name: 'sample.pcap' }
      }, 7000), okJson(['success', 'captureStats', 'anomalies', 'summary']));
      await check('PCAP protocol stats', () => request('POST', '/pcap/protocols', {
        packets: [{ protocol: 'TCP', srcPort: 49152, dstPort: 4444, length: 54, tcpFlags: ['SYN'], srcIP: '192.168.1.10', dstIP: '93.184.216.34' }]
      }, 4000), okJson(['protocolDistribution', 'conversations', 'topPorts']));
      await check('PCAP AI analysis', () => request('POST', '/pcap/ai-analyze', {
        summary: 'One suspicious TCP SYN to destination port 4444.',
        anomalies: [{ type: 'Suspicious Ports', severity: 'High' }],
        captureStats: { totalPackets: 1 }
      }, 7000), allowExternalSkip(['threatLevel', 'verdict']));
      await check('IP reputation fallback', () => request('POST', '/pcap/ip-reputation', { ip: '8.8.8.8' }, 4000), okJson(['ip', 'status']));

      await check('IR playbook generator', () => request('POST', '/ir/generate', {
        incidentType: 'Malware',
        severity: 'High',
        affectedSystems: ['workstation-7'],
        findings: 'Suspicious beacon to port 4444'
      }, 7000), allowExternalSkip(['playbookId', 'phases']));
      await check('IR step update', () => request('POST', '/ir/update-step', {
        playbookId: 'playbook-audit',
        stepId: 'P1-S1',
        status: 'completed',
        notes: 'Smoke test'
      }, 4000), okJson(['success', 'playbookId', 'stepId']));

      await check('Dark web breach lookup', () => request('POST', '/darkweb/breach', {
        query: 'audit@example.com',
        type: 'email'
      }, 7000), allowExternalSkip(['query', 'type', 'status']));
      await check('Dark web AI analysis', () => request('POST', '/darkweb/analyze', {
        query: 'audit@example.com',
        type: 'email',
        breaches: []
      }, 7000), allowExternalSkip(['riskScore', 'riskLevel']));
      await check('Dark web demo data', () => request('POST', '/darkweb/demo-data', {
        query: 'audit@example.com',
        type: 'email'
      }, 7000), allowExternalSkip(['breaches', 'pasteExposures']));
      await check('Dark web domain wrapper', () => request('POST', '/darkweb/domain', {
        domain: 'example.com'
      }, 7000), allowExternalSkip(['query', 'type', 'status']));

      await check('Security posture analyzer', () => request('POST', '/posture/analyze', {
        scanHistory: [{ scanType: 'Port Scan', risk_score: 75, summary: 'FTP exposed' }]
      }, 7000), allowExternalSkip(['overallScore', 'categoryScores']));
      await check('Red-team agent plan', () => request('POST', '/agent/plan', {
        target: '127.0.0.1',
        agentMode: 'active',
        objectives: ['Find exposed services']
      }, 7000), allowExternalSkip(['planTitle', 'steps']));
      await check('Red-team agent interpret', () => request('POST', '/agent/interpret', {
        stepNumber: 1,
        toolName: 'port_scan',
        toolInput: { ip: '127.0.0.1' },
        toolOutput: { openPorts: [{ port: 21, dangerous: true }] }
      }, 7000), allowExternalSkip(['interpretation', 'keyFindings']));
      await check('Red-team agent synthesize', () => request('POST', '/agent/synthesize', {
        target: '127.0.0.1',
        agentMode: 'active',
        allSteps: [{ stepNumber: 1, toolName: 'port_scan', status: 'complete' }],
        allInterpretations: [{ interpretation: 'FTP exposed', riskIndicators: ['FTP exposed'], keyFindings: ['Port 21 open'] }]
      }, 7000), allowExternalSkip(['reportTitle', 'overallRiskRating']));

      await check('Zero Trust generator', () => request('POST', '/zerotrust/generate', {
        targetEnvironment: 'linux edge server',
        openPorts: [{ port: 21, name: 'FTP' }],
        dangerousPorts: [{ port: 21, name: 'FTP' }],
        missingHeaders: ['Content-Security-Policy']
      }, 7000), allowExternalSkip(['policyTitle', 'configs', 'securityRules']));
      await check('Zero Trust validator', () => request('POST', '/zerotrust/validate', {
        configType: 'nginx',
        content: 'server { add_header X-Frame-Options DENY; }'
      }, 4000), okJson(['valid', 'errors', 'warnings']));
      await check('Vulnerability analyzer fallback', () => request('POST', '/vuln/analyze', {
        target: '127.0.0.1',
        context: 'Port 21 exposed'
      }, 7000), allowExternalSkip(['summary', 'findings', 'recommendations']));
      await check('ATT&CK classifier fallback', () => request('POST', '/attack/classify', {
        sourceModule: 'Smoke Test',
        rawFindings: 'Multiple SSH failures followed by success.',
        detectedIndicators: ['sshd failed password']
      }, 7000), okJson(['tactics', 'attackSummary', 'overallSeverity']));
      await check('ATT&CK technique lookup', () => request('POST', '/attack/technique', {
        techniqueId: 'T1110'
      }, 4000), okJson(['techniqueId', 'name', 'tactic']));
    });
  } finally {
    if (!child.killed) child.kill('SIGINT');
    await sleep(500);
    if (child.exitCode === null) child.kill('SIGKILL');
  }

  const counts = results.reduce((acc, result) => {
    acc[result.status] = (acc[result.status] || 0) + 1;
    return acc;
  }, {});

  console.log('\nBackend smoke results');
  console.log('=====================');
  for (const result of results) {
    const code = result.httpStatus ? `HTTP ${result.httpStatus}` : 'NO HTTP';
    const detail = result.message ? ` - ${result.message}` : '';
    console.log(`${result.status.padEnd(4)} ${code.padEnd(8)} ${String(result.ms).padStart(5)}ms  ${result.name}${detail}`);
  }
  console.log('---------------------');
  console.log(`PASS ${counts.PASS || 0} | SKIP ${counts.SKIP || 0} | FAIL ${counts.FAIL || 0}`);

  if (counts.FAIL) {
    console.log('\nRecent backend log tail');
    console.log('-----------------------');
    console.log(serverLogs.slice(-40).join('\n'));
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
