import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';
import dotenv from 'dotenv';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.join(__dirname, '..');
const envLocalPath = path.join(rootDir, '.env.local');
const envPath = path.join(rootDir, '.env');

// Prefer .env.local, then fallback to .env for missing values.
const envLocalResult = dotenv.config({ path: envLocalPath });
if (envLocalResult.error) {
  console.warn(`⚠️ Could not load .env.local from ${envLocalPath}: ${envLocalResult.error.message}`);
} else {
  console.log(`✅ Loaded environment variables from .env.local at ${envLocalPath}`);
}

const envResult = dotenv.config({ path: envPath, override: false });
if (envResult.error) {
  console.warn(`⚠️ Could not load .env from ${envPath}: ${envResult.error.message}`);
} else {
  console.log(`✅ Loaded fallback environment variables from .env at ${envPath}`);
}
import express from 'express';
import cors from 'cors';
import { createServer } from 'http';
import { GoogleGenAI } from '@google/genai';
import { WebSocketServer } from 'ws';
import net from 'net';
import macLookup from 'mac-lookup';
import { exec } from 'child_process';
import { promisify } from 'util';
import sslChecker from 'ssl-checker';
import fetch from 'node-fetch';
import dns from 'dns';
import CryptoJS from 'crypto-js';
import { EventEmitter } from 'events';
import { Readable } from 'stream';

const execAsync = promisify(exec);
const dnsResolve4 = promisify(dns.resolve4);
const require = createRequire(import.meta.url);

process.on('unhandledRejection', (reason) => {
  console.error('❌ Unhandled Promise Rejection:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
});

const app = express();
const PORT = 3001;
const GHOST_PORTS = [8080, 8443];
const API_AUTH_TOKEN = (process.env.INTERNAL_API_TOKEN || '').trim();
const ALLOW_UNAUTH_LOCAL = process.env.ALLOW_UNAUTH_LOCAL !== 'false';
const ALLOWED_ORIGINS = (process.env.CORS_ALLOWED_ORIGINS || 'http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

// E2EE Pre-Shared Key (Should be rotated securely in prod)
const E2EE_SHARED_KEY = process.env.VITE_E2EE_KEY || 'SECURAI_ENTERPRISE_E2EE_V1_SECRET_KEY';

// Optional dependencies (safe fallback if not installed)
let multerLib = null;
let pcapParserLib = null;

try {
  multerLib = require('multer');
  console.log('✅ Optional dependency loaded: multer');
} catch {
  console.warn('⚠️ Optional dependency missing: multer. Falling back to manual multipart parser for PCAP uploads.');
}

try {
  pcapParserLib = require('pcap-parser');
  console.log('✅ Optional dependency loaded: pcap-parser');
} catch {
  console.warn('⚠️ Optional dependency missing: pcap-parser. Using manual PCAP parser fallback.');
}

// ========================================
// AI provider key initialization
// ========================================
function normalizeApiKey(value) {
  const key = String(value || '').trim();
  if (!key || /^your_.*_api_key_here$/i.test(key)) return '';
  return key;
}

const GEMINI_API_KEY = normalizeApiKey(process.env.GEMINI_API_KEY || process.env.VITE_GEMINI_API_KEY);
const OPENROUTER_API_KEY = normalizeApiKey(process.env.OPENROUTER_API_KEY || process.env.VITE_OPENROUTER_API_KEY);
const NVIDIA_API_KEY = normalizeApiKey(process.env.NVIDIA_API_KEY || process.env.VITE_NVIDIA_API_KEY);

const AI_PROVIDER_MODE = String(process.env.AI_PROVIDER || process.env.DEFAULT_AI_PROVIDER || 'auto').trim().toLowerCase();
const AI_PROVIDER_ORDER = String(process.env.AI_PROVIDER_ORDER || 'gemini,openrouter,nvidia')
  .split(',')
  .map((provider) => provider.trim().toLowerCase())
  .filter(Boolean);
const AI_REQUEST_TIMEOUT_MS = Math.max(5000, Number(process.env.AI_REQUEST_TIMEOUT_MS || 45000));
const AI_OPENAI_COMPATIBLE_MAX_TOKENS = Math.max(256, Number(process.env.AI_MAX_TOKENS || 4096));

const AI_PROVIDER_CONFIG = [
  {
    id: 'gemini',
    label: 'Gemini',
    apiKey: GEMINI_API_KEY,
    model: process.env.GEMINI_MODEL || 'gemini-2.5-flash',
    type: 'gemini',
  },
  {
    id: 'openrouter',
    label: 'OpenRouter',
    apiKey: OPENROUTER_API_KEY,
    model: process.env.OPENROUTER_MODEL || 'google/gemini-2.5-flash',
    endpoint: process.env.OPENROUTER_BASE_URL || 'https://openrouter.ai/api/v1/chat/completions',
    type: 'openai-compatible',
  },
  {
    id: 'nvidia',
    label: 'NVIDIA',
    apiKey: NVIDIA_API_KEY,
    model: process.env.NVIDIA_MODEL || 'meta/llama-3.1-8b-instruct',
    endpoint: process.env.NVIDIA_BASE_URL || 'https://integrate.api.nvidia.com/v1/chat/completions',
    type: 'openai-compatible',
  },
];

if (!AI_PROVIDER_CONFIG.some((provider) => Boolean(provider.apiKey))) {
  console.error('\nCRITICAL: No AI provider API key found.');
  console.error('Set GEMINI_API_KEY, OPENROUTER_API_KEY, or NVIDIA_API_KEY in .env.local or .env.');
  console.error(`Checked .env.local at: ${envLocalPath}`);
  console.error(`Checked .env at: ${envPath}`);
  console.error('The application will continue but AI features will fail until a provider is configured.\n');
}

function decryptPayload(ciphertext) {
  try {
    const bytes = CryptoJS.AES.decrypt(ciphertext, E2EE_SHARED_KEY);
    const decryptedStr = bytes.toString(CryptoJS.enc.Utf8);
    return JSON.parse(decryptedStr);
  } catch (error) {
    console.error('Core Backend E2EE Decryption Failed:', error);
    return null;
  }
}

// ARP Spoofing Guard Storage
let gatewayIP = null;
let trustedGatewayMAC = null;
let arpStatus = {
  status: 'secure',
  details: 'Initializing ARP monitoring...',
  lastCheck: null,
  alerts: []
};

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length > 0) {
    return forwarded.split(',')[0].trim();
  }
  return req.ip || req.socket?.remoteAddress || '';
}

function isLoopbackAddress(ip) {
  const normalized = String(ip || '').toLowerCase();
  return normalized === '127.0.0.1'
    || normalized === '::1'
    || normalized === '::ffff:127.0.0.1'
    || normalized.endsWith('localhost');
}

function isAllowedOrigin(origin) {
  if (!origin) return true;
  return ALLOWED_ORIGINS.includes(origin);
}

function extractBearerToken(authHeader) {
  const value = String(authHeader || '');
  if (!value.toLowerCase().startsWith('bearer ')) return '';
  return value.slice(7).trim();
}

function requireEndpointAuth(req, res, next) {
  const providedToken = (req.headers['x-api-token'] || extractBearerToken(req.headers.authorization) || '').toString().trim();

  if (API_AUTH_TOKEN) {
    if (!providedToken || providedToken !== API_AUTH_TOKEN) {
      return res.status(401).json({
        error: 'UNAUTHORIZED',
        message: 'Valid API token is required for this endpoint.'
      });
    }
    return next();
  }

  if (ALLOW_UNAUTH_LOCAL) {
    const clientIp = getClientIp(req);
    if (isLoopbackAddress(clientIp)) {
      return next();
    }

    return res.status(403).json({
      error: 'FORBIDDEN',
      message: 'Access denied. Configure INTERNAL_API_TOKEN for non-local access.'
    });
  }

  return res.status(503).json({
    error: 'AUTH_NOT_CONFIGURED',
    message: 'INTERNAL_API_TOKEN is required when ALLOW_UNAUTH_LOCAL=false.'
  });
}

if (!API_AUTH_TOKEN && ALLOW_UNAUTH_LOCAL) {
  console.warn('⚠️ INTERNAL_API_TOKEN is not configured. Endpoint auth is currently restricted to local loopback only.');
}

// Middleware
app.use(cors({
  origin: (origin, callback) => {
    if (isAllowedOrigin(origin)) {
      return callback(null, true);
    }
    return callback(new Error(`CORS blocked for origin: ${origin}`));
  },
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Token'],
  credentials: true,
  optionsSuccessStatus: 204
}));
app.use(express.json());
app.use('/api', requireEndpointAuth);
app.use('/cve', requireEndpointAuth);
app.use('/darkweb', requireEndpointAuth);
app.use('/posture', requireEndpointAuth);
app.use('/attack', requireEndpointAuth);
app.use('/remediate', requireEndpointAuth);
app.use('/edr', requireEndpointAuth);
app.use('/network', requireEndpointAuth);
app.use('/scan', requireEndpointAuth);
app.use('/scan-ports', requireEndpointAuth);
app.use('/web', requireEndpointAuth);
app.use('/osint', requireEndpointAuth);
app.use('/alerts', requireEndpointAuth);
app.use('/canary-alerts', requireEndpointAuth);
app.use('/pcap', requireEndpointAuth);
app.use('/ir', requireEndpointAuth);
app.use('/agent', requireEndpointAuth);
app.use('/zerotrust', requireEndpointAuth);
app.use('/vuln', requireEndpointAuth);

// ========================================
// 🏥 HEALTH CHECK & ROOT ROUTE
// ========================================
app.get('/', (req, res) => {
  res.json({ 
    app: 'SecurAI Sentinel Backend', 
    status: 'Online',
    message: 'API is running normally. Please access the frontend at http://localhost:3000',
    endpoints: {
      api: 'POST /api/analyze - Main security analysis',
      providers: 'GET /api/ai-providers - AI provider routing status',
      cve: 'POST /cve/analyze - CVE analysis',
      dojo: 'POST /dojo/* - Cyber Dojo challenges',
      websocket: 'ws://localhost:3001 - Real-time alerts'
    }
  });
});

app.get('/api/ai-providers', (req, res) => {
  res.json(getAIProviderStatus());
});

app.post('/api/ai-providers/test', async (req, res) => {
  const configuredProviders = AI_PROVIDER_CONFIG.filter((provider) => Boolean(provider.apiKey));
  const results = [];

  for (const provider of configuredProviders) {
    const startedAt = Date.now();
    try {
      const text = provider.type === 'gemini'
        ? await callGeminiProvider(provider, 'Reply with exactly OK.', { temperature: 0, maxOutputTokens: 8 })
        : await callOpenAICompatibleProvider(provider, 'Reply with exactly OK.', { temperature: 0, maxOutputTokens: 8 });

      results.push({
        id: provider.id,
        label: provider.label,
        model: provider.model,
        ok: true,
        latencyMs: Date.now() - startedAt,
        sample: String(text || '').trim().slice(0, 80),
      });
    } catch (error) {
      results.push({
        id: provider.id,
        label: provider.label,
        model: provider.model,
        ok: false,
        latencyMs: Date.now() - startedAt,
        error: sanitizeProviderTestError(error),
      });
    }
  }

  res.json({
    testedAt: new Date().toISOString(),
    configuredCount: configuredProviders.length,
    healthyCount: results.filter((result) => result.ok).length,
    results,
  });
});

function sanitizeProviderTestError(error) {
  return String(error?.message || 'Unknown provider error')
    .replace(/[A-Za-z0-9_-]{24,}/g, '[redacted]')
    .slice(0, 360);
}

function normalizeCertificateHostname(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/^\*\./, '')
    .replace(/\.$/, '');
}

function isValidHostnameForDomain(hostname, domain) {
  const cleanHostname = normalizeCertificateHostname(hostname);
  const cleanDomain = normalizeCertificateHostname(domain);
  if (!cleanHostname || !cleanDomain) return false;
  if (cleanHostname.includes('@') || cleanHostname.includes(' ')) return false;
  if (cleanHostname !== cleanDomain && !cleanHostname.endsWith(`.${cleanDomain}`)) return false;

  return cleanHostname
    .split('.')
    .every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
}

// Store for active connections and alerts
const connectionAlerts = [];
const wsClients = new Set();

// Canary Factory Breach Tracking Storage
const breachLogs = [];

// HTTP Server
const server = createServer(app);

// WebSocket Server for real-time alerts
const wss = new WebSocketServer({
  server,
  verifyClient: (info, done) => {
    const origin = info.origin;
    if (!isAllowedOrigin(origin)) {
      return done(false, 403, 'CORS origin not allowed for WebSocket');
    }

    const req = info.req;
    const authHeader = req.headers.authorization;
    const tokenFromHeader = req.headers['x-api-token'];
    const tokenFromQuery = (() => {
      try {
        const base = req.headers.host ? `http://${req.headers.host}` : 'http://localhost';
        const url = new URL(req.url || '/', base);
        return url.searchParams.get('token') || '';
      } catch {
        return '';
      }
    })();

    const providedToken = String(tokenFromHeader || extractBearerToken(authHeader) || tokenFromQuery || '').trim();

    if (API_AUTH_TOKEN) {
      if (!providedToken || providedToken !== API_AUTH_TOKEN) {
        return done(false, 401, 'Invalid API token');
      }
      return done(true);
    }

    if (ALLOW_UNAUTH_LOCAL) {
      const remote = req.socket?.remoteAddress || '';
      if (isLoopbackAddress(remote)) {
        return done(true);
      }
      return done(false, 403, 'WebSocket local-only access without token');
    }

    return done(false, 503, 'WebSocket auth not configured');
  }
});

wss.on('connection', (ws) => {
  console.log('✅ Frontend connected to WebSocket');
  wsClients.add(ws);
  
  // Send existing alerts
  ws.send(JSON.stringify({ type: 'history', alerts: connectionAlerts }));
  
  ws.on('close', () => {
    wsClients.delete(ws);
    console.log('❌ Frontend disconnected from WebSocket');
  });
});

// ========================================
// ✉️ EVENT-DRIVEN NOTIFICATION ENGINE
// ========================================
const NotificationEngine = new EventEmitter();

NotificationEngine.on('broadcast', (payload) => {
  const message = JSON.stringify(payload);
  wsClients.forEach(client => {
    if (client.readyState === 1) { // OPEN
      client.send(message);
    }
  });
});

NotificationEngine.on('alert', (alert) => {
  NotificationEngine.emit('broadcast', { type: 'alert', data: alert });
});

NotificationEngine.on('canary_breach', (breachLog) => {
  NotificationEngine.emit('broadcast', { type: 'canary_breach', data: breachLog });
});

// Legacy wrapper to maintain compatibility
function broadcastAlert(alert) {
  NotificationEngine.emit('alert', alert);
}

// Ghost Port Listener
function setupGhostPorts() {
  GHOST_PORTS.forEach(port => {
    const ghostServer = net.createServer((socket) => {
      const alert = {
        timestamp: new Date().toISOString(),
        sourceIP: socket.remoteAddress,
        sourcePort: socket.remotePort,
        targetPort: port,
        message: `⚠️ Unauthorized connection attempt detected on port ${port}`,
        severity: 'HIGH'
      };
      
      console.log(`🚨 GHOST PORT TRIGGERED: ${alert.sourceIP}:${alert.sourcePort} → ${port}`);
      connectionAlerts.push(alert);
      
      // Broadcast to all connected WebSocket clients
      broadcastAlert(alert);
      
      // Close connection immediately
      socket.end();
    });
    
    ghostServer.listen(port, '0.0.0.0', () => {
      console.log(`👻 Ghost Port listening on ${port}`);
    });
    
    ghostServer.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        console.log(`⚠️ Port ${port} already in use - skipping ghost listener`);
      } else {
        console.error(`Ghost Port ${port} error:`, err);
      }
    });
  });
}

// API Endpoints

// GET /scan - Network device discovery with vendor lookup
app.get('/scan', async (req, res) => {
  try {
    console.log('🔍 Starting network scan...');
    const devices = await discoverLocalDevices();
    
    // Enhance device info with real vendor lookup
    const enhancedDevices = await Promise.all(
      devices.map(async (device) => {
        let vendor = 'Unknown';
        try {
          // Try mac-lookup first (uses official IEEE database)
          vendor = await macLookup.lookup(device.mac);
        } catch (error) {
          // Fallback to basic lookup if API fails
          vendor = getVendorFromMAC(device.mac);
        }
        
        return {
          ip: device.ip,
          mac: device.mac,
          name: device.name || 'Unknown',
          vendor: vendor,
          lastSeen: new Date().toISOString(),
          status: 'online'
        };
      })
    );
    
    console.log(`✅ Found ${enhancedDevices.length} devices`);
    res.json({ 
      success: true, 
      devices: enhancedDevices,
      scanTime: new Date().toISOString()
    });
  } catch (error) {
    console.error('❌ Scan error:', error);
    res.status(500).json({ 
      success: false, 
      error: error.message,
      devices: []
    });
  }
});

// POST /scan - Target port scan wrapper (agent-compatible endpoint)
app.post('/scan', async (req, res) => {
  const rawTarget = String(req.body?.ip || req.body?.target || req.body?.host || '').trim();
  if (!rawTarget) {
    return res.status(400).json({
      success: false,
      error: 'ip, target, or host is required'
    });
  }

  const normalizedHost = rawTarget.replace(/^https?:\/\//i, '').split('/')[0];
  let scanIp = normalizedHost;
  if (!/^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(normalizedHost)) {
    try {
      const resolvedIps = await dnsResolve4(normalizedHost);
      if (!resolvedIps || resolvedIps.length === 0) {
        throw new Error('No DNS A record');
      }
      [scanIp] = resolvedIps;
    } catch {
      return res.status(400).json({
        success: false,
        error: `Unable to resolve host: ${normalizedHost}`
      });
    }
  }

  const criticalPorts = [
    { port: 21, name: 'FTP', dangerous: true },
    { port: 22, name: 'SSH', dangerous: false },
    { port: 23, name: 'Telnet', dangerous: true },
    { port: 80, name: 'HTTP', dangerous: false },
    { port: 443, name: 'HTTPS', dangerous: false },
    { port: 445, name: 'SMB', dangerous: true },
    { port: 3389, name: 'RDP', dangerous: false }
  ];

  try {
    const scanResults = await Promise.all(
      criticalPorts.map(({ port, name, dangerous }) =>
        new Promise((resolve) => {
          const socket = new net.Socket();
          socket.setTimeout(500);
          socket.on('connect', () => {
            socket.destroy();
            resolve({ port, name, open: true, dangerous });
          });
          socket.on('timeout', () => {
            socket.destroy();
            resolve({ port, name, open: false, dangerous });
          });
          socket.on('error', () => {
            socket.destroy();
            resolve({ port, name, open: false, dangerous });
          });
          socket.connect(port, scanIp);
        })
      )
    );

    const openPorts = scanResults.filter((row) => row.open);
    const dangerousPorts = openPorts.filter((row) => row.dangerous);

    return res.json({
      success: true,
      target: normalizedHost,
      ip: scanIp,
      openPorts,
      totalOpen: openPorts.length,
      dangerous: dangerousPorts.length > 0,
      dangerousPorts
    });
  } catch (error) {
    console.error('❌ /scan POST error:', error);
    return res.status(500).json({
      success: false,
      error: error.message,
      openPorts: []
    });
  }
});

// POST /scan-ports - Scan target IP for open ports
app.post('/scan-ports', async (req, res) => {
  const { ip } = req.body;
  
  if (!ip) {
    return res.status(400).json({ 
      success: false, 
      error: 'IP address is required' 
    });
  }
  
  // Critical ports to scan
  const criticalPorts = [
    { port: 21, name: 'FTP', dangerous: true },
    { port: 22, name: 'SSH', dangerous: false },
    { port: 23, name: 'Telnet', dangerous: true },
    { port: 80, name: 'HTTP', dangerous: false },
    { port: 443, name: 'HTTPS', dangerous: false },
    { port: 445, name: 'SMB', dangerous: true },
    { port: 3389, name: 'RDP', dangerous: false }
  ];
  
  console.log(`🔍 Scanning ports on ${ip}...`);
  
  try {
    const scanResults = await Promise.all(
      criticalPorts.map(({ port, name, dangerous }) => 
        new Promise((resolve) => {
          const socket = new net.Socket();
          const timeout = 500; // 500ms timeout
          
          socket.setTimeout(timeout);
          
          socket.on('connect', () => {
            socket.destroy();
            resolve({ port, name, open: true, dangerous });
          });
          
          socket.on('timeout', () => {
            socket.destroy();
            resolve({ port, name, open: false, dangerous });
          });
          
          socket.on('error', () => {
            socket.destroy();
            resolve({ port, name, open: false, dangerous });
          });
          
          socket.connect(port, ip);
        })
      )
    );
    
    const openPorts = scanResults.filter(r => r.open);
    const dangerousPorts = openPorts.filter(r => r.dangerous);
    
    console.log(`✅ Scan complete: ${openPorts.length} open ports found`);
    
    res.json({
      success: true,
      ip,
      openPorts,
      totalOpen: openPorts.length,
      dangerous: dangerousPorts.length > 0,
      dangerousPorts
    });
  } catch (error) {
    console.error('❌ Port scan error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

// GET /alerts - Get ghost port connection alerts
app.get('/alerts', (req, res) => {
  res.json({
    success: true,
    alerts: connectionAlerts,
    count: connectionAlerts.length
  });
});

// POST /alerts/clear - Clear all alerts
app.post('/alerts/clear', (req, res) => {
  connectionAlerts.length = 0;
  res.json({ success: true, message: 'Alerts cleared' });
});

// GET /health - Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'online',
    timestamp: new Date().toISOString(),
    ghostPorts: GHOST_PORTS,
    activeConnections: wsClients.size
  });
});

// Canary trap storage
const canaryAlerts = [];

// GET /tracking_pixel.png - Canary trap detection endpoint
app.get('/tracking_pixel.png', (req, res) => {
  const alert = {
    type: 'canary_breach',
    timestamp: new Date().toISOString(),
    ip: req.ip || req.connection.remoteAddress,
    userAgent: req.headers['user-agent'] || 'Unknown',
    token: req.query.token || 'unknown',
    referer: req.headers.referer || 'Direct Access',
    severity: 'critical'
  };
  
  canaryAlerts.push(alert);
  console.log('🚨 CANARY TRAP TRIGGERED:', alert);
  
  // Broadcast alert to all connected WebSocket clients
  broadcastAlert(alert);
  
  // Return a 1x1 transparent PNG
  const pixel = Buffer.from(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=',
    'base64'
  );
  
  res.writeHead(200, {
    'Content-Type': 'image/png',
    'Content-Length': pixel.length,
    'Cache-Control': 'no-cache, no-store, must-revalidate'
  });
  res.end(pixel);
});

// GET /canary-alerts - Get all canary trap alerts
app.get('/canary-alerts', (req, res) => {
  res.json({
    success: true,
    alerts: canaryAlerts,
    count: canaryAlerts.length
  });
});

// POST /canary-alerts/clear - Clear canary alerts
app.post('/canary-alerts/clear', (req, res) => {
  canaryAlerts.length = 0;
  res.json({ success: true, message: 'Canary alerts cleared' });
});

// GET /network/arp-status - ARP Spoofing Guard status
app.get('/network/arp-status', (req, res) => {
  res.json({
    success: true,
    ...arpStatus,
    monitoring: gatewayIP !== null && trustedGatewayMAC !== null
  });
});

// POST /network/arp-reset - Reset ARP Guard (re-learn gateway MAC)
app.post('/network/arp-reset', async (req, res) => {
  console.log('🔄 Resetting ARP Guard...');
  arpStatus.alerts = [];
  await initializeARPGuard();
  await checkARPSpoofing();
  
  res.json({
    success: true,
    message: 'ARP Guard reset complete',
    status: arpStatus
  });
});

// Helper function to derive vendor from MAC address
function getVendorFromMAC(mac) {
  if (!mac) return 'Unknown';
  
  const prefix = mac.substring(0, 8).toUpperCase().replace(/:/g, '-');
  
  // Basic vendor mapping (first 3 octets of MAC)
  const vendors = {
    '00-50-56': 'VMware',
    '00-0C-29': 'VMware',
    '00-05-69': 'VMware',
    '00-1C-42': 'Parallels',
    '08-00-27': 'VirtualBox',
    '00-15-5D': 'Microsoft (Hyper-V)',
    '00-1B-21': 'Intel',
    '00-50-F2': 'Microsoft',
    'DC-A6-32': 'Raspberry Pi',
    'B8-27-EB': 'Raspberry Pi',
    'E4-5F-01': 'Raspberry Pi',
    '00-1A-62': 'Google',
    'F0-18-98': 'Apple',
    'AC-DE-48': 'Apple',
    '00-25-00': 'Apple',
    '28-CD-C1': 'Dell',
    '18-03-73': 'Dell',
    '00-14-22': 'Dell',
    '00-50-B6': 'HP',
    '00-1B-78': 'HP',
    '70-5A-0F': 'HP',
    '00-E0-4C': 'Realtek',
    'D8-49-0B': 'Tp-Link',
    'EC-08-6B': 'Tp-Link'
  };
  
  return vendors[prefix] || 'Unknown Vendor';
}

async function discoverLocalDevices() {
  const arpEntries = await getARPTable();
  const devicesByMac = new Map();

  for (const entry of arpEntries) {
    const ip = String(entry.ip || '').trim();
    const mac = String(entry.mac || '').trim().toUpperCase();
    if (!ip || !mac) continue;
    const firstMacOctet = parseInt(mac.slice(0, 2), 16);
    if ((firstMacOctet & 1) !== 0) continue;
    if (/^(?:0\.|127\.|169\.254\.|22[4-9]\.|23\d\.|24\d\.|25[0-5]\.)/.test(ip)) continue;
    if (!devicesByMac.has(mac)) {
      devicesByMac.set(mac, {
        ip,
        mac,
        name: ip,
      });
    }
  }

  return Array.from(devicesByMac.values());
}

// ============================================
// ARP SPOOFING GUARD FUNCTIONS
// ============================================

// Get default gateway IP address
async function getDefaultGateway() {
  try {
    const { stdout } = await execAsync('route print 0.0.0.0');
    const lines = stdout.split('\n');
    
    // Find the line with 0.0.0.0 default route
    for (const line of lines) {
      if (line.includes('0.0.0.0') && line.trim().startsWith('0.0.0.0')) {
        const parts = line.trim().split(/\s+/);
        // Format: 0.0.0.0  0.0.0.0  Gateway_IP  Interface_IP  Metric
        if (parts.length >= 3) {
          const gateway = parts[2];
          if (gateway && gateway !== '0.0.0.0' && gateway.match(/^\d+\.\d+\.\d+\.\d+$/)) {
            console.log(`🌐 Default Gateway detected: ${gateway}`);
            return gateway;
          }
        }
      }
    }
    throw new Error('Could not find default gateway');
  } catch (error) {
    console.error('❌ Error getting default gateway:', error.message);
    return null;
  }
}

// Get MAC address from ARP table for a specific IP
async function getMACFromARP(ip) {
  try {
    const { stdout } = await execAsync(`arp -a ${ip}`);
    const lines = stdout.split('\n');
    
    for (const line of lines) {
      if (line.includes(ip)) {
        // Parse the MAC address (format: xx-xx-xx-xx-xx-xx)
        const macMatch = line.match(/([0-9a-f]{2}[:-]){5}([0-9a-f]{2})/i);
        if (macMatch) {
          const mac = macMatch[0].replace(/-/g, ':').toUpperCase();
          return mac;
        }
      }
    }
    return null;
  } catch (error) {
    console.error(`❌ Error getting MAC for ${ip}:`, error.message);
    return null;
  }
}

// Get entire ARP table
async function getARPTable() {
  try {
    const { stdout } = await execAsync('arp -a');
    const entries = [];
    const lines = stdout.split('\n');
    
    for (const line of lines) {
      // Match lines with IP and MAC address
      const ipMatch = line.match(/(\d+\.\d+\.\d+\.\d+)/);
      const macMatch = line.match(/([0-9a-f]{2}[:-]){5}([0-9a-f]{2})/i);
      
      if (ipMatch && macMatch) {
        const ip = ipMatch[0];
        const mac = macMatch[0].replace(/-/g, ':').toUpperCase();
        
        // Skip invalid MACs
        if (mac !== '00:00:00:00:00:00' && mac !== 'FF:FF:FF:FF:FF:FF') {
          entries.push({ ip, mac });
        }
      }
    }
    
    return entries;
  } catch (error) {
    console.error('❌ Error getting ARP table:', error.message);
    return [];
  }
}

// Initialize ARP Guard - Find and store trusted gateway MAC
async function initializeARPGuard() {
  console.log('🛡️  Initializing ARP Spoofing Guard...');
  
  gatewayIP = await getDefaultGateway();
  if (!gatewayIP) {
    console.error('⚠️  Could not detect gateway IP - ARP Guard disabled');
    arpStatus.status = 'error';
    arpStatus.details = 'Failed to detect default gateway';
    return;
  }
  
  trustedGatewayMAC = await getMACFromARP(gatewayIP);
  if (!trustedGatewayMAC) {
    console.error('⚠️  Could not detect gateway MAC - ARP Guard disabled');
    arpStatus.status = 'error';
    arpStatus.details = 'Failed to detect gateway MAC address';
    return;
  }
  
  console.log(`✅ ARP Guard Initialized`);
  console.log(`   Gateway IP: ${gatewayIP}`);
  console.log(`   Trusted MAC: ${trustedGatewayMAC}`);
  
  arpStatus.status = 'secure';
  arpStatus.details = `Gateway ${gatewayIP} locked to MAC ${trustedGatewayMAC}`;
  arpStatus.lastCheck = new Date().toISOString();
  arpStatus.gatewayIP = gatewayIP;
  arpStatus.trustedMAC = trustedGatewayMAC;
}

// Check for ARP spoofing attacks
async function checkARPSpoofing() {
  if (!gatewayIP || !trustedGatewayMAC) {
    return; // ARP Guard not initialized
  }
  
  try {
    // Check 1: Gateway MAC Verification
    const currentGatewayMAC = await getMACFromARP(gatewayIP);
    
    if (!currentGatewayMAC) {
      arpStatus.status = 'warning';
      arpStatus.details = 'Gateway MAC not found in ARP table';
      arpStatus.lastCheck = new Date().toISOString();
      return;
    }
    
    if (currentGatewayMAC !== trustedGatewayMAC) {
      // CRITICAL: Gateway MAC has changed!
      const alert = {
        type: 'gateway_spoof',
        severity: 'CRITICAL',
        timestamp: new Date().toISOString(),
        message: `🚨 GATEWAY MAC CHANGED! Possible MitM Attack`,
        gatewayIP,
        expectedMAC: trustedGatewayMAC,
        detectedMAC: currentGatewayMAC
      };
      
      arpStatus.status = 'compromised';
      arpStatus.details = `Gateway MAC mismatch detected! Expected: ${trustedGatewayMAC}, Got: ${currentGatewayMAC}`;
      arpStatus.alerts.push(alert);
      arpStatus.lastCheck = new Date().toISOString();
      
      console.error('🚨🚨🚨 ARP SPOOFING DETECTED - GATEWAY MAC CHANGED! 🚨🚨🚨');
      console.error(`   Expected: ${trustedGatewayMAC}`);
      console.error(`   Detected: ${currentGatewayMAC}`);
      
      // Broadcast critical alert to all WebSocket clients
      broadcastAlert(alert);
      return;
    }
    
    // Check 2: Duplicate MAC Detection
    const arpTable = await getARPTable();
    const macCounts = {};
    
    for (const entry of arpTable) {
      // Skip multicast/broadcast MACs (first octet has LSB set, e.g., 01:00:5E:...)
      const firstOctet = parseInt(entry.mac.substring(0, 2), 16);
      if ((firstOctet & 1) !== 0) {
        continue; // Skip multicast addresses
      }
      
      if (!macCounts[entry.mac]) {
        macCounts[entry.mac] = [];
      }
      macCounts[entry.mac].push(entry.ip);
    }
    
    // Find MACs with multiple IPs
    const duplicates = Object.entries(macCounts).filter(([mac, ips]) => ips.length > 1);
    
    if (duplicates.length > 0) {
      const alert = {
        type: 'duplicate_mac',
        severity: 'HIGH',
        timestamp: new Date().toISOString(),
        message: `⚠️ Multiple IPs sharing same MAC address detected`,
        duplicates: duplicates.map(([mac, ips]) => ({ mac, ips }))
      };
      
      arpStatus.status = 'compromised';
      arpStatus.details = `Duplicate MAC addresses detected: ${duplicates.length} conflicts`;
      arpStatus.alerts.push(alert);
      arpStatus.lastCheck = new Date().toISOString();
      
      console.warn('⚠️  Duplicate MAC addresses detected:');
      duplicates.forEach(([mac, ips]) => {
        console.warn(`   MAC ${mac} -> IPs: ${ips.join(', ')}`);
      });
      
      broadcastAlert(alert);
      return;
    }
    
    // All checks passed
    arpStatus.status = 'secure';
    arpStatus.details = `Network secure. Gateway ${gatewayIP} verified at ${trustedGatewayMAC}`;
    arpStatus.lastCheck = new Date().toISOString();
    
  } catch (error) {
    console.error('❌ Error during ARP check:', error.message);
    arpStatus.status = 'error';
    arpStatus.details = `Check failed: ${error.message}`;
    arpStatus.lastCheck = new Date().toISOString();
  }
}

// Start ARP monitoring interval (every 10 seconds)
function startARPMonitoring() {
  // Initial check after 2 seconds
  setTimeout(async () => {
    await initializeARPGuard();
    await checkARPSpoofing();
  }, 2000);
  
  // Periodic checks every 10 seconds
  setInterval(async () => {
    await checkARPSpoofing();
  }, 10000);
  
  console.log('🔄 ARP monitoring started (10-second intervals)');
}

// ========================================
// 🌐 WEBSEC OPS ENDPOINTS
// ========================================

// SSL Certificate Checker
app.post('/web/ssl', async (req, res) => {
  try {
    const { domain } = req.body;
    
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }
    
    // Remove protocol and path if provided
    const cleanDomain = domain.replace(/^https?:\/\//, '').split('/')[0];
    
    console.log(`🔒 Checking SSL for: ${cleanDomain}`);
    
    const sslInfo = await sslChecker(cleanDomain, { method: 'GET', port: 443 });
    
    res.json({
      domain: cleanDomain,
      valid: sslInfo.valid,
      daysRemaining: sslInfo.daysRemaining,
      validFrom: sslInfo.validFrom,
      validTo: sslInfo.validTo,
      issuer: sslInfo.validFor?.[0] || cleanDomain
    });
  } catch (error) {
    console.error('SSL Check Error:', error.message);
    res.json({
      domain: String(req.body?.domain || '').replace(/^https?:\/\//, '').split('/')[0],
      valid: false,
      daysRemaining: 0,
      validFrom: null,
      validTo: null,
      issuer: 'Unavailable',
      status: 'unavailable',
      warning: 'SSL check could not be completed in the current environment.',
      details: error.message || 'SSL check failed',
      fallback: true
    });
  }
});

// HTTP Security Headers Checker
app.post('/web/headers', async (req, res) => {
  try {
    const { url } = req.body;
    
    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }
    
    // Ensure URL has protocol
    const fullUrl = url.startsWith('http') ? url : `https://${url}`;
    
    console.log(`📋 Fetching headers from: ${fullUrl}`);
    
    const response = await fetch(fullUrl, { 
      method: 'HEAD',
      redirect: 'follow',
      timeout: 10000
    });
    
    const headers = {};
    response.headers.forEach((value, key) => {
      headers[key] = value;
    });
    
    res.json({
      url: fullUrl,
      status: response.status,
      headers: headers
    });
  } catch (error) {
    console.error('Headers Check Error:', error.message);
    res.status(500).json({ 
      error: 'Headers fetch failed', 
      details: error.message 
    });
  }
});

// DNS Integrity Checker
app.post('/web/dns', async (req, res) => {
  try {
    const { domain } = req.body;
    
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }
    
    const cleanDomain = domain.replace(/^https?:\/\//, '').split('/')[0];
    
    console.log(`🔍 Checking DNS for: ${cleanDomain}`);
    
    // Resolve using system DNS
    const systemIPs = await dnsResolve4(cleanDomain);
    
    // Resolve using Google DNS (8.8.8.8)
    const { Resolver } = dns;
    const googleResolver = new Resolver();
    googleResolver.setServers(['8.8.8.8']);
    const googleResolve = promisify(googleResolver.resolve4.bind(googleResolver));
    const googleIPs = await googleResolve(cleanDomain);
    
    // Check if IPs match
    const match = systemIPs.some(ip => googleIPs.includes(ip));
    
    res.json({
      domain: cleanDomain,
      systemDNS: systemIPs,
      googleDNS: googleIPs,
      match: match,
      status: match ? 'secure' : 'warning'
    });
  } catch (error) {
    console.error('DNS Check Error:', error.message);
    res.json({
      domain: String(req.body?.domain || '').replace(/^https?:\/\//, '').split('/')[0],
      systemDNS: [],
      googleDNS: [],
      match: false,
      status: 'warning',
      warning: 'DNS comparison could not be completed; resolver or external DNS may be unavailable.',
      details: error.message || 'DNS resolution failed',
      fallback: true
    });
  }
});

// Subdomain Enumeration (OSINT)
app.post('/osint/subdomains', async (req, res) => {
  try {
    const { domain } = req.body;
    
    if (!domain) {
      return res.status(400).json({ error: 'Domain is required' });
    }
    
    const cleanDomain = domain.replace(/^https?:\/\//, '').split('/')[0];
    
    console.log(`🔎 Enumerating subdomains for: ${cleanDomain}`);
    
    // Query crt.sh certificate transparency logs
    const crtshUrl = `https://crt.sh/?q=%.${cleanDomain}&output=json`;
    const response = await fetch(crtshUrl, { timeout: 15000 });
    
    if (!response.ok) {
      throw new Error(`crt.sh returned status ${response.status}`);
    }
    
    const data = await response.json();
    
    // Extract unique subdomains
    const subdomains = new Set();
    data.forEach(entry => {
      if (entry.name_value) {
        entry.name_value.split('\n').forEach(name => {
          const cleaned = normalizeCertificateHostname(name);
          if (isValidHostnameForDomain(cleaned, cleanDomain)) {
            subdomains.add(cleaned);
          }
        });
      }
    });
    
    const sortedSubdomains = Array.from(subdomains).sort();
    
    res.json({
      domain: cleanDomain,
      count: sortedSubdomains.length,
      subdomains: sortedSubdomains,
      source: 'crt.sh'
    });
  } catch (error) {
    console.error('Subdomain Enumeration Error:', error.message);
    const cleanDomain = String(req.body?.domain || '').replace(/^https?:\/\//, '').split('/')[0];
    res.json({
      domain: cleanDomain,
      count: 0,
      subdomains: [],
      source: 'crt.sh unavailable',
      warning: 'Certificate transparency lookup failed; returning an empty fallback result.',
      details: error.message || 'Subdomain enumeration failed',
      fallback: true
    });
  }
});

// ========================================
// 🍯 CANARY FACTORY - TRAP LISTENER
// ========================================

// Generate a 1x1 transparent PNG pixel
const TRANSPARENT_PIXEL = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
  'base64'
);

// Tracking Pixel Endpoint - The Trap Trigger
app.get('/track/pixel.png', (req, res) => {
  try {
    const token = req.query.token || 'Unknown_Trap';
    
    // Extract client information
    const clientIP = req.headers['x-forwarded-for'] || 
                     req.connection.remoteAddress || 
                     req.socket.remoteAddress ||
                     req.ip;
    
    const userAgent = req.headers['user-agent'] || 'Unknown Device';
    
    // Create breach log entry
    const breachLog = {
      id: Date.now(),
      token: token,
      ip: clientIP,
      userAgent: userAgent,
      timestamp: new Date().toISOString()
    };
    
    // Store the breach
    breachLogs.unshift(breachLog); // Add to beginning of array
    
    // Keep only last 100 breaches to prevent memory issues
    if (breachLogs.length > 100) {
      breachLogs.pop();
    }
    
    // Log to console for server monitoring
    console.log('🚨 CANARY TRAP TRIGGERED!');
    console.log(`   Token: ${token}`);
    console.log(`   IP: ${clientIP}`);
    console.log(`   Device: ${userAgent}`);
    console.log(`   Time: ${new Date().toLocaleString()}`);
    
    // Broadcast to WebSocket clients for real-time alerts
    NotificationEngine.emit('canary_breach', breachLog);
    
    // Return transparent pixel (1x1 PNG)
    res.setHeader('Content-Type', 'image/png');
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.send(TRANSPARENT_PIXEL);
    
  } catch (error) {
    console.error('Tracking Pixel Error:', error);
    // Still return a pixel even on error to avoid suspicion
    res.setHeader('Content-Type', 'image/png');
    res.send(TRANSPARENT_PIXEL);
  }
});

// Get All Breach Alerts
app.get('/track/alerts', (req, res) => {
  try {
    res.json({
      count: breachLogs.length,
      alerts: breachLogs
    });
  } catch (error) {
    console.error('Get Alerts Error:', error);
    res.status(500).json({ error: 'Failed to fetch alerts' });
  }
});

// Clear/Archive Specific Alert
app.delete('/track/alerts/:id', (req, res) => {
  try {
    const alertId = parseInt(req.params.id);
    const index = breachLogs.findIndex(log => log.id === alertId);
    
    if (index !== -1) {
      const removed = breachLogs.splice(index, 1);
      console.log(`✅ Alert archived: ${removed[0].token}`);
      res.json({ 
        success: true, 
        message: 'Alert archived',
        removed: removed[0]
      });
    } else {
      res.status(404).json({ error: 'Alert not found' });
    }
  } catch (error) {
    console.error('Delete Alert Error:', error);
    res.status(500).json({ error: 'Failed to archive alert' });
  }
});

// Clear All Alerts
app.delete('/track/alerts', (req, res) => {
  try {
    const count = breachLogs.length;
    breachLogs.length = 0; // Clear array
    console.log(`✅ All alerts cleared (${count} total)`);
    res.json({ 
      success: true, 
      message: `Cleared ${count} alerts` 
    });
  } catch (error) {
    console.error('Clear All Alerts Error:', error);
    res.status(500).json({ error: 'Failed to clear alerts' });
  }
});

/*
 * Legacy duplicate WebSec handlers are intentionally disabled.
 * Active WebSec handlers are registered above the canary/trap routes.
// ============================================
// WEBSEC OPS MODULE - PHASE 3
// ============================================

// SSL Sentinel - Certificate Health Check
app.post('/web/ssl', async (req, res) => {
  const { domain } = req.body;
  
  if (!domain) {
    return res.status(400).json({ 
      success: false, 
      error: 'Domain is required' 
    });
  }
  
  try {
    console.log(`🔍 SSL Check: ${domain}`);
    
    const result = await sslChecker(domain);
    
    res.json({
      domain,
      valid: result.valid,
      daysRemaining: result.daysRemaining,
      validFrom: result.validFrom,
      validTo: result.validTo,
      issuer: result.issuer || 'Unknown'
    });
  } catch (error) {
    console.error('❌ SSL Check error:', error.message);
    res.status(500).json({
      error: true,
      details: error.message || 'SSL check failed'
    });
  }
});

// Security Header Grader
app.post('/web/headers', async (req, res) => {
  const { url } = req.body;
  
  if (!url) {
    return res.status(400).json({ 
      success: false, 
      error: 'URL is required' 
    });
  }
  
  try {
    console.log(`🔍 Header Check: ${url}`);
    
    // Perform HEAD request to get headers
    const response = await fetch(url, { 
      method: 'HEAD',
      redirect: 'follow',
      timeout: 5000
    });
    
    const headers = {};
    response.headers.forEach((value, key) => {
      headers[key] = value;
    });
    
    res.json({
      url,
      status: response.status,
      headers
    });
  } catch (error) {
    console.error('❌ Header Check error:', error.message);
    res.status(500).json({
      error: true,
      details: error.message || 'Header check failed'
    });
  }
});

// DNS Integrity Check - Poisoning Detection
app.post('/web/dns', async (req, res) => {
  const { domain } = req.body;
  
  if (!domain) {
    return res.status(400).json({ 
      success: false, 
      error: 'Domain is required' 
    });
  }
  
  try {
    console.log(`🔍 DNS Integrity Check: ${domain}`);
    
    // System DNS resolution (default)
    let systemDNS = [];
    try {
      systemDNS = await dnsResolve4(domain);
    } catch (err) {
      systemDNS = [];
    }
    
    // Google DNS resolution (8.8.8.8)
    let googleDNS = [];
    try {
      const googleResolver = new dns.Resolver();
      googleResolver.setServers(['8.8.8.8']);
      const resolveWithGoogle = promisify(googleResolver.resolve4.bind(googleResolver));
      googleDNS = await resolveWithGoogle(domain);
    } catch (err) {
      googleDNS = [];
    }
    
    const match = systemDNS.length > 0 && googleDNS.length > 0 && systemDNS[0] === googleDNS[0];
    const status = match ? 'Secure' : 'Warning: Possible DNS Poisoning';
    
    res.json({
      domain,
      systemDNS,
      googleDNS,
      match,
      status
    });
  } catch (error) {
    console.error('❌ DNS Integrity Check error:', error.message);
    res.status(500).json({
      error: true,
      details: error.message || 'DNS check failed'
    });
  }
});

// Recon-X - Subdomain Scanner via crt.sh
app.post('/osint/subdomains', async (req, res) => {
  const { domain } = req.body;
  
  if (!domain) {
    return res.status(400).json({ 
      success: false, 
      error: 'Domain is required' 
    });
  }
  
  try {
    console.log(`🔍 Subdomain Recon: ${domain}`);
    
    // Query crt.sh certificate transparency logs
    const crtUrl = `https://crt.sh/?q=%.${domain}&output=json`;
    const response = await fetch(crtUrl, { timeout: 10000 });
    
    if (!response.ok) {
      throw new Error(`crt.sh returned status ${response.status}`);
    }
    
    const data = await response.json();
    
    // Extract unique subdomains
    const subdomainSet = new Set();
    data.forEach(entry => {
      if (entry.name_value) {
        const names = entry.name_value.split('\n');
        names.forEach(name => {
          const cleaned = normalizeCertificateHostname(name);
          if (isValidHostnameForDomain(cleaned, domain)) {
            subdomainSet.add(cleaned);
          }
        });
      }
    });
    
    const subdomains = Array.from(subdomainSet).sort();
    
    console.log(`✅ Found ${subdomains.length} unique subdomains`);
    
    res.json({
      domain,
      count: subdomains.length,
      subdomains,
      source: 'crt.sh'
    });
  } catch (error) {
    console.error('❌ Subdomain Recon error:', error.message);
    res.status(500).json({
      error: true,
      details: error.message || 'Subdomain scan failed'
    });
  }
});

// ========================================
// 🛡️ CVE INTELLIGENCE HUB ENDPOINTS
// ========================================

*/

app.post('/cve/search', async (req, res) => {
  const { query } = req.body;
  if (!query) {
    return res.status(400).json({ error: 'Query is required' });
  }

  const isCveId = /^CVE-\d{4}-\d+$/i.test(query.trim());
  const baseUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
  const url = isCveId 
    ? `${baseUrl}?cveId=${query.trim().toUpperCase()}`
    : `${baseUrl}?keywordSearch=${encodeURIComponent(query)}&resultsPerPage=10`;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);
    
    console.log(`🔍 NVD API Search: ${url}`);
    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeoutId);

    if (!response.ok) {
      if (response.status === 429) {
        return res.status(429).json({ error: 'NVD is rate limited. Please wait 30 seconds and retry.' });
      }
      throw new Error(`NVD API returned status ${response.status}`);
    }

    const data = await response.json();
    res.json(data);
  } catch (error) {
    console.error('NVD Search Error:', error.message);
    if (error.name === 'AbortError') {
      return res.status(504).json({ error: 'NVD API timeout. Please try again.' });
    }
    res.status(500).json({ error: 'Cannot reach NVD. Check your internet connection.' });
  }
});

app.post('/api/analyze', async (req, res) => {
  const { payload } = req.body;
  if (!payload) {
    return res.status(400).json({ message: 'E2EE payload is required' });
  }

  const decryptedData = decryptPayload(payload);
  if (!decryptedData) {
    return res.status(403).json({ message: 'E2EE decryption failed - payload rejected' });
  }

  const { scanType, inputData } = decryptedData;
  if (!scanType || !inputData) {
    return res.status(400).json({ message: 'Invalid payload structure' });
  }

  try {
    console.log(`🤖 E2EE Secure AI Analysis requested for ${scanType}`);

    const prompt = `You are a highly experienced cybersecurity expert. Provide a comprehensive summary based on the scan rules below.
Data type: ${scanType}
Raw Info:
${inputData}

Respond ONLY with valid JSON formatting (no markdown blocks or backticks):
{
  "summary": "High-level overview",
  "threatLevel": "Critical | High | Medium | Low | Safe",
  "findings": [{"title": "String", "description": "String", "severity": "Critical|High|Medium|Low|Safe", "mitigation": "String"}],
  "recommendations": ["String"],
  "mitreAttckMappings": [{"tactic": "String", "technique": "String", "id": "TXXXX"}]
}`;

    const result = await generateAIJson(prompt);

    const normalizeThreatLevel = (value) => {
      const normalized = String(value || '').trim().toLowerCase();
      if (normalized === 'critical') return 'Critical';
      if (normalized === 'high') return 'High';
      if (normalized === 'medium') return 'Medium';
      if (normalized === 'low' || normalized === 'safe') return 'Low';
      return 'Medium';
    };

    const normalizedThreatLevel = normalizeThreatLevel(result?.threat_level || result?.threatLevel);
    const parsedScore = Number(result?.risk_score ?? result?.riskScore);
    const threatDefaultScore = normalizedThreatLevel === 'Critical'
      ? 90
      : normalizedThreatLevel === 'High'
        ? 75
        : normalizedThreatLevel === 'Medium'
          ? 50
          : 20;

    const normalizedRiskScore = Number.isFinite(parsedScore)
      ? Math.max(0, Math.min(100, Math.round(parsedScore)))
      : threatDefaultScore;

    const findings = Array.isArray(result?.findings) ? result.findings : [];
    const detailedFromFindings = findings
      .map((f, index) => {
        const title = String(f?.title || `Finding ${index + 1}`);
        const severity = String(f?.severity || 'Unknown');
        const description = String(f?.description || 'No description provided.');
        return `${index + 1}. [${severity}] ${title}\n${description}`;
      })
      .join('\n\n');

    const normalizedRecommendations = Array.isArray(result?.recommendations) && result.recommendations.length > 0
      ? result.recommendations
      : findings
          .map((f) => String(f?.mitigation || '').trim())
          .filter((item) => item.length > 0);

    const normalized = {
      threat_level: normalizedThreatLevel,
      risk_score: normalizedRiskScore,
      summary: String(result?.summary || '').trim() || 'Analysis completed. No summary was provided by the model.',
      detailed_analysis: String(result?.detailed_analysis || result?.detailedAnalysis || detailedFromFindings).trim() || 'Detailed analysis is unavailable.',
      recommendations: normalizedRecommendations.length > 0 ? normalizedRecommendations : ['No remediation recommendations returned.'],
      additional_notes: String(result?.additional_notes || result?.additionalNotes || result?.attackVector || result?.exploitationVector || '').trim() || 'No exploitation vector details were returned.'
    };

    res.json(normalized);
  } catch (error) {
    console.error('\n=== AI PROVIDER ERROR (/api/analyze) ===');
    console.error('Error Message:', error.message);
    console.error('Error Type:', error.constructor.name);
    console.error('Full Stack:', error.stack);
    if (error.response) {
      console.error('API Response Status:', error.response.status);
      console.error('API Response Body:', error.response.data || error.response);
    }
    console.error('====================================\n');
    res.json(localSecurityAnalysis(scanType, inputData, error.message || 'AI provider error'));
  }
});

app.post('/api/generate-script', async (req, res) => {
  const { threatLevel, summary, recommendations } = req.body || {};

  if (!threatLevel || !summary) {
    return res.status(400).json({ message: 'threatLevel and summary are required' });
  }

  try {
    const normalizedRecommendations = Array.isArray(recommendations) ? recommendations : [];
    const prompt = `Based on this security analysis, generate a remediation script.

Threat Level: ${threatLevel}
Summary: ${summary}
Recommendations:
${normalizedRecommendations.map((r, i) => `${i + 1}. ${r}`).join('\n') || 'No explicit recommendations provided.'}

Generate a practical Bash or Python script that implements these fixes. Include:
- Comments explaining each step
- Error handling
- Safety checks before making changes

Output ONLY the script body (no markdown fences).`;

    const { text: scriptText } = await generateAIText(prompt, { temperature: 0.3 });
    const cleanScript = stripMarkdownFence(scriptText);

    return res.json({ script: cleanScript || 'Script generation returned no content.' });
  } catch (error) {
    console.error('Generate Script Error:', error.message);
    return res.json({
      script: localRemediationScript(threatLevel, summary, recommendations),
      fallback: true,
      message: error.message || 'AI script generation unavailable'
    });
  }
});

app.post('/api/chat', async (req, res) => {
  const { message, context } = req.body || {};
  const userMessage = String(message || '').trim();

  if (!userMessage) {
    return res.status(400).json({ message: 'A chat message is required.' });
  }

  const analysisContext = context && typeof context === 'object'
    ? `Current analysis context:
- Threat level: ${context.threat_level || context.threatLevel || 'Unknown'}
- Risk score: ${context.risk_score || context.riskScore || 'Unknown'}
- Summary: ${context.summary || 'No summary provided.'}
- Details: ${context.detailed_analysis || context.detailedAnalysis || 'No details provided.'}
- Recommendations: ${Array.isArray(context.recommendations) ? context.recommendations.join('; ') : 'None provided.'}`
    : 'No active analysis context is available.';

  try {
    const prompt = `You are SecurAI Sentinel's cybersecurity assistant.
Answer as a practical senior security analyst. Be concise, specific, and avoid unsupported claims.
Do not ask the user to run destructive commands. If a remediation could disrupt systems, mention the validation step first.

${analysisContext}

User question:
${userMessage}`;

    const { text, provider } = await generateAIText(prompt, { temperature: 0.25 });
    const response = String(text || '').trim();

    return res.json({
      response: response || 'I could not generate a useful response for that request.',
      provider: provider?.id || null,
      model: provider?.model || null,
    });
  } catch (error) {
    console.error('AI Chat Error:', error.message);
    return res.json({
      response: 'Local fallback: review the evidence, validate exposure, apply the least disruptive mitigation first, and rerun provider-backed analysis when available.',
      provider: null,
      model: null,
      fallback: true,
      message: error.message || 'AI assistant unavailable'
    });
  }
});

app.post('/api/generate-challenge', async (req, res) => {
  const { gameType, prompt } = req.body || {};
  if (!gameType || !prompt) {
    return res.status(400).json({ message: 'gameType and prompt are required' });
  }

  try {
    const challenge = await generateGeminiJson(prompt);
    return res.json(challenge);
  } catch (error) {
    console.error('Challenge Generation Error:', error.message);
    return res.json(localDojoChallenge(gameType));
  }
});

app.post('/api/analyze-code', async (req, res) => {
  const { fileName, fileContent } = req.body || {};
  if (!fileName || !fileContent) {
    return res.status(400).json({ message: 'fileName and fileContent are required' });
  }

  try {
    const prompt = `You are a secure code remediation assistant.

File Name: ${fileName}
Source Code:
${fileContent}

Respond ONLY valid JSON (no markdown):
{
  "is_vulnerable": boolean,
  "fixed_content": "string or null",
  "analysis": {
    "threat_level": "Low|Medium|High|Critical",
    "risk_score": number,
    "summary": "string",
    "detailed_analysis": "string",
    "recommendations": ["string"],
    "additional_notes": "string"
  }
}`;

    const result = await generateGeminiJson(prompt);
    return res.json(result);
  } catch (error) {
    console.error('Code Analysis Error:', error.message);
    return res.json(localCodeAnalysis(fileName, fileContent, error.message || 'AI code analysis unavailable'));
  }
});

app.post('/cve/analyze', async (req, res) => {
  const { cveId, description, cvssScore, affectedProducts } = req.body;
  
  if (!cveId || !description) {
    return res.status(400).json({ error: 'CVE ID and description are required' });
  }

  try {
    console.log(`🤖 AI Analysis requested for ${cveId}`);

    const prompt = `You are a cybersecurity expert. Analyze this CVE and provide a structured JSON response.
CVE ID: ${cveId}
Description: ${description}
CVSS Score: ${cvssScore}
Affected Products: ${affectedProducts?.join(', ') || 'Unknown'}

Respond ONLY with valid JSON (no markdown, no backticks):
{
  "plainEnglish": "string (2-3 sentence simple explanation of what this vulnerability is)",
  "attackVector": "string (how an attacker would exploit this)",
  "impact": "string (what damage can be done)",
  "remediationSteps": ["string", "string", "string"],
  "urgency": "Critical" | "High" | "Medium" | "Low",
  "affectedPortsWarning": "string | null (if CVSS > 7, mention which common ports this typically affects)"
}`;

    const result = await generateAIJson(prompt);
    res.json(result);
  } catch (error) {
    console.error('\n=== AI PROVIDER ERROR (/cve/analyze) ===');
    console.error('CVE ID:', cveId);
    console.error('Error Message:', error.message);
    console.error('Error Type:', error.constructor.name);
    console.error('Full Stack:', error.stack);
    if (error.response) {
      console.error('API Response Status:', error.response.status);
      console.error('API Response Body:', error.response.data || error.response);
    }
    console.error('========================================\n');
    res.json(localCveAnalysis(cveId, description, cvssScore));
  }
});

// ========================================
// 🛡️ GLOBAL THREAT INTELLIGENCE (OSINT)
// ========================================

app.get('/osint/threat-intel', async (req, res) => {
  const { ip } = req.query;
  
  try {
    if (ip) {
      const response = await fetch(`https://internetdb.shodan.io/${ip}`);
      if (!response.ok) {
         if (response.status === 404) return res.json({ ip, vulnerabilities: [], ports: [], cpes: [], hostnames: [], tags: [] });
         throw new Error(`Shodan API error: ${response.status}`);
      }
      const data = await response.json();
      return res.json(data);
    } 
    
    return res.json({
      globalCampaigns: [
        { id: "TC-001", name: "LockBit 3.0 Ransomware Activity", target: "Healthcare, Manufacturing", active_cves: ["CVE-2023-46805", "CVE-2024-21887"], severity: "CRITICAL", description: "Widespread exploitation of Ivanti Connect Secure VPN appliances to deploy ransomware." },
        { id: "TC-002", name: "APT29 Cloud Credential Theft", target: "Government, Cloud Tenants", active_cves: ["CVE-2024-1234", "CVE-2024-6387"], severity: "HIGH", description: "Targeting cloud infrastructure misconfigurations and injecting malicious OAuth applications." },
        { id: "TC-003", name: "Mirai Botnet Expansion", target: "IoT, Routers", active_cves: ["CVE-2023-1389", "CVE-2017-1000367"], severity: "MEDIUM", description: "Scanning for newly unpatched TP-Link routers to expand DDoS botnet network." },
        { id: "TC-004", name: "Volt Typhoon Persistence", target: "Critical Infrastructure", active_cves: ["CVE-2023-2868", "CVE-2023-27997"], severity: "CRITICAL", description: "Living off the land techniques utilizing specific firewall vulnerabilities to maintain hidden access." }
      ],
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Threat Intel Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch global threat intelligence.' });
  }
});

// ========================================
// 🛡️ EDR FLEET MANAGEMENT ENDPOINTS
// ========================================

app.post('/edr/telemetry', (req, res) => {
  const { endpointId, hostname, os, events } = req.body;
  if (!endpointId || !events) {
    return res.status(400).json({ error: 'endpointId and events are required' });
  }

  // In a real application, this would pipe to a SIEM/Elasticsearch or save to IndexedDB.
  // We'll log it and acknowledge receipt.
  console.log(`📡 EDR Telemetry received from [${hostname}] (${events.length} events)`);
  
  res.json({ success: true, message: 'Telemetry ingested successfully' });
});

app.post('/edr/isolate', (req, res) => {
  const { endpointId, os = 'windows', reason } = req.body;
  if (!endpointId) return res.status(400).json({ error: 'endpointId is required' });

  console.log(`🛑 Isolation requested for endpoint [${endpointId}]: ${reason}`);

  let command = '';
  if (os.toLowerCase().includes('windows')) {
    command = `netsh advfirewall set allprofiles state on
netsh advfirewall firewall add rule name="EDR_ISOLATE_BLOCK_ALL" dir=out action=block
netsh advfirewall firewall add rule name="EDR_ISOLATE_BLOCK_ALL_IN" dir=in action=block
netsh advfirewall firewall add rule name="EDR_ALLOW_AGENT" dir=out action=allow remoteip=192.168.1.100`;
  } else {
    // Linux generic
    command = `sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT DROP
sudo iptables -A INPUT -s 192.168.1.100 -j ACCEPT
sudo iptables -A OUTPUT -d 192.168.1.100 -j ACCEPT`;
  }

  res.json({ success: true, command });
});

// ========================================
// 🛡️ AUTONOMOUS REMEDIATION ENDPOINTS
// ========================================

app.post('/remediate/firewall', (req, res) => {
  const { port, protocol = 'tcp', os = 'linux' } = req.body;
  if (!port) {
    return res.status(400).json({ error: 'Port is required' });
  }

  let command = '';
  if (os.toLowerCase() === 'windows') {
    command = `netsh advfirewall firewall add rule name="Block Port ${port}" dir=in action=block protocol=${protocol.toUpperCase()} localport=${port}`;
  } else {
    command = `sudo ufw deny ${port}/${protocol}
# OR iptables fallback:
sudo iptables -A INPUT -p ${protocol} --dport ${port} -j DROP`;
  }

  res.json({ success: true, command });
});

app.post('/remediate/iac', async (req, res) => {
  const { cveId, description, format = 'terraform' } = req.body;
  
  if (!cveId || !description) {
    return res.status(400).json({ error: 'CVE ID and description are required' });
  }

  try {
    console.log(`🤖 IaC Patching requested for ${cveId} format: ${format}`);

    const prompt = `You are a DevSecOps engineer. Generate a practical Infrastructure as Code (IaC) patch to remediate or block the following vulnerability.
CVE ID: ${cveId}
Description: ${description}
Requested Format: ${format} (Terraform, Ansible, or Kubernetes)

Output ONLY the exact code file content. Do not include markdown code block syntax (like \`\`\`yaml).`;

    const { text: patchCode } = await generateAIText(prompt, { temperature: 0.2 });
    const cleanPatch = stripMarkdownFence(patchCode);

    res.json({ success: true, patch: cleanPatch, format });
  } catch (error) {
    console.error('\n=== AI PROVIDER ERROR (/remediate/iac) ===');
    console.error('CVE ID:', cveId);
    console.error('Format:', format);
    console.error('Error Message:', error.message);
    console.error('Error Type:', error.constructor.name);
    console.error('Full Stack:', error.stack);
    if (error.response) {
      console.error('API Response Status:', error.response.status);
      console.error('API Response Body:', error.response.data || error.response);
    }
    console.error('========================================\n');
    res.json({
      success: true,
      patch: localIacPatch(cveId, description, format),
      format,
      fallback: true,
      message: error.message || 'AI IaC generation unavailable'
    });
  }
});

function parseJsonFromModelText(rawText) {
  const clean = String(rawText || '')
    .replace(/^```json\s*/i, '')
    .replace(/^```\s*/i, '')
    .replace(/\s*```$/i, '')
    .trim();
  try {
    return JSON.parse(clean);
  } catch (error) {
    const objectStart = clean.indexOf('{');
    const objectEnd = clean.lastIndexOf('}');
    const arrayStart = clean.indexOf('[');
    const arrayEnd = clean.lastIndexOf(']');

    if (objectStart !== -1 && objectEnd > objectStart) {
      return JSON.parse(clean.slice(objectStart, objectEnd + 1));
    }
    if (arrayStart !== -1 && arrayEnd > arrayStart) {
      return JSON.parse(clean.slice(arrayStart, arrayEnd + 1));
    }

    throw error;
  }
}

function orderedAIProviders() {
  const knownProviders = new Map(AI_PROVIDER_CONFIG.map((provider) => [provider.id, provider]));
  const orderedIds = AI_PROVIDER_MODE === 'auto'
    ? AI_PROVIDER_ORDER
    : [AI_PROVIDER_MODE, ...AI_PROVIDER_ORDER.filter((id) => id !== AI_PROVIDER_MODE)];

  const dedupedIds = [...new Set(orderedIds.filter((id) => knownProviders.has(id)))];
  const remainingIds = AI_PROVIDER_CONFIG
    .map((provider) => provider.id)
    .filter((id) => !dedupedIds.includes(id));

  return [...dedupedIds, ...remainingIds]
    .map((id) => knownProviders.get(id))
    .filter((provider) => provider && provider.apiKey);
}

function getAIProviderStatus() {
  const ordered = orderedAIProviders();
  const activeProvider = ordered[0] || null;
  const configuredIds = new Set(ordered.map((provider) => provider.id));
  const priorityById = new Map(ordered.map((provider, index) => [provider.id, index + 1]));

  return {
    mode: AI_PROVIDER_MODE,
    configuredCount: configuredIds.size,
    totalCount: AI_PROVIDER_CONFIG.length,
    activeProvider: activeProvider?.id || null,
    healthy: configuredIds.size > 0,
    message: configuredIds.size > 0
      ? `${configuredIds.size} AI provider${configuredIds.size === 1 ? '' : 's'} configured`
      : 'No AI provider API keys configured',
    providers: AI_PROVIDER_CONFIG.map((provider) => ({
      id: provider.id,
      label: provider.label,
      model: provider.model,
      configured: Boolean(provider.apiKey),
      selected: activeProvider?.id === provider.id,
      priority: priorityById.get(provider.id) || 0,
    })),
  };
}

function textFromGeminiResponse(response) {
  if (!response) return '';
  return typeof response.text === 'function' ? response.text() : String(response.text || '');
}

function stripMarkdownFence(rawText) {
  return String(rawText || '')
    .replace(/^```[a-z]*\s*/i, '')
    .replace(/\s*```$/i, '')
    .trim();
}

async function withAIRequestTimeout(promise, providerLabel) {
  let timeoutId;
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(() => {
      reject(new Error(`${providerLabel} request timed out after ${AI_REQUEST_TIMEOUT_MS}ms`));
    }, AI_REQUEST_TIMEOUT_MS);
  });

  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timeoutId);
  }
}

async function callGeminiProvider(provider, prompt, options = {}) {
  const ai = new GoogleGenAI({ apiKey: provider.apiKey });
  const response = await withAIRequestTimeout(
    ai.models.generateContent({
      model: provider.model,
      contents: prompt,
      config: {
        ...(options.responseMimeType ? { responseMimeType: options.responseMimeType } : {}),
        ...(typeof options.temperature === 'number' ? { temperature: options.temperature } : {}),
        ...(Number.isFinite(Number(options.maxOutputTokens || options.maxTokens))
          ? { maxOutputTokens: Math.max(1, Number(options.maxOutputTokens || options.maxTokens)) }
          : {}),
      },
    }),
    provider.label
  );

  return textFromGeminiResponse(response);
}

async function callOpenAICompatibleProvider(provider, prompt, options = {}) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), AI_REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(provider.endpoint, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${provider.apiKey}`,
        'Content-Type': 'application/json',
        ...(provider.id === 'openrouter'
          ? {
              'HTTP-Referer': process.env.OPENROUTER_SITE_URL || 'http://localhost:3000',
              'X-Title': process.env.OPENROUTER_APP_NAME || 'SecurAI Sentinel',
            }
          : {}),
      },
      body: JSON.stringify({
        model: provider.model,
        messages: [
          {
            role: 'system',
            content: options.responseMimeType === 'application/json'
              ? 'Return only valid JSON. Do not include markdown fences, commentary, or prose outside the JSON value.'
              : 'Return the requested content directly.',
          },
          { role: 'user', content: prompt },
        ],
        temperature: typeof options.temperature === 'number' ? options.temperature : 0.2,
        max_tokens: Number.isFinite(Number(options.maxOutputTokens || options.maxTokens))
          ? Math.max(1, Number(options.maxOutputTokens || options.maxTokens))
          : AI_OPENAI_COMPATIBLE_MAX_TOKENS,
      }),
      signal: controller.signal,
    });

    const bodyText = await response.text();
    if (!response.ok) {
      throw new Error(`${provider.label} returned ${response.status}: ${bodyText.slice(0, 500)}`);
    }

    const body = JSON.parse(bodyText);
    const text = body?.choices?.[0]?.message?.content || body?.choices?.[0]?.text || '';
    if (!text) {
      throw new Error(`${provider.label} returned no text content`);
    }

    return text;
  } finally {
    clearTimeout(timeoutId);
  }
}

async function generateAIText(prompt, options = {}) {
  const providers = orderedAIProviders();
  if (providers.length === 0) {
    const error = new Error('No AI provider configured. Set GEMINI_API_KEY, OPENROUTER_API_KEY, or NVIDIA_API_KEY.');
    error.statusCode = 503;
    throw error;
  }

  const failures = [];
  for (const provider of providers) {
    try {
      const text = provider.type === 'gemini'
        ? await callGeminiProvider(provider, prompt, options)
        : await callOpenAICompatibleProvider(provider, prompt, options);

      if (!String(text || '').trim()) {
        throw new Error(`${provider.label} returned empty content`);
      }

      return { text, provider };
    } catch (error) {
      const message = error?.name === 'AbortError'
        ? `${provider.label} request timed out after ${AI_REQUEST_TIMEOUT_MS}ms`
        : error.message || 'Unknown provider error';
      failures.push(`${provider.label}: ${message}`);
      console.warn(`AI provider failed (${provider.label}), trying next provider if available: ${message}`);
    }
  }

  const error = new Error(`All configured AI providers failed. ${failures.join(' | ')}`);
  error.statusCode = 502;
  throw error;
}

async function generateAIJson(prompt, options = {}) {
  const { text } = await generateAIText(prompt, {
    ...options,
    responseMimeType: 'application/json',
  });
  return parseJsonFromModelText(text);
}

async function generateGeminiJson(prompt) {
  return generateAIJson(prompt);
}

function sendApiKeyMissing(res, keyName) {
  return res.status(401).json({
    error: 'API_KEY_MISSING',
    message: `Configure ${keyName} in .env`
  });
}

function sendRateLimit(res, response) {
  const retryAfter = response.headers.get('retry-after');
  const message = retryAfter
    ? `Rate limit reached. Retry after ${retryAfter} seconds.`
    : 'Rate limit reached. Please retry shortly.';

  return res.status(429).json({
    error: 'RATE_LIMITED',
    message,
    retryAfter: retryAfter || null
  });
}

function keywordCount(text, patterns) {
  const source = String(text || '').toLowerCase();
  return patterns.reduce((count, pattern) => count + (pattern.test(source) ? 1 : 0), 0);
}

function localSecurityAnalysis(scanType, inputData, reason = 'AI provider unavailable') {
  const type = String(scanType || 'Security Analysis');
  const data = String(inputData || '');
  const indicators = [
    { label: 'critical service exposure', patterns: [/\b(21|23|445|3389|5900)\b/, /ftp|telnet|smb|rdp|vnc/i] },
    { label: 'credential or authentication attack', patterns: [/failed password|brute|credential|password|login/i] },
    { label: 'web application exploit signal', patterns: [/sql injection|xss|<script|or 1=1|cve-|payload/i] },
    { label: 'malware behavior', patterns: [/createremotethread|virtualalloc|beacon|c2|\.exe|\.dll|persistence/i] },
    { label: 'phishing indicators', patterns: [/spf:\s*fail|dkim:\s*none|urgent|verify|suspension|bit\.ly|redirect/i] }
  ];
  const hits = indicators.filter((item) => item.patterns.some((pattern) => pattern.test(data)));
  const score = Math.min(95, Math.max(20, 30 + hits.length * 15 + (data.length > 500 ? 10 : 0)));
  const threatLevel = score >= 85 ? 'Critical' : score >= 65 ? 'High' : score >= 40 ? 'Medium' : 'Low';
  const findingText = hits.length > 0 ? hits.map((item) => item.label).join(', ') : 'no high-confidence indicators matched local heuristics';

  return {
    threat_level: threatLevel,
    risk_score: score,
    summary: `${type} completed with local fallback analysis: ${findingText}.`,
    detailed_analysis: `Fallback reason: ${reason}. The local analyzer matched ${hits.length} indicator group(s) against the supplied sample and produced a conservative risk estimate.`,
    recommendations: [
      'Validate findings with authoritative scanner or SIEM data.',
      'Prioritize exposed legacy services, weak authentication signals, and known exploit patterns.',
      'Document compensating controls and rerun AI analysis when a provider is available.'
    ],
    additional_notes: 'fallback=true; external AI enrichment was not used.',
    fallback: true
  };
}

function localRemediationScript(threatLevel, summary, recommendations = []) {
  const commentSummary = String(summary || 'Security issue detected').replace(/\r?\n/g, ' ').slice(0, 160);
  const recLines = (Array.isArray(recommendations) ? recommendations : [])
    .map((item, index) => `echo "Recommendation ${index + 1}: ${String(item).replace(/"/g, '\\"')}"`)
    .join('\n');

  return `#!/usr/bin/env bash
set -euo pipefail

echo "SecurAI local remediation helper"
echo "Threat level: ${String(threatLevel || 'Unknown')}"
echo "Summary: ${commentSummary}"
${recLines || 'echo "Review the finding and apply the least disruptive mitigation first."'}

echo "Dry-run only: validate commands in staging before production changes."`;
}

function localDojoChallenge(gameType) {
  const type = String(gameType || '').toLowerCase();
  if (type === 'sqli') {
    return {
      context: 'Customer Support Ticket Search',
      hint: 'The backend query filters by ticket_id and customer_email.',
      vulnerability_type: 'Union-based SQL injection',
      target_table: 'support_tickets',
      difficulty: 'medium',
      fallback: true
    };
  }
  if (type === 'crypto') {
    return {
      encrypted_string: 'U0VDVVJBSXtMT0NBTF9GQUxMQkFDS30=',
      clear_text: 'SECURAI{LOCAL_FALLBACK}',
      encoding_type: 'base64',
      difficulty_hint: 'The trailing equals signs suggest a common binary-to-text encoding.',
      fallback: true
    };
  }
  if (type === 'log') {
    return {
      log_block: '10.0.0.5 - - [07/Jun/2026:13:00:01 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n203.0.113.10 - - [07/Jun/2026:13:00:04 +0000] "GET /admin?id=1%27%20OR%201=1-- HTTP/1.1" 500 0 "-" "sqlmap/1.8"\n10.0.0.6 - - [07/Jun/2026:13:00:06 +0000] "GET /status HTTP/1.1" 200 128 "-" "Mozilla/5.0"',
      malicious_line_index: 1,
      attack_type: 'SQL Injection',
      explanation: 'The request contains a tautology payload and an automated scanner user agent.',
      fallback: true
    };
  }
  if (type === 'pentest') {
    return {
      targetEnvironment: 'Training container exposing an unauthenticated admin panel',
      vulnerability: 'Missing authentication on administrative route',
      exploitScript: '#!/usr/bin/env bash\ncurl -i http://TARGET/admin',
      mitigationSteps: ['Require authentication on admin routes', 'Restrict admin access by network zone', 'Add audit logging for privileged routes'],
      difficulty: 'easy',
      fallback: true
    };
  }
  return {
    sender: 'security-alert@paypa1-verify.example',
    subject: 'Urgent account verification required',
    body: 'Your account will be suspended unless you verify your details today. Open the secure verification link and submit your password to restore access.',
    indicators: [
      { text: 'paypa1-verify.example', reason: 'Lookalike domain impersonating a trusted brand', type: 'domain' },
      { text: 'today', reason: 'Urgency pressure', type: 'urgency' },
      { text: 'submit your password', reason: 'Credential harvesting request', type: 'request' }
    ],
    theme: 'Account Security',
    fallback: true
  };
}

function localCodeAnalysis(fileName, fileContent, reason = 'AI provider unavailable') {
  const source = String(fileContent || '');
  const findings = [];
  if (/eval\s*\(|new Function\s*\(/i.test(source)) findings.push('Dynamic code execution detected');
  if (/password|api[_-]?key|secret/i.test(source)) findings.push('Possible hardcoded secret or credential');
  if (/innerHTML|dangerouslySetInnerHTML/i.test(source)) findings.push('Potential unsafe HTML injection sink');
  if (/SELECT .* \$\{|SELECT .* \+/i.test(source)) findings.push('Possible string-built SQL query');
  const vulnerable = findings.length > 0;

  return {
    is_vulnerable: vulnerable,
    fixed_content: vulnerable ? null : source,
    analysis: {
      threat_level: vulnerable ? 'High' : 'Low',
      risk_score: vulnerable ? Math.min(90, 45 + findings.length * 15) : 15,
      summary: `${fileName} reviewed with local fallback checks.`,
      detailed_analysis: findings.length ? findings.join('\n') : 'No high-confidence local code issues detected.',
      recommendations: findings.length
        ? ['Replace dynamic execution with explicit control flow.', 'Move secrets to environment or secret storage.', 'Use parameterized queries and safe rendering APIs.']
        : ['Run full SAST and dependency scanning before release.'],
      additional_notes: `fallback=true; ${reason}`
    },
    fallback: true
  };
}

function localCveAnalysis(cveId, description, cvssScore) {
  const score = Number(cvssScore || 0);
  const urgency = score >= 9 ? 'Critical' : score >= 7 ? 'High' : score >= 4 ? 'Medium' : 'Low';
  return {
    plainEnglish: `${cveId} describes a vulnerability that should be validated against deployed versions and exposure paths.`,
    attackVector: /remote|network|unauthenticated/i.test(description) ? 'Likely reachable over a network-exposed service if the affected product is present.' : 'Requires confirming product-specific exploit prerequisites.',
    impact: String(description || 'Impact depends on affected product and compensating controls.').slice(0, 400),
    remediationSteps: ['Confirm affected versions in inventory.', 'Apply vendor patches or mitigations.', 'Restrict exposure and monitor for exploitation indicators.'],
    urgency,
    affectedPortsWarning: score >= 7 ? 'Review exposed service ports for the affected product and restrict access until patched.' : null,
    fallback: true
  };
}

function localIacPatch(cveId, description, format) {
  const requested = String(format || 'terraform').toLowerCase();
  if (requested.includes('ansible')) {
    return `---
- name: Local fallback mitigation for ${cveId}
  hosts: all
  become: true
  tasks:
    - name: Ensure firewall denies risky legacy service ports
      ansible.builtin.ufw:
        rule: deny
        port: "{{ item }}"
        proto: tcp
      loop: [ "21", "23", "445", "3389" ]
`;
  }
  if (requested.includes('kubernetes') || requested.includes('k8s')) {
    return `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: securai-${String(cveId || 'fallback').toLowerCase()}-egress-control
spec:
  podSelector: {}
  policyTypes: ["Ingress", "Egress"]
`;
  }
  return `# Local fallback mitigation for ${cveId}
# ${String(description || '').slice(0, 160)}
resource "null_resource" "securai_review_required" {
  triggers = {
    cve = "${cveId}"
    action = "restrict_exposure_patch_and_monitor"
  }
}
`;
}

function localPcapAiAnalysis(summary, anomalies = [], captureStats = {}) {
  const highAnomalies = (Array.isArray(anomalies) ? anomalies : []).filter((item) => ['Critical', 'High'].includes(String(item?.severity)));
  const threatLevel = highAnomalies.length > 0 ? 'High' : anomalies.length > 0 ? 'Medium' : 'Low';
  return {
    threatLevel,
    verdict: `Local fallback verdict: ${summary}`,
    detectedAttacks: highAnomalies.map((item) => ({
      attackType: String(item?.type || 'Network anomaly'),
      confidence: 0.55,
      description: String(item?.description || 'Suspicious packet behavior detected by deterministic parser.'),
      affectedHosts: Array.isArray(item?.affectedIPs) ? item.affectedIPs : [],
      mitreTechnique: null,
      evidence: JSON.stringify(item).slice(0, 500)
    })),
    suspiciousFlows: [],
    c2Indicators: /4444|1337|31337|6666|9999/.test(`${summary} ${JSON.stringify(captureStats)}`) ? ['Suspicious high-risk port observed'] : [],
    exfiltrationRisk: highAnomalies.length > 0 ? 'Medium' : 'Low',
    recommendations: ['Correlate suspicious flows with endpoint telemetry.', 'Block known malicious ports where business use is absent.', 'Capture a longer sample if behavior is inconclusive.'],
    iocs: [],
    fallback: true
  };
}

function localIRPlaybook({ incidentType, severity, affectedSystems = [], findings }) {
  const incidentId = generateIncidentId();
  const now = Date.now();
  const safeSeverity = normalizeSeverity(severity);
  const assets = Array.isArray(affectedSystems) && affectedSystems.length ? affectedSystems : ['Unknown asset'];
  return {
    playbookId: `playbook_${incidentId}_${now}`,
    playbookTitle: `${incidentType} Incident Response Playbook`,
    incidentId,
    severity: safeSeverity,
    incidentType: String(incidentType || 'Security Incident'),
    createdAt: now,
    lastUpdated: now,
    executiveSummary: `Local fallback playbook generated for ${incidentType}. Findings: ${String(findings || '').slice(0, 240)}`,
    affectedAssets: assets,
    iocs: [],
    phases: [
      {
        phaseId: 1,
        phaseName: 'Triage and Containment',
        phaseIcon: 'ShieldAlert',
        estimatedDuration: '30-60 minutes',
        priority: safeSeverity === 'Critical' ? 'Immediate' : 'High',
        isExpanded: true,
        steps: [
          {
            stepId: 'P1-S1',
            title: 'Validate alert evidence',
            description: 'Confirm affected assets, timestamps, and observable indicators.',
            assignedRole: 'SOC Analyst',
            toolsRequired: ['SIEM', 'EDR', 'Network logs'],
            expectedOutcome: 'Confirmed incident scope',
            isAutomatable: false,
            bashCommand: null,
            status: 'pending',
            completedAt: null,
            completedBy: '',
            notes: ''
          },
          {
            stepId: 'P1-S2',
            title: 'Apply immediate containment',
            description: 'Restrict exposed services and isolate confirmed compromised endpoints.',
            assignedRole: 'Incident Commander',
            toolsRequired: ['Firewall', 'EDR'],
            expectedOutcome: 'Threat spread is limited',
            isAutomatable: true,
            bashCommand: 'echo "Review containment command before execution"',
            status: 'pending',
            completedAt: null,
            completedBy: '',
            notes: ''
          }
        ]
      }
    ],
    communicationPlan: {
      internalNotifications: ['SOC lead', 'System owner'],
      externalNotifications: [],
      regulatoryRequirements: ['Assess notification obligations after scope confirmation']
    },
    lessonsLearned: ['Review detection coverage and control gaps after recovery.'],
    references: ['NIST SP 800-61'],
    fallback: true
  };
}

function localDarkWebAnalysis({ query, type, breaches = [], abuseData }) {
  const breachCount = Array.isArray(breaches) ? breaches.length : 0;
  const abuseScore = Number(abuseData?.abuseConfidenceScore || 0);
  const riskScore = Math.min(100, breachCount * 25 + Math.min(60, abuseScore));
  const riskLevel = riskScore >= 80 ? 'Critical' : riskScore >= 55 ? 'High' : riskScore >= 25 ? 'Medium' : riskScore > 0 ? 'Low' : 'Clean';
  return {
    riskScore,
    riskLevel,
    summary: `Local fallback dark web assessment for ${query} (${type}). ${breachCount} breach record(s) supplied.`,
    exposedDataTypes: breachCount ? ['Unknown breach data classes'] : [],
    oldestBreach: breachCount ? String(breaches[0]?.BreachDate || 'Unknown') : 'N/A',
    mostRecentBreach: breachCount ? String(breaches[breachCount - 1]?.BreachDate || 'Unknown') : 'N/A',
    immediateActions: riskScore > 0 ? ['Rotate affected credentials', 'Enable MFA', 'Review suspicious login activity'] : ['Continue monitoring for exposure'],
    longTermRecommendations: ['Use unique passwords', 'Monitor breach feeds', 'Harden identity controls'],
    passwordChangeUrgency: riskScore >= 55 ? 'Immediate' : riskScore > 0 ? 'Soon' : 'N/A',
    fallback: true
  };
}

function localDarkWebDemoData(query, type) {
  const now = new Date().toISOString();
  return {
    breaches: [
      {
        Name: 'SecurAIDemoExposure',
        Title: 'SecurAI Demo Exposure Dataset',
        Domain: type === 'domain' ? String(query).replace(/^.*@/, '') : 'demo.local',
        BreachDate: '2024-10-12',
        AddedDate: now,
        ModifiedDate: now,
        PwnCount: 1,
        Description: 'Deterministic demo exposure generated because AI demo generation is unavailable.',
        LogoPath: '',
        DataClasses: ['Email addresses', 'Usernames'],
        IsVerified: true,
        IsFabricated: true,
        IsSensitive: false,
        IsRetired: false,
        IsSpamList: false,
        IsMalware: false
      }
    ],
    pasteExposures: type === 'email' ? [{ Source: 'DemoPaste', Id: 'demo-1', Title: 'Fallback combo list', Date: '2024-10-12', EmailCount: 1 }] : [],
    abuseData: type === 'ip' ? { abuseConfidenceScore: 5, totalReports: 1, countryCode: 'US', isp: 'Demo ISP', usageType: 'Data Center', reports: [] } : null,
    fallback: true
  };
}

function localPostureReport(scanHistory) {
  const rows = Array.isArray(scanHistory) ? scanHistory : Object.values(scanHistory || {});
  const riskValues = rows.map((row) => Number(row?.risk_score || row?.riskScore || row?.analysisResult?.risk_score || 0)).filter(Number.isFinite);
  const avgRisk = riskValues.length ? riskValues.reduce((sum, value) => sum + value, 0) / riskValues.length : 35;
  const overallScore = Math.max(0, Math.min(100, Math.round(100 - avgRisk)));
  const grade = overallScore >= 95 ? 'A+' : overallScore >= 85 ? 'A' : overallScore >= 72 ? 'B' : overallScore >= 60 ? 'C' : overallScore >= 45 ? 'D' : 'F';
  return {
    overallScore,
    grade,
    categoryScores: {
      networkSecurity: Math.max(0, overallScore - 5),
      webSecurity: overallScore,
      endpointSecurity: Math.max(0, overallScore - 10),
      dataProtection: Math.min(100, overallScore + 5),
      threatIntelligence: Math.max(0, overallScore - 8),
      incidentReadiness: Math.max(0, overallScore - 3)
    },
    criticalFindings: avgRisk >= 70 ? ['High-risk findings are present in recent scan history.'] : [],
    strengths: ['Local evidence pipeline is available', 'Scan history can be summarized without external AI'],
    improvementAreas: ['Enable AI provider for richer prioritization', 'Expand scan coverage across all assets'],
    complianceHints: {
      cisLevel1: overallScore >= 70 ? 'Partial' : 'Fail',
      cisLevel2: overallScore >= 80 ? 'Partial' : 'Fail',
      gdprReadiness: overallScore >= 75 ? 'Partial' : 'Fail',
      iso27001Hints: 'Fallback assessment: validate control evidence manually.'
    },
    nextScanRecommendations: ['Run WebSec Ops checks', 'Review endpoint telemetry', 'Generate an IR playbook for high-risk findings'],
    trendDirection: 'New',
    fallback: true
  };
}

function localAgentPlan(target, agentMode, objectives = []) {
  const passive = ['ssl_check', 'headers_check', 'dns_check', 'subdomain_enum', 'cve_search', 'darkweb_domain'];
  const active = [...passive, 'port_scan', 'ip_reputation'];
  const full = [...active, 'attack_classify', 'ir_generate'];
  const tools = agentMode === 'passive' ? passive : agentMode === 'active' ? active : full;
  return {
    planTitle: `${String(agentMode).toUpperCase()} fallback assessment for ${target}`,
    estimatedDuration: `${Math.max(20, tools.length * 5)} seconds`,
    steps: tools.map((toolName, index) => ({
      stepNumber: index + 1,
      toolName,
      toolInput: { target },
      rationale: `Local fallback plan step for ${toolName.replace(/_/g, ' ')}`,
      dependsOnStep: index === 0 ? null : index,
      expectedOutput: 'Structured security findings'
    })),
    agentObjective: Array.isArray(objectives) && objectives.length ? objectives.join(', ') : `Assess attack surface for ${target}`,
    riskLevel: 'Medium',
    fallback: true
  };
}

function localAgentInterpretation(stepNumber, toolName, toolOutput = {}) {
  const outputText = JSON.stringify(toolOutput);
  const risky = /dangerous|error|failed|open|breach|critical|high|4444|21|23|445|3389/i.test(outputText);
  return {
    interpretation: `Local fallback interpretation for step ${stepNumber}: ${toolName} ${risky ? 'returned risk-relevant evidence' : 'completed without high-confidence risk evidence'}.`,
    keyFindings: risky ? [`${toolName} produced notable evidence`] : [`${toolName} produced baseline evidence`],
    riskIndicators: risky ? ['Risk indicator present in tool output'] : [],
    shouldEscalate: risky,
    escalationReason: risky ? 'Tool output contains risky service, error, or high-severity language.' : null,
    suggestedNextTools: risky ? ['attack_classify', 'ir_generate'] : [],
    confidenceLevel: 0.45,
    agentThought: 'Continuing mission with deterministic fallback reasoning.',
    fallback: true
  };
}

function localAgentReport(target, agentMode, allSteps = [], allInterpretations = []) {
  const indicators = (Array.isArray(allInterpretations) ? allInterpretations : []).flatMap((item) => item?.riskIndicators || []);
  const findings = (Array.isArray(allInterpretations) ? allInterpretations : []).flatMap((item) => item?.keyFindings || []);
  const riskScore = Math.min(100, Math.max(10, indicators.length * 18 + findings.length * 5));
  const rating = riskScore >= 80 ? 'Critical' : riskScore >= 60 ? 'High' : riskScore >= 30 ? 'Medium' : riskScore > 10 ? 'Low' : 'Informational';
  return {
    reportTitle: `Fallback Assessment Report for ${target}`,
    executiveSummary: `The ${agentMode} mission completed using deterministic fallback synthesis across ${Array.isArray(allSteps) ? allSteps.length : 0} step(s).`,
    overallRiskRating: rating,
    attackSurface: {
      exposedServices: [],
      weakPoints: indicators.slice(0, 10),
      strongPoints: findings.slice(0, 10)
    },
    criticalFindings: indicators.slice(0, 8).map((indicator, index) => ({
      finding: String(indicator),
      evidence: 'Derived from fallback interpretation.',
      impact: 'Potential security exposure requiring validation.',
      recommendation: 'Validate evidence, prioritize patching, and add monitoring.',
      priority: index + 1
    })),
    mitreTacticsDetected: [],
    immediateActions: indicators.length ? ['Validate high-risk indicators', 'Restrict exposed services'] : ['Complete manual review of generated evidence'],
    shortTermActions: ['Patch confirmed vulnerable services', 'Review access controls'],
    longTermActions: ['Schedule recurring assessments', 'Improve telemetry coverage'],
    riskScore,
    complianceNotes: 'Fallback report; AI enrichment unavailable.',
    conclusionStatement: 'Mission pipeline completed with deterministic fallback synthesis.',
    fallback: true
  };
}

function localZeroTrustPolicy({ targetEnvironment, openPorts = [], dangerousPorts = [], missingHeaders = [], detectedThreats = [] }) {
  const riskyPorts = (Array.isArray(dangerousPorts) && dangerousPorts.length ? dangerousPorts : openPorts).slice(0, 6);
  const portRules = riskyPorts.map((entry, index) => ({
    ruleId: `ZT-${index + 1}`,
    ruleName: `Restrict ${entry?.name || entry?.port || 'risky service'}`,
    action: 'DENY',
    source: 'untrusted',
    destination: String(targetEnvironment || 'protected asset'),
    protocol: 'tcp',
    port: String(entry?.port || 'any'),
    rationale: 'Fallback policy denies risky exposure until business need is verified.'
  }));

  return {
    policyTitle: `Zero Trust fallback policy for ${targetEnvironment}`,
    riskReduction: 'Deterministic policy package generated while AI provider is unavailable.',
    configs: [
      {
        configType: 'iptables',
        fileName: 'securai-fallback-iptables.sh',
        language: 'bash',
        description: 'Restrict commonly risky exposed services.',
        content: ['#!/usr/bin/env bash', 'set -euo pipefail', ...riskyPorts.map((entry) => `iptables -A INPUT -p tcp --dport ${entry?.port || '0'} -j DROP`)].join('\n'),
        warningNote: 'Review business impact before applying.',
        testCommand: 'iptables -S'
      },
      {
        configType: 'csp',
        fileName: 'content-security-policy.txt',
        language: 'text',
        description: 'Baseline CSP for web hardening.',
        content: "Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';",
        warningNote: missingHeaders.length ? `Generated because missing headers were reported: ${missingHeaders.join(', ')}` : null,
        testCommand: null
      }
    ],
    securityRules: portRules.length ? portRules : [{
      ruleId: 'ZT-BASELINE',
      ruleName: 'Default deny untrusted ingress',
      action: 'DENY',
      source: 'untrusted',
      destination: String(targetEnvironment || 'protected asset'),
      protocol: 'tcp',
      port: 'any',
      rationale: 'Apply explicit allow-listing for inbound access.'
    }],
    immediateWins: ['Deny risky unauthenticated ingress', 'Add missing browser security headers', 'Log policy exceptions'],
    estimatedRiskReduction: detectedThreats.length || riskyPorts.length ? 45 : 30,
    implementationOrder: ['Review rules', 'Apply in staging', 'Monitor logs', 'Promote to production'],
    fallback: true
  };
}

function localVulnerabilityAnalysis(target, context = '') {
  const score = keywordCount(`${target} ${context}`, [/21|ftp/i, /23|telnet/i, /445|smb/i, /3389|rdp/i, /cve|exploit/i]);
  return {
    summary: `Local fallback vulnerability profile for ${target}.`,
    findings: score > 0 ? ['Potential risky exposure inferred from target context.'] : ['No high-confidence local vulnerability indicator matched.'],
    recommendations: ['Run an authenticated vulnerability scanner.', 'Patch exposed services.', 'Restrict management ports by source network.'],
    severity: score >= 3 ? 'High' : score > 0 ? 'Medium' : 'Low',
    confidence: score > 0 ? 0.45 : 0.25,
    fallback: true
  };
}

// ========================================
// 📦 PACKET CAPTURE ANALYZER HELPERS
// ========================================

const MAX_PCAP_FILE_SIZE_BYTES = 50 * 1024 * 1024;
const MAX_PARSED_PACKETS = 500;
const MAX_DISPLAY_PACKETS = 100;
const SUSPICIOUS_PORTS = new Set([4444, 1337, 31337, 6666, 9999]);

const PORT_SERVICE_MAP = {
  20: 'FTP-DATA',
  21: 'FTP',
  22: 'SSH',
  23: 'TELNET',
  25: 'SMTP',
  53: 'DNS',
  67: 'DHCP',
  68: 'DHCP',
  69: 'TFTP',
  80: 'HTTP',
  110: 'POP3',
  123: 'NTP',
  135: 'RPC',
  137: 'NetBIOS',
  138: 'NetBIOS',
  139: 'NetBIOS',
  143: 'IMAP',
  161: 'SNMP',
  389: 'LDAP',
  443: 'HTTPS',
  445: 'SMB',
  465: 'SMTPS',
  514: 'SYSLOG',
  587: 'SMTP-Submission',
  631: 'IPP',
  993: 'IMAPS',
  995: 'POP3S',
  1433: 'MSSQL',
  1521: 'Oracle',
  1723: 'PPTP',
  1883: 'MQTT',
  2049: 'NFS',
  2375: 'Docker',
  3306: 'MySQL',
  3389: 'RDP',
  5432: 'PostgreSQL',
  5900: 'VNC',
  6379: 'Redis',
  8080: 'HTTP-Alt',
  8443: 'HTTPS-Alt',
  9200: 'Elasticsearch'
};

const KNOWN_ETHERTYPES = new Set([0x0800, 0x0806, 0x86DD]);

const uploadPcap = multerLib
  ? multerLib({
      storage: multerLib.memoryStorage(),
      limits: { fileSize: MAX_PCAP_FILE_SIZE_BYTES }
    }).single('file')
  : null;

function toHexByte(value) {
  return value.toString(16).padStart(2, '0');
}

function formatMac(buffer, start) {
  return Array.from(buffer.slice(start, start + 6)).map(toHexByte).join(':');
}

function formatIPv4(buffer, start) {
  return `${buffer[start]}.${buffer[start + 1]}.${buffer[start + 2]}.${buffer[start + 3]}`;
}

function readUInt16(buffer, offset, littleEndian) {
  return littleEndian ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset);
}

function readUInt32(buffer, offset, littleEndian) {
  return littleEndian ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
}

function safeNumber(value, fallback = 0) {
  return Number.isFinite(value) ? value : fallback;
}

function getServiceName(port) {
  if (!Number.isInteger(port) || port <= 0 || port > 65535) return 'Unknown';
  return PORT_SERVICE_MAP[port] || 'Unknown';
}

function getThreatSeverityOrder(severity) {
  if (severity === 'Critical') return 4;
  if (severity === 'High') return 3;
  if (severity === 'Medium') return 2;
  if (severity === 'Low') return 1;
  return 0;
}

function detectCaptureFormat(buffer) {
  if (!buffer || buffer.length < 4) return null;
  const m0 = buffer[0];
  const m1 = buffer[1];
  const m2 = buffer[2];
  const m3 = buffer[3];

  const isPcap =
    (m0 === 0xd4 && m1 === 0xc3 && m2 === 0xb2 && m3 === 0xa1) ||
    (m0 === 0xa1 && m1 === 0xb2 && m2 === 0xc3 && m3 === 0xd4) ||
    (m0 === 0x4d && m1 === 0x3c && m2 === 0xb2 && m3 === 0xa1) ||
    (m0 === 0xa1 && m1 === 0xb2 && m2 === 0x3c && m3 === 0x4d);
  const isPcapNg = m0 === 0x0a && m1 === 0x0d && m2 === 0x0d && m3 === 0x0a;

  if (isPcapNg) return 'pcapng';
  if (isPcap) return 'pcap';
  return null;
}

function incrementMap(map, key, count = 1) {
  map.set(key, (map.get(key) || 0) + count);
}

function toTopArrayFromMap(map, limit = 10) {
  return Array.from(map.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit);
}

function packetProtocolLabel(protocolNumber) {
  if (protocolNumber === 6) return 'TCP';
  if (protocolNumber === 17) return 'UDP';
  if (protocolNumber === 1) return 'ICMP';
  return 'Other';
}

function decodeTcpFlags(flagsByte) {
  const flags = [];
  if (flagsByte & 0x01) flags.push('FIN');
  if (flagsByte & 0x02) flags.push('SYN');
  if (flagsByte & 0x04) flags.push('RST');
  if (flagsByte & 0x08) flags.push('PSH');
  if (flagsByte & 0x10) flags.push('ACK');
  if (flagsByte & 0x20) flags.push('URG');
  if (flagsByte & 0x40) flags.push('ECE');
  if (flagsByte & 0x80) flags.push('CWR');
  return flags;
}

function parsePacketData(packetData, linkType = 1) {
  const result = {
    srcMAC: null,
    dstMAC: null,
    srcIP: null,
    dstIP: null,
    srcPort: null,
    dstPort: null,
    protocol: 'Other',
    tcpFlags: null,
    service: null,
    ethertype: null
  };

  if (!Buffer.isBuffer(packetData) || packetData.length < 1) {
    return result;
  }

  // Ethernet
  if (linkType === 1 && packetData.length >= 14) {
    result.dstMAC = formatMac(packetData, 0);
    result.srcMAC = formatMac(packetData, 6);
    result.ethertype = packetData.readUInt16BE(12);

    if (result.ethertype === 0x0806) {
      result.protocol = 'ARP';
      return result;
    }

    if (result.ethertype !== 0x0800) {
      return result;
    }

    const ipOffset = 14;
    if (packetData.length < ipOffset + 20) {
      return result;
    }

    const versionIhl = packetData[ipOffset];
    const ihlBytes = (versionIhl & 0x0f) * 4;
    if (ihlBytes < 20 || packetData.length < ipOffset + ihlBytes) {
      return result;
    }

    const protocolNumber = packetData[ipOffset + 9];
    result.protocol = packetProtocolLabel(protocolNumber);
    result.srcIP = formatIPv4(packetData, ipOffset + 12);
    result.dstIP = formatIPv4(packetData, ipOffset + 16);

    const l4Offset = ipOffset + ihlBytes;
    if (protocolNumber === 6 && packetData.length >= l4Offset + 14) {
      result.srcPort = packetData.readUInt16BE(l4Offset);
      result.dstPort = packetData.readUInt16BE(l4Offset + 2);
      const flagsByte = packetData[l4Offset + 13];
      result.tcpFlags = decodeTcpFlags(flagsByte);
      result.service = getServiceName(result.dstPort);
      return result;
    }

    if (protocolNumber === 17 && packetData.length >= l4Offset + 8) {
      result.srcPort = packetData.readUInt16BE(l4Offset);
      result.dstPort = packetData.readUInt16BE(l4Offset + 2);
      result.service = getServiceName(result.dstPort);
      return result;
    }

    if (protocolNumber === 1) {
      result.service = 'ICMP';
      return result;
    }
  }

  return result;
}

function markPacketSuspicion(packet) {
  if (!packet) return packet;
  let reason = null;

  if (SUSPICIOUS_PORTS.has(packet.srcPort) || SUSPICIOUS_PORTS.has(packet.dstPort)) {
    const flaggedPort = SUSPICIOUS_PORTS.has(packet.dstPort) ? packet.dstPort : packet.srcPort;
    reason = `Traffic observed on suspicious port ${flaggedPort}`;
  } else if (packet.protocol === 'TCP' && Array.isArray(packet.tcpFlags) && packet.tcpFlags.includes('RST')) {
    reason = 'TCP reset traffic observed';
  } else if (packet.protocol === 'Other' && Number.isInteger(packet.ethertype) && !KNOWN_ETHERTYPES.has(packet.ethertype)) {
    reason = `Unusual ethertype 0x${packet.ethertype.toString(16)}`;
  }

  packet.isSuspicious = Boolean(reason);
  packet.suspicionReason = reason;
  return packet;
}

function buildCaptureStats(parsedPackets, totalPackets, captureStart, captureEnd) {
  const protocolCounts = new Map();
  const srcCounts = new Map();
  const dstCounts = new Map();
  const portCounts = new Map();

  parsedPackets.forEach((packet) => {
    incrementMap(protocolCounts, packet.protocol || 'Other');
    if (packet.srcIP) incrementMap(srcCounts, packet.srcIP);
    if (packet.dstIP) incrementMap(dstCounts, packet.dstIP);
    if (packet.srcPort) incrementMap(portCounts, packet.srcPort);
    if (packet.dstPort) incrementMap(portCounts, packet.dstPort);
  });

  const protocolTotal = parsedPackets.length || 1;
  const topProtocols = toTopArrayFromMap(protocolCounts, 10).map(([protocol, count]) => ({
    protocol,
    count,
    percentage: Number(((count / protocolTotal) * 100).toFixed(2))
  }));

  const topSrcIPs = toTopArrayFromMap(srcCounts, 10).map(([ip, count]) => ({ ip, count }));
  const topDstIPs = toTopArrayFromMap(dstCounts, 10).map(([ip, count]) => ({ ip, count }));
  const topPorts = toTopArrayFromMap(portCounts, 15).map(([port, count]) => ({
    port: Number(port),
    count,
    service: getServiceName(Number(port))
  }));

  const normalizedStart = safeNumber(captureStart, 0);
  const normalizedEnd = safeNumber(captureEnd, normalizedStart);

  return {
    totalPackets: safeNumber(totalPackets, parsedPackets.length),
    parsedPackets: parsedPackets.length,
    captureStart: normalizedStart,
    captureEnd: normalizedEnd,
    captureDuration: Math.max(0, Number((normalizedEnd - normalizedStart).toFixed(3))),
    topProtocols,
    topSrcIPs,
    topDstIPs,
    topPorts,
    packets: parsedPackets.slice(0, MAX_DISPLAY_PACKETS)
  };
}

function buildPcapSummary(captureStats, anomalies, parsedPackets) {
  const protocolSummary = captureStats.topProtocols
    .slice(0, 5)
    .map((entry) => `${entry.protocol} (${entry.percentage}%)`)
    .join(', ') || 'No protocol data';

  const srcSummary = captureStats.topSrcIPs
    .slice(0, 5)
    .map((entry) => `${entry.ip} (${entry.count})`)
    .join(', ') || 'N/A';

  const dstSummary = captureStats.topDstIPs
    .slice(0, 5)
    .map((entry) => `${entry.ip} (${entry.count})`)
    .join(', ') || 'N/A';

  const suspiciousPorts = new Set();
  parsedPackets.forEach((packet) => {
    if (SUSPICIOUS_PORTS.has(packet.srcPort)) suspiciousPorts.add(packet.srcPort);
    if (SUSPICIOUS_PORTS.has(packet.dstPort)) suspiciousPorts.add(packet.dstPort);
  });

  const suspiciousPortSummary = suspiciousPorts.size > 0
    ? Array.from(suspiciousPorts).sort((a, b) => a - b).join(', ')
    : 'None';

  const anomalySummary = anomalies.length > 0
    ? anomalies.map((item) => item.description).join(' | ')
    : 'No major anomalies detected';

  const sampleFlow = parsedPackets
    .slice(0, 20)
    .map((packet) => {
      const src = packet.srcIP ? `${packet.srcIP}${packet.srcPort ? `:${packet.srcPort}` : ''}` : 'Unknown';
      const dst = packet.dstIP ? `${packet.dstIP}${packet.dstPort ? `:${packet.dstPort}` : ''}` : 'Unknown';
      return `[#${packet.index}] ${src} -> ${dst} ${packet.protocol} len=${packet.length}`;
    })
    .join('; ');

  return `PCAP Analysis Summary:
Duration: ${captureStats.captureDuration} seconds, ${captureStats.totalPackets} total packets
Top protocols: ${protocolSummary}
Top source IPs: ${srcSummary}
Top destination IPs: ${dstSummary}
Suspicious ports detected: ${suspiciousPortSummary}
Anomalies found: ${anomalySummary}
Sample packet flow (first 20): ${sampleFlow || 'No packets available'}`;
}

function detectPcapAnomalies(parsedPackets) {
  const anomalies = [];
  const seenSignatures = new Set();

  const addAnomaly = (anomaly) => {
    const signature = `${anomaly.type}:${anomaly.description}`;
    if (seenSignatures.has(signature)) return;
    seenSignatures.add(signature);
    anomalies.push(anomaly);
  };

  // Port scan
  const srcToPorts = new Map();
  parsedPackets.forEach((packet) => {
    if (!packet.srcIP || !packet.dstPort) return;
    if (packet.protocol !== 'TCP' && packet.protocol !== 'UDP') return;
    if (!srcToPorts.has(packet.srcIP)) srcToPorts.set(packet.srcIP, new Set());
    srcToPorts.get(packet.srcIP).add(packet.dstPort);
  });

  srcToPorts.forEach((ports, srcIP) => {
    if (ports.size > 10) {
      addAnomaly({
        type: 'Port Scan',
        severity: 'High',
        description: `Source ${srcIP} touched ${ports.size} distinct destination ports`,
        affectedIPs: [srcIP],
        packetCount: parsedPackets.filter((p) => p.srcIP === srcIP).length
      });
    }
  });

  // SYN flood
  const tcpBySrc = new Map();
  parsedPackets.forEach((packet) => {
    if (packet.protocol !== 'TCP' || !packet.srcIP) return;
    if (!tcpBySrc.has(packet.srcIP)) tcpBySrc.set(packet.srcIP, { total: 0, synOnly: 0 });
    const row = tcpBySrc.get(packet.srcIP);
    row.total += 1;
    const flags = packet.tcpFlags || [];
    if (flags.includes('SYN') && !flags.includes('ACK')) row.synOnly += 1;
  });

  tcpBySrc.forEach((stats, srcIP) => {
    if (stats.total === 0) return;
    const ratio = stats.synOnly / stats.total;
    if (ratio > 0.8 && stats.total >= 10) {
      addAnomaly({
        type: 'SYN Flood',
        severity: 'Critical',
        description: `Possible SYN flood from ${srcIP}: ${(ratio * 100).toFixed(1)}% SYN-only packets`,
        affectedIPs: [srcIP],
        packetCount: stats.total
      });
    }
  });

  // Beaconing
  const pairTimestamps = new Map();
  parsedPackets.forEach((packet) => {
    if (!packet.srcIP || !packet.dstIP || !Number.isFinite(packet.timestamp)) return;
    const key = `${packet.srcIP}->${packet.dstIP}`;
    if (!pairTimestamps.has(key)) pairTimestamps.set(key, []);
    pairTimestamps.get(key).push(packet.timestamp);
  });

  pairTimestamps.forEach((timestamps, key) => {
    if (timestamps.length < 6) return;
    const sorted = [...timestamps].sort((a, b) => a - b);
    const intervals = [];
    for (let i = 1; i < sorted.length; i += 1) {
      intervals.push(sorted[i] - sorted[i - 1]);
    }
    if (intervals.length < 5) return;
    const avg = intervals.reduce((acc, value) => acc + value, 0) / intervals.length;
    const maxDeviation = Math.max(...intervals.map((value) => Math.abs(value - avg)));
    if (maxDeviation <= 2) {
      const [srcIP, dstIP] = key.split('->');
      addAnomaly({
        type: 'C2 Beaconing',
        severity: 'High',
        description: `Regular interval communication detected between ${srcIP} and ${dstIP}`,
        affectedIPs: [srcIP, dstIP],
        packetCount: sorted.length
      });
    }
  });

  // Large transfer / exfiltration candidate
  const flowBytes = new Map();
  parsedPackets.forEach((packet) => {
    if (!packet.srcIP || !packet.dstIP) return;
    const key = `${packet.srcIP}->${packet.dstIP}`;
    incrementMap(flowBytes, key, packet.length || 0);
  });

  flowBytes.forEach((bytes, key) => {
    if (bytes > 1024 * 1024) {
      const [srcIP, dstIP] = key.split('->');
      addAnomaly({
        type: 'Large Data Transfer',
        severity: 'High',
        description: `Flow ${srcIP} -> ${dstIP} transferred ${(bytes / (1024 * 1024)).toFixed(2)} MB`,
        affectedIPs: [srcIP, dstIP],
        packetCount: parsedPackets.filter((packet) => packet.srcIP === srcIP && packet.dstIP === dstIP).length
      });
    }
  });

  // Suspicious ports
  const suspiciousPackets = parsedPackets.filter(
    (packet) => SUSPICIOUS_PORTS.has(packet.srcPort) || SUSPICIOUS_PORTS.has(packet.dstPort)
  );
  if (suspiciousPackets.length > 0) {
    const ips = new Set();
    suspiciousPackets.forEach((packet) => {
      if (packet.srcIP) ips.add(packet.srcIP);
      if (packet.dstIP) ips.add(packet.dstIP);
    });
    addAnomaly({
      type: 'Suspicious Ports',
      severity: 'High',
      description: 'Traffic observed on known C2/reverse-shell suspicious ports',
      affectedIPs: Array.from(ips),
      packetCount: suspiciousPackets.length
    });
  }

  // Non-standard protocols / unusual ethertype
  const unusualEthPackets = parsedPackets.filter(
    (packet) => Number.isInteger(packet.ethertype) && !KNOWN_ETHERTYPES.has(packet.ethertype)
  );
  if (unusualEthPackets.length > 0) {
    addAnomaly({
      type: 'Non-standard Protocol',
      severity: 'Medium',
      description: 'Unusual ethernet ethertype values detected in capture',
      affectedIPs: Array.from(
        new Set(
          unusualEthPackets
            .flatMap((packet) => [packet.srcIP, packet.dstIP])
            .filter(Boolean)
        )
      ),
      packetCount: unusualEthPackets.length
    });
  }

  // DNS tunneling candidate
  const largeDnsPackets = parsedPackets.filter((packet) => {
    const isDns = packet.protocol === 'UDP' || packet.protocol === 'TCP'
      ? packet.srcPort === 53 || packet.dstPort === 53
      : false;
    return isDns && packet.length > 512;
  });
  if (largeDnsPackets.length > 0) {
    addAnomaly({
      type: 'DNS Tunneling Candidate',
      severity: 'Medium',
      description: 'Large DNS packets (>512 bytes) detected',
      affectedIPs: Array.from(
        new Set(
          largeDnsPackets
            .flatMap((packet) => [packet.srcIP, packet.dstIP])
            .filter(Boolean)
        )
      ),
      packetCount: largeDnsPackets.length
    });
  }

  return anomalies.sort((a, b) => getThreatSeverityOrder(b.severity) - getThreatSeverityOrder(a.severity));
}

function parsePcapBufferManual(buffer, maxParsedPackets = MAX_PARSED_PACKETS) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 24) {
    throw new Error('Invalid PCAP data: file is too small');
  }

  const magic = buffer.readUInt32LE(0);
  let littleEndian = true;
  let isNano = false;

  if (magic === 0xa1b2c3d4) {
    littleEndian = false;
  } else if (magic === 0xd4c3b2a1) {
    littleEndian = true;
  } else if (magic === 0x4d3cb2a1) {
    littleEndian = true;
    isNano = true;
  } else if (magic === 0xa1b23c4d) {
    littleEndian = false;
    isNano = true;
  } else {
    throw new Error('Unsupported PCAP magic bytes');
  }

  const network = readUInt32(buffer, 20, littleEndian);
  let offset = 24;
  let packetIndex = 0;
  let totalPackets = 0;
  let captureStart = null;
  let captureEnd = null;
  const parsedPackets = [];

  while (offset + 16 <= buffer.length) {
    const tsSec = readUInt32(buffer, offset, littleEndian);
    const tsSubsec = readUInt32(buffer, offset + 4, littleEndian);
    const inclLen = readUInt32(buffer, offset + 8, littleEndian);

    if (inclLen < 0 || inclLen > buffer.length || offset + 16 + inclLen > buffer.length) {
      break;
    }

    totalPackets += 1;
    const ts = tsSec + (isNano ? tsSubsec / 1e9 : tsSubsec / 1e6);
    captureStart = captureStart === null ? ts : Math.min(captureStart, ts);
    captureEnd = captureEnd === null ? ts : Math.max(captureEnd, ts);

    if (parsedPackets.length < maxParsedPackets) {
      const packetData = buffer.subarray(offset + 16, offset + 16 + inclLen);
      const parsed = parsePacketData(packetData, network);
      const packet = markPacketSuspicion({
        index: packetIndex + 1,
        timestamp: ts,
        length: inclLen,
        srcIP: parsed.srcIP,
        dstIP: parsed.dstIP,
        srcPort: parsed.srcPort,
        dstPort: parsed.dstPort,
        protocol: parsed.protocol,
        tcpFlags: parsed.tcpFlags,
        service: parsed.service || (parsed.protocol === 'ARP' ? 'ARP' : null),
        isSuspicious: false,
        suspicionReason: null,
        ethertype: parsed.ethertype,
        rawPreviewHex: packetData.subarray(0, 64).toString('hex')
      });
      parsedPackets.push(packet);
    }

    packetIndex += 1;
    offset += 16 + inclLen;
  }

  return {
    totalPackets,
    parsedPackets,
    captureStart: safeNumber(captureStart, 0),
    captureEnd: safeNumber(captureEnd, safeNumber(captureStart, 0))
  };
}

function parsePcapNgBufferManual(buffer, maxParsedPackets = MAX_PARSED_PACKETS) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) {
    throw new Error('Invalid PCAPNG data: file is too small');
  }

  const sectionMagic = buffer.readUInt32LE(0);
  if (sectionMagic !== 0x0a0d0d0a) {
    throw new Error('Invalid PCAPNG section header');
  }

  let littleEndian = true;
  if (buffer.length >= 12) {
    const byteOrderMagicLE = buffer.readUInt32LE(8);
    if (byteOrderMagicLE === 0x1a2b3c4d) {
      littleEndian = true;
    } else if (byteOrderMagicLE === 0x4d3c2b1a) {
      littleEndian = false;
    }
  }

  let offset = 0;
  let totalPackets = 0;
  let packetIndex = 0;
  let captureStart = null;
  let captureEnd = null;
  const parsedPackets = [];
  const interfaces = [];

  while (offset + 12 <= buffer.length) {
    const blockType = readUInt32(buffer, offset, littleEndian);
    const blockTotalLength = readUInt32(buffer, offset + 4, littleEndian);

    if (blockTotalLength < 12 || offset + blockTotalLength > buffer.length) {
      break;
    }

    const bodyOffset = offset + 8;
    const bodyLength = blockTotalLength - 12;

    if (blockType === 0x00000001 && bodyLength >= 8) {
      const linkType = readUInt16(buffer, bodyOffset, littleEndian);
      interfaces.push({ linkType });
    }

    if (blockType === 0x00000006 && bodyLength >= 20) {
      // Enhanced Packet Block
      const interfaceId = readUInt32(buffer, bodyOffset, littleEndian);
      const tsHigh = readUInt32(buffer, bodyOffset + 4, littleEndian);
      const tsLow = readUInt32(buffer, bodyOffset + 8, littleEndian);
      const capturedLength = readUInt32(buffer, bodyOffset + 12, littleEndian);
      const packetDataStart = bodyOffset + 20;
      const packetDataEnd = packetDataStart + capturedLength;
      if (packetDataEnd <= offset + blockTotalLength - 4) {
        totalPackets += 1;
        const ts = Number((BigInt(tsHigh) << 32n) | BigInt(tsLow)) / 1_000_000;
        captureStart = captureStart === null ? ts : Math.min(captureStart, ts);
        captureEnd = captureEnd === null ? ts : Math.max(captureEnd, ts);

        if (parsedPackets.length < maxParsedPackets) {
          const packetData = buffer.subarray(packetDataStart, packetDataEnd);
          const linkType = interfaces[interfaceId]?.linkType ?? 1;
          const parsed = parsePacketData(packetData, linkType);
          const packet = markPacketSuspicion({
            index: packetIndex + 1,
            timestamp: ts,
            length: capturedLength,
            srcIP: parsed.srcIP,
            dstIP: parsed.dstIP,
            srcPort: parsed.srcPort,
            dstPort: parsed.dstPort,
            protocol: parsed.protocol,
            tcpFlags: parsed.tcpFlags,
            service: parsed.service || (parsed.protocol === 'ARP' ? 'ARP' : null),
            isSuspicious: false,
            suspicionReason: null,
            ethertype: parsed.ethertype,
            rawPreviewHex: packetData.subarray(0, 64).toString('hex')
          });
          parsedPackets.push(packet);
        }
        packetIndex += 1;
      }
    }

    if (blockType === 0x00000003 && bodyLength >= 4) {
      // Simple Packet Block
      const originalLength = readUInt32(buffer, bodyOffset, littleEndian);
      const packetDataStart = bodyOffset + 4;
      const packetDataEnd = offset + blockTotalLength - 4;
      if (packetDataEnd > packetDataStart) {
        totalPackets += 1;
        const ts = packetIndex + 1;
        captureStart = captureStart === null ? ts : Math.min(captureStart, ts);
        captureEnd = captureEnd === null ? ts : Math.max(captureEnd, ts);

        if (parsedPackets.length < maxParsedPackets) {
          const packetData = buffer.subarray(packetDataStart, packetDataEnd);
          const parsed = parsePacketData(packetData, interfaces[0]?.linkType ?? 1);
          const packet = markPacketSuspicion({
            index: packetIndex + 1,
            timestamp: ts,
            length: originalLength,
            srcIP: parsed.srcIP,
            dstIP: parsed.dstIP,
            srcPort: parsed.srcPort,
            dstPort: parsed.dstPort,
            protocol: parsed.protocol,
            tcpFlags: parsed.tcpFlags,
            service: parsed.service || (parsed.protocol === 'ARP' ? 'ARP' : null),
            isSuspicious: false,
            suspicionReason: null,
            ethertype: parsed.ethertype,
            rawPreviewHex: packetData.subarray(0, 64).toString('hex')
          });
          parsedPackets.push(packet);
        }
        packetIndex += 1;
      }
    }

    offset += blockTotalLength;
  }

  return {
    totalPackets,
    parsedPackets,
    captureStart: safeNumber(captureStart, 0),
    captureEnd: safeNumber(captureEnd, safeNumber(captureStart, 0))
  };
}

async function parsePcapWithLibrary(buffer, maxParsedPackets = MAX_PARSED_PACKETS) {
  if (!pcapParserLib) {
    throw new Error('pcap-parser dependency is not available');
  }

  return new Promise((resolve, reject) => {
    try {
      const stream = Readable.from(buffer);
      const parser = pcapParserLib.parse(stream);
      let linkType = 1;
      let totalPackets = 0;
      let captureStart = null;
      let captureEnd = null;
      let packetIndex = 0;
      const parsedPackets = [];

      parser.on('globalHeader', (header) => {
        const candidate = header?.linkLayerType ?? header?.network ?? 1;
        linkType = Number.isFinite(candidate) ? candidate : 1;
      });

      parser.on('packet', (packet) => {
        totalPackets += 1;
        const tsSec = Number(packet?.header?.timestampSeconds || 0);
        const tsUsec = Number(packet?.header?.timestampMicroseconds || 0);
        const ts = tsSec + tsUsec / 1e6;
        captureStart = captureStart === null ? ts : Math.min(captureStart, ts);
        captureEnd = captureEnd === null ? ts : Math.max(captureEnd, ts);

        if (parsedPackets.length < maxParsedPackets) {
          const data = Buffer.from(packet?.data || []);
          const parsed = parsePacketData(data, linkType);
          const packetRow = markPacketSuspicion({
            index: packetIndex + 1,
            timestamp: ts,
            length: Number(packet?.header?.capturedLength || data.length || 0),
            srcIP: parsed.srcIP,
            dstIP: parsed.dstIP,
            srcPort: parsed.srcPort,
            dstPort: parsed.dstPort,
            protocol: parsed.protocol,
            tcpFlags: parsed.tcpFlags,
            service: parsed.service || (parsed.protocol === 'ARP' ? 'ARP' : null),
            isSuspicious: false,
            suspicionReason: null,
            ethertype: parsed.ethertype,
            rawPreviewHex: data.subarray(0, 64).toString('hex')
          });
          parsedPackets.push(packetRow);
        }

        packetIndex += 1;
      });

      parser.on('end', () => {
        resolve({
          totalPackets,
          parsedPackets,
          captureStart: safeNumber(captureStart, 0),
          captureEnd: safeNumber(captureEnd, safeNumber(captureStart, 0))
        });
      });

      parser.on('error', (error) => reject(error));
    } catch (error) {
      reject(error);
    }
  });
}

function parseMultipartContentDisposition(headerLine) {
  const nameMatch = headerLine.match(/name="([^"]+)"/i);
  const fileMatch = headerLine.match(/filename="([^"]*)"/i);
  return {
    fieldName: nameMatch ? nameMatch[1] : null,
    fileName: fileMatch ? fileMatch[1] : null
  };
}

function parseMultipartBuffer(rawBuffer, boundary) {
  const delimiter = Buffer.from(`--${boundary}`);
  const parts = [];
  let searchOffset = 0;

  while (searchOffset < rawBuffer.length) {
    const start = rawBuffer.indexOf(delimiter, searchOffset);
    if (start === -1) break;

    const next = rawBuffer.indexOf(delimiter, start + delimiter.length);
    if (next === -1) break;

    const partStart = start + delimiter.length + 2; // Skip boundary + CRLF
    const partEnd = next - 2; // Trim trailing CRLF
    if (partStart < partEnd) {
      parts.push(rawBuffer.subarray(partStart, partEnd));
    }
    searchOffset = next;
  }

  const fields = {};
  let file = null;

  parts.forEach((part) => {
    const separatorIndex = part.indexOf(Buffer.from('\r\n\r\n'));
    if (separatorIndex === -1) return;

    const headerText = part.subarray(0, separatorIndex).toString('utf8');
    const content = part.subarray(separatorIndex + 4);
    const headerLines = headerText.split('\r\n');
    const dispositionLine = headerLines.find((line) => line.toLowerCase().startsWith('content-disposition'));
    if (!dispositionLine) return;

    const { fieldName, fileName } = parseMultipartContentDisposition(dispositionLine);
    const contentTypeLine = headerLines.find((line) => line.toLowerCase().startsWith('content-type'));
    const mimeType = contentTypeLine ? contentTypeLine.split(':')[1]?.trim() : 'application/octet-stream';

    if (fileName && fieldName === 'file') {
      file = {
        fieldname: 'file',
        originalname: fileName || 'upload.pcap',
        encoding: '7bit',
        mimetype: mimeType || 'application/octet-stream',
        buffer: content,
        size: content.length
      };
      return;
    }

    if (fieldName) {
      fields[fieldName] = content.toString('utf8').trim();
    }
  });

  return { file, fields };
}

function parseMultipartWithoutMulter(req, res, next) {
  const contentType = String(req.headers['content-type'] || '');
  if (!contentType.toLowerCase().startsWith('multipart/form-data')) {
    return res.status(400).json({
      error: 'INVALID_CONTENT_TYPE',
      message: 'Content-Type must be multipart/form-data'
    });
  }

  const boundaryMatch = contentType.match(/boundary=([^;]+)/i);
  if (!boundaryMatch) {
    return res.status(400).json({
      error: 'MISSING_BOUNDARY',
      message: 'Multipart boundary is missing'
    });
  }

  const contentLength = Number(req.headers['content-length'] || 0);
  if (Number.isFinite(contentLength) && contentLength > MAX_PCAP_FILE_SIZE_BYTES) {
    return res.status(413).json({
      error: 'FILE_TOO_LARGE',
      message: 'File exceeds 50MB maximum size'
    });
  }

  const chunks = [];
  let totalLength = 0;

  req.on('data', (chunk) => {
    totalLength += chunk.length;
    if (totalLength > MAX_PCAP_FILE_SIZE_BYTES + 1024 * 1024) {
      req.destroy();
      return;
    }
    chunks.push(chunk);
  });

  req.on('error', (error) => {
    return res.status(400).json({ error: 'MULTIPART_READ_FAILED', message: error.message || 'Failed to read multipart payload' });
  });

  req.on('end', () => {
    try {
      if (totalLength > MAX_PCAP_FILE_SIZE_BYTES) {
        return res.status(413).json({
          error: 'FILE_TOO_LARGE',
          message: 'File exceeds 50MB maximum size'
        });
      }

      const rawBuffer = Buffer.concat(chunks);
      const parsed = parseMultipartBuffer(rawBuffer, boundaryMatch[1]);
      req.body = { ...(req.body || {}), ...(parsed?.fields || {}) };
      req.file = parsed?.file || null;

      return next();
    } catch (error) {
      return res.status(400).json({
        error: 'MULTIPART_PARSE_FAILED',
        message: error.message || 'Failed to parse multipart form data'
      });
    }
  });
}

function pcapUploadMiddleware(req, res, next) {
  if (uploadPcap) {
    uploadPcap(req, res, (error) => {
      if (error) {
        if (error.code === 'LIMIT_FILE_SIZE') {
          return res.status(413).json({
            error: 'FILE_TOO_LARGE',
            message: 'File exceeds 50MB maximum size'
          });
        }
        return res.status(400).json({
          error: 'UPLOAD_FAILED',
          message: error.message || 'Failed to process uploaded file'
        });
      }
      return next();
    });
    return;
  }

  parseMultipartWithoutMulter(req, res, next);
}

function normalizeThreatLevel(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'critical') return 'Critical';
  if (normalized === 'high') return 'High';
  if (normalized === 'medium') return 'Medium';
  if (normalized === 'low') return 'Low';
  if (normalized === 'clean') return 'Clean';
  return 'Medium';
}

function normalizeExfiltrationRisk(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'high') return 'High';
  if (normalized === 'medium') return 'Medium';
  if (normalized === 'low') return 'Low';
  if (normalized === 'none') return 'None';
  return 'Low';
}

function normalizeSeverity(value) {
  const normalized = String(value || '').trim().toLowerCase();
  if (normalized === 'critical') return 'Critical';
  if (normalized === 'high') return 'High';
  if (normalized === 'medium') return 'Medium';
  if (normalized === 'low') return 'Low';
  return 'Medium';
}

function buildConversationStats(packets) {
  const flowMap = new Map();
  packets.forEach((packet) => {
    const src = packet.srcIP || 'Unknown';
    const dst = packet.dstIP || 'Unknown';
    const protocol = packet.protocol || 'Other';
    const key = `${src}|${dst}|${protocol}`;
    if (!flowMap.has(key)) {
      flowMap.set(key, {
        srcIP: src,
        dstIP: dst,
        protocol,
        packets: 0,
        bytes: 0,
        firstTimestamp: packet.timestamp || 0,
        lastTimestamp: packet.timestamp || 0,
        flags: new Set(),
        risk: packet.isSuspicious ? 'High' : 'Low'
      });
    }
    const row = flowMap.get(key);
    row.packets += 1;
    row.bytes += packet.length || 0;
    row.firstTimestamp = Math.min(row.firstTimestamp, packet.timestamp || row.firstTimestamp);
    row.lastTimestamp = Math.max(row.lastTimestamp, packet.timestamp || row.lastTimestamp);
    (packet.tcpFlags || []).forEach((flag) => row.flags.add(flag));
    if (packet.isSuspicious) row.risk = 'High';
  });

  return Array.from(flowMap.values())
    .map((row) => ({
      srcIP: row.srcIP,
      dstIP: row.dstIP,
      protocol: row.protocol,
      packets: row.packets,
      bytes: row.bytes,
      duration: Math.max(0, Number((row.lastTimestamp - row.firstTimestamp).toFixed(3))),
      flags: Array.from(row.flags),
      risk: row.risk
    }))
    .sort((a, b) => b.bytes - a.bytes);
}

// In-memory progress storage for IR playbooks
const irProgress = new Map();

function generateIncidentId() {
  const year = new Date().getFullYear();
  const randomPart = String(Math.floor(Math.random() * 9000) + 1000);
  return `IR-${year}-${randomPart}`;
}

// POST /pcap/analyze - Parse PCAP/PCAPNG and run algorithmic anomaly detection
app.post('/pcap/analyze', pcapUploadMiddleware, async (req, res) => {
  const uploadedFile = req.file;
  const analysisDepth = String(req.body?.analysisDepth || 'quick').toLowerCase() === 'deep' ? 'deep' : 'quick';

  if (!uploadedFile || !Buffer.isBuffer(uploadedFile.buffer)) {
    return res.status(400).json({
      error: 'FILE_REQUIRED',
      message: 'A .pcap or .pcapng file is required in the multipart "file" field.'
    });
  }

  if (uploadedFile.size > MAX_PCAP_FILE_SIZE_BYTES) {
    return res.status(413).json({
      error: 'FILE_TOO_LARGE',
      message: 'File exceeds 50MB maximum size'
    });
  }

  const captureType = detectCaptureFormat(uploadedFile.buffer);
  if (!captureType) {
    return res.status(400).json({
      error: 'INVALID_CAPTURE_TYPE',
      message: 'Only .pcap and .pcapng files are supported. Uploaded file does not match PCAP magic bytes.'
    });
  }

  try {
    let parseResult;
    if (captureType === 'pcap') {
      if (pcapParserLib) {
        try {
          parseResult = await parsePcapWithLibrary(uploadedFile.buffer, MAX_PARSED_PACKETS);
        } catch (libraryError) {
          console.warn(`⚠️ pcap-parser failed, using manual parser fallback: ${libraryError.message}`);
          parseResult = parsePcapBufferManual(uploadedFile.buffer, MAX_PARSED_PACKETS);
        }
      } else {
        parseResult = parsePcapBufferManual(uploadedFile.buffer, MAX_PARSED_PACKETS);
      }
    } else {
      parseResult = parsePcapNgBufferManual(uploadedFile.buffer, MAX_PARSED_PACKETS);
    }

    const anomalies = detectPcapAnomalies(parseResult.parsedPackets);
    const captureStats = buildCaptureStats(
      parseResult.parsedPackets,
      parseResult.totalPackets,
      parseResult.captureStart,
      parseResult.captureEnd
    );
    const summary = buildPcapSummary(captureStats, anomalies, parseResult.parsedPackets);

    return res.json({
      success: true,
      fileName: uploadedFile.originalname || 'capture.pcap',
      fileSize: uploadedFile.size,
      captureType,
      analysisDepth,
      captureStats,
      anomalies,
      summary
    });
  } catch (error) {
    console.error('PCAP Parse Error:', error.message);
    return res.status(400).json({
      error: 'PCAP_PARSE_FAILED',
      message: error.message || 'Failed to parse packet capture file'
    });
  }
});

// POST /pcap/ai-analyze - AI network forensics intelligence from summary/anomalies
app.post('/pcap/ai-analyze', async (req, res) => {
  const { summary, anomalies = [], captureStats = {} } = req.body || {};
  if (!summary || typeof summary !== 'string') {
    return res.status(400).json({
      error: 'SUMMARY_REQUIRED',
      message: 'summary is required'
    });
  }

  try {
    const prompt = `You are a network forensics expert. Analyze this packet capture summary.
Respond ONLY with valid JSON (no markdown, no backticks):

Summary: ${summary}
Detected Anomalies: ${JSON.stringify(anomalies)}
Capture Stats: ${JSON.stringify(captureStats)}

{
  "threatLevel": "Critical" | "High" | "Medium" | "Low" | "Clean",
  "verdict": "string",
  "detectedAttacks": [
    {
      "attackType": "string",
      "confidence": 0,
      "description": "string",
      "affectedHosts": ["string"],
      "mitreTechnique": "string | null",
      "evidence": "string"
    }
  ],
  "suspiciousFlows": [
    {
      "srcIP": "string",
      "dstIP": "string",
      "port": 0,
      "protocol": "string",
      "reason": "string",
      "severity": "Critical" | "High" | "Medium" | "Low"
    }
  ],
  "c2Indicators": ["string"],
  "exfiltrationRisk": "High" | "Medium" | "Low" | "None",
  "recommendations": ["string"],
  "iocs": ["string"]
}`;

    const aiResult = await generateGeminiJson(prompt);
    const normalizedResult = {
      threatLevel: normalizeThreatLevel(aiResult?.threatLevel),
      verdict: String(aiResult?.verdict || 'No additional AI verdict provided.'),
      detectedAttacks: Array.isArray(aiResult?.detectedAttacks) ? aiResult.detectedAttacks : [],
      suspiciousFlows: Array.isArray(aiResult?.suspiciousFlows) ? aiResult.suspiciousFlows : [],
      c2Indicators: Array.isArray(aiResult?.c2Indicators) ? aiResult.c2Indicators : [],
      exfiltrationRisk: normalizeExfiltrationRisk(aiResult?.exfiltrationRisk),
      recommendations: Array.isArray(aiResult?.recommendations) ? aiResult.recommendations : [],
      iocs: Array.isArray(aiResult?.iocs) ? aiResult.iocs : []
    };

    return res.json(normalizedResult);
  } catch (error) {
    console.error('PCAP AI Analyze Error:', error.message);
    return res.json(localPcapAiAnalysis(summary, anomalies, captureStats));
  }
});

// POST /pcap/protocols - Compute protocol and conversation statistics
app.post('/pcap/protocols', (req, res) => {
  const { packets = [] } = req.body || {};
  if (!Array.isArray(packets)) {
    return res.status(400).json({
      error: 'INVALID_PACKETS',
      message: 'packets must be an array'
    });
  }

  const protocolCounts = new Map();
  const tcpFlagCounts = new Map();
  const portCounts = new Map();
  const sizeDistribution = { small: 0, medium: 0, large: 0 };

  packets.forEach((packet) => {
    const protocol = packet.protocol || 'Other';
    incrementMap(protocolCounts, protocol);

    if (packet.srcPort) incrementMap(portCounts, packet.srcPort);
    if (packet.dstPort) incrementMap(portCounts, packet.dstPort);

    (packet.tcpFlags || []).forEach((flag) => incrementMap(tcpFlagCounts, flag));

    const length = Number(packet.length || 0);
    if (length < 64) sizeDistribution.small += 1;
    else if (length <= 1024) sizeDistribution.medium += 1;
    else sizeDistribution.large += 1;
  });

  const total = packets.length || 1;
  const protocolDistribution = toTopArrayFromMap(protocolCounts, 20).map(([protocol, count]) => ({
    protocol,
    count,
    percentage: Number(((count / total) * 100).toFixed(2))
  }));

  const tcpFlagDistribution = toTopArrayFromMap(tcpFlagCounts, 16).map(([flag, count]) => ({ flag, count }));
  const topPorts = toTopArrayFromMap(portCounts, 20).map(([port, count]) => ({
    port: Number(port),
    count,
    service: getServiceName(Number(port))
  }));
  const conversations = buildConversationStats(packets);

  return res.json({
    protocolDistribution,
    conversations,
    tcpFlagDistribution,
    packetSizeDistribution: sizeDistribution,
    topPorts
  });
});

// POST /ir/generate - Generate NIST-aligned incident response playbook
app.post('/ir/generate', async (req, res) => {
  const {
    incidentType,
    severity,
    affectedSystems = [],
    findings,
    organizationContext = ''
  } = req.body || {};

  if (!incidentType || !severity || !findings) {
    return res.status(400).json({
      error: 'INVALID_REQUEST',
      message: 'incidentType, severity and findings are required'
    });
  }

  try {
    const prompt = `You are a senior incident response expert following NIST SP 800-61 guidelines.
Generate a comprehensive IR playbook for this incident.

Incident Type: ${incidentType}
Severity: ${severity}
Affected Systems: ${JSON.stringify(Array.isArray(affectedSystems) ? affectedSystems : [])}
Findings: ${findings}
Organization Context: ${organizationContext}

Respond ONLY with valid JSON (no markdown, no backticks):
{
  "playbookTitle": "string",
  "incidentId": "string",
  "severity": "Critical" | "High" | "Medium" | "Low",
  "incidentType": "string",
  "executiveSummary": "string",
  "affectedAssets": ["string"],
  "iocs": ["string"],
  "phases": [
    {
      "phaseId": 1,
      "phaseName": "Preparation",
      "phaseIcon": "string",
      "estimatedDuration": "string",
      "priority": "Immediate" | "High" | "Medium" | "Low",
      "steps": [
        {
          "stepId": "string",
          "title": "string",
          "description": "string",
          "assignedRole": "string",
          "toolsRequired": ["string"],
          "expectedOutcome": "string",
          "isAutomatable": true,
          "bashCommand": "string | null"
        }
      ]
    }
  ],
  "communicationPlan": {
    "internalNotifications": ["string"],
    "externalNotifications": ["string"],
    "regulatoryRequirements": ["string"]
  },
  "lessonsLearned": ["string"],
  "references": ["string"]
}`;

    const generated = await generateGeminiJson(prompt);
    const incidentId = /^IR-\d{4}-\d{4}$/i.test(String(generated?.incidentId || ''))
      ? String(generated.incidentId).toUpperCase()
      : generateIncidentId();
    const playbookId = String(generated?.playbookId || `playbook_${incidentId}_${Date.now()}`);
    const now = Date.now();

    const normalizedPhases = Array.isArray(generated?.phases)
      ? generated.phases.map((phase, index) => ({
          phaseId: Number(phase?.phaseId || index + 1),
          phaseName: String(phase?.phaseName || `Phase ${index + 1}`),
          phaseIcon: String(phase?.phaseIcon || 'Shield'),
          estimatedDuration: String(phase?.estimatedDuration || 'TBD'),
          priority: ['Immediate', 'High', 'Medium', 'Low'].includes(phase?.priority) ? phase.priority : 'Medium',
          isExpanded: index === 0,
          steps: Array.isArray(phase?.steps)
            ? phase.steps.map((step, stepIndex) => ({
                stepId: String(step?.stepId || `P${index + 1}-S${stepIndex + 1}`),
                title: String(step?.title || `Step ${stepIndex + 1}`),
                description: String(step?.description || ''),
                assignedRole: String(step?.assignedRole || 'SOC Analyst'),
                toolsRequired: Array.isArray(step?.toolsRequired) ? step.toolsRequired : [],
                expectedOutcome: String(step?.expectedOutcome || ''),
                isAutomatable: Boolean(step?.isAutomatable),
                bashCommand: step?.bashCommand ? String(step.bashCommand) : null,
                status: 'pending',
                completedAt: null,
                completedBy: '',
                notes: ''
              }))
            : []
        }))
      : [];

    const responsePayload = {
      playbookId,
      playbookTitle: String(generated?.playbookTitle || `${incidentType} Incident Response Playbook`),
      incidentId,
      severity: normalizeSeverity(generated?.severity || severity),
      incidentType: String(generated?.incidentType || incidentType),
      createdAt: now,
      lastUpdated: now,
      executiveSummary: String(generated?.executiveSummary || ''),
      affectedAssets: Array.isArray(generated?.affectedAssets) ? generated.affectedAssets : (Array.isArray(affectedSystems) ? affectedSystems : []),
      iocs: Array.isArray(generated?.iocs) ? generated.iocs : [],
      phases: normalizedPhases,
      communicationPlan: {
        internalNotifications: Array.isArray(generated?.communicationPlan?.internalNotifications) ? generated.communicationPlan.internalNotifications : [],
        externalNotifications: Array.isArray(generated?.communicationPlan?.externalNotifications) ? generated.communicationPlan.externalNotifications : [],
        regulatoryRequirements: Array.isArray(generated?.communicationPlan?.regulatoryRequirements) ? generated.communicationPlan.regulatoryRequirements : []
      },
      lessonsLearned: Array.isArray(generated?.lessonsLearned) ? generated.lessonsLearned : [],
      references: Array.isArray(generated?.references) ? generated.references : []
    };

    return res.json(responsePayload);
  } catch (error) {
    console.error('IR Generate Error:', error.message);
    return res.json(localIRPlaybook({ incidentType, severity, affectedSystems, findings }));
  }
});

// POST /ir/update-step - Persist in-memory server-side progress snapshot
app.post('/ir/update-step', (req, res) => {
  const {
    playbookId,
    stepId,
    status,
    notes = '',
    completedBy = ''
  } = req.body || {};

  if (!playbookId || !stepId || !status) {
    return res.status(400).json({
      error: 'INVALID_REQUEST',
      message: 'playbookId, stepId and status are required'
    });
  }

  if (!irProgress.has(playbookId)) {
    irProgress.set(playbookId, new Map());
  }

  const allowedStatuses = new Set(['pending', 'in_progress', 'completed', 'skipped']);
  const normalizedStatus = allowedStatuses.has(status) ? status : 'pending';
  const stepState = {
    status: normalizedStatus,
    notes: String(notes || ''),
    completedBy: String(completedBy || ''),
    updatedAt: Date.now()
  };

  irProgress.get(playbookId).set(stepId, stepState);

  return res.json({
    success: true,
    playbookId,
    stepId,
    status: normalizedStatus
  });
});

// ========================================
// 🕶️ DARK WEB MONITOR ENDPOINTS
// ========================================

app.post('/darkweb/breach', async (req, res) => {
  const { query, type } = req.body || {};

  if (!query || !type) {
    return res.status(400).json({ error: 'query and type are required' });
  }

  try {
    if (type === 'email') {
      const hibpKey = process.env.HIBP_API_KEY;
      if (!hibpKey) {
        return sendApiKeyMissing(res, 'HIBP_API_KEY');
      }

      const encodedEmail = encodeURIComponent(String(query).trim().toLowerCase());
      const breachUrl = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodedEmail}?truncateResponse=false`;
      const pasteUrl = `https://haveibeenpwned.com/api/v3/pasteaccount/${encodedEmail}`;

      const headers = {
        'hibp-api-key': hibpKey,
        'User-Agent': 'SecurAI-Sentinel'
      };

      const [breachResp, pasteResp] = await Promise.all([
        fetch(breachUrl, { headers }),
        fetch(pasteUrl, { headers })
      ]);

      if (breachResp.status === 429 || pasteResp.status === 429) {
        return sendRateLimit(res, breachResp.status === 429 ? breachResp : pasteResp);
      }

      const breachIsClean = breachResp.status === 404;
      const pasteIsClean = pasteResp.status === 404;

      if (breachResp.ok || breachIsClean) {
        const breaches = breachResp.ok ? await breachResp.json() : [];
        const pasteExposures = pasteResp.ok ? await pasteResp.json() : [];

        return res.json({
          query,
          type,
          breaches,
          pasteExposures,
          status: breaches.length > 0 || pasteExposures.length > 0 ? 'breached' : 'clean'
        });
      }

      const breachError = await breachResp.text();
      return res.status(breachResp.status).json({ error: 'HIBP_ERROR', message: breachError || 'HIBP request failed' });
    }

    if (type === 'domain') {
      const hibpKey = process.env.HIBP_API_KEY;
      if (!hibpKey) {
        return sendApiKeyMissing(res, 'HIBP_API_KEY');
      }

      const domain = String(query).trim().toLowerCase();
      const response = await fetch(
        `https://haveibeenpwned.com/api/v3/breaches?domain=${encodeURIComponent(domain)}`,
        {
          headers: {
            'hibp-api-key': hibpKey,
            'User-Agent': 'SecurAI-Sentinel'
          }
        }
      );

      if (response.status === 429) {
        return sendRateLimit(res, response);
      }

      if (response.status === 404) {
        return res.json({ query: domain, type, breaches: [], pasteExposures: [], status: 'clean' });
      }

      if (!response.ok) {
        const details = await response.text();
        return res.status(response.status).json({ error: 'HIBP_ERROR', message: details || 'Domain breach lookup failed' });
      }

      const breaches = await response.json();
      return res.json({
        query: domain,
        type,
        breaches,
        pasteExposures: [],
        status: breaches.length > 0 ? 'breached' : 'clean'
      });
    }

    if (type === 'ip') {
      const abuseKey = process.env.ABUSEIPDB_API_KEY;
      if (!abuseKey) {
        return sendApiKeyMissing(res, 'ABUSEIPDB_API_KEY');
      }

      const ipAddress = String(query).trim();
      const response = await fetch(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ipAddress)}&maxAgeInDays=90&verbose`,
        {
          headers: {
            Key: abuseKey,
            Accept: 'application/json'
          }
        }
      );

      if (response.status === 429) {
        return sendRateLimit(res, response);
      }

      if (!response.ok) {
        const details = await response.text();
        return res.status(response.status).json({ error: 'ABUSEIPDB_ERROR', message: details || 'IP reputation lookup failed' });
      }

      const data = await response.json();
      return res.json({
        query: ipAddress,
        type,
        breaches: [],
        pasteExposures: [],
        abuseData: data?.data || null,
        status: (data?.data?.abuseConfidenceScore || 0) > 0 ? 'breached' : 'clean'
      });
    }

    if (type === 'username') {
      const username = String(query).trim();
      const prompt = `Based on public OSINT, what are the risks of username '${username}' being exposed? Respond ONLY valid JSON with this schema:\n{\n  \"riskLevel\": \"Critical|High|Medium|Low\",\n  \"commonPlatforms\": [\"string\"],\n  \"recommendations\": [\"string\"]\n}`;

      const simulated = await generateGeminiJson(prompt);
      return res.json({
        query: username,
        type,
        breaches: [
          {
            Name: 'OSINT Username Exposure Model',
            Title: 'Username Risk Profile',
            Domain: 'public-osint',
            BreachDate: new Date().toISOString().slice(0, 10),
            AddedDate: new Date().toISOString(),
            ModifiedDate: new Date().toISOString(),
            PwnCount: 1,
            Description: `Potential username exposure risk: ${simulated.riskLevel || 'Unknown'}`,
            LogoPath: '',
            DataClasses: ['Usernames'],
            IsVerified: true,
            IsFabricated: false,
            IsSensitive: false,
            IsRetired: false,
            IsSpamList: false,
            IsMalware: false,
            osintSimulation: simulated
          }
        ],
        pasteExposures: [],
        status: 'breached'
      });
    }

    return res.status(400).json({ error: 'INVALID_TYPE', message: 'type must be email, domain, ip, or username' });
  } catch (error) {
    console.error('Dark Web Breach Endpoint Error:', error.message);
    return res.status(500).json({ error: 'DARKWEB_BREACH_FAILED', message: error.message || 'Dark web breach lookup failed' });
  }
});

app.post('/darkweb/analyze', async (req, res) => {
  const { query, type, breaches = [], abuseData } = req.body || {};

  if (!query || !type) {
    return res.status(400).json({ error: 'query and type are required' });
  }

  try {
    const prompt = `You are a cybersecurity expert analyzing dark web exposure data.
Target: ${query} (Type: ${type})
Breach Data: ${JSON.stringify(breaches)}
IP Abuse Data: ${JSON.stringify(abuseData || null)}

Respond ONLY with valid JSON (no markdown, no backticks):
{
  "riskScore": number,
  "riskLevel": "Critical" | "High" | "Medium" | "Low" | "Clean",
  "summary": "string",
  "exposedDataTypes": ["string"],
  "oldestBreach": "string",
  "mostRecentBreach": "string",
  "immediateActions": ["string"],
  "longTermRecommendations": ["string"],
  "passwordChangeUrgency": "Immediate" | "Soon" | "Optional" | "N/A"
}`;

    const report = await generateGeminiJson(prompt);
    return res.json(report);
  } catch (error) {
    console.error('Dark Web Analyze Endpoint Error:', error.message);
    return res.json(localDarkWebAnalysis({ query, type, breaches, abuseData }));
  }
});

app.post('/darkweb/demo-data', async (req, res) => {
  const { query, type } = req.body || {};
  if (!query || !type) {
    return res.status(400).json({ message: 'query and type are required' });
  }

  try {
    const prompt = `Generate realistic DEMO dark web exposure data for query '${query}' and type '${type}'. Respond only valid JSON:
{
  "breaches": [{
    "Name": "string",
    "Title": "string",
    "Domain": "string",
    "BreachDate": "YYYY-MM-DD",
    "AddedDate": "ISO string",
    "ModifiedDate": "ISO string",
    "PwnCount": number,
    "Description": "string",
    "LogoPath": "",
    "DataClasses": ["string"],
    "IsVerified": boolean,
    "IsFabricated": boolean,
    "IsSensitive": boolean,
    "IsRetired": boolean,
    "IsSpamList": boolean,
    "IsMalware": boolean
  }],
  "pasteExposures": [{"Source":"string","Id":"string","Title":"string","Date":"YYYY-MM-DD","EmailCount":number}],
  "abuseData": {"abuseConfidenceScore": number, "totalReports": number, "countryCode": "string", "isp": "string", "usageType": "string", "reports": []}
}`;

    const data = await generateGeminiJson(prompt);
    return res.json(data);
  } catch (error) {
    console.error('Darkweb Demo Data Error:', error.message);
    return res.json(localDarkWebDemoData(query, type));
  }
});

app.post('/darkweb/pastes', async (req, res) => {
  const { email } = req.body || {};
  if (!email) {
    return res.status(400).json({ error: 'email is required' });
  }

  const hibpKey = process.env.HIBP_API_KEY;
  if (!hibpKey) {
    return res.json({
      query: domain,
      type: 'domain',
      breaches: [],
      pasteExposures: [],
      status: 'unknown',
      message: 'HIBP_API_KEY is not configured; returning fallback domain exposure status for agent continuity.',
      fallback: true
    });
  }

  try {
    const encodedEmail = encodeURIComponent(String(email).trim().toLowerCase());
    const response = await fetch(`https://haveibeenpwned.com/api/v3/pasteaccount/${encodedEmail}`, {
      headers: {
        'hibp-api-key': hibpKey,
        'User-Agent': 'SecurAI-Sentinel'
      }
    });

    if (response.status === 404) {
      return res.json({ email, pastes: [] });
    }

    if (response.status === 429) {
      return sendRateLimit(res, response);
    }

    if (!response.ok) {
      const details = await response.text();
      return res.status(response.status).json({ error: 'HIBP_ERROR', message: details || 'Paste search failed' });
    }

    const pastes = await response.json();
    return res.json({ email, pastes });
  } catch (error) {
    console.error('Dark Web Paste Endpoint Error:', error.message);
    return res.status(500).json({ error: 'DARKWEB_PASTE_FAILED', message: error.message || 'Paste search failed' });
  }
});

// ========================================
// 📊 SECURITY POSTURE SCORE ENDPOINT
// ========================================

app.post('/posture/analyze', async (req, res) => {
  const { scanHistory } = req.body || {};

  if (!scanHistory) {
    return res.status(400).json({ error: 'scanHistory is required' });
  }

  try {
    const prompt = `You are a senior cybersecurity auditor. Analyze this security scan history from a SecurAI Sentinel deployment and generate a comprehensive posture report.

Scan History: ${JSON.stringify(scanHistory)}

Respond ONLY with valid JSON (no markdown, no backticks):
{
  "overallScore": number,
  "grade": "A+" | "A" | "B" | "C" | "D" | "F",
  "categoryScores": {
    "networkSecurity": number,
    "webSecurity": number,
    "endpointSecurity": number,
    "dataProtection": number,
    "threatIntelligence": number,
    "incidentReadiness": number
  },
  "criticalFindings": ["string"],
  "strengths": ["string"],
  "improvementAreas": ["string"],
  "complianceHints": {
    "cisLevel1": "Pass" | "Partial" | "Fail",
    "cisLevel2": "Pass" | "Partial" | "Fail",
    "gdprReadiness": "Pass" | "Partial" | "Fail",
    "iso27001Hints": "string"
  },
  "nextScanRecommendations": ["string"],
  "trendDirection": "Improving" | "Stable" | "Declining" | "New"
}`;

    const report = await generateGeminiJson(prompt);
    return res.json(report);
  } catch (error) {
    console.error('Posture Analyze Endpoint Error:', error.message);
    return res.json(localPostureReport(scanHistory));
  }
});

// ========================================
// 🤖 AI RED TEAM AGENT ENDPOINTS
// ========================================

app.post('/agent/plan', async (req, res) => {
  const { target, agentMode, objectives = [] } = req.body || {};
  if (!target || !agentMode) {
    return res.status(400).json({ error: 'target and agentMode are required' });
  }

  if (!['passive', 'active', 'full'].includes(String(agentMode))) {
    return res.status(400).json({ error: 'agentMode must be passive, active, or full' });
  }

  try {
    const prompt = `You are an AI security agent planner. Given a target and objectives,
create an ordered investigation plan.

Target: ${target}
Mode: ${agentMode}
Objectives: ${JSON.stringify(Array.isArray(objectives) ? objectives : [])}

Available tools:
- port_scan: Check open ports on an IP/hostname
- ssl_check: Validate SSL certificate for a domain
- headers_check: Check HTTP security headers
- dns_check: Check DNS integrity
- subdomain_enum: Enumerate subdomains via crt.sh
- cve_search: Search NVD for relevant CVEs
- darkweb_domain: Check domain in breach databases
- attack_classify: Map findings to MITRE ATT&CK
- ip_reputation: Check IP abuse reputation
- ir_generate: Generate incident response playbook

Passive mode: no active scanning (ssl, headers, dns, subdomain, cve, darkweb only)
Active mode: includes port scanning and IP reputation
Full mode: all tools including attack classification and IR generation

Respond ONLY with valid JSON (no markdown):
{
  "planTitle": "string",
  "estimatedDuration": "string",
  "steps": [
    {
      "stepNumber": 1,
      "toolName": "string",
      "toolInput": {},
      "rationale": "string",
      "dependsOnStep": null,
      "expectedOutput": "string"
    }
  ],
  "agentObjective": "string",
  "riskLevel": "string"
}`;

    const rawPlan = await generateGeminiJson(prompt);
    const rawSteps = Array.isArray(rawPlan?.steps) ? rawPlan.steps : [];
    const normalizedSteps = rawSteps.map((step, index) => ({
      stepNumber: Number(step?.stepNumber || index + 1),
      toolName: String(step?.toolName || 'headers_check'),
      toolInput: typeof step?.toolInput === 'object' && step?.toolInput ? step.toolInput : {},
      rationale: String(step?.rationale || 'Automated investigation step'),
      dependsOnStep: step?.dependsOnStep == null ? null : Number(step.dependsOnStep),
      expectedOutput: String(step?.expectedOutput || 'Findings summary')
    }));

    return res.json({
      planTitle: String(rawPlan?.planTitle || `Investigation plan for ${target}`),
      estimatedDuration: String(rawPlan?.estimatedDuration || `${Math.max(20, normalizedSteps.length * 5)} seconds`),
      steps: normalizedSteps,
      agentObjective: String(rawPlan?.agentObjective || 'Assess attack surface risk'),
      riskLevel: String(rawPlan?.riskLevel || 'Medium')
    });
  } catch (error) {
    console.error('Agent Plan Endpoint Error:', error.message);
    return res.json(localAgentPlan(target, agentMode, objectives));
  }
});

app.post('/agent/interpret', async (req, res) => {
  const { stepNumber, toolName, toolInput = {}, toolOutput = {}, previousFindings = '' } = req.body || {};
  if (stepNumber == null || !toolName) {
    return res.status(400).json({ error: 'stepNumber and toolName are required' });
  }

  try {
    const prompt = `You are an AI security agent. You just executed a security tool.
Interpret the results and decide what this means for the investigation.

Step: ${stepNumber}
Tool Used: ${toolName}
Input: ${JSON.stringify(toolInput)}
Output: ${JSON.stringify(toolOutput)}
Previous Findings: ${previousFindings}

Respond ONLY with valid JSON (no markdown):
{
  "interpretation": "string",
  "keyFindings": ["string"],
  "riskIndicators": ["string"],
  "shouldEscalate": false,
  "escalationReason": null,
  "suggestedNextTools": ["string"],
  "confidenceLevel": 0.0,
  "agentThought": "string"
}`;

    const interpreted = await generateGeminiJson(prompt);
    return res.json({
      interpretation: String(interpreted?.interpretation || 'No interpretation generated'),
      keyFindings: Array.isArray(interpreted?.keyFindings) ? interpreted.keyFindings.map(String) : [],
      riskIndicators: Array.isArray(interpreted?.riskIndicators) ? interpreted.riskIndicators.map(String) : [],
      shouldEscalate: Boolean(interpreted?.shouldEscalate),
      escalationReason: interpreted?.escalationReason == null ? null : String(interpreted.escalationReason),
      suggestedNextTools: Array.isArray(interpreted?.suggestedNextTools) ? interpreted.suggestedNextTools.map(String) : [],
      confidenceLevel: Number.isFinite(Number(interpreted?.confidenceLevel))
        ? Math.max(0, Math.min(1, Number(interpreted.confidenceLevel)))
        : 0.5,
      agentThought: String(interpreted?.agentThought || 'Continue with next planned action.')
    });
  } catch (error) {
    console.error('Agent Interpret Endpoint Error:', error.message);
    return res.json(localAgentInterpretation(stepNumber, toolName, toolOutput));
  }
});

app.post('/agent/synthesize', async (req, res) => {
  const { target, allSteps = [], allInterpretations = [], agentMode } = req.body || {};
  if (!target || !agentMode) {
    return res.status(400).json({ error: 'target and agentMode are required' });
  }

  try {
    const prompt = `You are a senior penetration tester writing a final assessment report.
You have completed an automated security investigation.

Target: ${target}
Mode: ${agentMode}
All Steps and Results: ${JSON.stringify(allSteps)}
All Interpretations: ${JSON.stringify(allInterpretations)}

Respond ONLY with valid JSON (no markdown):
{
  "reportTitle": "string",
  "executiveSummary": "string",
  "overallRiskRating": "Critical" | "High" | "Medium" | "Low" | "Informational",
  "attackSurface": {
    "exposedServices": ["string"],
    "weakPoints": ["string"],
    "strongPoints": ["string"]
  },
  "criticalFindings": [
    {
      "finding": "string",
      "evidence": "string",
      "impact": "string",
      "recommendation": "string",
      "priority": 1
    }
  ],
  "mitreTacticsDetected": ["string"],
  "immediateActions": ["string"],
  "shortTermActions": ["string"],
  "longTermActions": ["string"],
  "riskScore": 0,
  "complianceNotes": "string",
  "conclusionStatement": "string"
}`;

    const report = await generateGeminiJson(prompt);
    const riskRating = ['Critical', 'High', 'Medium', 'Low', 'Informational'].includes(String(report?.overallRiskRating))
      ? report.overallRiskRating
      : 'Medium';
    return res.json({
      reportTitle: String(report?.reportTitle || `Assessment report for ${target}`),
      executiveSummary: String(report?.executiveSummary || 'Automated red-team mission completed.'),
      overallRiskRating: riskRating,
      attackSurface: {
        exposedServices: Array.isArray(report?.attackSurface?.exposedServices) ? report.attackSurface.exposedServices.map(String) : [],
        weakPoints: Array.isArray(report?.attackSurface?.weakPoints) ? report.attackSurface.weakPoints.map(String) : [],
        strongPoints: Array.isArray(report?.attackSurface?.strongPoints) ? report.attackSurface.strongPoints.map(String) : []
      },
      criticalFindings: Array.isArray(report?.criticalFindings)
        ? report.criticalFindings.map((finding, index) => ({
            finding: String(finding?.finding || `Finding ${index + 1}`),
            evidence: String(finding?.evidence || ''),
            impact: String(finding?.impact || ''),
            recommendation: String(finding?.recommendation || ''),
            priority: Number(finding?.priority || index + 1)
          }))
        : [],
      mitreTacticsDetected: Array.isArray(report?.mitreTacticsDetected) ? report.mitreTacticsDetected.map(String) : [],
      immediateActions: Array.isArray(report?.immediateActions) ? report.immediateActions.map(String) : [],
      shortTermActions: Array.isArray(report?.shortTermActions) ? report.shortTermActions.map(String) : [],
      longTermActions: Array.isArray(report?.longTermActions) ? report.longTermActions.map(String) : [],
      riskScore: Number.isFinite(Number(report?.riskScore)) ? Math.max(0, Math.min(100, Number(report.riskScore))) : 50,
      complianceNotes: String(report?.complianceNotes || 'No compliance notes generated.'),
      conclusionStatement: String(report?.conclusionStatement || 'Assessment completed.')
    });
  } catch (error) {
    console.error('Agent Synthesize Endpoint Error:', error.message);
    return res.json(localAgentReport(target, agentMode, allSteps, allInterpretations));
  }
});

// ========================================
// 🧱 ZERO TRUST POLICY BUILDER ENDPOINTS
// ========================================

app.post('/zerotrust/generate', async (req, res) => {
  const {
    scanResults = {},
    targetEnvironment,
    openPorts = [],
    dangerousPorts = [],
    missingHeaders = [],
    detectedThreats = [],
    domain = null,
    internalIPs = []
  } = req.body || {};

  if (!targetEnvironment) {
    return res.status(400).json({ error: 'targetEnvironment is required' });
  }

  try {
    const prompt = `You are a senior security engineer specializing in Zero Trust architecture.
Generate production-ready security configurations based on scan results.

Target Environment: ${targetEnvironment}
Scan Results: ${JSON.stringify(scanResults)}
Open Ports: ${JSON.stringify(openPorts)}
Dangerous Ports: ${JSON.stringify(dangerousPorts)}
Missing Headers: ${JSON.stringify(missingHeaders)}
Detected Threats: ${JSON.stringify(detectedThreats)}
Domain: ${domain}
Internal IPs: ${JSON.stringify(internalIPs)}

Respond ONLY with valid JSON (no markdown, no backticks):
{
  "policyTitle": "string",
  "riskReduction": "string",
  "configs": [
    {
      "configType": "string",
      "fileName": "string",
      "language": "string",
      "description": "string",
      "content": "string",
      "warningNote": null,
      "testCommand": null
    }
  ],
  "securityRules": [
    {
      "ruleId": "string",
      "ruleName": "string",
      "action": "ALLOW" | "DENY" | "LOG" | "RATE_LIMIT",
      "source": "string",
      "destination": "string",
      "protocol": "string",
      "port": "string",
      "rationale": "string"
    }
  ],
  "immediateWins": ["string"],
  "estimatedRiskReduction": 0,
  "implementationOrder": ["string"]
}`;

    const generated = await generateGeminiJson(prompt);
    return res.json({
      policyTitle: String(generated?.policyTitle || 'Zero Trust Policy Package'),
      riskReduction: String(generated?.riskReduction || 'Policy package generated for staged deployment.'),
      configs: Array.isArray(generated?.configs)
        ? generated.configs.map((cfg, idx) => ({
            configType: String(cfg?.configType || 'generic'),
            fileName: String(cfg?.fileName || `policy-${idx + 1}.conf`),
            language: String(cfg?.language || 'text'),
            description: String(cfg?.description || 'Generated security configuration.'),
            content: String(cfg?.content || ''),
            warningNote: cfg?.warningNote == null ? null : String(cfg.warningNote),
            testCommand: cfg?.testCommand == null ? null : String(cfg.testCommand)
          }))
        : [],
      securityRules: Array.isArray(generated?.securityRules)
        ? generated.securityRules.map((rule, idx) => ({
            ruleId: String(rule?.ruleId || `RULE-${idx + 1}`),
            ruleName: String(rule?.ruleName || 'Generated Rule'),
            action: ['ALLOW', 'DENY', 'LOG', 'RATE_LIMIT'].includes(String(rule?.action)) ? rule.action : 'DENY',
            source: String(rule?.source || 'any'),
            destination: String(rule?.destination || 'protected-zone'),
            protocol: String(rule?.protocol || 'tcp'),
            port: String(rule?.port || 'any'),
            rationale: String(rule?.rationale || 'Risk reduction control')
          }))
        : [],
      immediateWins: Array.isArray(generated?.immediateWins) ? generated.immediateWins.map(String) : [],
      estimatedRiskReduction: Number.isFinite(Number(generated?.estimatedRiskReduction))
        ? Math.max(0, Math.min(100, Number(generated.estimatedRiskReduction)))
        : 35,
      implementationOrder: Array.isArray(generated?.implementationOrder) ? generated.implementationOrder.map(String) : []
    });
  } catch (error) {
    console.error('Zero Trust Generate Endpoint Error:', error.message);
    return res.json(localZeroTrustPolicy({
      targetEnvironment,
      openPorts,
      dangerousPorts,
      missingHeaders,
      detectedThreats
    }));
  }
});

app.post('/zerotrust/validate', (req, res) => {
  const { configType = '', content = '' } = req.body || {};
  const type = String(configType || '').toLowerCase();
  const source = String(content || '');
  const errors = [];
  const warnings = [];

  if (!source.trim()) {
    return res.status(400).json({ valid: false, errors: ['Configuration content is required'], warnings: [] });
  }

  if (type.includes('iptables')) {
    const lines = source.split('\n').map((line) => line.trim()).filter((line) => line.length > 0 && !line.startsWith('#'));
    const invalid = lines.filter(
      (line) =>
        !line.startsWith('iptables') &&
        !/^-(A|I|P|N|F|X|t)\b/.test(line) &&
        !/^for\s+\w+\s+in\b/.test(line) &&
        !/^do$/.test(line) &&
        !/^done$/.test(line)
    );
    if (invalid.length > 0) {
      errors.push(`Invalid iptables syntax near: ${invalid.slice(0, 3).join(' | ')}`);
    }
  } else if (type.includes('nginx')) {
    const openBraces = (source.match(/\{/g) || []).length;
    const closeBraces = (source.match(/\}/g) || []).length;
    if (openBraces !== closeBraces) {
      errors.push('Unbalanced braces in nginx configuration');
    }
    if (!/(add_header|server|location|limit_req_zone)/.test(source)) {
      warnings.push('No common nginx security directives detected');
    }
  } else if (type.includes('csp')) {
    const normalized = source.replace(/^content-security-policy:\s*/i, '').trim();
    if (!normalized.includes(';')) {
      errors.push('CSP header should include semicolon-separated directives');
    }
    if (!/default-src/.test(normalized)) {
      warnings.push('CSP missing default-src directive');
    }
  }

  if (source.length > 15000) {
    warnings.push('Configuration is large; review manually before deployment');
  }

  return res.json({
    valid: errors.length === 0,
    errors,
    warnings
  });
});

// Fallback endpoint for red-team tool orchestration.
app.post('/vuln/analyze', async (req, res) => {
  const { target, context = '' } = req.body || {};
  if (!target) {
    return res.status(400).json({ error: 'target is required' });
  }

  try {
    const prompt = `You are a vulnerability analyst.
Target: ${target}
Context: ${context}
Return ONLY JSON:
{
  "summary": "string",
  "findings": ["string"],
  "recommendations": ["string"],
  "severity": "Critical|High|Medium|Low",
  "confidence": 0.0
}`;
    const analyzed = await generateGeminiJson(prompt);
    return res.json({
      summary: String(analyzed?.summary || `Vulnerability profile generated for ${target}`),
      findings: Array.isArray(analyzed?.findings) ? analyzed.findings.map(String) : [],
      recommendations: Array.isArray(analyzed?.recommendations) ? analyzed.recommendations.map(String) : [],
      severity: ['Critical', 'High', 'Medium', 'Low'].includes(String(analyzed?.severity)) ? analyzed.severity : 'Medium',
      confidence: Number.isFinite(Number(analyzed?.confidence)) ? Math.max(0, Math.min(1, Number(analyzed.confidence))) : 0.5
    });
  } catch (error) {
    console.error('Vuln Analyze Endpoint Error:', error.message);
    return res.json(localVulnerabilityAnalysis(target, context));
  }
});

// Domain wrapper endpoint for agent orchestration.
app.post('/darkweb/domain', async (req, res) => {
  const domain = String(req.body?.domain || req.body?.query || '').trim().toLowerCase();
  if (!domain) {
    return res.status(400).json({ error: 'domain is required' });
  }

  const hibpKey = process.env.HIBP_API_KEY;
  if (!hibpKey) {
    return res.json({
      query: domain,
      type: 'domain',
      breaches: [],
      pasteExposures: [],
      status: 'unknown',
      message: 'HIBP_API_KEY is not configured; returning fallback domain exposure status for agent continuity.',
      fallback: true
    });
  }

  try {
    const response = await fetch(
      `https://haveibeenpwned.com/api/v3/breaches?domain=${encodeURIComponent(domain)}`,
      {
        headers: {
          'hibp-api-key': hibpKey,
          'User-Agent': 'SecurAI-Sentinel'
        }
      }
    );

    if (response.status === 429) {
      return sendRateLimit(res, response);
    }
    if (response.status === 404) {
      return res.json({ query: domain, type: 'domain', breaches: [], pasteExposures: [], status: 'clean' });
    }
    if (!response.ok) {
      const details = await response.text();
      return res.status(response.status).json({ error: 'HIBP_ERROR', message: details || 'Domain breach lookup failed' });
    }

    const breaches = await response.json();
    return res.json({
      query: domain,
      type: 'domain',
      breaches,
      pasteExposures: [],
      status: breaches.length > 0 ? 'breached' : 'clean'
    });
  } catch (error) {
    console.error('Darkweb Domain Endpoint Error:', error.message);
    return res.json({
      query: domain,
      type: 'domain',
      breaches: [],
      pasteExposures: [],
      status: 'unknown',
      message: error.message || 'Domain breach lookup failed; returning fallback status.',
      fallback: true
    });
  }
});

// IP reputation endpoint wrapper for red-team orchestration.
app.post('/pcap/ip-reputation', async (req, res) => {
  const ip = String(req.body?.ip || '').trim();
  if (!ip) {
    return res.status(400).json({ error: 'ip is required' });
  }

  const abuseKey = process.env.ABUSEIPDB_API_KEY;
  if (!abuseKey) {
    return res.json({
      ip,
      abuseConfidenceScore: 0,
      totalReports: 0,
      status: 'unknown',
      message: 'ABUSEIPDB_API_KEY is not configured; returning simulated clean score.'
    });
  }

  try {
    const response = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`,
      {
        headers: {
          Key: abuseKey,
          Accept: 'application/json'
        }
      }
    );

    if (response.status === 429) {
      return sendRateLimit(res, response);
    }
    if (!response.ok) {
      const details = await response.text();
      return res.status(response.status).json({ error: 'ABUSEIPDB_ERROR', message: details || 'IP reputation lookup failed' });
    }

    const data = await response.json();
    const abuse = data?.data || {};
    return res.json({
      ip,
      abuseConfidenceScore: Number(abuse?.abuseConfidenceScore || 0),
      totalReports: Number(abuse?.totalReports || 0),
      countryCode: abuse?.countryCode || null,
      isp: abuse?.isp || null,
      usageType: abuse?.usageType || null,
      reports: Array.isArray(abuse?.reports) ? abuse.reports : [],
      status: Number(abuse?.abuseConfidenceScore || 0) > 25 ? 'suspicious' : 'clean'
    });
  } catch (error) {
    console.error('IP Reputation Endpoint Error:', error.message);
    return res.status(500).json({ error: 'IP_REPUTATION_FAILED', message: error.message || 'IP reputation lookup failed' });
  }
});

// ========================================
// 🎯 MITRE ATT&CK MAPPER ENDPOINTS
// ========================================

const ATTACK_TECHNIQUES = {
  T1190: {
    name: 'Exploit Public-Facing Application',
    tactic: 'Initial Access',
    description: 'Adversaries may attempt to take advantage of a weakness in an Internet-facing host or system.',
    platforms: ['Linux', 'Windows', 'macOS'],
    dataSource: 'Network Traffic, Application Log',
    mitreUrl: 'https://attack.mitre.org/techniques/T1190/'
  },
  T1059: {
    name: 'Command and Scripting Interpreter',
    tactic: 'Execution',
    description: 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.',
    platforms: ['Linux', 'Windows', 'macOS'],
    dataSource: 'Process, Command Execution',
    mitreUrl: 'https://attack.mitre.org/techniques/T1059/'
  },
  T1078: {
    name: 'Valid Accounts',
    tactic: 'Defense Evasion / Persistence',
    description: 'Adversaries may obtain and abuse credentials of existing accounts.',
    platforms: ['Linux', 'Windows', 'SaaS'],
    dataSource: 'Authentication Logs',
    mitreUrl: 'https://attack.mitre.org/techniques/T1078/'
  },
  T1110: {
    name: 'Brute Force',
    tactic: 'Credential Access',
    description: 'Adversaries may use brute force techniques to gain access to accounts.',
    platforms: ['Linux', 'Windows', 'Cloud'],
    dataSource: 'Authentication Logs, Network Traffic',
    mitreUrl: 'https://attack.mitre.org/techniques/T1110/'
  },
  T1046: {
    name: 'Network Service Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may attempt to get a listing of services running on remote hosts.',
    platforms: ['Linux', 'Windows', 'macOS'],
    dataSource: 'Network Traffic',
    mitreUrl: 'https://attack.mitre.org/techniques/T1046/'
  },
  T1566: {
    name: 'Phishing',
    tactic: 'Initial Access',
    description: 'Adversaries may send phishing messages to gain access to victim systems.',
    platforms: ['SaaS', 'Office 365'],
    dataSource: 'Email Logs',
    mitreUrl: 'https://attack.mitre.org/techniques/T1566/'
  },
  T1055: {
    name: 'Process Injection',
    tactic: 'Defense Evasion',
    description: 'Adversaries may inject code into processes to evade process-based defenses.',
    platforms: ['Windows', 'Linux'],
    dataSource: 'Process, Memory',
    mitreUrl: 'https://attack.mitre.org/techniques/T1055/'
  },
  T1486: {
    name: 'Data Encrypted for Impact',
    tactic: 'Impact',
    description: 'Adversaries may encrypt data on target systems to interrupt availability.',
    platforms: ['Linux', 'Windows', 'macOS'],
    dataSource: 'File Access, Process Execution',
    mitreUrl: 'https://attack.mitre.org/techniques/T1486/'
  },
  T1083: {
    name: 'File and Directory Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may enumerate files and directories.',
    platforms: ['Linux', 'Windows', 'macOS'],
    dataSource: 'Process, File Monitoring',
    mitreUrl: 'https://attack.mitre.org/techniques/T1083/'
  },
  T1071: {
    name: 'Application Layer Protocol',
    tactic: 'Command and Control',
    description: 'Adversaries may communicate using application layer protocols to avoid detection.',
    platforms: ['Linux', 'Windows', 'macOS'],
    dataSource: 'Network Traffic',
    mitreUrl: 'https://attack.mitre.org/techniques/T1071/'
  },
  T1021: {
    name: 'Remote Services',
    tactic: 'Lateral Movement',
    description: 'Adversaries may use valid accounts to log into a service designed to accept remote connections.',
    platforms: ['Linux', 'Windows'],
    dataSource: 'Authentication Logs, Network Traffic',
    mitreUrl: 'https://attack.mitre.org/techniques/T1021/'
  },
  T1003: {
    name: 'OS Credential Dumping',
    tactic: 'Credential Access',
    description: 'Adversaries may attempt to dump credentials to obtain account login and credential material.',
    platforms: ['Linux', 'Windows'],
    dataSource: 'Process, Memory',
    mitreUrl: 'https://attack.mitre.org/techniques/T1003/'
  },
  T1218: {
    name: 'Signed Binary Proxy Execution',
    tactic: 'Defense Evasion',
    description: 'Adversaries may abuse trusted signed binaries to proxy execution of malicious payloads.',
    platforms: ['Windows'],
    dataSource: 'Process, Command Execution',
    mitreUrl: 'https://attack.mitre.org/techniques/T1218/'
  },
  T1547: {
    name: 'Boot or Logon Autostart Execution',
    tactic: 'Persistence',
    description: 'Adversaries may configure system settings to automatically execute a program during system boot or logon.',
    platforms: ['Linux', 'Windows', 'macOS'],
    dataSource: 'Registry, Autoruns',
    mitreUrl: 'https://attack.mitre.org/techniques/T1547/'
  },
  T1105: {
    name: 'Ingress Tool Transfer',
    tactic: 'Command and Control',
    description: 'Adversaries may transfer tools or other files from an external system into a compromised environment.',
    platforms: ['Linux', 'Windows', 'macOS'],
    dataSource: 'Network Traffic, File Monitoring',
    mitreUrl: 'https://attack.mitre.org/techniques/T1105/'
  },
  T1499: {
    name: 'Endpoint Denial of Service',
    tactic: 'Impact',
    description: 'Adversaries may perform endpoint denial of service to degrade or block services.',
    platforms: ['Linux', 'Windows'],
    dataSource: 'System Metrics, Process Monitoring',
    mitreUrl: 'https://attack.mitre.org/techniques/T1499/'
  },
  T1041: {
    name: 'Exfiltration Over C2 Channel',
    tactic: 'Exfiltration',
    description: 'Adversaries may steal data by exfiltrating it over an existing command and control channel.',
    platforms: ['Linux', 'Windows', 'macOS'],
    dataSource: 'Network Traffic',
    mitreUrl: 'https://attack.mitre.org/techniques/T1041/'
  },
  T1018: {
    name: 'Remote System Discovery',
    tactic: 'Discovery',
    description: 'Adversaries may attempt to discover remote systems and resources in a target network.',
    platforms: ['Linux', 'Windows', 'macOS'],
    dataSource: 'Network Traffic',
    mitreUrl: 'https://attack.mitre.org/techniques/T1018/'
  },
  T1090: {
    name: 'Proxy',
    tactic: 'Command and Control',
    description: 'Adversaries may use a connection proxy to direct network traffic between systems.',
    platforms: ['Linux', 'Windows', 'macOS'],
    dataSource: 'Network Traffic, Proxy Logs',
    mitreUrl: 'https://attack.mitre.org/techniques/T1090/'
  },
  T1552: {
    name: 'Unsecured Credentials',
    tactic: 'Credential Access',
    description: 'Adversaries may search compromised systems for credentials that are stored insecurely.',
    platforms: ['Linux', 'Windows', 'macOS'],
    dataSource: 'File Access, Process Monitoring',
    mitreUrl: 'https://attack.mitre.org/techniques/T1552/'
  }
};

const ATTACK_CLASSIFICATION_FALLBACK = {
  tactics: [],
  killChainStage: 'Unknown',
  attackSummary: 'No ATT&CK mapping could be generated from the provided findings.',
  threatActorProfile: 'Unknown',
  overallSeverity: 'Low'
};

app.post('/attack/classify', async (req, res) => {
  const { sourceModule, rawFindings, detectedIndicators = [] } = req.body || {};

  if (!sourceModule || !rawFindings) {
    return res.status(400).json({ error: 'sourceModule and rawFindings are required' });
  }

  try {
    const prompt = `You are a MITRE ATT&CK framework expert. Analyze the following security findings and map them to ATT&CK tactics and techniques.

Source Module: ${sourceModule}
Findings: ${rawFindings}
Indicators: ${JSON.stringify(detectedIndicators)}

Respond ONLY with valid JSON (no markdown, no backticks):
{
  "tactics": [
    {
      "tacticId": "string",
      "tacticName": "string",
      "tacticPhase": 1,
      "confidence": 0,
      "techniques": [
        {
          "techniqueId": "string",
          "techniqueName": "string",
          "subTechniqueId": null,
          "subTechniqueName": null,
          "confidence": 0,
          "evidence": "string",
          "severity": "Critical" | "High" | "Medium" | "Low",
          "mitigation": "string",
          "detectionTip": "string"
        }
      ]
    }
  ],
  "killChainStage": "string",
  "attackSummary": "string",
  "threatActorProfile": "string",
  "overallSeverity": "Critical" | "High" | "Medium" | "Low"
}`;

    const result = await generateGeminiJson(prompt);
    res.json(result);
  } catch (error) {
    console.error('ATT&CK Classification Error:', error.message);
    res.json(ATTACK_CLASSIFICATION_FALLBACK);
  }
});

app.post('/attack/technique', (req, res) => {
  const { techniqueId } = req.body || {};
  if (!techniqueId) {
    return res.status(400).json({ error: 'techniqueId is required' });
  }

  const normalized = String(techniqueId).toUpperCase().trim();
  const detail = ATTACK_TECHNIQUES[normalized] || {
    name: normalized,
    tactic: 'Unknown',
    description: 'Technique detail not available in local dataset.',
    platforms: ['Unknown'],
    dataSource: 'Unknown',
    mitreUrl: `https://attack.mitre.org/techniques/${normalized}/`
  };

  res.json({
    techniqueId: normalized,
    ...detail
  });
});

// Start server
server.listen(PORT, '0.0.0.0', () => {
  console.log('\n🚀 SecurAI Companion Server Started');
  console.log(`📡 API Server: http://localhost:${PORT}`);
  console.log(`🔌 WebSocket: ws://localhost:${PORT}`);
  console.log(`👻 Ghost Ports: ${GHOST_PORTS.join(', ')}`);
  console.log('\n✅ Ready for Network Watchtower requests\n');
  
  // Setup ghost port listeners
  setupGhostPorts();
  
  // Start ARP Spoofing Guard
  startARPMonitoring();
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down server...');
  server.close(() => {
    console.log('✅ Server closed');
    process.exit(0);
  });
});
