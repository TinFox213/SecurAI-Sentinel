import React, { useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Shield, 
  Search, 
  Lock, 
  Globe, 
  AlertTriangle, 
  CheckCircle, 
  XCircle,
  Loader2,
  ShieldCheck,
  ShieldAlert,
  Trophy,
  Sparkles,
  Info
} from 'lucide-react';
import { logForensicsEvent } from '../../utils/forensicsLogger';
import { saveSetting } from '../../services/db';
import { ScanType } from '../../types/types';
import { toast } from 'react-hot-toast';

interface WebSecOpsProps {
  onNavigate?: (type: ScanType) => void;
}

interface SSLInfo {
  domain: string;
  valid: boolean;
  daysRemaining: number;
  validFrom: string;
  validTo: string;
  issuer: string;
}

interface HeadersInfo {
  url: string;
  status: number;
  headers: Record<string, string>;
}

interface DNSInfo {
  domain: string;
  systemDNS: string[];
  googleDNS: string[];
  match: boolean;
  status: string;
}

interface SubdomainsInfo {
  domain: string;
  count: number;
  subdomains: string[];
  source: string;
}

interface SecurityGrade {
  score: number;
  grade: string;
  color: string;
  glowColor: string;
  missing: string[];
}

export default function WebSecOps({ onNavigate }: WebSecOpsProps) {
  // Module A: Recon-X (Subdomain Scanner)
  const [reconDomain, setReconDomain] = useState('');
  const [reconLoading, setReconLoading] = useState(false);
  const [subdomains, setSubdomains] = useState<SubdomainsInfo | null>(null);
  const [reconError, setReconError] = useState<string | null>(null);

  // Module B: SSL Sentinel
  const [sslDomain, setSslDomain] = useState('');
  const [sslLoading, setSslLoading] = useState(false);
  const [sslInfo, setSslInfo] = useState<SSLInfo | null>(null);
  const [sslError, setSslError] = useState<string | null>(null);

  const loadReconSample = () => {
    setReconDomain('tesla.com');
  };

  const loadSSLSample = () => {
    setSslDomain('expired.badssl.com');
  };

  const loadHeaderSample = () => {
    setHeaderUrl('https://example.com');
  };

  const loadDNSSample = () => {
    setDnsDomain('netflix.com');
  };

  // Module C: Security Header Grader
  const [headerUrl, setHeaderUrl] = useState('');
  const [headerLoading, setHeaderLoading] = useState(false);
  const [headersInfo, setHeadersInfo] = useState<HeadersInfo | null>(null);
  const [headerGrade, setHeaderGrade] = useState<SecurityGrade | null>(null);
  const [headerError, setHeaderError] = useState<string | null>(null);

  // Module D: DNS Integrity
  const [dnsDomain, setDnsDomain] = useState('');
  const [dnsLoading, setDnsLoading] = useState(false);
  const [dnsInfo, setDnsInfo] = useState<DNSInfo | null>(null);
  const [dnsError, setDnsError] = useState<string | null>(null);

  const extractDomain = (value: string) => {
    const clean = value.trim();
    if (!clean) return '';
    const noProtocol = clean.replace(/^https?:\/\//i, '');
    return noProtocol.split('/')[0];
  };

  const latestTarget = useMemo(() => {
    return (
      sslInfo?.domain ||
      dnsInfo?.domain ||
      subdomains?.domain ||
      extractDomain(headerUrl) ||
      extractDomain(sslDomain) ||
      extractDomain(dnsDomain) ||
      extractDomain(reconDomain)
    );
  }, [sslInfo, dnsInfo, subdomains, headerUrl, sslDomain, dnsDomain, reconDomain]);

  const latestMissingHeaders = useMemo(() => {
    const map: Record<string, string> = {
      HSTS: 'Strict-Transport-Security (HSTS)',
      CSP: 'Content-Security-Policy'
    };
    return (headerGrade?.missing || []).map((item) => map[item] || item);
  }, [headerGrade]);

  // ========================================
  // Module A: Recon-X Functions
  // ========================================
  const runReconScan = async () => {
    if (!reconDomain.trim()) return;

    setReconLoading(true);
    setReconError(null);
    setSubdomains(null);

    try {
      const response = await fetch('http://localhost:3001/osint/subdomains', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: reconDomain.trim() })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.details || 'Subdomain enumeration failed');
      }

      setSubdomains(data);
    } catch (error: any) {
      console.error('Recon Error:', error);
      setReconError(error.message || 'Failed to enumerate subdomains');
    } finally {
      setReconLoading(false);
    }
  };

  // ========================================
  // Module B: SSL Sentinel Functions
  // ========================================
  const runSSLCheck = async () => {
    if (!sslDomain.trim()) return;

    setSslLoading(true);
    setSslError(null);
    setSslInfo(null);

    try {
      const response = await fetch('http://localhost:3001/web/ssl', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: sslDomain.trim() })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.details || 'SSL check failed');
      }

      setSslInfo(data);

      try {
        if (!data.valid || (typeof data.daysRemaining === 'number' && data.daysRemaining <= 7)) {
          await logForensicsEvent({
            timestamp: Date.now(),
            eventType: 'ssl_expired',
            sourceModule: 'WebSec Ops',
            severity: !data.valid || data.daysRemaining <= 0 ? 'High' : 'Medium',
            title: `SSL issue detected for ${data.domain}`,
            description: !data.valid ? 'Certificate is invalid or expired.' : `Certificate expires in ${data.daysRemaining} days.`,
            details: data,
            attackPhase: 'Initial Access',
            ioc: [data.domain],
            tags: ['ssl', 'websec']
          });
        }
      } catch (forensicsErr) {
        console.error('Forensics event logging skipped:', forensicsErr);
      }
    } catch (error: any) {
      console.error('SSL Error:', error);
      setSslError(error.message || 'Failed to check SSL certificate');
    } finally {
      setSslLoading(false);
    }
  };

  // ========================================
  // Module C: Security Header Grader Functions
  // ========================================
  const calculateHeaderGrade = (headers: Record<string, string>): SecurityGrade => {
    let score = 100;
    const missing: string[] = [];

    const criticalHeaders = {
      'strict-transport-security': 'HSTS',
      'content-security-policy': 'CSP',
      'x-frame-options': 'X-Frame-Options',
      'x-content-type-options': 'X-Content-Type-Options'
    };

    Object.entries(criticalHeaders).forEach(([key, name]) => {
      if (!headers[key]) {
        score -= 20;
        missing.push(name);
      }
    });

    // Bonus deduction for completely missing security headers
    if (missing.length === 4) {
      score -= 10;
    }

    let grade = 'F';
    let color = 'text-red-500';
    let glowColor = 'red';

    if (score >= 90) {
      grade = 'A';
      color = 'text-green-500';
      glowColor = 'green';
    } else if (score >= 80) {
      grade = 'B';
      color = 'text-blue-500';
      glowColor = 'blue';
    } else if (score >= 70) {
      grade = 'C';
      color = 'text-yellow-500';
      glowColor = 'yellow';
    } else if (score >= 60) {
      grade = 'D';
      color = 'text-orange-500';
      glowColor = 'orange';
    }

    return { score: Math.max(0, score), grade, color, glowColor, missing };
  };

  const runHeaderCheck = async () => {
    if (!headerUrl.trim()) return;

    setHeaderLoading(true);
    setHeaderError(null);
    setHeadersInfo(null);
    setHeaderGrade(null);

    try {
      const response = await fetch('http://localhost:3001/web/headers', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: headerUrl.trim() })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.details || 'Headers fetch failed');
      }

      setHeadersInfo(data);
      const grade = calculateHeaderGrade(data.headers);
      setHeaderGrade(grade);
      try {
        await saveSetting('websec_latest_result', {
          domain: extractDomain(headerUrl),
          missingHeaders: grade.missing,
          score: grade.score,
          grade: grade.grade,
          checkedAt: Date.now()
        });
      } catch (settingError) {
        console.error('Failed to persist WebSec header snapshot:', settingError);
      }
    } catch (error: any) {
      console.error('Headers Error:', error);
      setHeaderError(error.message || 'Failed to fetch security headers');
    } finally {
      setHeaderLoading(false);
    }
  };

  // ========================================
  // Module D: DNS Integrity Functions
  // ========================================
  const runDNSCheck = async () => {
    if (!dnsDomain.trim()) return;

    setDnsLoading(true);
    setDnsError(null);
    setDnsInfo(null);

    try {
      const response = await fetch('http://localhost:3001/web/dns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: dnsDomain.trim() })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.details || 'DNS check failed');
      }

      setDnsInfo(data);

      try {
        if (!data.match || data.status === 'warning') {
          await logForensicsEvent({
            timestamp: Date.now(),
            eventType: 'dns_anomaly',
            sourceModule: 'WebSec Ops',
            severity: 'Medium',
            title: `DNS anomaly detected for ${data.domain}`,
            description: 'System resolver result does not match trusted resolver output.',
            details: data,
            attackPhase: 'Command and Control',
            ioc: [data.domain, ...(data.systemDNS || []), ...(data.googleDNS || [])],
            tags: ['dns', 'websec']
          });
        }
      } catch (forensicsErr) {
        console.error('Forensics event logging skipped:', forensicsErr);
      }
    } catch (error: any) {
      console.error('DNS Error:', error);
      setDnsError(error.message || 'Failed to resolve DNS');
    } finally {
      setDnsLoading(false);
    }
  };

  const openRedTeamAgent = async () => {
    const target = latestTarget || extractDomain(reconDomain) || extractDomain(sslDomain) || extractDomain(dnsDomain);
    if (!target) {
      toast.error('Run at least one WebSec scan to pre-fill a target');
      return;
    }

    try {
      await saveSetting('agent_prefill_payload', {
        target,
        agentMode: 'passive',
        objectives: ['Map attack surface', 'Verify security headers', 'Check breach exposure'],
        sourceModule: 'WebSec Ops',
        createdAt: Date.now()
      });
      if (onNavigate) {
        onNavigate(ScanType.AI_RED_TEAM);
        toast.success('Red Team Agent opened with WebSec target');
      } else {
        toast.success('Red Team Agent prefill saved');
      }
    } catch (error) {
      console.error('Failed to set Red Team prefill:', error);
      toast.error('Could not open Red Team Agent');
    }
  };

  const openZeroTrustBuilder = async () => {
    const target = latestTarget || extractDomain(headerUrl);
    if (!target && latestMissingHeaders.length === 0) {
      toast.error('Run header checks first to generate Zero Trust policy context');
      return;
    }

    try {
      await saveSetting('zerotrust_prefill_payload', {
        sourceModule: 'WebSec Ops',
        openPorts: [],
        dangerousPorts: [],
        missingHeaders: latestMissingHeaders,
        detectedThreats: latestMissingHeaders.map((h) => `Missing ${h}`),
        domain: target || null,
        internalIPs: [],
        targetEnvironment: 'nginx',
        createdAt: Date.now()
      });
      if (onNavigate) {
        onNavigate(ScanType.ZERO_TRUST);
        toast.success('Zero Trust Builder opened with WebSec findings');
      } else {
        toast.success('Zero Trust prefill saved');
      }
    } catch (error) {
      console.error('Failed to set Zero Trust prefill:', error);
      toast.error('Could not open Zero Trust Builder');
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-purple-950/20 to-slate-950 p-8">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-4 mb-4">
          <div className="p-3 rounded-xl bg-gradient-to-br from-purple-500/20 to-pink-500/20 
                          border border-purple-500/30 backdrop-blur-sm">
            <Globe className="w-8 h-8 text-purple-400" />
          </div>
          <div>
            <h1 className="text-4xl font-bold text-white">
              WebSec Ops
            </h1>
            <p className="text-gray-400 mt-1">
              External Reconnaissance & Security Audit Suite
            </p>
          </div>
        </div>
      </div>

      {/* 4-Quadrant Grid Dashboard */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* ========================================
            MODULE A: RECON-X (Subdomain Scanner)
            ======================================== */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6
                     hover:border-purple-500/50 transition-all duration-300"
        >
          <div className="flex items-center gap-3 mb-4">
            <Search className="w-6 h-6 text-purple-400" />
            <h2 className="text-2xl font-bold text-white">Recon-X</h2>
            <span className="text-sm text-gray-500">Subdomain Enumeration</span>
          </div>

          {/* Input */}
          <div className="flex gap-2 mb-4">
            <input
              type="text"
              value={reconDomain}
              onChange={(e) => setReconDomain(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && runReconScan()}
              placeholder="example.com"
              className="flex-1 px-4 py-3 bg-slate-800/50 border border-slate-600/50 rounded-lg
                         text-white placeholder-gray-500 focus:border-purple-500/50 
                         focus:outline-none transition-colors"
              disabled={reconLoading}
            />
            <button
              onClick={loadReconSample}
              type="button"
              className="bg-slate-800/50 border border-slate-700 hover:bg-slate-700/50 text-xs px-3 py-1 rounded flex items-center gap-2 text-slate-200"
            >
              <Sparkles className="w-3.5 h-3.5" />
              Load Sample
            </button>
            <button
              onClick={runReconScan}
              disabled={reconLoading || !reconDomain.trim()}
              className="px-6 py-3 bg-gradient-to-r from-purple-500 to-pink-500 
                         rounded-lg font-semibold text-white
                         hover:from-purple-600 hover:to-pink-600 
                         disabled:opacity-50 disabled:cursor-not-allowed
                         transition-all duration-200 flex items-center gap-2"
            >
              {reconLoading ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Search className="w-5 h-5" />
                  Scan
                </>
              )}
            </button>
          </div>

          {/* Results Area */}
          <div className="min-h-[300px] max-h-[400px] overflow-y-auto bg-slate-950/50 rounded-lg p-4
                          border border-slate-700/30 scrollbar-thin scrollbar-thumb-purple-500/30 
                          scrollbar-track-slate-800/30">
            <AnimatePresence mode="wait">
              {reconLoading && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex flex-col items-center justify-center h-full"
                >
                  <Loader2 className="w-12 h-12 text-purple-400 animate-spin mb-4" />
                  <p className="text-gray-400">Querying certificate transparency logs...</p>
                </motion.div>
              )}

              {reconError && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.9 }}
                  className="flex flex-col items-center justify-center h-full text-center"
                >
                  <XCircle className="w-12 h-12 text-red-400 mb-4" />
                  <p className="text-red-400 font-semibold mb-2">Source Unreachable</p>
                  <p className="text-gray-500 text-sm">{reconError}</p>
                </motion.div>
              )}

              {subdomains && !reconLoading && !reconError && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                >
                  <div className="flex items-center justify-between mb-4 pb-2 border-b border-slate-700/50">
                    <span className="text-gray-400 text-sm">
                      Found {subdomains.count} subdomains
                    </span>
                    <span className="text-xs text-gray-600">via {subdomains.source}</span>
                  </div>
                  
                  {subdomains.count === 0 ? (
                    <div className="text-center py-8">
                      <Info className="w-10 h-10 text-gray-600 mx-auto mb-2" />
                      <p className="text-gray-500">No subdomains found</p>
                    </div>
                  ) : (
                    <div className="space-y-1">
                      {subdomains.subdomains.map((subdomain, idx) => (
                        <motion.div
                          key={subdomain}
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: idx * 0.02 }}
                          className="px-3 py-2 bg-slate-800/30 rounded border border-slate-700/30
                                     hover:border-purple-500/50 hover:bg-slate-800/50 
                                     transition-all cursor-default"
                        >
                          <code className="text-green-400 text-sm font-mono">
                            {subdomain}
                          </code>
                        </motion.div>
                      ))}
                    </div>
                  )}
                </motion.div>
              )}

              {!reconLoading && !reconError && !subdomains && (
                <div className="flex flex-col items-center justify-center h-full text-center">
                  <Search className="w-12 h-12 text-gray-600 mb-4" />
                  <p className="text-gray-500">Enter a domain to start enumeration</p>
                  <p className="text-gray-600 text-sm mt-2">e.g., tesla.com, github.com</p>
                </div>
              )}
            </AnimatePresence>
          </div>
        </motion.div>

        {/* ========================================
            MODULE B: SSL SENTINEL
            ======================================== */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6
                     hover:border-green-500/50 transition-all duration-300"
        >
          <div className="flex items-center gap-3 mb-4">
            <Lock className="w-6 h-6 text-green-400" />
            <h2 className="text-2xl font-bold text-white">SSL Sentinel</h2>
            <span className="text-sm text-gray-500">Certificate Validator</span>
          </div>

          {/* Input */}
          <div className="flex gap-2 mb-4">
            <input
              type="text"
              value={sslDomain}
              onChange={(e) => setSslDomain(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && runSSLCheck()}
              placeholder="google.com"
              className="flex-1 px-4 py-3 bg-slate-800/50 border border-slate-600/50 rounded-lg
                         text-white placeholder-gray-500 focus:border-green-500/50 
                         focus:outline-none transition-colors"
              disabled={sslLoading}
            />
            <button
              onClick={loadSSLSample}
              type="button"
              className="bg-slate-800/50 border border-slate-700 hover:bg-slate-700/50 text-xs px-3 py-1 rounded flex items-center gap-2 text-slate-200"
            >
              <Sparkles className="w-3.5 h-3.5" />
              Load Sample
            </button>
            <button
              onClick={runSSLCheck}
              disabled={sslLoading || !sslDomain.trim()}
              className="px-6 py-3 bg-gradient-to-r from-green-500 to-emerald-500 
                         rounded-lg font-semibold text-white
                         hover:from-green-600 hover:to-emerald-600 
                         disabled:opacity-50 disabled:cursor-not-allowed
                         transition-all duration-200 flex items-center gap-2"
            >
              {sslLoading ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Checking...
                </>
              ) : (
                <>
                  <Lock className="w-5 h-5" />
                  Check
                </>
              )}
            </button>
          </div>

          {/* Results Area */}
          <div className="min-h-[300px] flex items-center justify-center bg-slate-950/50 rounded-lg p-6
                          border border-slate-700/30">
            <AnimatePresence mode="wait">
              {sslLoading && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex flex-col items-center"
                >
                  <Loader2 className="w-12 h-12 text-green-400 animate-spin mb-4" />
                  <p className="text-gray-400">Validating SSL certificate...</p>
                </motion.div>
              )}

              {sslError && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.9 }}
                  className="text-center"
                >
                  <XCircle className="w-12 h-12 text-red-400 mb-4 mx-auto" />
                  <p className="text-red-400 font-semibold mb-2">Certificate Check Failed</p>
                  <p className="text-gray-500 text-sm">{sslError}</p>
                </motion.div>
              )}

              {sslInfo && !sslLoading && !sslError && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.9 }}
                  className="w-full"
                >
                  {/* Certificate Health Card */}
                  <div className="text-center mb-6">
                    {sslInfo.valid && sslInfo.daysRemaining > 30 ? (
                      <div className="inline-flex items-center gap-3 px-6 py-3 
                                      bg-green-500/20 border border-green-500/50 rounded-xl">
                        <ShieldCheck className="w-10 h-10 text-green-400" />
                        <div className="text-left">
                          <p className="text-green-400 font-bold text-lg">Valid Certificate</p>
                          <p className="text-green-300 text-sm">Trusted & Secure</p>
                        </div>
                      </div>
                    ) : sslInfo.valid && sslInfo.daysRemaining <= 30 ? (
                      <div className="inline-flex items-center gap-3 px-6 py-3 
                                      bg-yellow-500/20 border border-yellow-500/50 rounded-xl">
                        <ShieldAlert className="w-10 h-10 text-yellow-400" />
                        <div className="text-left">
                          <p className="text-yellow-400 font-bold text-lg">Expiring Soon</p>
                          <p className="text-yellow-300 text-sm">Renewal Recommended</p>
                        </div>
                      </div>
                    ) : (
                      <div className="inline-flex items-center gap-3 px-6 py-3 
                                      bg-red-500/20 border border-red-500/50 rounded-xl">
                        <ShieldAlert className="w-10 h-10 text-red-400" />
                        <div className="text-left">
                          <p className="text-red-400 font-bold text-lg">Invalid Certificate</p>
                          <p className="text-red-300 text-sm">Expired or Self-Signed</p>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Certificate Details */}
                  <div className="space-y-3">
                    <div className="flex justify-between items-center p-3 bg-slate-800/30 rounded-lg">
                      <span className="text-gray-400">Domain</span>
                      <span className="text-white font-mono text-sm">{sslInfo.domain}</span>
                    </div>
                    <div className="flex justify-between items-center p-3 bg-slate-800/30 rounded-lg">
                      <span className="text-gray-400">Issuer</span>
                      <span className="text-white font-mono text-sm">{sslInfo.issuer}</span>
                    </div>
                    <div className="flex justify-between items-center p-3 bg-slate-800/30 rounded-lg">
                      <span className="text-gray-400">Valid Until</span>
                      <span className="text-white text-sm">
                        {new Date(sslInfo.validTo).toLocaleDateString()}
                      </span>
                    </div>
                    
                    {/* Days Remaining Progress Bar */}
                    <div className="p-4 bg-slate-800/30 rounded-lg">
                      <div className="flex justify-between items-center mb-2">
                        <span className="text-gray-400">Days Remaining</span>
                        <span className={`font-bold text-lg ${
                          sslInfo.daysRemaining > 30 ? 'text-green-400' :
                          sslInfo.daysRemaining > 0 ? 'text-yellow-400' :
                          'text-red-400'
                        }`}>
                          {sslInfo.daysRemaining}
                        </span>
                      </div>
                      <div className="w-full h-3 bg-slate-700/50 rounded-full overflow-hidden">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ 
                            width: `${Math.min(100, (sslInfo.daysRemaining / 365) * 100)}%` 
                          }}
                          transition={{ duration: 1, ease: "easeOut" }}
                          className={`h-full rounded-full ${
                            sslInfo.daysRemaining > 30 ? 'bg-gradient-to-r from-green-500 to-emerald-500' :
                            sslInfo.daysRemaining > 0 ? 'bg-gradient-to-r from-yellow-500 to-orange-500' :
                            'bg-gradient-to-r from-red-500 to-pink-500'
                          }`}
                        />
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}

              {!sslLoading && !sslError && !sslInfo && (
                <div className="text-center">
                  <Lock className="w-12 h-12 text-gray-600 mb-4 mx-auto" />
                  <p className="text-gray-500">Enter a domain to validate certificate</p>
                  <p className="text-gray-600 text-sm mt-2">e.g., google.com, github.com</p>
                </div>
              )}
            </AnimatePresence>
          </div>
        </motion.div>

        {/* ========================================
            MODULE C: SECURITY HEADER GRADER
            ======================================== */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="bg-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6
                     hover:border-blue-500/50 transition-all duration-300"
        >
          <div className="flex items-center gap-3 mb-4">
            <Shield className="w-6 h-6 text-blue-400" />
            <h2 className="text-2xl font-bold text-white">Header Grader</h2>
            <span className="text-sm text-gray-500">Security Audit</span>
          </div>

          {/* Input */}
          <div className="flex gap-2 mb-4">
            <input
              type="text"
              value={headerUrl}
              onChange={(e) => setHeaderUrl(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && runHeaderCheck()}
              placeholder="https://example.com"
              className="flex-1 px-4 py-3 bg-slate-800/50 border border-slate-600/50 rounded-lg
                         text-white placeholder-gray-500 focus:border-blue-500/50 
                         focus:outline-none transition-colors"
              disabled={headerLoading}
            />
            <button
              onClick={loadHeaderSample}
              type="button"
              className="bg-slate-800/50 border border-slate-700 hover:bg-slate-700/50 text-xs px-3 py-1 rounded flex items-center gap-2 text-slate-200"
            >
              <Sparkles className="w-3.5 h-3.5" />
              Load Sample
            </button>
            <button
              onClick={runHeaderCheck}
              disabled={headerLoading || !headerUrl.trim()}
              className="px-6 py-3 bg-gradient-to-r from-blue-500 to-cyan-500 
                         rounded-lg font-semibold text-white
                         hover:from-blue-600 hover:to-cyan-600 
                         disabled:opacity-50 disabled:cursor-not-allowed
                         transition-all duration-200 flex items-center gap-2"
            >
              {headerLoading ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Grading...
                </>
              ) : (
                <>
                  <Shield className="w-5 h-5" />
                  Grade
                </>
              )}
            </button>
          </div>

          {/* Results Area */}
          <div className="min-h-[300px] flex items-center justify-center bg-slate-950/50 rounded-lg p-6
                          border border-slate-700/30">
            <AnimatePresence mode="wait">
              {headerLoading && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex flex-col items-center"
                >
                  <Loader2 className="w-12 h-12 text-blue-400 animate-spin mb-4" />
                  <p className="text-gray-400">Analyzing security headers...</p>
                </motion.div>
              )}

              {headerError && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.9 }}
                  className="text-center"
                >
                  <XCircle className="w-12 h-12 text-red-400 mb-4 mx-auto" />
                  <p className="text-red-400 font-semibold mb-2">Headers Analysis Failed</p>
                  <p className="text-gray-500 text-sm">{headerError}</p>
                </motion.div>
              )}

              {headerGrade && headersInfo && !headerLoading && !headerError && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.9 }}
                  className="w-full text-center"
                >
                  {/* Giant Grade Letter */}
                  <motion.div
                    initial={{ scale: 0, rotate: -180 }}
                    animate={{ scale: 1, rotate: 0 }}
                    transition={{ type: "spring", stiffness: 200, damping: 15 }}
                    className="mb-6"
                  >
                    <div className={`inline-block text-9xl font-black ${headerGrade.color}
                                    drop-shadow-[0_0_30px_rgba(${
                                      headerGrade.glowColor === 'green' ? '34,197,94' :
                                      headerGrade.glowColor === 'blue' ? '59,130,246' :
                                      headerGrade.glowColor === 'yellow' ? '234,179,8' :
                                      headerGrade.glowColor === 'orange' ? '249,115,22' :
                                      '239,68,68'
                                    },0.6)]`}
                    >
                      {headerGrade.grade}
                    </div>
                  </motion.div>

                  {/* Score */}
                  <div className="mb-6">
                    <p className="text-2xl font-bold text-white mb-1">
                      Score: {headerGrade.score}/100
                    </p>
                    <p className="text-gray-400 text-sm">
                      HTTP Status: {headersInfo.status}
                    </p>
                  </div>

                  {/* Missing Headers */}
                  {headerGrade.missing.length > 0 && (
                    <div className="text-left space-y-2">
                      <p className="text-red-400 font-semibold mb-2 flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4" />
                        Missing Critical Headers:
                      </p>
                      {headerGrade.missing.map((header) => (
                        <div key={header} className="px-3 py-2 bg-red-500/10 border border-red-500/30 
                                                     rounded-lg text-red-400 text-sm">
                          • {header}
                        </div>
                      ))}
                    </div>
                  )}

                  {headerGrade.missing.length === 0 && (
                    <div className="flex items-center justify-center gap-2 px-4 py-3 
                                    bg-green-500/20 border border-green-500/50 rounded-lg">
                      <Trophy className="w-5 h-5 text-green-400" />
                      <span className="text-green-400 font-semibold">
                        All critical headers present!
                      </span>
                    </div>
                  )}
                </motion.div>
              )}

              {!headerLoading && !headerError && !headerGrade && (
                <div className="text-center">
                  <Shield className="w-12 h-12 text-gray-600 mb-4 mx-auto" />
                  <p className="text-gray-500">Enter a URL to grade security headers</p>
                  <p className="text-gray-600 text-sm mt-2">e.g., https://google.com</p>
                </div>
              )}
            </AnimatePresence>
          </div>
        </motion.div>

        {/* ========================================
            MODULE D: DNS INTEGRITY
            ======================================== */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4 }}
          className="bg-slate-900/50 backdrop-blur-xl border border-slate-700/50 rounded-2xl p-6
                     hover:border-cyan-500/50 transition-all duration-300"
        >
          <div className="flex items-center gap-3 mb-4">
            <Globe className="w-6 h-6 text-cyan-400" />
            <h2 className="text-2xl font-bold text-white">DNS Integrity</h2>
            <span className="text-sm text-gray-500">Poisoning Detector</span>
          </div>

          {/* Input */}
          <div className="flex gap-2 mb-4">
            <input
              type="text"
              value={dnsDomain}
              onChange={(e) => setDnsDomain(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && runDNSCheck()}
              placeholder="example.com"
              className="flex-1 px-4 py-3 bg-slate-800/50 border border-slate-600/50 rounded-lg
                         text-white placeholder-gray-500 focus:border-cyan-500/50 
                         focus:outline-none transition-colors"
              disabled={dnsLoading}
            />
            <button
              onClick={loadDNSSample}
              type="button"
              className="bg-slate-800/50 border border-slate-700 hover:bg-slate-700/50 text-xs px-3 py-1 rounded flex items-center gap-2 text-slate-200"
            >
              <Sparkles className="w-3.5 h-3.5" />
              Load Sample
            </button>
            <button
              onClick={runDNSCheck}
              disabled={dnsLoading || !dnsDomain.trim()}
              className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-500 
                         rounded-lg font-semibold text-white
                         hover:from-cyan-600 hover:to-blue-600 
                         disabled:opacity-50 disabled:cursor-not-allowed
                         transition-all duration-200 flex items-center gap-2"
            >
              {dnsLoading ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Resolving...
                </>
              ) : (
                <>
                  <Globe className="w-5 h-5" />
                  Check
                </>
              )}
            </button>
          </div>

          {/* Results Area */}
          <div className="min-h-[300px] flex items-center justify-center bg-slate-950/50 rounded-lg p-6
                          border border-slate-700/30">
            <AnimatePresence mode="wait">
              {dnsLoading && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex flex-col items-center"
                >
                  <Loader2 className="w-12 h-12 text-cyan-400 animate-spin mb-4" />
                  <p className="text-gray-400">Comparing DNS resolvers...</p>
                </motion.div>
              )}

              {dnsError && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.9 }}
                  className="text-center"
                >
                  <XCircle className="w-12 h-12 text-red-400 mb-4 mx-auto" />
                  <p className="text-red-400 font-semibold mb-2">DNS Resolution Failed</p>
                  <p className="text-gray-500 text-sm">{dnsError}</p>
                </motion.div>
              )}

              {dnsInfo && !dnsLoading && !dnsError && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.9 }}
                  className="w-full"
                >
                  {/* Match/Mismatch Status */}
                  <div className="text-center mb-6">
                    {dnsInfo.match ? (
                      <div className="inline-flex items-center gap-3 px-6 py-3 
                                      bg-green-500/20 border border-green-500/50 rounded-xl">
                        <CheckCircle className="w-10 h-10 text-green-400" />
                        <div className="text-left">
                          <p className="text-green-400 font-bold text-lg">DNS Match</p>
                          <p className="text-green-300 text-sm">No poisoning detected</p>
                        </div>
                      </div>
                    ) : (
                      <div className="inline-flex items-center gap-3 px-6 py-3 
                                      bg-red-500/20 border border-red-500/50 rounded-xl animate-pulse">
                        <AlertTriangle className="w-10 h-10 text-red-400" />
                        <div className="text-left">
                          <p className="text-red-400 font-bold text-lg">DNS Mismatch</p>
                          <p className="text-red-300 text-sm">Possible poisoning!</p>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* DNS Resolution Details */}
                  <div className="space-y-4">
                    <div className="p-4 bg-slate-800/30 rounded-lg border border-slate-700/30">
                      <p className="text-gray-400 text-sm mb-2 flex items-center gap-2">
                        <Globe className="w-4 h-4" />
                        System DNS
                      </p>
                      <div className="space-y-1">
                        {dnsInfo.systemDNS.map((ip, idx) => (
                          <div key={idx} className="text-cyan-400 font-mono text-sm 
                                                    px-2 py-1 bg-slate-900/50 rounded">
                            {ip}
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="p-4 bg-slate-800/30 rounded-lg border border-slate-700/30">
                      <p className="text-gray-400 text-sm mb-2 flex items-center gap-2">
                        <Globe className="w-4 h-4" />
                        Google DNS (8.8.8.8)
                      </p>
                      <div className="space-y-1">
                        {dnsInfo.googleDNS.map((ip, idx) => (
                          <div key={idx} className="text-cyan-400 font-mono text-sm 
                                                    px-2 py-1 bg-slate-900/50 rounded">
                            {ip}
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}

              {!dnsLoading && !dnsError && !dnsInfo && (
                <div className="text-center">
                  <Globe className="w-12 h-12 text-gray-600 mb-4 mx-auto" />
                  <p className="text-gray-500">Enter a domain to check DNS integrity</p>
                  <p className="text-gray-600 text-sm mt-2">e.g., google.com, cloudflare.com</p>
                </div>
              )}
            </AnimatePresence>
          </div>
        </motion.div>

      </div>

      <motion.div
        initial={{ opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
        className="mt-6 bg-slate-900/60 border border-cyan-500/20 rounded-2xl p-4 backdrop-blur-xl"
      >
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-lg font-bold text-slate-100">Cross-Module Actions</h3>
            <p className="text-xs text-slate-400">
              Use WebSec findings to launch autonomous red teaming and generate Zero Trust policy controls.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={openRedTeamAgent}
              className="px-3 py-2 rounded-lg border border-cyan-500/40 bg-cyan-500/10 text-cyan-200 text-sm font-semibold"
            >
              Run Red Team Agent
            </button>
            <button
              onClick={openZeroTrustBuilder}
              className="px-3 py-2 rounded-lg border border-emerald-500/40 bg-emerald-500/10 text-emerald-200 text-sm font-semibold"
            >
              Generate Zero Trust Policy
            </button>
          </div>
        </div>
      </motion.div>
    </div>
  );
}
