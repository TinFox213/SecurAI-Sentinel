import React, { useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import {
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  BarChart3,
  CheckCircle2,
  Globe,
  Network,
  RefreshCw,
  Server,
  Shield,
  ShieldCheck,
  Siren,
  Target,
  TerminalSquare,
  Wrench,
  Zap
} from 'lucide-react';
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { PostureHistoryEntry, PostureReport, ScanType, ThreatLevel } from '../../types/types';
import { db, getAllScans, getDarkWebScans, getPostureHistory, savePostureHistory, saveScanToHistory } from '../../services/db';
import { toast } from 'react-hot-toast';

interface Props {
  onNavigate: (type: ScanType) => void;
}

type WindowFilter = '7d' | '30d' | 'all';

type CategoryKey = keyof PostureReport['categoryScores'];

const scoreColor = (score: number): string => {
  if (score <= 40) return '#ef4444';
  if (score <= 60) return '#f97316';
  if (score <= 75) return '#eab308';
  if (score <= 90) return '#14b8a6';
  return '#22c55e';
};

const complianceColor = (value: 'Pass' | 'Partial' | 'Fail'): string => {
  if (value === 'Pass') return 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30';
  if (value === 'Partial') return 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30';
  return 'bg-red-500/15 text-red-300 border-red-500/30';
};

const gradeFromScore = (score: number): PostureReport['grade'] => {
  if (score >= 91) return 'A+';
  if (score >= 76) return 'A';
  if (score >= 61) return 'B';
  if (score >= 41) return 'C';
  if (score >= 21) return 'D';
  return 'F';
};

const moduleMapForCoverage: Array<{ label: string; type: ScanType }> = [
  { label: 'Port Scanner', type: ScanType.PORT_SCAN },
  { label: 'Vulnerability Scanner', type: ScanType.VULN_SCAN },
  { label: 'CVE Intel', type: ScanType.CVE_INTEL },
  { label: 'Phishing Detect', type: ScanType.PHISHING },
  { label: 'Dark Web Monitor', type: ScanType.DARK_WEB },
  { label: 'Malware Analysis', type: ScanType.MALWARE },
  { label: 'Keylogger Detect', type: ScanType.KEYLOGGER },
  { label: 'General Logs', type: ScanType.GENERAL_LOG },
  { label: 'CryptoVault', type: ScanType.FILE_CRYPTO },
  { label: 'Cyber Dojo', type: ScanType.CYBER_DOJO },
  { label: 'Canary Factory', type: ScanType.CANARY_FACTORY },
  { label: 'Network Watchtower', type: ScanType.NETWORK_WATCHTOWER },
  { label: 'WebSec Ops', type: ScanType.WEBSEC_OPS },
  { label: 'Utility Belt', type: ScanType.UTILITY_BELT }
];

const recommendationMap: Record<string, ScanType> = {
  port: ScanType.PORT_SCAN,
  network: ScanType.NETWORK_WATCHTOWER,
  web: ScanType.WEBSEC_OPS,
  phishing: ScanType.PHISHING,
  malware: ScanType.MALWARE,
  cve: ScanType.CVE_INTEL,
  dark: ScanType.DARK_WEB,
  breach: ScanType.DARK_WEB,
  crypto: ScanType.FILE_CRYPTO,
  logs: ScanType.GENERAL_LOG,
  keylogger: ScanType.KEYLOGGER,
  dojo: ScanType.CYBER_DOJO,
  canary: ScanType.CANARY_FACTORY,
  utility: ScanType.UTILITY_BELT
};

const SecurityPostureScore: React.FC<Props> = ({ onNavigate }) => {
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<PostureReport | null>(null);
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);
  const [history, setHistory] = useState<PostureHistoryEntry[]>([]);
  const [windowFilter, setWindowFilter] = useState<WindowFilter>('30d');
  const [expandedCategory, setExpandedCategory] = useState<CategoryKey | null>(null);
  const [scanCount, setScanCount] = useState(0);
  const [usedModules, setUsedModules] = useState<Set<ScanType>>(new Set());
  const [error, setError] = useState<string | null>(null);

  const resolveTargetType = (text: string): ScanType => {
    const lower = text.toLowerCase();
    for (const [key, type] of Object.entries(recommendationMap)) {
      if (lower.includes(key)) return type;
    }
    return ScanType.PORT_SCAN;
  };

  const noData = useMemo(() => scanCount === 0, [scanCount]);

  const filteredHistory = useMemo(() => {
    const now = Date.now();
    const cutoffDays = windowFilter === '7d' ? 7 : windowFilter === '30d' ? 30 : 0;

    const rows = history
      .map((h) => ({
        ...h,
        dateLabel: new Date(h.timestamp).toLocaleDateString(),
        ts: new Date(h.timestamp).getTime()
      }))
      .filter((h) => (cutoffDays ? h.ts >= now - cutoffDays * 24 * 60 * 60 * 1000 : true));

    return rows;
  }, [history, windowFilter]);

  const refreshScore = async () => {
    setLoading(true);
    setError(null);

    try {
      const [scans, darkweb, posture, agentReports] = await Promise.all([
        getAllScans(),
        getDarkWebScans(),
        getPostureHistory(),
        db.settings.where('id').startsWith('agent_report_').toArray()
      ]);

      const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
      const hasRecentAgentAssessment = agentReports.some((entry) => {
        const fromKey = Number(String(entry.id || '').split('_').pop());
        const valueAny = entry.value as { createdAt?: number; timestamp?: number } | undefined;
        const fromValue = Number(valueAny?.createdAt || valueAny?.timestamp || 0);
        const ts = Number.isFinite(fromKey) && fromKey > 0 ? fromKey : fromValue;
        return Number.isFinite(ts) && ts >= sevenDaysAgo;
      });

      const allModules = new Set<ScanType>();
      scans.forEach((scan) => allModules.add(scan.scanType));
      if (darkweb.length > 0) allModules.add(ScanType.DARK_WEB);

      setUsedModules(allModules);
      setScanCount(scans.length + darkweb.length);

      if (scans.length + darkweb.length === 0) {
        setReport(null);
        setHistory(posture);
        setUpdatedAt(new Date().toISOString());
        return;
      }

      const payload = {
        standardScans: scans.map((s) => ({
          timestamp: s.timestamp,
          scanType: s.scanType,
          riskScore: s.analysisResult?.risk_score ?? 0,
          threatLevel: s.analysisResult?.threat_level ?? 'Low',
          summary: s.analysisResult?.summary ?? ''
        })),
        darkwebScans: darkweb,
        moduleUsage: Array.from(allModules)
      };

      const response = await fetch('http://localhost:3001/posture/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scanHistory: payload })
      });

      if (!response.ok) {
        throw new Error('Failed to generate posture report');
      }

      const generatedRaw: PostureReport = await response.json();
      const generated: PostureReport = hasRecentAgentAssessment
        ? {
            ...generatedRaw,
            overallScore: Math.min(100, Number(generatedRaw.overallScore || 0) + 5),
            strengths: [
              ...(Array.isArray(generatedRaw.strengths) ? generatedRaw.strengths : []),
              'AI Red Team assessment executed in the last 7 days (+5 posture bonus)'
            ]
          }
        : generatedRaw;

      setReport(generated);
      setUpdatedAt(new Date().toISOString());

      const postureEntry: PostureHistoryEntry = {
        score: generated.overallScore,
        grade: generated.grade,
        categoryScores: generated.categoryScores,
        timestamp: new Date().toISOString()
      };
      await savePostureHistory(postureEntry);

      const freshHistory = await getPostureHistory();
      setHistory(freshHistory);
    } catch (err: any) {
      const message = err?.message || 'Unable to refresh posture score';
      setError(message);
      toast.error(`Posture analysis failed: ${message}`);
    } finally {
      setLoading(false);
    }
  };

  const loadSamplePostureData = async () => {
    setLoading(true);
    setError(null);
    try {
      await saveScanToHistory(
        ScanType.PORT_SCAN,
        `Target: 192.168.1.15\nOpen Ports:\n- 22/tcp (SSH) - OpenSSH 7.2p2 Ubuntu 4ubuntu2.10\n- 80/tcp (HTTP) - Apache httpd 2.4.18\n- 21/tcp (FTP) - vsftpd 3.0.3\n- 3306/tcp (MySQL) - MySQL 5.7.33`,
        {
          threat_level: ThreatLevel.HIGH,
          risk_score: 75,
          summary: 'Exposed vulnerable ports detected, including ssh (22), http (80), ftp (21), mysql (3306).',
          detailed_analysis: 'A local port scanner identified services running on administrative and utility ports. The FTP service is vulnerable to cleartext interception, and SSH daemon is exposed.',
          recommendations: ['Disable FTP', 'Upgrade OpenSSH'],
          additional_notes: 'Remediation advised immediately.'
        }
      );
      await saveScanToHistory(
        ScanType.PHISHING,
        `Subject: URGENT: Account Suspension Notice\nFrom: support@secure-bank-login-verify.com\nLinks: \n- http://bit.ly/2xk3s (Redirects to http://login-verify-secure.com/auth)\nContent: "Your account has been flagged. Click here to verify immediately or lose access."\nSPF: Fail\nDKIM: None`,
        {
          threat_level: ThreatLevel.HIGH,
          risk_score: 80,
          summary: 'Phishing email detected with failed SPF verification and redirecting links.',
          detailed_analysis: 'Heuristics scanned incoming corporate mail. The sender domain failed SPF validation checks and links redirect to non-banking login page hosts.',
          recommendations: ['Block domain', 'Train employees'],
          additional_notes: 'None'
        }
      );
      await saveScanToHistory(
        ScanType.MALWARE,
        `File: invoice_scan.exe\nHash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nStrings Extracted:\n- CreateRemoteThread\n- VirtualAlloc\n- advapi32.dll\n- C:\\Windows\\System32\\cmd.exe\n- http://c2-server.attacker-site.ru/beacon.php`,
        {
          threat_level: ThreatLevel.CRITICAL,
          risk_score: 95,
          summary: 'Malware file calling Windows APIs for process injection and beaconing to C2.',
          detailed_analysis: 'File dissection identified critical suspicious strings. Win32 APIs CreateRemoteThread and VirtualAlloc indicate memory injection. The sample makes outbound DNS requests to known malware C2 beaconing domains.',
          recommendations: ['Isolate endpoint', 'Run EDR remediations'],
          additional_notes: 'IOCs forwarded to threat intelligence stream.'
        }
      );
      toast.success('Sample scan history loaded successfully.');
      await refreshScore();
    } catch (err: any) {
      toast.error('Failed to load sample data');
    } finally {
      setLoading(false);
    }
  };

  React.useEffect(() => {
    refreshScore();
  }, []);

  const gauge = useMemo(() => {
    const score = report?.overallScore || 0;
    const radius = 80;
    const circumference = 2 * Math.PI * radius;
    const progress = (score / 100) * circumference;
    return { score, radius, circumference, progress };
  }, [report]);

  const trendIcon = useMemo(() => {
    const trend = report?.trendDirection;
    if (trend === 'Improving') return <ArrowUpRight className="w-4 h-4 text-emerald-400" />;
    if (trend === 'Declining') return <ArrowDownRight className="w-4 h-4 text-red-400" />;
    return <span className="text-slate-400">-</span>;
  }, [report]);

  const categoryCards: Array<{ key: CategoryKey; label: string; icon: React.ReactNode; hint: string }> = [
    { key: 'networkSecurity', label: 'Network Security', icon: <Network className="w-4 h-4" />, hint: 'Port exposure and segmentation posture' },
    { key: 'webSecurity', label: 'Web Security', icon: <Globe className="w-4 h-4" />, hint: 'Headers, SSL, DNS and web risk' },
    { key: 'endpointSecurity', label: 'Endpoint Security', icon: <Server className="w-4 h-4" />, hint: 'Malware and keylogger resilience' },
    { key: 'dataProtection', label: 'Data Protection', icon: <ShieldCheck className="w-4 h-4" />, hint: 'Credential and encryption hygiene' },
    { key: 'threatIntelligence', label: 'Threat Intelligence', icon: <Target className="w-4 h-4" />, hint: 'CVE and external exposure awareness' },
    { key: 'incidentReadiness', label: 'Incident Readiness', icon: <Siren className="w-4 h-4" />, hint: 'Detection, response and recovery' }
  ];

  const moduleShortcuts = [
    { label: 'Port Scanner', type: ScanType.PORT_SCAN, icon: <Network className="w-4 h-4" /> },
    { label: 'Vulnerability Scanner', type: ScanType.VULN_SCAN, icon: <Shield className="w-4 h-4" /> },
    { label: 'WebSec Ops', type: ScanType.WEBSEC_OPS, icon: <Globe className="w-4 h-4" /> },
    { label: 'Phishing Detect', type: ScanType.PHISHING, icon: <AlertTriangle className="w-4 h-4" /> },
    { label: 'Network Watchtower', type: ScanType.NETWORK_WATCHTOWER, icon: <Server className="w-4 h-4" /> }
  ];

  return (
    <div className="space-y-6">
      <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-6 backdrop-blur-xl">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/15 border border-cyan-500/30">
              <BarChart3 className="w-6 h-6 text-cyan-300" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-slate-100">Security Posture Score</h1>
              <p className="text-sm text-slate-400">Aggregated security health across all modules</p>
            </div>
          </div>
          <div className="flex items-center gap-3 flex-wrap">
            <button
              onClick={loadSamplePostureData}
              disabled={loading}
              className="px-4 py-2 rounded-lg bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/30 disabled:opacity-60 transition-all text-xs font-semibold"
            >
              Load Sample Data
            </button>
            <button
              onClick={refreshScore}
              disabled={loading}
              className="px-4 py-2 rounded-lg bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/30 disabled:opacity-60"
            >
              <span className="inline-flex items-center gap-2">
                <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                Refresh Score
              </span>
            </button>
            <div className="text-xs text-slate-500">
              Last updated: {updatedAt ? new Date(updatedAt).toLocaleString() : 'N/A'}
            </div>
          </div>
        </div>
      </div>

      {error && <div className="bg-red-500/10 border border-red-500/30 text-red-300 rounded-xl p-4">{error}</div>}

      {noData && (
        <div className="bg-slate-900/40 border border-white/10 rounded-2xl p-8 text-center space-y-4">
          <BarChart3 className="w-14 h-14 mx-auto text-cyan-400" />
          <h3 className="text-2xl font-bold text-slate-100">No scan data yet</h3>
          <p className="text-slate-400">Run at least 3 modules to generate your security posture score</p>
          <div>
            <button
              onClick={loadSamplePostureData}
              disabled={loading}
              className="px-6 py-2.5 rounded-lg bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/30 font-semibold text-sm transition-all animate-pulse"
            >
              Load Sample Data
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-5 gap-3 pt-3">
            {moduleShortcuts.map((item) => (
              <button
                key={item.label}
                onClick={() => onNavigate(item.type)}
                className="p-3 rounded-lg border border-white/10 bg-slate-950/50 text-slate-200 hover:border-cyan-500/40 hover:text-cyan-300"
              >
                <div className="flex items-center justify-center gap-2 text-sm font-medium">
                  {item.icon}
                  {item.label}
                </div>
              </button>
            ))}
          </div>
        </div>
      )}

      {report && (
        <>
          <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-6">
            <div className="flex flex-col lg:flex-row items-center gap-8">
              <div className="relative">
                <svg width="210" height="210" viewBox="0 0 210 210">
                  <circle cx="105" cy="105" r={gauge.radius} stroke="rgba(148,163,184,0.2)" strokeWidth="16" fill="none" />
                  <motion.circle
                    cx="105"
                    cy="105"
                    r={gauge.radius}
                    stroke={scoreColor(gauge.score)}
                    strokeWidth="16"
                    fill="none"
                    strokeLinecap="round"
                    transform="rotate(-90 105 105)"
                    strokeDasharray={gauge.circumference}
                    initial={{ strokeDashoffset: gauge.circumference }}
                    animate={{ strokeDashoffset: gauge.circumference - gauge.progress }}
                    transition={{ duration: 2, ease: 'easeOut' }}
                  />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center text-center">
                  <div>
                    <div className="text-4xl font-bold text-slate-100">{report.overallScore}</div>
                    <div className="text-xs text-slate-400">OVERALL SCORE</div>
                  </div>
                </div>
              </div>

              <div className="flex-1">
                <div className="text-6xl font-black text-slate-100">{report.grade}</div>
                <div className="mt-2 flex items-center gap-2 text-sm text-slate-300">
                  {trendIcon}
                  Trend: {report.trendDirection}
                </div>
                <p className="text-slate-400 mt-2 text-sm">
                  Based on {scanCount} scans across {usedModules.size} modules
                </p>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {categoryCards.map((card, idx) => {
              const score = report.categoryScores[card.key] || 0;
              const expanded = expandedCategory === card.key;
              return (
                <motion.button
                  key={card.key}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: idx * 0.05 }}
                  onClick={() => setExpandedCategory(expanded ? null : card.key)}
                  className="text-left bg-slate-900/45 border border-white/10 rounded-xl p-4 hover:border-cyan-500/30"
                >
                  <div className="flex items-center justify-between text-slate-200">
                    <span className="inline-flex items-center gap-2 font-semibold">{card.icon}{card.label}</span>
                    <span className="text-sm text-slate-300">{score}/100</span>
                  </div>
                  <div className="h-2 rounded-full bg-slate-800 mt-3 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${score}%` }}
                      transition={{ duration: 0.8 }}
                      style={{ backgroundColor: scoreColor(score) }}
                      className="h-full"
                    />
                  </div>
                  <p className="text-xs text-slate-500 mt-2">{card.hint}</p>
                  {expanded && (
                    <div className="mt-3 border-t border-white/10 pt-3 text-xs text-slate-400">
                      Relevant activity found in module history. Expand score coverage by running additional scans in this category.
                    </div>
                  )}
                </motion.button>
              );
            })}
          </div>

          <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-5">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-lg font-bold text-slate-100">Score History</h3>
              <div className="flex gap-2">
                {(['7d', '30d', 'all'] as WindowFilter[]).map((f) => (
                  <button
                    key={f}
                    onClick={() => setWindowFilter(f)}
                    className={`px-2.5 py-1 text-xs rounded border ${windowFilter === f ? 'border-cyan-500/40 text-cyan-300 bg-cyan-500/10' : 'border-white/10 text-slate-400'}`}
                  >
                    {f === 'all' ? 'All time' : `Last ${f.replace('d', ' days')}`}
                  </button>
                ))}
              </div>
            </div>

            {filteredHistory.length <= 1 ? (
              <p className="text-sm text-slate-500">Run more scans to see your trend</p>
            ) : (
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={filteredHistory}>
                    <defs>
                      <linearGradient id="scoreFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.5} />
                        <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.15)" />
                    <XAxis dataKey="dateLabel" stroke="#94a3b8" tick={{ fill: '#94a3b8', fontSize: 12 }} />
                    <YAxis domain={[0, 100]} stroke="#94a3b8" tick={{ fill: '#94a3b8', fontSize: 12 }} />
                    <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid rgba(148,163,184,0.2)', color: '#cbd5e1' }} />
                    <Area type="monotone" dataKey="score" stroke="#06b6d4" fill="url(#scoreFill)" strokeWidth={3} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>

          <div className="bg-red-500/10 border border-red-500/40 rounded-2xl p-5">
            <h3 className="text-lg font-bold text-red-300 flex items-center gap-2"><AlertTriangle className="w-5 h-5" />Critical Findings</h3>
            {report.criticalFindings.length === 0 ? (
              <div className="mt-3 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-sm">No critical findings detected</div>
            ) : (
              <ol className="mt-4 space-y-2 text-sm text-slate-200">
                {report.criticalFindings.map((finding, idx) => {
                  const targetType = resolveTargetType(finding);
                  return (
                    <li key={idx} className="flex flex-col md:flex-row md:items-center md:justify-between gap-2 bg-slate-950/40 border border-white/10 rounded-lg p-3">
                      <span>{idx + 1}. {finding}</span>
                      <button
                        onClick={() => onNavigate(targetType)}
                        className="px-3 py-1 rounded border border-red-500/30 text-red-200 text-xs"
                      >
                        View Module
                      </button>
                    </li>
                  );
                })}
              </ol>
            )}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="bg-teal-500/10 border border-teal-500/40 rounded-2xl p-5">
              <h3 className="text-lg font-bold text-teal-300 flex items-center gap-2"><Shield className="w-5 h-5" />Security Strengths</h3>
              <ul className="mt-3 list-disc pl-5 text-sm text-slate-200 space-y-1">
                {report.strengths.map((s, idx) => <li key={idx}>{s}</li>)}
              </ul>
            </div>
            <div className="bg-blue-500/10 border border-blue-500/40 rounded-2xl p-5">
              <h3 className="text-lg font-bold text-blue-300 flex items-center gap-2"><Zap className="w-5 h-5" />Recommended Next Scans</h3>
              <ol className="mt-3 space-y-2 text-sm text-slate-200">
                {report.nextScanRecommendations.map((item, idx) => (
                  <li key={idx} className="flex flex-col md:flex-row md:items-center md:justify-between gap-2 bg-slate-950/40 border border-white/10 rounded-lg p-3">
                    <span>{idx + 1}. {item}</span>
                    <button
                      onClick={() => onNavigate(resolveTargetType(item))}
                      className="px-3 py-1 rounded border border-blue-500/30 text-blue-200 text-xs"
                    >
                      Run Now
                    </button>
                  </li>
                ))}
              </ol>
            </div>
          </div>

          <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-5">
            <h3 className="text-lg font-bold text-slate-100 mb-4">Compliance Snapshot</h3>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
              <ComplianceCard name="CIS Level 1" value={report.complianceHints.cisLevel1} icon={<CheckCircle2 className="w-4 h-4" />} />
              <ComplianceCard name="CIS Level 2" value={report.complianceHints.cisLevel2} icon={<CheckCircle2 className="w-4 h-4" />} />
              <ComplianceCard name="GDPR Readiness" value={report.complianceHints.gdprReadiness} icon={<ShieldCheck className="w-4 h-4" />} />
              <div className="bg-slate-950/50 border border-white/10 rounded-lg p-3">
                <div className="text-sm text-slate-200 inline-flex items-center gap-2"><TerminalSquare className="w-4 h-4" />ISO 27001</div>
                <p className="text-xs text-slate-400 mt-2">{report.complianceHints.iso27001Hints}</p>
              </div>
            </div>
            <p className="text-xs text-slate-500 mt-3">This is a hint based on scan coverage, not a formal audit</p>
          </div>

          <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-5">
            <h3 className="text-lg font-bold text-slate-100">Scan Coverage</h3>
            <p className="text-sm text-slate-400 mt-1">Full coverage unlocks maximum score accuracy</p>
            <div className="mt-3 h-2 rounded-full bg-slate-800 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 to-emerald-500"
                style={{ width: `${Math.round((Array.from(usedModules).filter((m) => moduleMapForCoverage.some((c) => c.type === m)).length / moduleMapForCoverage.length) * 100)}%` }}
              />
            </div>
            <p className="text-xs text-slate-500 mt-2">
              {Array.from(usedModules).filter((m) => moduleMapForCoverage.some((c) => c.type === m)).length}/{moduleMapForCoverage.length} modules used
            </p>
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2 mt-3">
              {moduleMapForCoverage.map((module) => {
                const active = usedModules.has(module.type);
                return (
                  <div key={module.label} className={`rounded-lg border p-2 text-xs ${active ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300' : 'border-white/10 bg-slate-950/50 text-slate-500'}`}>
                    <div className="inline-flex items-center gap-1">
                      {active ? <CheckCircle2 className="w-3 h-3" /> : <Wrench className="w-3 h-3" />}
                      <span>{module.label}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <details className="bg-slate-900/35 border border-white/10 rounded-2xl p-4">
            <summary className="cursor-pointer text-slate-200 font-semibold">How score is calculated</summary>
            <p className="text-sm text-slate-400 mt-3">
              Your score is calculated from: open port risks (20%), web security headers (20%), breach exposure (20%), threat detection (20%), scan coverage (20%).
            </p>
          </details>
        </>
      )}
    </div>
  );
};

const ComplianceCard: React.FC<{ name: string; value: 'Pass' | 'Partial' | 'Fail'; icon: React.ReactNode }> = ({ name, value, icon }) => (
  <div className="bg-slate-950/50 border border-white/10 rounded-lg p-3">
    <div className="text-sm text-slate-200 inline-flex items-center gap-2">{icon}{name}</div>
    <span className={`inline-flex mt-2 px-2 py-1 rounded-full border text-xs ${complianceColor(value)}`}>{value}</span>
  </div>
);

export default SecurityPostureScore;
