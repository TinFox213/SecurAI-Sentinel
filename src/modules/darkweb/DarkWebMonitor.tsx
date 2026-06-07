import React, { useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle, BadgeCheck, CheckCircle2, ChevronDown, ChevronUp, Eye, Loader2, Search, ShieldAlert } from 'lucide-react';
import { toast } from 'react-hot-toast';
import { AbuseData, DarkWebAIAnalysis, DarkWebScanResult, HIBPBreach, PasteExposure } from '../../types/types';
import {
  clearDarkWebScans,
  getDarkWebScanResultByTimestamp,
  getDarkWebScans,
  saveDarkWebScan,
  DarkWebScanSummary
} from '../../services/db';
import { logForensicsEvent } from '../../utils/forensicsLogger';

type QueryType = 'email' | 'domain' | 'ip' | 'username';

const placeholders: Record<QueryType, string> = {
  email: 'Enter email address... e.g. user@example.com',
  domain: 'Enter domain... e.g. company.com',
  ip: 'Enter IP address... e.g. 192.168.1.1',
  username: 'Enter username... e.g. johndoe'
};

const demoValues: Record<QueryType, string> = {
  email: 'test@example.com',
  domain: 'adobe.com',
  ip: '1.1.1.1',
  username: 'admin'
};

type DemoDarkWebPayload = {
  breaches: HIBPBreach[];
  pasteExposures: PasteExposure[];
  abuseData?: AbuseData;
};

const parseModelJson = (raw: string): DemoDarkWebPayload => {
  const clean = String(raw || '')
    .replace(/^```json\s*/i, '')
    .replace(/^```\s*/i, '')
    .replace(/\s*```$/i, '')
    .trim();
  return JSON.parse(clean) as DemoDarkWebPayload;
};

const levelColor = (score: number): string => {
  if (score <= 30) return '#22c55e';
  if (score <= 60) return '#eab308';
  if (score <= 80) return '#f97316';
  return '#ef4444';
};

const formatMonthYear = (dateStr: string): string => {
  const d = new Date(dateStr);
  if (Number.isNaN(d.getTime())) return dateStr;
  return d.toLocaleString('en-US', { month: 'long', year: 'numeric' });
};

const dataClassColor = (value: string): string => {
  const norm = value.toLowerCase();
  if (norm.includes('password')) return 'bg-red-500/15 text-red-300 border-red-500/30';
  if (norm.includes('email')) return 'bg-blue-500/15 text-blue-300 border-blue-500/30';
  if (norm.includes('phone')) return 'bg-orange-500/15 text-orange-300 border-orange-500/30';
  if (norm.includes('physical') || norm.includes('address')) return 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30';
  if (norm.includes('credit')) return 'bg-purple-500/15 text-purple-300 border-purple-500/30';
  return 'bg-slate-500/15 text-slate-300 border-slate-500/30';
};

const fallbackAnalysis = (query: string, type: QueryType, breaches: HIBPBreach[]): DarkWebAIAnalysis => {
  const riskScore = Math.min(95, breaches.length * 18 + (type === 'ip' ? 20 : 10));
  const riskLevel: DarkWebAIAnalysis['riskLevel'] = riskScore >= 81 ? 'Critical' : riskScore >= 61 ? 'High' : riskScore >= 41 ? 'Medium' : riskScore > 0 ? 'Low' : 'Clean';
  const years = breaches.map((b) => (b.BreachDate || '').slice(0, 4)).filter(Boolean);

  return {
    riskScore,
    riskLevel,
    summary: `${query} shows ${breaches.length} known exposures. Prioritize credential hygiene and identity hardening immediately to reduce account takeover risk.`,
    exposedDataTypes: Array.from(new Set(breaches.flatMap((b) => b.DataClasses || []))).slice(0, 8),
    oldestBreach: years.length ? years.sort()[0] : 'N/A',
    mostRecentBreach: years.length ? years.sort().reverse()[0] : 'N/A',
    immediateActions: [
      'Change passwords for affected accounts immediately.',
      'Enable MFA on all critical services.',
      'Review active sessions and revoke unknown logins.'
    ],
    longTermRecommendations: [
      'Use a password manager with unique credentials per site.',
      'Add breach monitoring for all corporate and personal emails.',
      'Implement quarterly identity and access reviews.'
    ],
    passwordChangeUrgency: riskScore >= 60 ? 'Immediate' : 'Soon'
  };
};

const getDemoDataWithGemini = async (query: string, type: QueryType): Promise<DemoDarkWebPayload> => {
  try {
    const response = await fetch('http://localhost:3001/darkweb/demo-data', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, type })
    });

    if (!response.ok) {
      throw new Error('Demo data generation failed');
    }

    return await response.json() as DemoDarkWebPayload;
  } catch {
    return {
      breaches: [
        {
          Name: 'DemoBreach',
          Title: 'Demo Breach Dataset',
          Domain: type === 'domain' ? query : 'example.com',
          BreachDate: '2021-08-14',
          AddedDate: '2021-08-20T00:00:00Z',
          ModifiedDate: '2022-01-01T00:00:00Z',
          PwnCount: 1250000,
          Description: 'A demo exposure event containing credential and profile data. Generated for feature preview mode.',
          LogoPath: '',
          DataClasses: ['Email addresses', 'Passwords', 'Phone numbers'],
          IsVerified: true,
          IsFabricated: false,
          IsSensitive: false,
          IsRetired: false,
          IsSpamList: false,
          IsMalware: false
        }
      ],
      pasteExposures: type === 'email' ? [{ Source: 'Pastebin', Id: 'demo-1', Title: 'Combo List', Date: '2023-10-12', EmailCount: 1 }] : [],
      abuseData: type === 'ip' ? {
        abuseConfidenceScore: 74,
        totalReports: 19,
        countryCode: 'US',
        isp: 'Example Transit',
        usageType: 'Data Center/Web Hosting/Transit',
        reports: []
      } : undefined
    };
  }
};

const DarkWebMonitor: React.FC = () => {
  const [queryType, setQueryType] = useState<QueryType>('email');
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<DarkWebScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<DarkWebScanSummary[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [descExpanded, setDescExpanded] = useState<Record<string, boolean>>({});
  const [checklistDone, setChecklistDone] = useState<Record<number, boolean>>({});
  const [showApiKeyBanner, setShowApiKeyBanner] = useState(false);

  const loadHistory = async () => {
    const scans = await getDarkWebScans();
    setHistory(scans);
  };

  const runScan = async (overrideQuery?: string, overrideType?: QueryType) => {
    const activeQuery = overrideQuery !== undefined ? overrideQuery : query;
    const activeType = overrideType !== undefined ? overrideType : queryType;
    if (!activeQuery.trim()) return;

    setLoading(true);
    setError(null);
    setShowApiKeyBanner(false);
    setChecklistDone({});

    try {
      const breachRes = await fetch('http://localhost:3001/darkweb/breach', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: activeQuery.trim(), type: activeType })
      });

      const breachPayload = await breachRes.json();
      let breaches: HIBPBreach[] = breachPayload.breaches || [];
      let pasteExposures: PasteExposure[] = breachPayload.pasteExposures || [];
      let abuseData: AbuseData | undefined = breachPayload.abuseData;
      let isDemoMode = false;

      if (breachPayload?.error === 'API_KEY_MISSING') {
        setShowApiKeyBanner(true);
        isDemoMode = true;
        const demoData = await getDemoDataWithGemini(query.trim(), queryType);
        breaches = demoData.breaches || [];
        pasteExposures = demoData.pasteExposures || [];
        abuseData = demoData.abuseData;
      } else if (!breachRes.ok) {
        throw new Error(breachPayload?.message || 'Dark web lookup failed');
      }

      let aiAnalysis: DarkWebAIAnalysis | null = null;
      try {
        const analysisRes = await fetch('http://localhost:3001/darkweb/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: activeQuery.trim(), type: activeType, breaches, abuseData })
        });

        if (analysisRes.ok) {
          aiAnalysis = await analysisRes.json();
        }
      } catch {
        aiAnalysis = null;
      }

      if (!aiAnalysis) {
        aiAnalysis = fallbackAnalysis(activeQuery.trim(), activeType, breaches);
      }

      const fullResult: DarkWebScanResult = {
        query: activeQuery.trim(),
        type: activeType,
        breaches,
        pasteExposures,
        abuseData,
        aiAnalysis,
        isDemoMode,
        timestamp: new Date().toISOString()
      };

      setResult(fullResult);
      await saveDarkWebScan(fullResult);

      try {
        if (fullResult.breaches.length > 0 || fullResult.pasteExposures.length > 0) {
          await logForensicsEvent({
            timestamp: Date.now(),
            eventType: 'breach_found',
            sourceModule: 'Dark Web Monitor',
            severity: fullResult.aiAnalysis?.riskLevel === 'Critical' ? 'Critical' : fullResult.aiAnalysis?.riskLevel === 'High' ? 'High' : fullResult.aiAnalysis?.riskLevel === 'Medium' ? 'Medium' : 'Low',
            title: `Breach exposure detected for ${fullResult.query}`,
            description: fullResult.aiAnalysis?.summary || `Detected ${fullResult.breaches.length} breach records and ${fullResult.pasteExposures.length} paste exposures.`,
            details: {
              query: fullResult.query,
              type: fullResult.type,
              breachCount: fullResult.breaches.length,
              pasteCount: fullResult.pasteExposures.length
            },
            attackPhase: 'Credential Access',
            ioc: [fullResult.query, ...fullResult.breaches.map((b) => b.Name).slice(0, 6)],
            tags: ['dark-web', 'breach-intel']
          });
        }
      } catch (forensicsErr) {
        console.error('Forensics event logging skipped:', forensicsErr);
      }

      await loadHistory();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Dark web scan failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const stats = useMemo(() => {
    if (!result?.aiAnalysis) return null;
    return {
      breachesFound: result.breaches.length,
      dataTypesExposed: result.aiAnalysis.exposedDataTypes.length,
      riskScore: result.aiAnalysis.riskScore,
      pasteExposures: result.pasteExposures.length
    };
  }, [result]);

  const gauge = useMemo(() => {
    const score = result?.aiAnalysis?.riskScore || 0;
    const radius = 65;
    const circumference = 2 * Math.PI * radius;
    const progress = (score / 100) * circumference;
    return { radius, circumference, progress, score };
  }, [result]);

  return (
    <div className="space-y-6">
      <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-6 backdrop-blur-xl shadow-2xl relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-cyan-500/5 via-transparent to-fuchsia-500/5" />
        <div className="relative flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-cyan-500/15 border border-cyan-500/30">
                <Eye className="w-6 h-6 text-cyan-300" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-slate-100">Dark Web Monitor</h1>
                <p className="text-sm text-slate-400">Check exposure across breach databases and dark web sources</p>
              </div>
            </div>
          </div>
          <button
            onClick={() => {
              setQueryType('email');
              setQuery('test@example.com');
              runScan('test@example.com', 'email');
              toast.success('Sample Dark Web scan initiated.');
            }}
            className="px-4 py-2 rounded-lg bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/30 text-xs font-semibold transition-all"
          >
            Load Sample Data
          </button>
        </div>

        <div className="relative mt-6 space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
            {(['email', 'domain', 'ip', 'username'] as QueryType[]).map((tab) => (
              <button
                key={tab}
                onClick={() => setQueryType(tab)}
                className={`px-3 py-2 rounded-lg text-sm font-semibold border transition-all ${
                  queryType === tab
                    ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40'
                    : 'bg-slate-900/50 text-slate-400 border-white/10 hover:text-slate-200'
                }`}
              >
                {tab.toUpperCase()}
              </button>
            ))}
          </div>

          {showApiKeyBanner && (
            <div className="bg-yellow-500/10 border border-yellow-500/30 text-yellow-300 rounded-lg p-3 text-sm">
              HIBP API key not configured. Add HIBP_API_KEY to your .env file for real breach data. Running in demo mode.
            </div>
          )}

          <div className="bg-slate-950/70 border border-cyan-500/20 rounded-xl p-3 flex items-center gap-2">
            <Search className="w-5 h-5 text-cyan-400" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && runScan()}
              placeholder={placeholders[queryType]}
              className="w-full bg-transparent outline-none text-slate-200 font-mono"
            />
            <button
              onClick={() => runScan()}
              disabled={loading || !query.trim()}
              className="px-4 py-2 rounded-lg bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/30 disabled:opacity-50"
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <span className="inline-flex items-center gap-2"><Eye className="w-4 h-4" />Scan Dark Web</span>}
            </button>
          </div>

          <p className="text-xs text-slate-500">Your query is checked against public breach APIs only. Nothing is stored on our servers.</p>

          <div className="flex flex-wrap gap-2">
            {(['email', 'domain', 'ip', 'username'] as QueryType[]).map((chipType) => (
              <button
                key={chipType}
                onClick={() => {
                  setQueryType(chipType);
                  setQuery(demoValues[chipType]);
                }}
                className="px-3 py-1 rounded-full text-xs border border-white/10 text-slate-300 hover:bg-white/5"
              >
                {demoValues[chipType]}
              </button>
            ))}
          </div>
        </div>
      </div>

      {!result && !loading && !error && (
        <div className="bg-slate-900/35 border border-white/10 rounded-2xl p-8 text-center">
          <Eye className="w-14 h-14 mx-auto text-cyan-400 animate-pulse" />
          <h3 className="text-xl font-bold text-slate-200 mt-4">Monitor your digital footprint</h3>
          <p className="text-slate-400 mt-2">Check if your credentials have been compromised in known data breaches</p>
        </div>
      )}

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-300 rounded-xl p-4">{error}</div>
      )}

      {stats && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <StatCard label="Breaches Found" value={stats.breachesFound} />
          <StatCard label="Data Types Exposed" value={stats.dataTypesExposed} />
          <StatCard label="Risk Score" value={stats.riskScore} />
          <StatCard label="Paste Exposures" value={stats.pasteExposures} />
        </div>
      )}

      {result && result.aiAnalysis && (
        <>
          <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-6 backdrop-blur-xl relative">
            {result.isDemoMode && <DemoBadge />}
            <div className="flex flex-col lg:flex-row gap-6 items-center">
              <div className="relative">
                <svg width="170" height="170" viewBox="0 0 170 170">
                  <circle cx="85" cy="85" r={gauge.radius} stroke="rgba(148,163,184,0.2)" strokeWidth="14" fill="none" />
                  <motion.circle
                    cx="85"
                    cy="85"
                    r={gauge.radius}
                    stroke={levelColor(gauge.score)}
                    strokeWidth="14"
                    fill="none"
                    strokeLinecap="round"
                    transform="rotate(-90 85 85)"
                    strokeDasharray={gauge.circumference}
                    initial={{ strokeDashoffset: gauge.circumference }}
                    animate={{ strokeDashoffset: gauge.circumference - gauge.progress }}
                    transition={{ duration: 1.2, ease: 'easeOut' }}
                  />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <div className="text-center">
                    <div className="text-3xl font-bold text-slate-100">{result.aiAnalysis.riskScore}</div>
                    <div className="text-xs text-slate-400">RISK SCORE</div>
                  </div>
                </div>
              </div>
              <div className="flex-1">
                <span className={`inline-flex px-3 py-1 rounded-full border text-sm font-semibold ${dataClassColor(result.aiAnalysis.riskLevel)}`}>
                  {result.aiAnalysis.riskLevel}
                </span>
                <p className="text-slate-300 mt-3 leading-relaxed">{result.aiAnalysis.summary}</p>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            {result.breaches.map((breach, idx) => {
              const expanded = !!descExpanded[`${breach.Name}-${idx}`];
              return (
                <motion.div
                  key={`${breach.Name}-${idx}`}
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: idx * 0.08 }}
                  className="bg-slate-900/45 border border-white/10 rounded-xl p-5 backdrop-blur-lg relative"
                >
                  {result.isDemoMode && <DemoBadge />}
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <h3 className="text-lg font-bold text-slate-100">{breach.Title || breach.Name}</h3>
                      <p className="text-sm text-slate-400">{formatMonthYear(breach.BreachDate)} • {breach.Domain || 'Unknown domain'}</p>
                    </div>
                    <span className={`text-xs px-2 py-1 rounded-full border ${breach.IsVerified ? 'text-emerald-300 border-emerald-500/30 bg-emerald-500/10' : 'text-yellow-300 border-yellow-500/30 bg-yellow-500/10'}`}>
                      {breach.IsVerified ? 'Verified' : 'Unverified'}
                    </span>
                  </div>

                  <div className="mt-3 flex flex-wrap gap-2">
                    {(breach.DataClasses || []).map((dc) => (
                      <span key={dc} className={`px-2 py-1 rounded-full text-xs border ${dataClassColor(dc)}`}>{dc}</span>
                    ))}
                  </div>

                  <p className={`text-sm text-slate-300 mt-3 ${expanded ? '' : 'line-clamp-2'}`}>{breach.Description || 'No description available.'}</p>
                  <button
                    onClick={() => setDescExpanded((prev) => ({ ...prev, [`${breach.Name}-${idx}`]: !expanded }))}
                    className="text-xs text-cyan-400 mt-2"
                  >
                    {expanded ? 'Show less' : 'Expand'}
                  </button>

                  <p className="text-sm text-slate-400 mt-3">
                    {(breach.PwnCount || 0).toLocaleString()} accounts exposed
                  </p>
                </motion.div>
              );
            })}
          </div>

          {result.type === 'email' && (
            <div className="bg-slate-900/45 border border-orange-500/30 rounded-xl p-5 relative">
              {result.isDemoMode && <DemoBadge />}
              <h3 className="text-lg font-bold text-orange-300">Paste Exposures</h3>
              <p className="text-sm text-slate-300 mt-1">Your email appeared in {result.pasteExposures.length} paste dumps</p>
              <div className="mt-3 space-y-2">
                {result.pasteExposures.length === 0 && <p className="text-sm text-slate-400">No paste dumps detected.</p>}
                {result.pasteExposures.map((paste: PasteExposure, i: number) => (
                  <div key={`${paste.Id || i}`} className="bg-slate-950/60 border border-white/10 rounded-lg p-3 text-sm text-slate-300 grid grid-cols-2 md:grid-cols-4 gap-2">
                    <span><strong>Source:</strong> {paste.Source || 'Unknown'}</span>
                    <span><strong>Title:</strong> {paste.Title || 'Untitled'}</span>
                    <span><strong>Date:</strong> {paste.Date ? formatMonthYear(paste.Date) : 'N/A'}</span>
                    <span><strong>Email Count:</strong> {paste.EmailCount || 1}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {result.type === 'ip' && result.abuseData && (
            <div className="bg-slate-900/45 border border-purple-500/30 rounded-xl p-5 relative">
              {result.isDemoMode && <DemoBadge />}
              <h3 className="text-lg font-bold text-purple-300">IP Reputation</h3>
              <div className="mt-4 space-y-4">
                <div>
                  <div className="flex justify-between text-sm text-slate-300 mb-1">
                    <span>Abuse Confidence Score</span>
                    <span>{result.abuseData.abuseConfidenceScore || 0}%</span>
                  </div>
                  <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
                    <div className="h-full bg-gradient-to-r from-yellow-500 to-red-500" style={{ width: `${Math.min(100, result.abuseData.abuseConfidenceScore || 0)}%` }} />
                  </div>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm text-slate-300">
                  <InfoCell label="Total Reports" value={String(result.abuseData.totalReports || 0)} />
                  <InfoCell label="Country" value={result.abuseData.countryCode || 'N/A'} />
                  <InfoCell label="ISP" value={result.abuseData.isp || 'N/A'} />
                  <InfoCell label="Usage Type" value={result.abuseData.usageType || 'N/A'} />
                </div>
                <div className="overflow-auto">
                  <table className="w-full text-xs text-left text-slate-300">
                    <thead className="text-slate-400 border-b border-white/10">
                      <tr>
                        <th className="py-2">Date</th>
                        <th>Category</th>
                        <th>Comment</th>
                        <th>Reporter Country</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(result.abuseData.reports || []).slice(0, 5).map((report, idx: number) => (
                        <tr key={idx} className="border-b border-white/5">
                          <td className="py-2">{report.reportedAt ? formatMonthYear(report.reportedAt) : 'N/A'}</td>
                          <td>{Array.isArray(report.categories) ? report.categories.join(',') : 'N/A'}</td>
                          <td className="max-w-[260px] truncate">{report.comment || 'No comment'}</td>
                          <td>{report.reporterCountryCode || 'N/A'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="bg-red-500/10 border border-red-500/40 rounded-xl p-5 relative">
              {result.isDemoMode && <DemoBadge />}
              <h3 className="text-lg font-bold text-red-300 flex items-center gap-2"><ShieldAlert className="w-5 h-5" />Immediate Actions Required</h3>
              <ol className="mt-4 space-y-3">
                {result.aiAnalysis.immediateActions.map((action, idx) => (
                  <li key={idx} className="flex items-start gap-3 text-slate-200 text-sm">
                    <input
                      type="checkbox"
                      checked={!!checklistDone[idx]}
                      onChange={() => setChecklistDone((prev) => ({ ...prev, [idx]: !prev[idx] }))}
                      className="mt-1"
                    />
                    <span>{idx + 1}. {action}</span>
                  </li>
                ))}
              </ol>
              <button
                onClick={() => {
                  const done: Record<number, boolean> = {};
                  result.aiAnalysis?.immediateActions.forEach((_, idx) => { done[idx] = true; });
                  setChecklistDone(done);
                }}
                className="mt-4 px-4 py-2 rounded-lg bg-red-500/20 border border-red-500/40 text-red-200 text-sm"
              >
                Mark All Complete
              </button>
            </div>

            <div className="bg-teal-500/10 border border-teal-500/40 rounded-xl p-5 relative">
              {result.isDemoMode && <DemoBadge />}
              <h3 className="text-lg font-bold text-teal-300 flex items-center gap-2"><BadgeCheck className="w-5 h-5" />Long-term Recommendations</h3>
              <ul className="mt-4 space-y-2 text-sm text-slate-200 list-disc pl-5">
                {result.aiAnalysis.longTermRecommendations.map((item, idx) => (
                  <li key={idx}>{item}</li>
                ))}
              </ul>
            </div>
          </div>
        </>
      )}

      <div className="bg-slate-900/40 border border-white/10 rounded-xl p-4">
        <button
          onClick={async () => {
            const next = !showHistory;
            setShowHistory(next);
            if (next) await loadHistory();
          }}
          className="w-full flex items-center justify-between text-slate-200"
        >
          <span className="font-semibold">Scan History</span>
          {showHistory ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>

        <AnimatePresence>
          {showHistory && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="mt-4 space-y-2"
            >
              <div className="flex justify-end">
                <button
                  onClick={async () => {
                    await clearDarkWebScans();
                    await loadHistory();
                  }}
                  className="text-xs px-3 py-1 rounded border border-red-500/30 text-red-300"
                >
                  Clear History
                </button>
              </div>
              {history.length === 0 && <p className="text-sm text-slate-500">No dark web scans yet.</p>}
              {history.map((entry) => (
                <div key={entry.id} className="bg-slate-950/60 border border-white/10 rounded-lg p-3 flex flex-col md:flex-row md:items-center md:justify-between gap-3">
                  <div className="text-sm text-slate-300">
                    <div>{entry.query} <span className="text-xs text-slate-500">({entry.type})</span></div>
                    <div className="text-xs text-slate-500">{new Date(entry.timestamp).toLocaleString()}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-1 rounded text-xs border border-white/10 text-slate-300">Risk {entry.riskScore}</span>
                    <span className={`px-2 py-1 rounded text-xs border ${dataClassColor(entry.riskLevel)}`}>{entry.riskLevel}</span>
                    <button
                      onClick={async () => {
                        const saved = await getDarkWebScanResultByTimestamp(entry.timestamp);
                        if (saved) setResult(saved);
                      }}
                      className="px-3 py-1 rounded text-xs border border-cyan-500/30 text-cyan-300"
                    >
                      View
                    </button>
                  </div>
                </div>
              ))}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
};

const InfoCell: React.FC<{ label: string; value: string }> = ({ label, value }) => (
  <div className="bg-slate-950/50 border border-white/10 rounded-lg p-3">
    <div className="text-xs text-slate-500">{label}</div>
    <div className="text-sm text-slate-200 mt-1 break-words">{value}</div>
  </div>
);

const StatCard: React.FC<{ label: string; value: string | number }> = ({ label, value }) => (
  <div className="bg-slate-900/45 border border-white/10 rounded-xl p-4 text-center">
    <div className="text-2xl font-bold text-cyan-300">{value}</div>
    <div className="text-xs text-slate-500 uppercase tracking-wider">{label}</div>
  </div>
);

const DemoBadge: React.FC = () => (
  <div className="absolute top-3 right-3 text-[10px] px-2 py-1 rounded bg-fuchsia-500/20 border border-fuchsia-500/30 text-fuchsia-300 font-bold tracking-wider">
    DEMO DATA
  </div>
);

export default DarkWebMonitor;
