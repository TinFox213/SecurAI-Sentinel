import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldAlert, Search, AlertTriangle, CheckCircle, Clock, Database, ChevronDown, ChevronUp, Sparkles, Copy, FileText, BookmarkPlus, BookmarkMinus, Activity, Network, Loader2, Code, Globe } from 'lucide-react';
import { CVERecord, NVDVulnerability, ScanType } from '../../types/types';
import { getSetting, saveSetting, getAllScans, ScanHistory } from '../../services/db';
import { logForensicsEvent } from '../../utils/forensicsLogger';
import { toast } from 'react-hot-toast';

const QUICK_SEARCHES = ["Log4Shell", "EternalBlue", "Heartbleed", "CVE-2024-6387", "PrintNightmare"];

export default function CVEIntelHub() {
  const [query, setQuery] = useState('');
  const [isSearching, setIsSearching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [results, setResults] = useState<CVERecord[]>([]);
  const [watchlist, setWatchlist] = useState<any[]>([]);
  const [showWatchlist, setShowWatchlist] = useState(false);
  const [portScans, setPortScans] = useState<ScanHistory[]>([]);
  
  // Phase 2 State
  const [activeTab, setActiveTab] = useState<'search' | 'global'>('search');
  const [globalThreats, setGlobalThreats] = useState<any[]>([]);

  useEffect(() => {
    loadWatchlist();
    loadPortScans();
    loadGlobalThreats();
  }, []);

  const loadGlobalThreats = async () => {
    try {
      const res = await fetch('http://localhost:3001/osint/threat-intel');
      const data = await res.json();
      if (data.globalCampaigns) setGlobalThreats(data.globalCampaigns);
    } catch (e) {
      console.error(e);
    }
  };

  const loadWatchlist = async () => {
    const data = await getSetting('cve_watchlist');
    if (data && data.value) {
      setWatchlist(data.value);
    }
  };

  const saveWatchlist = async (newList: any[]) => {
    setWatchlist(newList);
    await saveSetting('cve_watchlist', newList);
  };

  const loadPortScans = async () => {
    const scans = await getAllScans();
    const ports = scans.filter(s => s.scanType === ScanType.PORT_SCAN);
    setPortScans(ports);
  };

  const loadSampleCVE = () => {
    setQuery('CVE-2021-44228');
    setResults([
      {
        vulnerability: {
          id: 'CVE-2021-44228',
          sourceIdentifier: 'cve@mitre.org',
          published: '2021-12-10T14:15:00',
          lastModified: '2022-01-20T19:15:00',
          vulnStatus: 'Analyzed',
          descriptions: [
            {
              lang: 'en',
              value: 'Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.15.0) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.'
            }
          ],
          metrics: {
            cvssMetricV31: [
              {
                cvssData: {
                  vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
                  attackVector: 'NETWORK',
                  attackComplexity: 'LOW',
                  privilegesRequired: 'NONE',
                  userInteraction: 'NONE',
                  baseScore: 10.0,
                  baseSeverity: 'CRITICAL'
                }
              }
            ]
          },
          references: [
            {
              url: 'https://logging.apache.org/log4j/2.x/security.html',
              source: 'cve@mitre.org'
            },
            {
              url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
              source: 'cve@mitre.org'
            }
          ]
        },
        aiAnalysis: {
          plainEnglish: 'A critical vulnerability in Apache Log4j (a logging library widely used in Java applications). It allows an attacker to execute arbitrary code on the server simply by sending a specific text string that the application logs.',
          attackVector: 'Network (Remote Exploitation)',
          impact: 'Complete system takeover (Remote Code Execution)',
          affectedPortsWarning: 'LDAP (389) or RMI (1099) outbound connections triggered during exploitation.',
          remediationSteps: [
            'Upgrade Apache Log4j to version 2.17.1 or higher immediately.',
            'Apply -Dlog4j2.formatMsgNoLookups=true system property workaround if patching is delayed.',
            'Restrict outbound Internet traffic from servers, especially LDAP and RMI ports.'
          ],
          urgency: 'Critical'
        },
        isAnalyzing: false,
        analysisError: null
      }
    ]);
    toast.success('Sample CVE data with AI Analysis loaded.');
  };

  const handleSearch = async (forceQuery?: string) => {
    const q = forceQuery || query;
    if (!q.trim()) return;
    
    setIsSearching(true);
    setError(null);
    setResults([]);

    try {
      const res = await fetch('http://localhost:3001/cve/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: q })
      });

      if (!res.ok) {
        if (res.status === 429) {
          throw new Error('NVD is rate limited. Please wait 30 seconds and retry.');
        }
        throw new Error('Cannot reach NVD. Check your internet connection.');
      }

      const data = await res.json();
      
      if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
        setError('No CVEs found for this query. Try a different keyword.');
        setIsSearching(false);
        return;
      }

      const formattedResults: CVERecord[] = data.vulnerabilities.map((v: any) => ({
        vulnerability: v.cve,
        aiAnalysis: null,
        isAnalyzing: false,
        analysisError: null
      }));

      setResults(formattedResults);
    } catch (err: any) {
      const message = err.message || 'An unknown error occurred';
      setError(message);
      toast.error(`CVE search failed: ${message}`);
    } finally {
      setIsSearching(false);
    }
  };

  const handleAIAnalysis = async (cveId: string, index: number) => {
    const targetRecord = results[index];
    if (!targetRecord) return;

    // Update state to show analyzing
    const newResults = [...results];
    newResults[index].isAnalyzing = true;
    newResults[index].analysisError = null;
    setResults(newResults);

    try {
      const v = targetRecord.vulnerability;
      const desc = v.descriptions.find(d => d.lang === 'en')?.value || 'No description available';
      let score = 0;
      if (v.metrics?.cvssMetricV31) score = v.metrics.cvssMetricV31[0].cvssData.baseScore;
      else if (v.metrics?.cvssMetricV2) score = v.metrics.cvssMetricV2[0].cvssData.baseScore;

      const res = await fetch('http://localhost:3001/cve/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          cveId,
          description: desc,
          cvssScore: score,
          affectedProducts: [] // Usually requires CPE parsing which is complex, passing empty helps AI generalize
        })
      });

      if (!res.ok) throw new Error('AI analysis failed');
      const aiData = await res.json();

      const finalResults = [...results];
      finalResults[index].aiAnalysis = aiData;
      finalResults[index].isAnalyzing = false;
      setResults(finalResults);

    } catch (err: any) {
      const errorResults = [...results];
      errorResults[index].isAnalyzing = false;
      errorResults[index].analysisError = 'AI analysis unavailable. Raw NVD data is shown.';
      setResults(errorResults);
      toast.error('AI analysis unavailable. Showing raw NVD data.');
    }
  };

  const toggleWatchlist = (cve: NVDVulnerability) => {
    const exists = watchlist.find(w => w.id === cve.id);
    if (exists) {
      saveWatchlist(watchlist.filter(w => w.id !== cve.id));
    } else {
      let severity = 'UNKNOWN';
      if (cve.metrics?.cvssMetricV31) severity = cve.metrics.cvssMetricV31[0].cvssData.baseSeverity;
      else if (cve.metrics?.cvssMetricV2) severity = cve.metrics.cvssMetricV2[0].cvssData.baseSeverity;
      
      saveWatchlist([...watchlist, { id: cve.id, severity, dateAdded: new Date().toISOString() }]);

      // Additive forensic logging on CVE watchlist additions.
      try {
        const description = cve.descriptions?.find((d) => d.lang === 'en')?.value || 'CVE added to watchlist';
        logForensicsEvent({
          timestamp: Date.now(),
          eventType: 'cve_added',
          sourceModule: 'CVE Intelligence Hub',
          severity: severity === 'CRITICAL' ? 'Critical' : severity === 'HIGH' ? 'High' : severity === 'MEDIUM' ? 'Medium' : 'Low',
          title: `CVE added to watchlist: ${cve.id}`,
          description,
          details: { cveId: cve.id, severity },
          attackPhase: 'Discovery',
          ioc: [cve.id],
          tags: ['cve', 'watchlist']
        });
      } catch (forensicsErr) {
        console.error('Forensics event logging skipped:', forensicsErr);
      }
    }
  };

  // Stats computation
  const criticalCount = results.filter(r => {
    const m = r.vulnerability.metrics;
    return m?.cvssMetricV31?.[0]?.cvssData?.baseSeverity?.toUpperCase() === 'CRITICAL';
  }).length;

  const highCount = results.filter(r => {
    const m = r.vulnerability.metrics;
    const sev = m?.cvssMetricV31?.[0]?.cvssData?.baseSeverity?.toUpperCase();
    return sev === 'HIGH';
  }).length;

  return (
    <div className="flex flex-col h-full overflow-hidden relative">
      {/* Header */}
      <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-6 mb-6 shadow-2xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-red-500/20 rounded-lg">
            <ShieldAlert className="w-6 h-6 text-red-500" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-100 tracking-tight">CVE Intelligence Hub</h1>
            <p className="text-sm text-slate-400">Live vulnerability intelligence powered by NVD & Gemini AI</p>
          </div>
        </div>
        
        {/* Module Tabs */}
        <div className="flex items-center gap-2 bg-slate-950/50 p-1.5 rounded-lg border border-white/5">
          <button 
            onClick={() => setActiveTab('search')}
            className={`px-4 py-2 rounded-md text-sm font-bold transition-all flex items-center gap-2 ${activeTab === 'search' ? 'bg-cyan-600/20 text-cyan-400 shadow-sm border border-cyan-500/30' : 'text-slate-500 hover:text-slate-300'}`}
          >
            <Search className="w-4 h-4" /> Vulnerability Search
          </button>
          <button 
            onClick={() => setActiveTab('global')}
            className={`px-4 py-2 rounded-md text-sm font-bold transition-all flex items-center gap-2 ${activeTab === 'global' ? 'bg-purple-600/20 text-purple-400 shadow-sm border border-purple-500/30' : 'text-slate-500 hover:text-slate-300'}`}
          >
            <Globe className="w-4 h-4" /> Global Threat Context
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto scrollbar-hide pr-2 flex gap-6">
        
        {/* Main Content Area */}
        {activeTab === 'search' ? (
          <div className="flex-1 space-y-6">

          
          {/* Search Bar */}
          <motion.div 
            initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
            className="bg-slate-900/40 backdrop-blur-xl border border-white/10 rounded-xl p-6 shadow-lg"
          >
            <div className="relative mb-4">
              <Search className="absolute left-4 top-3.5 w-5 h-5 text-slate-500" />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                placeholder="Search CVE ID or keyword... e.g. CVE-2024-1234 or 'Apache RCE'"
                className="w-full bg-slate-950 text-slate-200 font-mono text-sm py-3 pl-12 pr-32 rounded-lg border border-slate-700/50 focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/50 outline-none transition-all"
              />
              <button
                onClick={() => handleSearch()}
                disabled={isSearching || !query.trim()}
                className="absolute right-2 top-2 px-4 py-1.5 bg-cyan-600/20 hover:bg-cyan-600/40 text-cyan-400 font-medium rounded border border-cyan-500/30 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isSearching ? <Loader2 className="w-4 h-4 animate-spin" /> : 'Search'}
              </button>
            </div>

            <div className="mb-3">
              <button
                onClick={loadSampleCVE}
                className="bg-slate-800/50 border border-slate-700 hover:bg-slate-700/50 text-xs px-3 py-1 rounded flex items-center gap-2 text-slate-200"
              >
                <Sparkles className="w-3.5 h-3.5" />
                Load Sample Data
              </button>
            </div>
            
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-semibold text-slate-500">QUICK SEARCH:</span>
              {QUICK_SEARCHES.map(qs => (
                <button
                  key={qs}
                  onClick={() => { setQuery(qs); handleSearch(qs); }}
                  className="px-3 py-1 bg-slate-800/50 hover:bg-slate-700 border border-white/5 rounded-full text-xs text-slate-400 hover:text-cyan-400 transition-all"
                >
                  {qs}
                </button>
              ))}
            </div>

            {error && (
              <div className="mt-4 p-3 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center gap-3 text-red-400 text-sm">
                <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                <p>{error}</p>
              </div>
            )}
          </motion.div>

          {/* Stats Bar */}
          {(results.length > 0 || isSearching) && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <StatCard label="Total Results" value={isSearching ? '-' : results.length} />
              <StatCard label="Critical Risk" value={isSearching ? '-' : criticalCount} color="red" />
              <StatCard label="High Risk" value={isSearching ? '-' : highCount} color="orange" />
              <StatCard label="In Watchlist" value={watchlist.length} color="cyan" />
            </div>
          )}

          {/* Empty State */}
          {!isSearching && results.length === 0 && !error && (
            <div className="py-20 flex flex-col items-center justify-center text-slate-500">
              <ShieldAlert className="w-24 h-24 text-slate-800 mb-6 animate-pulse" />
              <h2 className="text-xl font-bold text-slate-300 mb-2">Search the NVD database</h2>
              <p className="text-sm">Over 250,000 CVEs indexed. Search by ID or keyword.</p>
            </div>
          )}

          {/* Results Loading */}
          {isSearching && (
            <div className="space-y-6">
              {[1,2].map(i => (
                <div key={i} className="bg-slate-900/40 border border-white/10 rounded-xl p-6 h-64 animate-pulse">
                  <div className="h-6 w-1/3 bg-slate-800 rounded mb-4"></div>
                  <div className="h-4 w-full bg-slate-800 rounded mb-2"></div>
                  <div className="h-4 w-5/6 bg-slate-800 rounded mb-6"></div>
                  <div className="h-32 w-full bg-slate-800 rounded"></div>
                </div>
              ))}
            </div>
          )}

          {/* Results Grid */}
          {!isSearching && results.map((record, idx) => (
            <motion.div
              key={record.vulnerability.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: idx * 0.1 }}
              className="bg-slate-900/50 backdrop-blur-xl border border-white/10 rounded-xl overflow-hidden shadow-xl"
            >
              <CVECard 
                record={record} 
                index={idx}
                portScans={portScans}
                onAnalyze={() => handleAIAnalysis(record.vulnerability.id, idx)}
                isWatched={!!watchlist.find(w => w.id === record.vulnerability.id)}
                onWatch={() => toggleWatchlist(record.vulnerability)}
              />
            </motion.div>
          ))}
          </div>
        ) : (
          /* Global Threat Context UI */
          <div className="flex-1 space-y-6 animate-fade-in">
            <h2 className="text-xl font-bold text-slate-200 flex items-center gap-2">
              <Activity className="w-5 h-5 text-purple-400" /> Active Global Campaigns
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {globalThreats.map((campaign, i) => (
                <div key={i} className="bg-slate-900/50 backdrop-blur-xl border border-white/10 rounded-xl p-6 relative overflow-hidden group">
                  <div className="absolute inset-0 bg-gradient-to-br from-purple-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-all"></div>
                  <div className="relative z-10">
                    <div className="flex items-start justify-between mb-4">
                      <div className="p-2 bg-purple-500/20 rounded-lg shrink-0 border border-purple-500/30">
                        <Globe className="w-5 h-5 text-purple-400" />
                      </div>
                      <SeverityBadge severity={campaign.severity} />
                    </div>
                    <h3 className="font-bold text-lg text-slate-200 mb-2 truncate" title={campaign.name}>{campaign.name}</h3>
                    <p className="text-sm text-slate-400 mb-6 h-10 line-clamp-2">{campaign.description}</p>
                    
                    <div className="mb-4">
                      <span className="text-[10px] uppercase font-bold text-slate-500 block mb-1">Target Sectors</span>
                      <div className="text-xs font-semibold text-slate-300 bg-slate-950/50 px-2 py-1.5 rounded inline-block border border-white/5">{campaign.target}</div>
                    </div>

                    <div>
                      <span className="text-[10px] uppercase font-bold text-slate-500 block mb-2">Weaponized CVEs</span>
                      <div className="flex flex-wrap gap-2">
                        {campaign.active_cves.map((cve: string) => (
                          <button 
                            key={cve}
                            onClick={() => { setActiveTab('search'); setQuery(cve); handleSearch(cve); }}
                            className="text-xs font-mono px-2 py-1 bg-red-500/10 hover:bg-red-500/30 text-red-400 rounded transition-all border border-red-500/20"
                            title="Search this CVE"
                          >
                            {cve}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
            
            <div className="mt-8 bg-blue-900/10 border border-blue-500/20 rounded-xl p-6 flex gap-4 items-start">
              <Activity className="w-6 h-6 text-blue-400 shrink-0" />
              <div>
                <h4 className="text-blue-300 font-bold mb-1">Intelligence Feed Connected</h4>
                <p className="text-sm text-slate-400 leading-relaxed">
                  The SecurAI Sentinel engine is continuously synchronizing with global threat networks. 
                  When scanning local endpoints or analyzing software hashes, the engine leverages this real-time context to accurately map threats to the MITRE ATT&CK framework and evaluate local risk dynamically.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Watchlist Sidebar Panel */}
        <div className="w-80 flex-shrink-0 hidden lg:block">
          <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-5 sticky top-0 h-[calc(100vh-140px)] flex flex-col">
            <div className="flex items-center justify-between mb-4 border-b border-white/10 pb-4">
              <h3 className="font-bold text-slate-200 flex items-center gap-2">
                <BookmarkPlus className="w-4 h-4 text-cyan-400" /> Watch List
              </h3>
              <span className="bg-cyan-500/20 text-cyan-400 text-xs px-2 py-0.5 rounded-full">{watchlist.length}</span>
            </div>
            
            <div className="flex-1 overflow-y-auto pr-2 space-y-3 scrollbar-hide">
              {watchlist.length === 0 ? (
                <div className="text-center text-slate-500 text-sm py-10">Your watchlist is empty</div>
              ) : (
                watchlist.map(w => (
                  <div key={w.id} className="bg-slate-950/50 border border-white/5 p-3 rounded-lg relative group">
                    <div className="text-sm font-mono text-cyan-400 mb-1">{w.id}</div>
                    <div className="flex items-center justify-between">
                      <SeverityBadge severity={w.severity} small />
                      <button 
                        onClick={() => toggleWatchlist({ id: w.id } as any)}
                        className="opacity-0 group-hover:opacity-100 text-slate-500 hover:text-red-400 transition-all"
                      >
                        <Trash2w3 />
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
            
            {watchlist.length > 0 && (
              <div className="pt-4 border-t border-white/10 mt-auto">
                <button 
                  onClick={() => saveWatchlist([])}
                  className="w-full py-2 text-xs font-semibold text-slate-500 hover:text-red-400 hover:bg-red-500/10 rounded transition-all"
                >
                  Clear All
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// -------------------------------------------------------------
// Helper Components
// -------------------------------------------------------------

function StatCard({ label, value, color = 'slate' }: any) {
  const colorMap: any = {
    slate: 'text-slate-200 bg-slate-800/50 border-slate-700/50',
    red: 'text-red-400 bg-red-500/10 border-red-500/20',
    orange: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
    cyan: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20'
  };
  return (
    <div className={`p-4 rounded-lg border ${colorMap[color]} backdrop-blur-sm flex flex-col justify-center`}>
      <div className="text-xs uppercase font-semibold opacity-70 mb-1">{label}</div>
      <div className="text-2xl font-bold">{value}</div>
    </div>
  );
}

function SeverityBadge({ severity, small = false }: { severity: string, small?: boolean }) {
  const s = (severity || 'UNKNOWN').toUpperCase();
  let bg = 'bg-slate-500/20 text-slate-400 border-slate-500/30';
  if (s === 'CRITICAL') bg = 'bg-red-500/20 text-red-500 border-red-500/30';
  if (s === 'HIGH') bg = 'bg-orange-500/20 text-orange-500 border-orange-500/30';
  if (s === 'MEDIUM') bg = 'bg-yellow-500/20 text-yellow-500 border-yellow-500/30';
  if (s === 'LOW') bg = 'bg-green-500/20 text-green-500 border-green-500/30';

  return (
    <span className={`inline-flex items-center justify-center font-bold uppercase tracking-wider border rounded ${small ? 'px-1.5 py-0.5 text-[9px]' : 'px-2 py-1 text-[10px]'} ${bg}`}>
      {s}
    </span>
  );
}

function Trash2w3() {
  return <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 6h18"></path><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"></path><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>;
}

// -------------------------------------------------------------
// CVE Card Component
// -------------------------------------------------------------
function CVECard({ record, index, portScans, onAnalyze, isWatched, onWatch }: { record: CVERecord, index: number, portScans: ScanHistory[], onAnalyze: () => void, isWatched: boolean, onWatch: () => void }) {
  const [iacPatch, setIacPatch] = useState<string | null>(null);
  const [isGeneratingIaC, setIsGeneratingIaC] = useState(false);
  const [iacFormat, setIacFormat] = useState('terraform');

  const v = record.vulnerability;
  const desc = v.descriptions.find(d => d.lang === 'en')?.value || 'No description found.';
  
  let score = 'N/A';
  let severity = 'UNKNOWN';
  let vector = '';
  
  if (v.metrics?.cvssMetricV31) {
    score = v.metrics.cvssMetricV31[0].cvssData.baseScore.toString();
    severity = v.metrics.cvssMetricV31[0].cvssData.baseSeverity;
    vector = v.metrics.cvssMetricV31[0].cvssData.vectorString;
  } else if (v.metrics?.cvssMetricV2) {
    score = v.metrics.cvssMetricV2[0].cvssData.baseScore.toString();
    severity = v.metrics.cvssMetricV2[0].cvssData.baseSeverity;
  }

  // Network Exposure Logic
  const hasDangerousPorts = portScans.some(scan => {
    if (typeof scan.analysisResult === 'string') return false; // Safety fallback
    const txt = JSON.stringify(scan.rawData).toLowerCase();
    // Rough heuristic: if AI previously marked scan as having dangerous exposure or we see it explicitly
    return txt.includes('open') && (txt.includes('dangerous') || txt.includes('vulnerable'));
  });

  return (
    <div>
      {/* Card Header */}
      <div className="bg-slate-950/60 p-5 flex flex-wrap items-center justify-between gap-4 border-b border-white/5">
        <div className="flex items-center gap-4">
          <div className="text-2xl font-mono font-bold text-cyan-400">{v.id}</div>
          <SeverityBadge severity={severity} />
          <div className="flex flex-col items-center justify-center bg-slate-900 border border-white/10 rounded px-3 py-1">
            <span className="text-[10px] text-slate-500 font-semibold mb-0.5">CVSS</span>
            <span className="text-lg font-bold text-slate-200 leading-none">{score}</span>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-xs text-slate-500 font-mono">
          <div className="bg-slate-800/50 px-2 py-1 rounded">Status: <span className="text-slate-300">{v.vulnStatus}</span></div>
          <div>Pub: {new Date(v.published).toLocaleDateString()}</div>
          <div>Mod: {new Date(v.lastModified).toLocaleDateString()}</div>
        </div>
      </div>

      {/* Card Body - 3 Columns */}
      <div className="grid grid-cols-1 xl:grid-cols-3 divide-y xl:divide-y-0 xl:divide-x divide-white/10">
        
        {/* Column 1: Raw Info */}
        <div className="p-5 xl:col-span-1 space-y-4">
          <h4 className="font-semibold text-slate-300 flex items-center gap-2 text-sm"><FileText className="w-4 h-4 text-slate-500"/> Raw NVD Data</h4>
          <p className="text-sm text-slate-400 leading-relaxed max-h-40 overflow-y-auto pr-2 scrollbar-hide">{desc}</p>
          
          {vector && (
            <div className="bg-slate-950/50 p-2 rounded border border-white/5 font-mono text-[10px] text-slate-400 break-all">
              {vector}
            </div>
          )}
          
          {v.references && v.references.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-slate-500 mb-2">References:</div>
              <ul className="space-y-1">
                {v.references.slice(0, 3).map((ref, i) => (
                  <li key={i} className="text-[11px] truncate">
                    <a href={ref.url} target="_blank" rel="noreferrer" className="text-cyan-500 hover:text-cyan-400 hover:underline">
                      {ref.url}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* Column 2: AI Analysis */}
        <div className="p-5 xl:col-span-1 bg-cyan-950/10">
          <div className="flex items-center justify-between mb-4">
            <h4 className="font-semibold text-cyan-300 flex items-center gap-2 text-sm">
              <Sparkles className="w-4 h-4" /> AI Intelligence
            </h4>
          </div>

          {!record.aiAnalysis && !record.isAnalyzing && !record.analysisError && (
            <div className="h-full flex flex-col items-center justify-center min-h-[150px]">
              <button 
                onClick={onAnalyze}
                className="px-4 py-2 bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 rounded border border-indigo-500/30 font-medium text-sm transition-all flex items-center gap-2"
              >
                <Sparkles className="w-4 h-4" /> Generate AI Analysis
              </button>
            </div>
          )}

          {record.isAnalyzing && (
            <div className="h-full flex flex-col items-center justify-center min-h-[150px] text-indigo-400 space-y-3">
              <Loader2 className="w-6 h-6 animate-spin" />
              <div className="text-xs animate-pulse">Consulting Gemini AI Model...</div>
            </div>
          )}

          {record.analysisError && (
            <div className="text-sm text-red-400 p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
              {record.analysisError}
              <button onClick={onAnalyze} className="mt-2 text-xs underline block hover:text-red-300">Retry</button>
            </div>
          )}

          {record.aiAnalysis && (
            <div className="space-y-4 animate-fade-in">
              <div className="bg-indigo-950/30 border border-indigo-500/20 p-3 rounded-lg text-sm text-indigo-200">
                <span className="font-bold text-indigo-400 block mb-1">Plain English:</span>
                {record.aiAnalysis.plainEnglish}
              </div>
              
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-slate-950/40 p-2 border border-white/5 rounded">
                  <span className="text-[10px] uppercase font-bold text-slate-500 block">Attack Vector</span>
                  <div className="text-xs text-slate-300 mt-0.5">{record.aiAnalysis.attackVector}</div>
                </div>
                <div className="bg-slate-950/40 p-2 border border-white/5 rounded">
                  <span className="text-[10px] uppercase font-bold text-slate-500 block">Impact</span>
                  <div className="text-xs text-slate-300 mt-0.5">{record.aiAnalysis.impact}</div>
                </div>
              </div>

              {record.aiAnalysis.affectedPortsWarning && (
                <div className="bg-yellow-500/10 border border-yellow-500/20 p-2 rounded flex items-start gap-2 text-yellow-500/90 text-xs">
                  <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
                  <span>{record.aiAnalysis.affectedPortsWarning}</span>
                </div>
              )}

              <div>
                <span className="text-[10px] uppercase font-bold text-slate-500 block mb-1">Remediation Steps</span>
                <ul className="space-y-1">
                  {record.aiAnalysis.remediationSteps.map((step, i) => (
                    <li key={i} className="text-xs text-slate-400 flex items-start gap-1.5">
                      <CheckCircle className="w-3 h-3 text-emerald-500 mt-0.5 flex-shrink-0" />
                      <span>{step}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </div>

        {/* Column 3: Network Exposure */}
        <div className="p-5 xl:col-span-1 border-white/5 bg-slate-900/20">
          <h4 className="font-semibold text-slate-300 flex items-center gap-2 text-sm mb-4">
            <Network className="w-4 h-4 text-slate-500" /> Network Exposure
          </h4>
          
          <div className="bg-slate-950/60 border border-white/5 rounded-lg p-4 h-[calc(100%-2rem)] flex flex-col">
            {portScans.length === 0 ? (
              <div className="text-center text-slate-500 my-auto text-sm">
                <Database className="w-8 h-8 opacity-20 mx-auto mb-2" />
                No local network scan history found.
                <div className="text-xs mt-1">Run Port Scanner first to check exposure.</div>
              </div>
            ) : hasDangerousPorts ? (
              <div className="my-auto">
                <div className="flex items-center gap-2 text-red-400 bg-red-500/10 p-2 rounded border border-red-500/20 mb-3 justify-center">
                  <AlertTriangle className="w-5 h-5 animate-pulse" />
                  <span className="font-bold text-sm">POTENTIALLY EXPOSED</span>
                </div>
                <p className="text-xs text-slate-400 text-center leading-relaxed">
                  Historical scans detected open dangerous ports (e.g., 22, 23, 445, 3389) on your network that might align with this attack vector.
                </p>
              </div>
            ) : (
              <div className="text-center my-auto">
                <div className="inline-flex p-2 bg-emerald-500/10 border border-emerald-500/20 rounded-full mb-2">
                  <CheckCircle className="w-5 h-5 text-emerald-500" />
                </div>
                <div className="text-sm font-semibold text-emerald-400">No Obvious Local Risk</div>
                <div className="text-xs text-slate-500 mt-1 mt-2">Historical port scans appear clean.</div>
              </div>
            )}
            
            <button className="w-full mt-4 py-2 border border-white/10 rounded text-xs font-semibold text-slate-400 hover:text-white hover:bg-white/5 transition-all">
              Launch Active Port Scan
            </button>
          </div>
        </div>
      </div>

      {/* IaC Generator (High/Critical Only) */}
      {(severity === 'HIGH' || severity === 'CRITICAL') && (
        <div className="p-5 border-t border-white/5 bg-slate-900/40">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4">
            <div>
              <h4 className="font-semibold text-emerald-400 flex items-center gap-2 text-sm">
                <Code className="w-4 h-4" /> Autonomous IaC Patching
              </h4>
              <p className="text-xs text-slate-400 mt-1">Generate Infrastructure as Code to mitigate this vulnerability.</p>
            </div>
            <div className="flex items-center gap-2">
              <select 
                value={iacFormat} 
                onChange={e => setIacFormat(e.target.value)}
                className="bg-slate-950 border border-slate-700 text-xs text-slate-300 rounded px-2 py-1.5 focus:outline-none focus:ring-1 focus:ring-emerald-500/50"
              >
                <option value="terraform">Terraform</option>
                <option value="kubernetes">Kubernetes</option>
                <option value="ansible">Ansible</option>
              </select>
              <button 
                onClick={async () => {
                  setIsGeneratingIaC(true);
                  try {
                    const res = await fetch('http://localhost:3001/remediate/iac', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ cveId: v.id, description: desc, format: iacFormat })
                    });
                    const data = await res.json();
                    if (data.success) {
                      setIacPatch(data.patch);
                    }
                  } catch (e) {
                    setIacPatch('// Failed to generate patch.');
                  } finally {
                    setIsGeneratingIaC(false);
                  }
                }}
                disabled={isGeneratingIaC}
                className="px-3 py-1.5 bg-emerald-600/20 hover:bg-emerald-600/30 border border-emerald-500/30 text-emerald-400 rounded text-xs font-semibold transition-all flex items-center gap-2 disabled:opacity-50"
              >
                {isGeneratingIaC ? <Loader2 className="w-3 h-3 animate-spin" /> : <Sparkles className="w-3 h-3" />}
                Generate Patch
              </button>
            </div>
          </div>
          
          {iacPatch && (
            <div className="relative mt-2">
              <pre className="bg-slate-950 p-4 rounded-lg font-mono text-xs text-emerald-300 border border-slate-800 overflow-x-auto">
                {iacPatch}
              </pre>
              <button 
                onClick={() => { navigator.clipboard.writeText(iacPatch); alert('IaC Patch Copied!'); }}
                className="absolute top-2 right-2 p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded transition-all"
              >
                <Copy className="w-3 h-3" />
              </button>
            </div>
          )}
        </div>
      )}

      {/* Card Footer */}
      <div className="bg-slate-950 p-3 flex border-t border-white/5 justify-end gap-2">
        <button 
          onClick={() => navigator.clipboard.writeText(v.id)}
          className="px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-cyan-400 hover:bg-cyan-500/10 rounded flex items-center gap-1.5 transition-all"
        >
          <Copy className="w-3 h-3" /> Copy ID
        </button>
        <button className="px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-indigo-400 hover:bg-indigo-500/10 rounded flex items-center gap-1.5 transition-all">
          <FileText className="w-3 h-3" /> Export Report
        </button>
        <button 
          onClick={onWatch}
          className={`px-3 py-1.5 text-xs font-medium rounded flex items-center gap-1.5 transition-all ${isWatched ? 'text-red-400 bg-red-500/10 border border-red-500/20 hover:bg-red-500/20' : 'text-slate-300 bg-emerald-600/20 border border-emerald-500/30 hover:bg-emerald-600/30'}`}
        >
          {isWatched ? <BookmarkMinus className="w-3 h-3" /> : <BookmarkPlus className="w-3 h-3" />}
          {isWatched ? 'Remove Watch' : 'Add to Watchlist'}
        </button>
      </div>
    </div>
  );
}
