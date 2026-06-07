import React, { useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Copy, Crosshair, Download, ExternalLink, Loader2, Save, Sparkles, X } from 'lucide-react';
import { AttackClassification, AttackTechnique, ScanType } from '../../types/types';
import { deleteSetting, getAllScans, getSetting, ScanHistory } from '../../services/db';
import { logForensicsEvent } from '../../utils/forensicsLogger';

const sourceModules = [
  'Port Scanner',
  'Vulnerability Scanner',
  'Phishing Detect',
  'Malware Analysis',
  'Keylogger Detect',
  'General Logs',
  'Packet Analyzer',
  'CryptoVault',
  'Cyber Dojo',
  'Canary Factory',
  'Network Watchtower',
  'WebSec Ops',
  'Utility Belt'
];

const killChain = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact'
];

const emptyClassification: AttackClassification = {
  tactics: [],
  killChainStage: 'Unknown',
  attackSummary: 'No attack mapping available yet.',
  threatActorProfile: 'Unknown',
  overallSeverity: 'Low'
};

const sevColor = (s: string) => {
  if (s === 'Critical') return 'bg-red-500/20 border-red-500/40 text-red-300';
  if (s === 'High') return 'bg-orange-500/20 border-orange-500/40 text-orange-300';
  if (s === 'Medium') return 'bg-yellow-500/20 border-yellow-500/40 text-yellow-300';
  return 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300';
};

const phaseColor = (severity: string) => {
  if (severity === 'Critical') return 'bg-red-500/25 border-red-400/50 text-red-200 shadow-[0_0_16px_rgba(239,68,68,0.35)]';
  if (severity === 'High') return 'bg-orange-500/25 border-orange-400/50 text-orange-200 shadow-[0_0_16px_rgba(249,115,22,0.35)]';
  if (severity === 'Medium') return 'bg-yellow-500/25 border-yellow-400/50 text-yellow-200 shadow-[0_0_16px_rgba(234,179,8,0.35)]';
  return 'bg-slate-800/80 border-slate-700 text-slate-400';
};

const MitreAttackMapper: React.FC = () => {
  const [mode, setMode] = useState<'paste' | 'history'>('paste');
  const [sourceModule, setSourceModule] = useState(sourceModules[0]);
  const [rawFindings, setRawFindings] = useState('');
  const [indicatorInput, setIndicatorInput] = useState('');
  const [indicators, setIndicators] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [classification, setClassification] = useState<AttackClassification | null>(null);
  const [selectedTechnique, setSelectedTechnique] = useState<(AttackTechnique & { tacticName: string }) | null>(null);
  const [selectedTechniqueDetail, setSelectedTechniqueDetail] = useState<any | null>(null);
  const [historyScans, setHistoryScans] = useState<ScanHistory[]>([]);
  const [selectedHistoryIds, setSelectedHistoryIds] = useState<Set<number>>(new Set());

  const loadSampleFindings = () => {
    setRawFindings('The threat actor gained initial access via a phishing email containing a malicious macro in a Word document. Upon execution, it utilized PowerShell to download a secondary payload, established persistence via a Scheduled Task, and attempted to dump credentials using ProcDump.');
  };

  const loadHistory = async () => {
    const scans = await getAllScans();
    setHistoryScans(scans.slice(0, 30));
  };

  React.useEffect(() => {
    const loadPrefill = async () => {
      const payload = await getSetting('mitre_prefill_payload');
      if (!payload?.value) return;

      const value = payload.value as { sourceModule?: string; findings?: string; indicators?: string[] } | null;
      if (value) {
        if (value.sourceModule) setSourceModule(value.sourceModule);
        if (value.findings) setRawFindings(value.findings);
        if (Array.isArray(value.indicators)) setIndicators(value.indicators);
      }

      await deleteSetting('mitre_prefill_payload');
    };

    loadPrefill();
  }, []);

  const runProgress = async () => {
    setProgress(0);
    for (let i = 1; i <= 30; i++) {
      await new Promise((r) => setTimeout(r, 100));
      setProgress(Math.min(95, i * 3));
    }
  };

  const classify = async (moduleName: string, findings: string, iocs: string[]) => {
    setLoading(true);
    setSelectedTechnique(null);
    setSelectedTechniqueDetail(null);

    try {
      runProgress();
      const res = await fetch('http://localhost:3001/attack/classify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sourceModule: moduleName, rawFindings: findings, detectedIndicators: iocs })
      });
      const data = await res.json();
      setClassification(data || emptyClassification);
      setProgress(100);
    } catch {
      setClassification(emptyClassification);
      setProgress(100);
    } finally {
      setTimeout(() => setLoading(false), 350);
    }
  };

  const classifyPaste = async () => {
    if (!rawFindings.trim()) return;
    await classify(sourceModule, rawFindings.trim(), indicators);
  };

  const classifyHistory = async () => {
    const selected = historyScans.filter((s) => s.id && selectedHistoryIds.has(s.id));
    if (selected.length === 0) return;

    const combined = selected
      .map((s) => `[${s.scanType}] ${s.rawData}\nSummary: ${s.analysisResult?.summary || ''}`)
      .join('\n\n-----\n\n');

    const iocs = selected
      .flatMap((s) => [s.scanType, ...(s.rawData.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b|CVE-\d{4}-\d+|\b\d{2,5}\/tcp\b/gi) || [])])
      .slice(0, 40)
      .map((x) => String(x));

    await classify('Multi-Module History', combined, iocs);
  };

  const detectedTacticsByName = useMemo(() => {
    const map = new Map<string, { confidence: number; techniques: number; severity: string }>();
    (classification?.tactics || []).forEach((tactic) => {
      const topSeverity = tactic.techniques.find((t) => t.severity === 'Critical')?.severity ||
        tactic.techniques.find((t) => t.severity === 'High')?.severity ||
        tactic.techniques.find((t) => t.severity === 'Medium')?.severity || 'Low';

      map.set(tactic.tacticName, {
        confidence: tactic.confidence,
        techniques: tactic.techniques.length,
        severity: topSeverity
      });
    });
    return map;
  }, [classification]);

  const techniqueRows = useMemo(() => {
    if (!classification) return [] as Array<{ tacticName: string; technique: AttackTechnique }>;
    return classification.tactics.flatMap((t) => t.techniques.map((tech) => ({ tacticName: t.tacticName, technique: tech })));
  }, [classification]);

  const maxRows = useMemo(() => {
    const max = Math.max(
      ...killChain.map((k) => classification?.tactics.find((t) => t.tacticName === k)?.techniques.length || 0),
      1
    );
    return Math.min(max, 8);
  }, [classification]);

  const stats = useMemo(() => {
    if (!classification) return null;
    const allTech = techniqueRows;
    const highest = allTech.sort((a, b) => b.technique.confidence - a.technique.confidence)[0];
    return {
      tacticsDetected: classification.tactics.length,
      techniquesMapped: allTech.length,
      highest: highest ? `${highest.technique.techniqueName} (${highest.technique.confidence}%)` : 'N/A',
      severity: classification.overallSeverity
    };
  }, [classification, techniqueRows]);

  const openTechnique = async (tech: AttackTechnique, tacticName: string) => {
    setSelectedTechnique({ ...tech, tacticName });
    try {
      const res = await fetch('http://localhost:3001/attack/technique', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ techniqueId: tech.techniqueId })
      });
      const detail = await res.json();
      setSelectedTechniqueDetail(detail);
    } catch {
      setSelectedTechniqueDetail(null);
    }
  };

  const exportNavigatorJson = () => {
    if (!classification) return;
    const techniques = classification.tactics.flatMap((t) =>
      t.techniques.map((tech) => ({
        techniqueID: tech.techniqueId,
        score: tech.confidence,
        color: tech.severity === 'Critical' ? '#ff4d4f' : tech.severity === 'High' ? '#fa8c16' : tech.severity === 'Medium' ? '#fadb14' : '#73d13d',
        comment: tech.evidence
      }))
    );

    const payload = {
      name: 'SecurAI Sentinel Export',
      versions: { attack: '14', navigator: '4.9', layer: '4.5' },
      domain: 'enterprise-attack',
      techniques
    };

    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `securai-attack-layer-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copySummary = async () => {
    if (!classification) return;
    const text = `Threat Actor Profile: ${classification.threatActorProfile}\nAttack Summary: ${classification.attackSummary}\nKill Chain Stage: ${classification.killChainStage}\nOverall Severity: ${classification.overallSeverity}`;
    await navigator.clipboard.writeText(text);
  };

  const saveToForensics = async () => {
    if (!classification) return;
    try {
      await logForensicsEvent({
        timestamp: Date.now(),
        eventType: 'attack_classified',
        sourceModule: 'MITRE ATT&CK Mapper',
        severity: classification.overallSeverity,
        title: 'ATT&CK classification saved',
        description: classification.attackSummary,
        details: classification,
        attackPhase: classification.killChainStage,
        ioc: indicators,
        tags: ['mitre', 'attack-mapping']
      });
    } catch (forensicsErr) {
      console.error('Forensics event logging skipped:', forensicsErr);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-slate-900/50 border border-white/10 rounded-2xl p-6 backdrop-blur-xl">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/20 border border-cyan-500/40">
              <Crosshair className="w-6 h-6 text-cyan-300" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-slate-100">MITRE ATT&CK Mapper</h1>
              <p className="text-sm text-slate-400">Classify threats to the ATT&CK framework and visualize the kill chain</p>
            </div>
          </div>
          <span className="text-xs px-3 py-1 rounded-full border border-slate-700 bg-slate-800/80 text-slate-400">MITRE ATT&CK®</span>
        </div>

        <div className="mt-5">
          <div className="inline-flex p-1 rounded-lg bg-slate-950/60 border border-white/10">
            <button
              onClick={() => setMode('paste')}
              className={`px-4 py-2 rounded text-sm ${mode === 'paste' ? 'bg-cyan-500/20 text-cyan-300' : 'text-slate-400'}`}
            >
              Paste Findings
            </button>
            <button
              onClick={async () => {
                setMode('history');
                await loadHistory();
              }}
              className={`px-4 py-2 rounded text-sm ${mode === 'history' ? 'bg-cyan-500/20 text-cyan-300' : 'text-slate-400'}`}
            >
              Load from History
            </button>
          </div>
        </div>

        {mode === 'paste' ? (
          <div className="mt-4 space-y-3">
            <select
              value={sourceModule}
              onChange={(e) => setSourceModule(e.target.value)}
              className="w-full bg-slate-950/60 border border-white/10 rounded-lg p-3 text-slate-200"
            >
              {sourceModules.map((m) => <option key={m} value={m}>{m}</option>)}
            </select>

            <textarea
              value={rawFindings}
              onChange={(e) => setRawFindings(e.target.value)}
              className="w-full h-36 bg-slate-950/60 border border-white/10 rounded-lg p-3 text-slate-200 font-mono text-sm"
              placeholder="Paste analysis output or findings here..."
            />

            <button
              onClick={loadSampleFindings}
              className="bg-slate-800/50 border border-slate-700 hover:bg-slate-700/50 text-xs px-3 py-1 rounded flex items-center gap-2 text-slate-200"
            >
              <Sparkles className="w-3.5 h-3.5" />
              Load Sample Data
            </button>

            <div className="bg-slate-950/60 border border-white/10 rounded-lg p-3">
              <input
                value={indicatorInput}
                onChange={(e) => setIndicatorInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && indicatorInput.trim()) {
                    e.preventDefault();
                    setIndicators((prev) => Array.from(new Set([...prev, indicatorInput.trim()])));
                    setIndicatorInput('');
                  }
                }}
                placeholder="Add indicators (IOCs, ports, process names)..."
                className="w-full bg-transparent text-slate-200 outline-none"
              />
              <div className="flex flex-wrap gap-2 mt-2">
                {indicators.map((ioc) => (
                  <button key={ioc} onClick={() => setIndicators((prev) => prev.filter((x) => x !== ioc))} className="text-xs px-2 py-1 rounded-full border border-cyan-500/30 text-cyan-300">
                    {ioc} ×
                  </button>
                ))}
              </div>
            </div>

            <button onClick={classifyPaste} disabled={loading || !rawFindings.trim()} className="px-4 py-2 rounded-lg border border-cyan-500/40 bg-cyan-500/20 text-cyan-300">
              <span className="inline-flex items-center gap-2">
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Crosshair className="w-4 h-4" />} Classify with AI
              </span>
            </button>
          </div>
        ) : (
          <div className="mt-4 space-y-3">
            <div className="max-h-56 overflow-auto space-y-2">
              {historyScans.map((scan) => (
                <label key={scan.id} className="flex gap-3 p-3 rounded-lg border border-white/10 bg-slate-950/40 text-slate-200">
                  <input
                    type="checkbox"
                    checked={scan.id ? selectedHistoryIds.has(scan.id) : false}
                    onChange={() => {
                      if (!scan.id) return;
                      setSelectedHistoryIds((prev) => {
                        const next = new Set(prev);
                        if (next.has(scan.id!)) next.delete(scan.id!);
                        else next.add(scan.id!);
                        return next;
                      });
                    }}
                  />
                  <div>
                    <div className="text-sm font-semibold">{scan.scanType}</div>
                    <div className="text-xs text-slate-500">{new Date(scan.timestamp).toLocaleString()}</div>
                    <div className="text-xs text-slate-400 line-clamp-1">{scan.analysisResult?.summary}</div>
                  </div>
                </label>
              ))}
            </div>

            <button onClick={classifyHistory} disabled={loading || selectedHistoryIds.size === 0} className="px-4 py-2 rounded-lg border border-cyan-500/40 bg-cyan-500/20 text-cyan-300">
              <span className="inline-flex items-center gap-2">
                {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Crosshair className="w-4 h-4" />} Map Selected Findings
              </span>
            </button>
          </div>
        )}
      </div>

      {loading && (
        <div className="bg-slate-900/50 border border-cyan-500/30 rounded-xl p-4">
          <div className="text-sm text-cyan-300 mb-2">Analyzing against 14 MITRE ATT&CK tactics and 200+ techniques...</div>
          <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
            <motion.div className="h-full bg-gradient-to-r from-cyan-500 to-blue-500" animate={{ width: `${progress}%` }} />
          </div>
        </div>
      )}

      {classification && (
        <>
          <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-4 overflow-x-auto">
            <div className="min-w-[1200px] flex items-center gap-2">
              {killChain.map((phase, idx) => {
                const info = detectedTacticsByName.get(phase);
                const detected = !!info;
                const isHere = classification.killChainStage.toLowerCase() === phase.toLowerCase();
                return (
                  <React.Fragment key={phase}>
                    <div className={`rounded-lg border px-3 py-2 min-w-[120px] text-center relative ${detected ? `${phaseColor(info!.severity)} animate-pulse` : 'bg-slate-900/80 border-slate-800 text-slate-600'}`}>
                      <div className="text-xs font-semibold">{phase}</div>
                      {detected && <div className="text-[10px] mt-1">{info!.confidence}% • {info!.techniques} techniques</div>}
                      {isHere && <div className="absolute -top-5 left-1/2 -translate-x-1/2 text-[10px] text-red-300">YOU ARE HERE</div>}
                    </div>
                    {idx < killChain.length - 1 && <div className="text-slate-600">→</div>}
                  </React.Fragment>
                );
              })}
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-5 gap-4">
            <div className="xl:col-span-3 bg-slate-900/45 border border-white/10 rounded-2xl p-4 overflow-x-auto">
              <div className="min-w-[1100px]">
                <div className="grid grid-cols-14 gap-2 text-[10px] text-slate-400 mb-2">
                  {killChain.map((k) => <div key={k} className="text-center truncate">{k.slice(0, 8)}</div>)}
                </div>
                <div className="space-y-2">
                  {Array.from({ length: maxRows }).map((_, rowIdx) => (
                    <div key={rowIdx} className="grid grid-cols-14 gap-2">
                      {killChain.map((phase) => {
                        const tactic = classification.tactics.find((t) => t.tacticName === phase);
                        const tech = tactic?.techniques[rowIdx];
                        if (!tech) {
                          return <div key={`${phase}-${rowIdx}`} className="h-14 rounded border border-slate-800 bg-slate-900/70" />;
                        }
                        return (
                          <button
                            key={`${phase}-${tech.techniqueId}-${rowIdx}`}
                            onClick={() => openTechnique(tech, phase)}
                            className={`h-14 rounded border p-1 text-left ${sevColor(tech.severity)}`}
                            style={{ opacity: Math.max(0.35, tech.confidence / 100) }}
                          >
                            <div className="text-[10px] font-mono truncate">{tech.techniqueId}</div>
                            <div className="text-[10px] truncate">{tech.techniqueName}</div>
                          </button>
                        );
                      })}
                    </div>
                  ))}
                </div>
                <div className="mt-3 text-xs text-slate-400">Legend: color = severity, opacity = confidence.</div>
              </div>
            </div>

            <div className="xl:col-span-2 relative">
              <AnimatePresence>
                {selectedTechnique && (
                  <motion.div
                    initial={{ x: 80, opacity: 0 }}
                    animate={{ x: 0, opacity: 1 }}
                    exit={{ x: 80, opacity: 0 }}
                    className="bg-slate-900/60 border border-white/10 rounded-2xl p-4 sticky top-0"
                  >
                    <div className="flex justify-between items-start gap-2">
                      <div>
                        <h3 className="text-lg font-bold text-slate-100">{selectedTechnique.techniqueId} • {selectedTechnique.techniqueName}</h3>
                        <p className="text-xs text-slate-400 mt-1">Tactic: {selectedTechnique.tacticName}</p>
                      </div>
                      <button onClick={() => setSelectedTechnique(null)} className="text-slate-400 hover:text-slate-200"><X className="w-4 h-4" /></button>
                    </div>

                    <div className="mt-3 space-y-3 text-sm">
                      <div className="flex gap-2 flex-wrap">
                        <span className={`px-2 py-1 rounded border text-xs ${sevColor(selectedTechnique.severity)}`}>{selectedTechnique.severity}</span>
                        <span className="px-2 py-1 rounded border border-cyan-500/30 text-cyan-300 text-xs">Confidence {selectedTechnique.confidence}%</span>
                      </div>
                      <div>
                        <p className="text-slate-400 text-xs">Evidence</p>
                        <p className="text-slate-200">{selectedTechnique.evidence}</p>
                      </div>
                      <div>
                        <p className="text-slate-400 text-xs">Mitigation</p>
                        <p className="text-slate-200">{selectedTechnique.mitigation}</p>
                      </div>
                      <div>
                        <p className="text-slate-400 text-xs">Detection Tip</p>
                        <p className="text-slate-200">{selectedTechnique.detectionTip}</p>
                      </div>
                      <div>
                        <p className="text-slate-400 text-xs">MITRE URL</p>
                        <a href={selectedTechniqueDetail?.mitreUrl || `https://attack.mitre.org/techniques/${selectedTechnique.techniqueId}/`} target="_blank" rel="noreferrer" className="text-cyan-300 inline-flex items-center gap-1">
                          View on MITRE ATT&CK <ExternalLink className="w-3 h-3" />
                        </a>
                      </div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>

          <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-5">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <div>
                <h3 className="text-sm font-semibold text-slate-400">Threat Actor Profile</h3>
                <p className="text-slate-100 mt-1">{classification.threatActorProfile}</p>
              </div>
              <div className="lg:col-span-2">
                <h3 className="text-sm font-semibold text-slate-400">Attack Summary</h3>
                <p className="text-slate-100 mt-1">{classification.attackSummary}</p>
                <p className="text-sm text-slate-300 mt-2">Attacker appears to be at: <span className="text-cyan-300">{classification.killChainStage}</span></p>
              </div>
            </div>
          </div>

          {stats && (
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
              <StatCard label="Tactics Detected" value={`${stats.tacticsDetected} / 14`} />
              <StatCard label="Techniques Mapped" value={stats.techniquesMapped} />
              <StatCard label="Highest Confidence" value={stats.highest} />
              <StatCard label="Overall Severity" value={stats.severity} highlightClass={sevColor(stats.severity)} />
            </div>
          )}

          <div className="flex flex-wrap gap-3">
            <button onClick={exportNavigatorJson} className="px-4 py-2 rounded-lg border border-cyan-500/40 bg-cyan-500/20 text-cyan-300 inline-flex items-center gap-2">
              <Download className="w-4 h-4" /> Export ATT&CK Navigator JSON
            </button>
            <button onClick={copySummary} className="px-4 py-2 rounded-lg border border-white/15 bg-slate-900/60 text-slate-200 inline-flex items-center gap-2">
              <Copy className="w-4 h-4" /> Copy Summary
            </button>
            <button onClick={saveToForensics} className="px-4 py-2 rounded-lg border border-emerald-500/40 bg-emerald-500/20 text-emerald-300 inline-flex items-center gap-2">
              <Save className="w-4 h-4" /> Save to Forensics Timeline
            </button>
          </div>
        </>
      )}
    </div>
  );
};

const StatCard: React.FC<{ label: string; value: string | number; highlightClass?: string }> = ({ label, value, highlightClass }) => (
  <div className="bg-slate-900/45 border border-white/10 rounded-xl p-4">
    <div className={`text-sm font-semibold ${highlightClass || 'text-slate-100'}`}>{value}</div>
    <div className="text-xs text-slate-500 mt-1">{label}</div>
  </div>
);

export default MitreAttackMapper;
