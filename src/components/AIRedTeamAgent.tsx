import React, { useEffect, useMemo, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import {
  AlertTriangle,
  Bot,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ClipboardList,
  Crosshair,
  Eye,
  EyeOff,
  FileSearch,
  Globe,
  Loader2,
  Lock,
  Network,
  Search,
  Server,
  ShieldAlert,
  Target,
  XCircle,
  Zap
} from 'lucide-react';
import { toast } from 'react-hot-toast';
import { ScanType, AgentReport, AgentStep } from '../types/types';
import { deleteSetting, getSetting, saveSetting } from '../services/db';
import { useAgentMission } from '../hooks/useAgentMission';

interface AIRedTeamAgentProps {
  onNavigate?: (type: ScanType) => void;
}

type AgentMode = 'passive' | 'active' | 'full';

const toolLabelMap: Record<string, string> = {
  port_scan: 'Port Scan',
  ssl_check: 'SSL Certificate Check',
  headers_check: 'Security Headers Check',
  dns_check: 'DNS Integrity Check',
  subdomain_enum: 'Subdomain Enumeration',
  cve_search: 'CVE Intelligence Search',
  vuln_analyze: 'Vulnerability Analysis',
  darkweb_domain: 'Dark Web Domain Check',
  attack_classify: 'MITRE ATT&CK Classification',
  ip_reputation: 'IP Reputation Check',
  ir_generate: 'IR Playbook Generation'
};

const toolIconMap: Record<string, React.ComponentType<{ className?: string }>> = {
  port_scan: Network,
  ssl_check: Lock,
  headers_check: FileSearch,
  dns_check: Server,
  subdomain_enum: Search,
  cve_search: ShieldAlert,
  vuln_analyze: ShieldAlert,
  darkweb_domain: EyeOff,
  attack_classify: Crosshair,
  ip_reputation: Globe,
  ir_generate: ClipboardList
};

const suggestedObjectives = [
  'Find open ports',
  'Check breach exposure',
  'Map attack surface',
  'Verify security headers',
  'Enumerate subdomains',
  'Generate IR plan'
];

const modeCards: Array<{
  mode: AgentMode;
  title: string;
  desc: string;
  color: string;
  tools: string;
  icon: React.ComponentType<{ className?: string }>;
}> = [
  {
    mode: 'passive',
    title: 'Passive Recon',
    desc: 'OSINT only. No active connections to target.',
    color: 'border-emerald-500/40 bg-emerald-500/10',
    tools: 'SSL, Headers, DNS, Subdomains, CVE Search, Dark Web',
    icon: Eye
  },
  {
    mode: 'active',
    title: 'Active Scan',
    desc: 'Includes port scanning and IP reputation checks.',
    color: 'border-orange-500/40 bg-orange-500/10',
    tools: 'All passive + Port Scanner, IP Reputation',
    icon: Zap
  },
  {
    mode: 'full',
    title: 'Full Assessment',
    desc: 'Complete attack surface mapping with AI classification.',
    color: 'border-red-500/40 bg-red-500/10',
    tools: 'All active + MITRE ATT&CK, IR Playbook',
    icon: Target
  }
];

const formatElapsed = (seconds: number) => {
  const h = String(Math.floor(seconds / 3600)).padStart(2, '0');
  const m = String(Math.floor((seconds % 3600) / 60)).padStart(2, '0');
  const s = String(seconds % 60).padStart(2, '0');
  return `${h}:${m}:${s}`;
};

const isValidTarget = (value: string) => {
  const v = value.trim();
  const domainRegex = /^(?!:\/\/)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$/;
  const ipRegex = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
  return domainRegex.test(v) || ipRegex.test(v);
};

const riskColor = (score: number) => {
  if (score <= 30) return 'text-emerald-400 border-emerald-500/40';
  if (score <= 60) return 'text-yellow-400 border-yellow-500/40';
  if (score <= 80) return 'text-orange-400 border-orange-500/40';
  return 'text-red-400 border-red-500/40';
};

const ratingBadge = (rating: AgentReport['overallRiskRating']) => {
  if (rating === 'Critical') return 'bg-red-500/20 border-red-500/40 text-red-300';
  if (rating === 'High') return 'bg-orange-500/20 border-orange-500/40 text-orange-300';
  if (rating === 'Medium') return 'bg-yellow-500/20 border-yellow-500/40 text-yellow-300';
  if (rating === 'Low') return 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300';
  return 'bg-cyan-500/20 border-cyan-500/40 text-cyan-300';
};

const AIRedTeamAgent: React.FC<AIRedTeamAgentProps> = ({ onNavigate }) => {
  const [target, setTarget] = useState('');
  const [agentMode, setAgentMode] = useState<AgentMode>('passive');
  const [objectives, setObjectives] = useState<string[]>([]);
  const [objectiveInput, setObjectiveInput] = useState('');
  const [permissionConfirmed, setPermissionConfirmed] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [maxSteps, setMaxSteps] = useState(8);
  const [timeoutPerStepSec, setTimeoutPerStepSec] = useState(30);
  const [autoGenerateIR, setAutoGenerateIR] = useState(true);
  const [saveToForensics, setSaveToForensics] = useState(true);
  const [expandedSteps, setExpandedSteps] = useState<Set<number>>(new Set());
  const [expandedFindings, setExpandedFindings] = useState<Set<number>>(new Set());

  const thoughtRef = useRef<HTMLDivElement | null>(null);

  const {
    agentState,
    plan,
    steps,
    thoughtLog,
    finalReport,
    riskScore,
    elapsedTime,
    currentToolName,
    error,
    isAborted,
    isRunning,
    runMission,
    abortMission,
    resetMission
  } = useAgentMission();

  useEffect(() => {
    const loadPrefill = async () => {
      try {
        const prefillRaw = localStorage.getItem('agent_target_prefill');
        if (prefillRaw && !target.trim()) {
          setTarget(prefillRaw);
          localStorage.removeItem('agent_target_prefill');
        }
      } catch {
        // Non-blocking local prefill.
      }
    };
    loadPrefill();
  }, [target]);

  useEffect(() => {
    const loadDbPrefill = async () => {
      try {
        const payload = await getSetting('agent_prefill_payload');
        if (!payload?.value) return;
        const value = payload.value as any;
        if (value?.target && !target.trim()) setTarget(String(value.target));
        if (Array.isArray(value?.objectives) && value.objectives.length > 0) {
          setObjectives(value.objectives.map(String).slice(0, 6));
        }
        if (value?.agentMode && ['passive', 'active', 'full'].includes(String(value.agentMode))) {
          setAgentMode(value.agentMode);
        }
        await deleteSetting('agent_prefill_payload');
      } catch (prefillErr) {
        console.error('Failed to load Red Team prefill:', prefillErr);
      }
    };
    loadDbPrefill();
  }, [target]);

  useEffect(() => {
    if (!thoughtRef.current) return;
    thoughtRef.current.scrollTop = thoughtRef.current.scrollHeight;
  }, [thoughtLog]);

  const stepProgress = useMemo(() => {
    if (steps.length === 0) return 0;
    const done = steps.filter((s) => ['complete', 'failed', 'skipped'].includes(s.status)).length;
    return Math.round((done / steps.length) * 100);
  }, [steps]);

  const targetValid = isValidTarget(target);
  const canLaunch = permissionConfirmed && targetValid && !!agentMode && !isRunning;

  const statusText = useMemo(() => {
    if (agentState === 'planning') return '🧠 Planning investigation...';
    if (agentState === 'executing') return `⚡ Executing: ${toolLabelMap[currentToolName] || currentToolName || 'Tool step'}`;
    if (agentState === 'interpreting') return '🔍 Interpreting results...';
    if (agentState === 'deciding') return '🧭 Deciding next step...';
    if (agentState === 'synthesizing') return '📊 Synthesizing final report...';
    if (agentState === 'complete') return isAborted ? '✅ Mission stopped. Partial results ready.' : '✅ Mission complete.';
    if (agentState === 'error') return '🚨 Mission error.';
    return 'Awaiting mission launch.';
  }, [agentState, currentToolName, isAborted]);

  const addObjective = (value: string) => {
    const clean = value.trim();
    if (!clean || objectives.includes(clean)) return;
    setObjectives((prev) => [...prev, clean].slice(0, 10));
  };

  const launchMission = async () => {
    if (!canLaunch) return;
    await runMission({
      target: target.trim(),
      mode: agentMode,
      objectives,
      options: {
        maxSteps,
        timeoutPerStepMs: timeoutPerStepSec * 1000,
        autoGenerateIR,
        saveToForensicsTimeline: saveToForensics
      }
    });
  };

  const toggleStepExpand = (stepNumber: number) => {
    setExpandedSteps((prev) => {
      const next = new Set(prev);
      if (next.has(stepNumber)) next.delete(stepNumber);
      else next.add(stepNumber);
      return next;
    });
  };

  const exportReportPdf = (report: AgentReport) => {
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    let y = 16;

    const addText = (title: string, text: string) => {
      if (y > pageHeight - 30) {
        doc.addPage();
        y = 16;
      }
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(12);
      doc.text(title, 14, y);
      y += 6;
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(10);
      const lines = doc.splitTextToSize(text || 'N/A', pageWidth - 28);
      doc.text(lines, 14, y);
      y += lines.length * 5 + 4;
    };

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(18);
    doc.text(report.reportTitle || 'AI Red Team Report', 14, y);
    y += 8;
    addText('Executive Summary', report.executiveSummary || '');
    addText('Conclusion', report.conclusionStatement || '');
    addText('Compliance Notes', report.complianceNotes || '');

    autoTable(doc, {
      startY: y,
      head: [['Priority', 'Finding', 'Impact', 'Recommendation']],
      body: [...report.criticalFindings]
        .sort((a, b) => a.priority - b.priority)
        .map((f) => [String(f.priority), f.finding, f.impact, f.recommendation]),
      styles: { fontSize: 9 },
      headStyles: { fillColor: [6, 182, 212] }
    });

    doc.addPage();
    addText('Immediate Actions', report.immediateActions.join(' | '));
    addText('Short-Term Actions', report.shortTermActions.join(' | '));
    addText('Long-Term Actions', report.longTermActions.join(' | '));
    addText('MITRE Tactics', report.mitreTacticsDetected.join(', '));

    doc.save(`red-team-agent-report-${Date.now()}.pdf`);
  };

  const persistReport = async () => {
    if (!finalReport) return;
    try {
      const key = `agent_report_${Date.now()}`;
      await saveSetting(key, {
        target: target.trim(),
        mode: agentMode,
        report: finalReport,
        steps,
        createdAt: Date.now()
      });
      toast.success('Agent report saved');
    } catch (saveErr: any) {
      toast.error(saveErr?.message || 'Failed to save report');
    }
  };

  const mapToAttack = async () => {
    if (!finalReport) return;
    try {
      await saveSetting('mitre_prefill_payload', {
        sourceModule: 'AI Red Team Agent',
        findings: `${finalReport.executiveSummary}\n\n${finalReport.criticalFindings.map((f) => `- ${f.finding}`).join('\n')}`,
        indicators: finalReport.mitreTacticsDetected,
        createdAt: Date.now()
      });
      if (onNavigate) onNavigate(ScanType.MITRE_ATTACK);
    } catch (err) {
      console.error('Failed to prefill ATT&CK:', err);
    }
  };

  const openIRPlaybook = async () => {
    if (!finalReport) return;
    try {
      await saveSetting('ir_playbook_prefill', {
        incidentType: 'Automated Red Team Findings',
        severity:
          finalReport.overallRiskRating === 'Informational'
            ? 'Low'
            : finalReport.overallRiskRating,
        findings: `${finalReport.executiveSummary}\n\n${finalReport.criticalFindings
          .map((f) => `${f.finding}: ${f.impact}. Recommendation: ${f.recommendation}`)
          .join('\n')}`,
        affectedSystems: [target.trim()]
      });
      if (onNavigate) onNavigate(ScanType.IR_PLAYBOOK);
    } catch (err) {
      console.error('Failed to prefill IR Playbook:', err);
    }
  };

  const viewForensicsTimeline = () => {
    if (onNavigate) onNavigate(ScanType.FORENSICS_TIMELINE);
  };

  const renderRiskGauge = () => {
    const radius = 70;
    const circumference = 2 * Math.PI * radius;
    const progress = (Math.max(0, Math.min(100, riskScore)) / 100) * circumference;
    const stroke =
      riskScore <= 30 ? '#22c55e' : riskScore <= 60 ? '#eab308' : riskScore <= 80 ? '#f97316' : '#ef4444';
    return (
      <div className="bg-slate-950/50 border border-white/10 rounded-xl p-4">
        <h4 className="text-sm text-slate-300 font-semibold mb-3">Live Risk Meter</h4>
        <div className="flex items-center gap-4">
          <div className="relative w-[170px] h-[170px]">
            <svg width="170" height="170" viewBox="0 0 170 170">
              <circle cx="85" cy="85" r={radius} stroke="rgba(148,163,184,0.2)" strokeWidth="14" fill="none" />
              <motion.circle
                cx="85"
                cy="85"
                r={radius}
                stroke={stroke}
                strokeWidth="14"
                fill="none"
                strokeLinecap="round"
                transform="rotate(-90 85 85)"
                strokeDasharray={circumference}
                animate={{ strokeDashoffset: circumference - progress }}
                initial={{ strokeDashoffset: circumference }}
                transition={{ duration: 0.5, ease: 'easeOut' }}
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <div className="text-3xl font-bold text-slate-100">{riskScore}</div>
              <div className="text-xs text-slate-500">/100</div>
            </div>
          </div>
          <div>
            <div className={`inline-flex px-3 py-1 rounded-full border text-xs font-semibold ${riskColor(riskScore)}`}>
              {riskScore <= 30 ? 'Low Risk' : riskScore <= 60 ? 'Moderate Risk' : riskScore <= 80 ? 'High Risk' : 'Critical Risk'}
            </div>
            <p className="text-slate-400 text-xs mt-2">Risk updates after each interpreted step.</p>
          </div>
        </div>
      </div>
    );
  };

  const showRunningView = ['planning', 'executing', 'interpreting', 'deciding', 'synthesizing'].includes(agentState);
  const showComplete = agentState === 'complete' && finalReport;

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="bg-slate-900/55 border border-cyan-500/20 rounded-2xl p-6 backdrop-blur-xl">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-start gap-4">
            <motion.div
              animate={{ rotate: [0, 8, -8, 0] }}
              transition={{ duration: 3, repeat: Infinity, ease: 'easeInOut' }}
              className="p-3 rounded-xl bg-cyan-500/20 border border-cyan-500/40"
            >
              <Bot className="w-8 h-8 text-cyan-300" />
            </motion.div>
            <div>
              <h1 className="text-3xl font-bold text-slate-100">AI Red Team Agent</h1>
              <p className="text-sm text-slate-400 mt-1">
                Autonomous security investigation — chain tools, interpret results, synthesize reports
              </p>
            </div>
          </div>
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-cyan-400/60 bg-cyan-500/10 text-cyan-300 text-xs font-bold tracking-widest shadow-[0_0_20px_rgba(6,182,212,0.35)]">
            <span className="w-2 h-2 rounded-full bg-cyan-300 animate-pulse" />
            AUTONOMOUS
          </div>
        </div>

        <div className="mt-5 p-4 rounded-xl border border-amber-500/40 bg-amber-500/10 text-amber-100">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 mt-0.5 text-amber-300" />
            <div className="flex-1">
              <p className="text-sm">
                Active mode performs real network requests against the target. Only scan systems you own or have explicit permission to test.
              </p>
              <label className="mt-3 inline-flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={permissionConfirmed}
                  onChange={(e) => setPermissionConfirmed(e.target.checked)}
                  className="accent-cyan-500"
                />
                I confirm I have permission to scan this target
              </label>
            </div>
          </div>
        </div>
      </motion.div>

      {!showRunningView && !showComplete && (
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="bg-slate-900/45 border border-white/10 rounded-2xl p-6 backdrop-blur-xl">
          <div className="flex items-center justify-between mb-5 flex-wrap gap-2">
            <h2 className="text-xl font-bold text-slate-100">Configure Agent Mission</h2>
            <button
              onClick={() => {
                setTarget('target.local');
                setAgentMode('full');
                setObjectives(['Find open ports', 'Map attack surface', 'Verify security headers', 'Check breach exposure']);
                setPermissionConfirmed(true);
                toast.success('Sample Red Team configuration loaded.');
              }}
              className="px-4 py-2 rounded-lg bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/30 text-xs font-semibold transition-all"
            >
              Load Sample Data
            </button>
          </div>

          <div className="space-y-5">
            <div>
              <label className="text-sm text-slate-300 font-semibold mb-2 block">Target</label>
              <div className="relative">
                <Globe className="w-4 h-4 text-slate-500 absolute left-3 top-3.5" />
                <input
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="Enter domain (e.g. example.com) or IP address"
                  className="w-full pl-10 pr-10 py-3 rounded-lg bg-slate-950/60 border border-white/10 text-slate-100 focus:outline-none focus:border-cyan-500/50"
                />
                <div className="absolute right-3 top-3">
                  {target.trim().length === 0 ? null : targetValid ? (
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  ) : (
                    <XCircle className="w-5 h-5 text-red-400" />
                  )}
                </div>
              </div>
            </div>

            <div>
              <label className="text-sm text-slate-300 font-semibold mb-2 block">Agent Mode</label>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {modeCards.map((card) => (
                  <button
                    key={card.mode}
                    onClick={() => setAgentMode(card.mode)}
                    className={`text-left p-4 rounded-xl border transition-all ${
                      agentMode === card.mode ? `${card.color} shadow-[0_0_20px_rgba(56,189,248,0.18)]` : 'border-white/10 bg-slate-950/40 hover:border-cyan-500/30'
                    }`}
                  >
                    <div className="flex items-center gap-2 mb-2">
                      <card.icon className="w-5 h-5 text-cyan-300" />
                      <h3 className="font-bold text-slate-100">{card.title}</h3>
                    </div>
                    <p className="text-xs text-slate-400">{card.desc}</p>
                    <p className="text-[11px] text-slate-500 mt-2">{card.tools}</p>
                  </button>
                ))}
              </div>
            </div>

            <div>
              <label className="text-sm text-slate-300 font-semibold mb-2 block">Custom Objectives</label>
              <input
                value={objectiveInput}
                onChange={(e) => setObjectiveInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    addObjective(objectiveInput);
                    setObjectiveInput('');
                  }
                }}
                placeholder="Add objective and press Enter (e.g. 'Check SSL expiry')"
                className="w-full px-3 py-2.5 rounded-lg bg-slate-950/60 border border-white/10 text-slate-100 focus:outline-none focus:border-cyan-500/50"
              />
              <div className="flex flex-wrap gap-2 mt-2">
                {objectives.map((obj) => (
                  <button
                    key={obj}
                    onClick={() => setObjectives((prev) => prev.filter((item) => item !== obj))}
                    className="px-2.5 py-1 rounded-full text-xs border border-cyan-500/40 bg-cyan-500/10 text-cyan-300"
                  >
                    {obj} ×
                  </button>
                ))}
              </div>
              <div className="flex flex-wrap gap-2 mt-3">
                {suggestedObjectives.map((obj) => (
                  <button
                    key={obj}
                    onClick={() => addObjective(obj)}
                    className="px-2.5 py-1 rounded-full text-xs border border-white/10 bg-slate-800/60 text-slate-300 hover:border-cyan-500/40"
                  >
                    {obj}
                  </button>
                ))}
              </div>
            </div>

            <div className="rounded-xl border border-white/10 bg-slate-950/40">
              <button
                onClick={() => setShowAdvanced((prev) => !prev)}
                className="w-full px-4 py-3 flex items-center justify-between text-slate-200 text-sm font-semibold"
              >
                <span>Advanced Options</span>
                {showAdvanced ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
              </button>
              {showAdvanced && (
                <div className="px-4 pb-4 space-y-4 border-t border-white/10">
                  <div>
                    <label className="text-xs text-slate-400">Max steps: {maxSteps}</label>
                    <input
                      type="range"
                      min={5}
                      max={15}
                      value={maxSteps}
                      onChange={(e) => setMaxSteps(Number(e.target.value))}
                      className="w-full mt-1"
                    />
                  </div>
                  <div>
                    <label className="text-xs text-slate-400">Timeout per step: {timeoutPerStepSec}s</label>
                    <input
                      type="range"
                      min={10}
                      max={60}
                      value={timeoutPerStepSec}
                      onChange={(e) => setTimeoutPerStepSec(Number(e.target.value))}
                      className="w-full mt-1"
                    />
                  </div>
                  <label className="flex items-center justify-between text-sm text-slate-300">
                    Auto-generate IR playbook on critical findings
                    <input type="checkbox" checked={autoGenerateIR} onChange={(e) => setAutoGenerateIR(e.target.checked)} className="accent-cyan-500" />
                  </label>
                  <label className="flex items-center justify-between text-sm text-slate-300">
                    Save results to Forensics Timeline
                    <input type="checkbox" checked={saveToForensics} onChange={(e) => setSaveToForensics(e.target.checked)} className="accent-cyan-500" />
                  </label>
                </div>
              )}
            </div>

            <button
              onClick={launchMission}
              disabled={!canLaunch}
              className="w-full py-3 rounded-xl border border-cyan-400/40 bg-gradient-to-r from-cyan-500/20 to-purple-500/20 text-cyan-200 font-bold hover:from-cyan-500/30 hover:to-purple-500/30 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              🤖 Launch Agent Mission
            </button>
          </div>
        </motion.div>
      )}

      {showRunningView && (
        <div className="space-y-4">
          <div className="bg-slate-900/50 border border-white/10 rounded-2xl p-4 backdrop-blur-xl">
            <div className="flex flex-wrap items-center gap-4 justify-between">
              <div className="flex items-center gap-3">
                <motion.div animate={{ scale: [1, 1.12, 1] }} transition={{ repeat: Infinity, duration: 1.2 }}>
                  <Bot className="w-6 h-6 text-cyan-300" />
                </motion.div>
                <div>
                  <p className="text-slate-100 font-semibold">{statusText}</p>
                  <p className="text-xs text-slate-400">
                    Elapsed: {formatElapsed(elapsedTime)} · {steps.filter((s) => s.status === 'complete').length}/{steps.length} completed
                  </p>
                </div>
              </div>
              <button
                onClick={() => {
                  if (isRunning) abortMission();
                }}
                className="px-3 py-1.5 rounded-lg border border-red-500/40 bg-red-500/10 text-red-300 text-sm font-semibold"
              >
                {isRunning ? 'Abort Mission' : isAborted ? 'View Partial Results' : 'Mission Controls'}
              </button>
            </div>
            <div className="h-2 bg-slate-800 rounded-full mt-4 overflow-hidden">
              <motion.div
                className="h-full bg-gradient-to-r from-cyan-500 to-blue-500"
                animate={{ width: `${stepProgress}%` }}
                transition={{ duration: 0.35 }}
              />
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-5 gap-4">
            <div className="xl:col-span-2 bg-black/80 border border-emerald-500/30 rounded-2xl p-4">
              <h3 className="text-sm uppercase tracking-wider text-emerald-400 font-semibold mb-3">Agent Thought Stream</h3>
              <div ref={thoughtRef} className="h-[520px] overflow-y-auto pr-1 space-y-2 font-mono text-xs">
                {thoughtLog.map((line, idx) => (
                  <motion.div key={`${line}-${idx}`} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} className="text-emerald-300">
                    <span className={line.includes('🎯') ? 'text-cyan-300 italic' : ''}>{line}</span>
                  </motion.div>
                ))}
              </div>
            </div>

            <div className="xl:col-span-3 space-y-4">
              <div className="space-y-3">
                {steps.map((step) => {
                  const Icon = toolIconMap[step.toolName] || Bot;
                  const open = expandedSteps.has(step.stepNumber);
                  const duration =
                    step.startedAt && step.completedAt
                      ? `${((step.completedAt - step.startedAt) / 1000).toFixed(1)}s`
                      : step.startedAt
                        ? 'Running...'
                        : '';
                  const statusClass =
                    step.status === 'running'
                      ? 'border-blue-500/40 bg-blue-500/10'
                      : step.status === 'complete'
                        ? 'border-emerald-500/30 bg-emerald-500/10'
                        : step.status === 'failed'
                          ? 'border-red-500/30 bg-red-500/10'
                          : step.status === 'skipped'
                            ? 'border-yellow-500/30 bg-yellow-500/10'
                            : 'border-white/10 bg-slate-900/40';

                  return (
                    <div key={step.stepNumber} className={`rounded-xl border p-3 ${statusClass}`}>
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex items-start gap-3">
                          <div className="w-8 h-8 rounded-full border border-white/20 flex items-center justify-center text-xs font-bold text-slate-100">
                            {step.stepNumber}
                          </div>
                          <div>
                            <p className="text-slate-100 font-semibold inline-flex items-center gap-2">
                              <Icon className="w-4 h-4 text-cyan-300" />
                              {toolLabelMap[step.toolName] || step.toolName}
                              {step.status === 'running' && <Loader2 className="w-3.5 h-3.5 animate-spin text-blue-300" />}
                            </p>
                            <p className="text-xs text-slate-400 mt-1">{step.rationale}</p>
                            {step.status === 'complete' && step.interpretation && step.interpretation.keyFindings.length > 0 && (
                              <div className="mt-2 text-xs text-slate-300 space-y-1">
                                {step.interpretation.keyFindings.slice(0, 3).map((finding, i) => (
                                  <p key={i}>• {finding}</p>
                                ))}
                              </div>
                            )}
                            {step.status === 'failed' && (
                              <p className="text-xs text-red-300 mt-2">
                                {(step.actualOutput && (step.actualOutput.error || step.actualOutput.message)) || 'Step failed'}
                              </p>
                            )}
                          </div>
                        </div>
                        <div className="text-right">
                          <span className="text-[10px] px-2 py-0.5 rounded-full border border-white/15 text-slate-300 uppercase">
                            {step.status}
                          </span>
                          {duration && <p className="text-[10px] text-slate-500 mt-1">took {duration}</p>}
                          <button onClick={() => toggleStepExpand(step.stepNumber)} className="text-xs text-cyan-300 mt-2">
                            {open ? 'Hide JSON' : 'Expand JSON'}
                          </button>
                        </div>
                      </div>
                      <AnimatePresence>
                        {open && (
                          <motion.pre
                            initial={{ opacity: 0, height: 0 }}
                            animate={{ opacity: 1, height: 'auto' }}
                            exit={{ opacity: 0, height: 0 }}
                            className="mt-3 max-h-56 overflow-auto bg-slate-950/80 border border-white/10 rounded-lg p-3 text-xs text-slate-300"
                          >
                            {JSON.stringify(step.actualOutput, null, 2)}
                          </motion.pre>
                        )}
                      </AnimatePresence>
                    </div>
                  );
                })}
              </div>

              {renderRiskGauge()}
            </div>
          </div>
        </div>
      )}

      {showComplete && finalReport && (
        <div className="space-y-5">
          <div className={`rounded-2xl border p-5 ${ratingBadge(finalReport.overallRiskRating)}`}>
            <h2 className="text-2xl font-bold">
              ✅ Mission Complete — {finalReport.overallRiskRating} Risk Detected
            </h2>
            <p className="text-sm mt-1">
              Investigated {steps.length} attack vectors in {formatElapsed(elapsedTime)}
            </p>
          </div>

          <div className="bg-slate-900/50 border border-white/10 rounded-2xl p-6 space-y-6">
            <section>
              <h3 className="text-lg font-bold text-slate-100 mb-2">Executive Summary</h3>
              <p className="text-slate-300 leading-relaxed">{finalReport.executiveSummary}</p>
            </section>

            <section className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="bg-slate-950/60 border border-white/10 rounded-xl p-4 flex items-center gap-4">
                <div className="text-5xl font-black text-cyan-300">{finalReport.riskScore}</div>
                <div>
                  <div className={`inline-flex px-3 py-1 rounded-full border text-xs font-semibold ${ratingBadge(finalReport.overallRiskRating)}`}>
                    {finalReport.overallRiskRating}
                  </div>
                  <p className="text-sm text-slate-300 mt-2">{finalReport.conclusionStatement}</p>
                </div>
              </div>
              <div className="bg-slate-950/60 border border-white/10 rounded-xl p-4">
                <h4 className="text-sm text-slate-200 font-semibold mb-2">Attack Surface Map</h4>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
                  <div className="border border-red-500/30 bg-red-500/10 rounded-lg p-3">
                    <p className="font-semibold text-red-300 mb-1">Exposed Services</p>
                    <ul className="text-slate-300 space-y-1">{finalReport.attackSurface.exposedServices.map((s, i) => <li key={i}>• {s}</li>)}</ul>
                  </div>
                  <div className="border border-orange-500/30 bg-orange-500/10 rounded-lg p-3">
                    <p className="font-semibold text-orange-300 mb-1">Weak Points</p>
                    <ul className="text-slate-300 space-y-1">{finalReport.attackSurface.weakPoints.map((s, i) => <li key={i}>• {s}</li>)}</ul>
                  </div>
                  <div className="border border-emerald-500/30 bg-emerald-500/10 rounded-lg p-3">
                    <p className="font-semibold text-emerald-300 mb-1">Strong Points</p>
                    <ul className="text-slate-300 space-y-1">{finalReport.attackSurface.strongPoints.map((s, i) => <li key={i}>• {s}</li>)}</ul>
                  </div>
                </div>
              </div>
            </section>

            <section>
              <h3 className="text-lg font-bold text-slate-100 mb-3">Critical Findings</h3>
              <div className="space-y-2">
                {[...finalReport.criticalFindings].sort((a, b) => a.priority - b.priority).map((finding, idx) => {
                  const open = expandedFindings.has(idx);
                  return (
                    <div key={`${finding.finding}-${idx}`} className="border border-white/10 rounded-xl p-3 bg-slate-950/50">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <p className="text-slate-100 font-semibold">
                            <span className="inline-flex px-2 py-0.5 rounded border border-red-500/40 text-red-300 text-xs mr-2">P{finding.priority}</span>
                            {finding.finding}
                          </p>
                          <p className="text-sm text-slate-400 mt-1">{finding.impact}</p>
                        </div>
                        <button
                          onClick={() =>
                            setExpandedFindings((prev) => {
                              const next = new Set(prev);
                              if (next.has(idx)) next.delete(idx);
                              else next.add(idx);
                              return next;
                            })
                          }
                          className="text-xs text-cyan-300"
                        >
                          {open ? 'Hide Evidence' : 'Show Evidence'}
                        </button>
                      </div>
                      {open && (
                        <div className="mt-3 space-y-2">
                          <div className="text-xs text-slate-300 bg-slate-900/60 border border-white/10 rounded p-2">{finding.evidence}</div>
                          <div className="text-xs text-amber-200 bg-amber-500/10 border border-amber-500/30 rounded p-2">
                            Recommendation: {finding.recommendation}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </section>

            <section>
              <h3 className="text-lg font-bold text-slate-100 mb-3">MITRE Tactics Detected</h3>
              <div className="flex gap-2 overflow-x-auto pb-2">
                {finalReport.mitreTacticsDetected.length === 0 ? (
                  <span className="text-sm text-slate-500">No tactics detected</span>
                ) : (
                  finalReport.mitreTacticsDetected.map((tactic) => (
                    <button
                      key={tactic}
                      onClick={mapToAttack}
                      className="px-3 py-1 rounded-full border border-cyan-500/40 bg-cyan-500/10 text-cyan-200 text-xs whitespace-nowrap"
                    >
                      {tactic}
                    </button>
                  ))
                )}
              </div>
            </section>

            <section className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="border border-red-500/30 bg-red-500/10 rounded-xl p-3">
                <p className="text-sm font-semibold text-red-300 mb-2">Do Now</p>
                <ol className="text-sm text-slate-200 list-decimal list-inside space-y-1">{finalReport.immediateActions.map((a, i) => <li key={i}>{a}</li>)}</ol>
              </div>
              <div className="border border-orange-500/30 bg-orange-500/10 rounded-xl p-3">
                <p className="text-sm font-semibold text-orange-300 mb-2">This Week</p>
                <ol className="text-sm text-slate-200 list-decimal list-inside space-y-1">{finalReport.shortTermActions.map((a, i) => <li key={i}>{a}</li>)}</ol>
              </div>
              <div className="border border-yellow-500/30 bg-yellow-500/10 rounded-xl p-3">
                <p className="text-sm font-semibold text-yellow-300 mb-2">This Month</p>
                <ol className="text-sm text-slate-200 list-decimal list-inside space-y-1">{finalReport.longTermActions.map((a, i) => <li key={i}>{a}</li>)}</ol>
              </div>
            </section>

            <section className="border border-white/10 rounded-xl p-4 bg-slate-950/40">
              <h3 className="text-lg font-bold text-slate-100 mb-2">Compliance Notes</h3>
              <p className="text-sm text-slate-300">{finalReport.complianceNotes}</p>
            </section>

            <section className="flex flex-wrap gap-2">
              <button onClick={() => exportReportPdf(finalReport)} className="px-3 py-2 rounded-lg border border-purple-500/40 bg-purple-500/10 text-purple-200 text-sm">
                Export Full Report PDF
              </button>
              <button onClick={openIRPlaybook} className="px-3 py-2 rounded-lg border border-orange-500/40 bg-orange-500/10 text-orange-200 text-sm">
                Generate IR Playbook
              </button>
              <button onClick={viewForensicsTimeline} className="px-3 py-2 rounded-lg border border-emerald-500/40 bg-emerald-500/10 text-emerald-200 text-sm">
                View in Forensics Timeline
              </button>
              <button onClick={mapToAttack} className="px-3 py-2 rounded-lg border border-cyan-500/40 bg-cyan-500/10 text-cyan-200 text-sm">
                Map to ATT&CK
              </button>
              <button
                onClick={() => {
                  resetMission();
                  setObjectives([]);
                  setExpandedFindings(new Set());
                  setExpandedSteps(new Set());
                }}
                className="px-3 py-2 rounded-lg border border-white/20 bg-slate-900/50 text-slate-200 text-sm"
              >
                Run New Mission
              </button>
              <button onClick={persistReport} className="px-3 py-2 rounded-lg border border-cyan-500/40 bg-cyan-500/10 text-cyan-200 text-sm">
                Save Report
              </button>
            </section>
          </div>
        </div>
      )}

      {agentState === 'error' && (
        <div className="border border-red-500/40 bg-red-500/10 rounded-xl p-4 text-red-200">
          <p className="font-semibold">Mission Error</p>
          <p className="text-sm mt-1">{error || 'Unexpected mission failure.'}</p>
        </div>
      )}
    </div>
  );
};

export default AIRedTeamAgent;
