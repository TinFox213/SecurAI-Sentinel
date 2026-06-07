import React, { useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import jsPDF from 'jspdf';
import {
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  ClipboardList,
  Copy,
  Download,
  Loader2,
  Save,
  Trash2
} from 'lucide-react';
import { toast } from 'react-hot-toast';
import { IRPlaybook, IRPhase, IRStep, ScanType, StepStatus } from '../types/types';
import { db, deleteSetting, getAllScans, getSetting, saveSetting } from '../services/db';
import { logForensicsEvent } from '../utils/forensicsLogger';

interface SavedPlaybookEntry {
  key: string;
  playbook: IRPlaybook;
}

interface QuickLoadItem {
  label: string;
  value: string;
}

const incidentTypeOptions = [
  'Ransomware',
  'Data Breach',
  'Phishing Attack',
  'Malware Infection',
  'DDoS Attack',
  'Insider Threat',
  'Supply Chain Attack',
  'Zero-Day Exploit',
  'SQL Injection',
  'Credential Theft',
  'APT Intrusion',
  'Custom'
];

const severityOptions: Array<'Critical' | 'High' | 'Medium' | 'Low'> = ['Critical', 'High', 'Medium', 'Low'];

const statusClass: Record<StepStatus, string> = {
  pending: 'border-slate-700 bg-slate-900/50',
  in_progress: 'border-blue-500/40 bg-blue-500/10 animate-pulse',
  completed: 'border-emerald-500/40 bg-emerald-500/10',
  skipped: 'border-slate-600 bg-slate-800/50'
};

function calculateOverallProgress(playbook: IRPlaybook): number {
  const allSteps = playbook.phases.flatMap((phase) => phase.steps);
  if (allSteps.length === 0) return 0;
  const completed = allSteps.filter((step) => step.status === 'completed').length;
  return Math.round((completed / allSteps.length) * 100);
}

function countStepStats(playbook: IRPlaybook) {
  const allSteps = playbook.phases.flatMap((phase) => phase.steps);
  return {
    total: allSteps.length,
    completed: allSteps.filter((step) => step.status === 'completed').length
  };
}

function cycleStatus(status: StepStatus): StepStatus {
  if (status === 'pending') return 'in_progress';
  if (status === 'in_progress') return 'completed';
  if (status === 'completed') return 'pending';
  return 'pending';
}

function normalizePlaybook(playbook: IRPlaybook): IRPlaybook {
  const normalizedPhases = (playbook.phases || []).map((phase, phaseIdx) => ({
    ...phase,
    phaseId: Number(phase.phaseId || phaseIdx + 1),
    isExpanded: Boolean(phase.isExpanded),
    steps: (phase.steps || []).map((step, stepIdx) => ({
      ...step,
      stepId: String(step.stepId || `P${phaseIdx + 1}-S${stepIdx + 1}`),
      status: (step.status || 'pending') as StepStatus,
      completedAt: step.completedAt || null,
      completedBy: step.completedBy || '',
      notes: step.notes || '',
      toolsRequired: step.toolsRequired || [],
      bashCommand: step.bashCommand || null
    }))
  }));

  const normalized = {
    ...playbook,
    phases: normalizedPhases,
    createdAt: Number(playbook.createdAt || Date.now()),
    lastUpdated: Number(playbook.lastUpdated || Date.now()),
    communicationPlan: {
      internalNotifications: playbook.communicationPlan?.internalNotifications || [],
      externalNotifications: playbook.communicationPlan?.externalNotifications || [],
      regulatoryRequirements: playbook.communicationPlan?.regulatoryRequirements || []
    },
    lessonsLearned: playbook.lessonsLearned || [],
    references: playbook.references || []
  };
  return {
    ...normalized,
    overallProgress: calculateOverallProgress(normalized)
  };
}

const IncidentResponsePlaybook: React.FC = () => {
  const [incidentType, setIncidentType] = useState<string>('Ransomware');
  const [customIncidentType, setCustomIncidentType] = useState('');
  const [severity, setSeverity] = useState<'Critical' | 'High' | 'Medium' | 'Low'>('High');
  const [affectedSystemsInput, setAffectedSystemsInput] = useState('');
  const [affectedSystems, setAffectedSystems] = useState<string[]>([]);
  const [findings, setFindings] = useState('');
  const [organizationContext, setOrganizationContext] = useState('');
  const [quickLoads, setQuickLoads] = useState<QuickLoadItem[]>([]);
  const [savedPlaybooks, setSavedPlaybooks] = useState<SavedPlaybookEntry[]>([]);
  const [activePlaybook, setActivePlaybook] = useState<IRPlaybook | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [newLesson, setNewLesson] = useState('');
  const [commChecks, setCommChecks] = useState<Record<string, boolean>>({});

  const playbookStats = useMemo(() => (activePlaybook ? countStepStats(activePlaybook) : null), [activePlaybook]);

  const activeIncidentType = incidentType === 'Custom' ? customIncidentType.trim() || 'Custom Incident' : incidentType;

  const loadSavedPlaybooks = async () => {
    const rows = await db.settings.where('id').startsWith('ir_playbook_').toArray();
    const mapped = rows
      .map((row) => {
        try {
          const playbook = normalizePlaybook(row.value as IRPlaybook);
          return { key: row.id, playbook };
        } catch {
          return null;
        }
      })
      .filter(Boolean) as SavedPlaybookEntry[];
    mapped.sort((a, b) => b.playbook.lastUpdated - a.playbook.lastUpdated);
    setSavedPlaybooks(mapped);
  };

  const loadQuickFindings = async () => {
    const scans = await getAllScans();
    const lastByType = new Map<string, string>();

    scans.forEach((scan) => {
      if (!lastByType.has(scan.scanType)) {
        const value = `[${scan.scanType}] ${scan.rawData}\n\nSummary: ${scan.analysisResult?.summary || 'N/A'}`;
        lastByType.set(scan.scanType, value);
      }
    });

    const candidates: Array<{ type: ScanType; label: string }> = [
      { type: ScanType.PORT_SCAN, label: 'Load Last Port Scan' },
      { type: ScanType.MALWARE, label: 'Load Last Malware Analysis' },
      { type: ScanType.PHISHING, label: 'Load Last Phishing Detection' },
      { type: ScanType.GENERAL_LOG, label: 'Load Last General Logs' },
      { type: ScanType.PACKET_ANALYZER, label: 'Load Last Packet Analyzer' }
    ];

    const items = candidates
      .map((candidate) => ({
        label: candidate.label,
        value: lastByType.get(candidate.type) || ''
      }))
      .filter((item) => item.value.length > 0);
    setQuickLoads(items);
  };

  useEffect(() => {
    loadSavedPlaybooks();
    loadQuickFindings();
  }, []);

  useEffect(() => {
    const loadPrefill = async () => {
      try {
        const payload = await getSetting('ir_playbook_prefill');
        if (!payload?.value) return;
        const value = payload.value as {
          incidentType?: string;
          severity?: 'Critical' | 'High' | 'Medium' | 'Low';
          findings?: string;
          affectedSystems?: string[];
        };

        if (value.incidentType) {
          if (incidentTypeOptions.includes(value.incidentType)) {
            setIncidentType(value.incidentType);
          } else {
            setIncidentType('Custom');
            setCustomIncidentType(value.incidentType);
          }
        }
        if (value.severity && severityOptions.includes(value.severity)) {
          setSeverity(value.severity);
        }
        if (value.findings) {
          setFindings(value.findings);
        }
        if (Array.isArray(value.affectedSystems)) {
          setAffectedSystems(value.affectedSystems.map(String));
        }

        await deleteSetting('ir_playbook_prefill');
      } catch (prefillError) {
        console.error('Failed to load IR prefill payload:', prefillError);
      }
    };
    loadPrefill();
  }, []);

  useEffect(() => {
    if (!activePlaybook) return;
    const timer = setTimeout(async () => {
      const key = `ir_playbook_${activePlaybook.playbookId}`;
      const payload = {
        ...activePlaybook,
        lastUpdated: Date.now(),
        overallProgress: calculateOverallProgress(activePlaybook)
      };
      await saveSetting(key, payload);
      setSavedPlaybooks((prev) => {
        const next = prev.filter((row) => row.key !== key);
        next.unshift({ key, playbook: normalizePlaybook(payload) });
        return next.sort((a, b) => b.playbook.lastUpdated - a.playbook.lastUpdated);
      });
    }, 500);

    return () => clearTimeout(timer);
  }, [activePlaybook]);

  const addAffectedSystem = () => {
    const value = affectedSystemsInput.trim();
    if (!value || affectedSystems.includes(value)) return;
    setAffectedSystems((prev) => [...prev, value]);
    setAffectedSystemsInput('');
  };

  const removeAffectedSystem = (value: string) => {
    setAffectedSystems((prev) => prev.filter((item) => item !== value));
  };

  const updateStep = (phaseId: number, stepId: string, mutate: (step: IRStep) => IRStep) => {
    setActivePlaybook((prev) => {
      if (!prev) return prev;
      const nextPhases = prev.phases.map((phase) => {
        if (phase.phaseId !== phaseId) return phase;
        return {
          ...phase,
          steps: phase.steps.map((step) => (step.stepId === stepId ? mutate(step) : step))
        };
      });

      const next = normalizePlaybook({
        ...prev,
        phases: nextPhases,
        lastUpdated: Date.now()
      });
      return next;
    });
  };

  const sendStepStatusUpdate = async (playbookId: string, stepId: string, status: StepStatus, notes: string, completedBy: string) => {
    try {
      await fetch('http://localhost:3001/ir/update-step', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          playbookId,
          stepId,
          status,
          notes,
          completedBy
        })
      });
    } catch {
      // Server-side sync is secondary; IndexedDB is primary for continuity.
    }
  };

  const handleCheckboxCycle = (phase: IRPhase, step: IRStep) => {
    const nextStatus = cycleStatus(step.status);
    const completedAt = nextStatus === 'completed' ? (step.completedAt || Date.now()) : null;
    updateStep(phase.phaseId, step.stepId, (old) => ({
      ...old,
      status: nextStatus,
      completedAt
    }));

    if (activePlaybook) {
      sendStepStatusUpdate(activePlaybook.playbookId, step.stepId, nextStatus, step.notes, step.completedBy);
    }
  };

  const handleStatusChange = (phase: IRPhase, step: IRStep, value: StepStatus) => {
    const completedAt = value === 'completed' ? (step.completedAt || Date.now()) : null;
    updateStep(phase.phaseId, step.stepId, (old) => ({
      ...old,
      status: value,
      completedAt
    }));

    if (activePlaybook) {
      sendStepStatusUpdate(activePlaybook.playbookId, step.stepId, value, step.notes, step.completedBy);
    }
  };

  const generatePlaybook = async () => {
    if (!findings.trim()) {
      toast.error('Findings are required');
      return;
    }
    setIsGenerating(true);

    try {
      const response = await fetch('http://localhost:3001/ir/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          incidentType: activeIncidentType,
          severity,
          affectedSystems,
          findings,
          organizationContext
        })
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data?.message || 'Failed to generate playbook');
      }

      const withDefaults: IRPlaybook = normalizePlaybook({
        ...data,
        overallProgress: 0
      } as IRPlaybook);
      setActivePlaybook(withDefaults);

      const saveKey = `ir_playbook_${withDefaults.playbookId}`;
      await saveSetting(saveKey, withDefaults);
      await loadSavedPlaybooks();

      try {
        await logForensicsEvent({
          timestamp: Date.now(),
          eventType: 'custom',
          sourceModule: 'IR Playbook',
          severity: withDefaults.severity,
          title: `IR Playbook generated: ${withDefaults.incidentId}`,
          description: withDefaults.executiveSummary,
          details: { playbookId: withDefaults.playbookId, incidentType: withDefaults.incidentType },
          attackPhase: 'Recovery',
          ioc: withDefaults.iocs || [],
          tags: ['incident-response', 'playbook']
        });
      } catch (forensicsErr) {
        console.error('Forensics event logging skipped:', forensicsErr);
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to generate playbook';
      toast.error(message);
    } finally {
      setIsGenerating(false);
    }
  };

  const savePlaybookNow = async () => {
    if (!activePlaybook) return;
    const key = `ir_playbook_${activePlaybook.playbookId}`;
    const payload = normalizePlaybook({ ...activePlaybook, lastUpdated: Date.now() });
    await saveSetting(key, payload);
    await loadSavedPlaybooks();
    toast.success('Playbook saved');
  };

  const deletePlaybook = async (key: string) => {
    const ok = window.confirm('Delete this saved playbook?');
    if (!ok) return;
    await deleteSetting(key);
    if (activePlaybook && `ir_playbook_${activePlaybook.playbookId}` === key) {
      setActivePlaybook(null);
    }
    await loadSavedPlaybooks();
  };

  const openSavedPlaybook = (entry: SavedPlaybookEntry) => {
    setActivePlaybook(normalizePlaybook(entry.playbook));
    toast.success(`Loaded ${entry.playbook.incidentId}`);
  };

  const addCustomLesson = () => {
    const lesson = newLesson.trim();
    if (!lesson || !activePlaybook) return;
    setActivePlaybook((prev) => prev ? normalizePlaybook({
      ...prev,
      lessonsLearned: [...prev.lessonsLearned, lesson],
      lastUpdated: Date.now()
    }) : prev);
    setNewLesson('');
  };

  const copyCommand = async (command: string | null) => {
    if (!command) return;
    await navigator.clipboard.writeText(command);
    toast.success('Command copied');
  };

  const exportPdf = () => {
    if (!activePlaybook) return;
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    let page = 1;

    const addPageNumber = () => {
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(9);
      doc.text(`Page ${page}`, pageWidth / 2, pageHeight - 8, { align: 'center' });
    };

    // Page 1: Cover
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(18);
    doc.text('INCIDENT RESPONSE PLAYBOOK', 14, 30);
    doc.setFontSize(14);
    doc.text(activePlaybook.playbookTitle, 14, 42);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(11);
    doc.text(`Incident ID: ${activePlaybook.incidentId}`, 14, 55);
    doc.text(`Incident Type: ${activePlaybook.incidentType}`, 14, 62);
    doc.text(`Severity: ${activePlaybook.severity}`, 14, 69);
    doc.text(`Generated by SecurAI Sentinel`, 14, 78);
    doc.text(`Date/Time: ${new Date(activePlaybook.createdAt).toLocaleString()}`, 14, 85);
    doc.setFontSize(9);
    doc.text('CONFIDENTIAL — RESTRICTED DISTRIBUTION', 14, 96);
    doc.line(14, 100, pageWidth - 14, 100);
    addPageNumber();

    // Page 2: Executive summary
    doc.addPage();
    page += 1;
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(14);
    doc.text('Executive Summary', 14, 20);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(11);
    doc.text(doc.splitTextToSize(activePlaybook.executiveSummary || 'N/A', pageWidth - 28), 14, 30);
    doc.setFont('helvetica', 'bold');
    doc.text('Affected Assets', 14, 72);
    doc.setFont('helvetica', 'normal');
    activePlaybook.affectedAssets.forEach((asset, idx) => {
      doc.text(`- ${asset}`, 18, 80 + idx * 6);
    });
    const iocStart = 100 + activePlaybook.affectedAssets.length * 6;
    doc.setFont('helvetica', 'bold');
    doc.text('IOC List', 14, iocStart);
    doc.setFont('helvetica', 'normal');
    activePlaybook.iocs.forEach((ioc, idx) => {
      doc.text(`- ${ioc}`, 18, iocStart + 8 + idx * 6);
    });
    addPageNumber();

    // Pages 3+: one per phase
    activePlaybook.phases.forEach((phase) => {
      doc.addPage();
      page += 1;
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(14);
      doc.text(`${phase.phaseId}. ${phase.phaseName}`, 14, 20);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(11);
      doc.text(`Priority: ${phase.priority} | Estimated Duration: ${phase.estimatedDuration}`, 14, 28);
      doc.line(14, 32, pageWidth - 14, 32);

      let y = 40;
      phase.steps.forEach((step, idx) => {
        if (y > pageHeight - 30) {
          addPageNumber();
          doc.addPage();
          page += 1;
          y = 20;
        }
        doc.setFont('helvetica', 'bold');
        doc.text(`${idx + 1}. ${step.title}`, 14, y);
        y += 5;
        doc.setFont('helvetica', 'normal');
        doc.text(doc.splitTextToSize(step.description || 'N/A', pageWidth - 28), 16, y);
        y += 10;
        doc.text(`Role: ${step.assignedRole} | Status: ${step.status}`, 16, y);
        y += 6;
        doc.text(`Notes: ${step.notes || '-'}`, 16, y);
        y += 8;
        doc.line(14, y, pageWidth - 14, y);
        y += 6;
      });
      addPageNumber();
    });

    // Final page
    doc.addPage();
    page += 1;
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(14);
    doc.text('Communication Plan', 14, 20);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(11);
    doc.text('Internal Notifications:', 14, 30);
    activePlaybook.communicationPlan.internalNotifications.forEach((item, idx) => doc.text(`- ${item}`, 18, 38 + idx * 6));
    const extStart = 48 + activePlaybook.communicationPlan.internalNotifications.length * 6;
    doc.text('External Notifications:', 14, extStart);
    activePlaybook.communicationPlan.externalNotifications.forEach((item, idx) => doc.text(`- ${item}`, 18, extStart + 8 + idx * 6));
    const regStart = extStart + 16 + activePlaybook.communicationPlan.externalNotifications.length * 6;
    doc.text('Regulatory Requirements:', 14, regStart);
    activePlaybook.communicationPlan.regulatoryRequirements.forEach((item, idx) => doc.text(`- ${item}`, 18, regStart + 8 + idx * 6));
    const refStart = regStart + 18 + activePlaybook.communicationPlan.regulatoryRequirements.length * 6;
    doc.setFont('helvetica', 'bold');
    doc.text('References', 14, refStart);
    doc.setFont('helvetica', 'normal');
    activePlaybook.references.forEach((item, idx) => doc.text(`- ${item}`, 18, refStart + 8 + idx * 6));
    addPageNumber();

    doc.save(`ir-playbook-${activePlaybook.incidentId}.pdf`);
  };

  const togglePhaseExpanded = (phaseId: number) => {
    setActivePlaybook((prev) => prev ? normalizePlaybook({
      ...prev,
      phases: prev.phases.map((phase) => phase.phaseId === phaseId ? { ...phase, isExpanded: !phase.isExpanded } : phase),
      lastUpdated: Date.now()
    }) : prev);
  };

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="bg-slate-900/50 border border-white/10 rounded-2xl p-6 backdrop-blur-xl">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/20 border border-cyan-500/35">
              <ClipboardList className="w-6 h-6 text-cyan-300" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-slate-100">Incident Response Playbook</h1>
              <p className="text-sm text-slate-400">AI-generated NIST SP 800-61 compliant IR plans</p>
            </div>
          </div>
          <span className="text-xs px-3 py-1 rounded-full border border-slate-700 bg-slate-800/80 text-slate-300">NIST SP 800-61</span>
        </div>
      </motion.div>

      <div className="grid grid-cols-1 2xl:grid-cols-5 gap-4">
        <div className="2xl:col-span-3 bg-slate-900/45 border border-white/10 rounded-2xl p-5 backdrop-blur-xl space-y-4">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-semibold text-slate-200">Playbook Generator</h3>
            <button
              onClick={() => {
                setIncidentType('Ransomware');
                setSeverity('High');
                setAffectedSystems(['workstation-7', 'fileserver-02']);
                setFindings('Target: fileserver-02\nAnomalies:\n- Massive files encrypted with extension .locked\n- Threat actor dumped lsass memory\n- Suspicious outbound connection to C2 C:\\Windows\\System32\\cmd.exe -> 203.0.113.50:4444');
                setOrganizationContext('Enterprise file server and local workstation compromised.');
                toast.success('Sample incident response details loaded.');
              }}
              className="px-4 py-2 rounded-lg bg-cyan-500/20 border border-cyan-500/40 text-cyan-300 hover:bg-cyan-500/30 text-xs font-semibold transition-all"
            >
              Load Sample Data
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div>
              <label className="text-xs text-slate-400">Incident Type</label>
              <select value={incidentType} onChange={(e) => setIncidentType(e.target.value)} className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-200 text-sm">
                {incidentTypeOptions.map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="text-xs text-slate-400">Severity</label>
              <select value={severity} onChange={(e) => setSeverity(e.target.value as 'Critical' | 'High' | 'Medium' | 'Low')} className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-200 text-sm">
                {severityOptions.map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {incidentType === 'Custom' && (
            <div>
              <label className="text-xs text-slate-400">Custom Incident Type</label>
              <input
                value={customIncidentType}
                onChange={(e) => setCustomIncidentType(e.target.value)}
                placeholder="Describe the incident type"
                className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-200 text-sm"
              />
            </div>
          )}

          <div>
            <label className="text-xs text-slate-400">Affected Systems</label>
            <div className="mt-1 flex gap-2">
              <input
                value={affectedSystemsInput}
                onChange={(e) => setAffectedSystemsInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    addAffectedSystem();
                  }
                }}
                placeholder="Press Enter to add a system"
                className="flex-1 px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-200 text-sm"
              />
              <button onClick={addAffectedSystem} className="px-3 py-2 rounded-lg border border-slate-600 bg-slate-800 text-slate-200 text-sm">
                Add
              </button>
            </div>
            <div className="mt-2 flex flex-wrap gap-2">
              {affectedSystems.map((system) => (
                <span key={system} className="inline-flex items-center gap-1 px-2 py-1 rounded-full border border-cyan-500/30 bg-cyan-500/10 text-cyan-200 text-xs">
                  {system}
                  <button onClick={() => removeAffectedSystem(system)}>×</button>
                </span>
              ))}
            </div>
          </div>

          <div>
            <label className="text-xs text-slate-400">Findings</label>
            <textarea
              value={findings}
              onChange={(e) => setFindings(e.target.value)}
              rows={7}
              placeholder="Paste findings from any module..."
              className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-200 text-sm"
            />
            <div className="mt-2 flex flex-wrap gap-2">
              {quickLoads.map((item) => (
                <button key={item.label} onClick={() => setFindings(item.value)} className="px-2 py-1 rounded border border-slate-700 bg-slate-900 text-slate-300 text-xs hover:border-cyan-500/40 hover:text-cyan-200">
                  {item.label}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="text-xs text-slate-400">Organization Context (optional)</label>
            <textarea
              value={organizationContext}
              onChange={(e) => setOrganizationContext(e.target.value)}
              rows={3}
              placeholder="e.g. Healthcare company, 200 employees, HIPAA regulated"
              className="mt-1 w-full px-3 py-2 rounded-lg border border-slate-700 bg-slate-950 text-slate-200 text-sm"
            />
          </div>

          <button
            disabled={isGenerating}
            onClick={generatePlaybook}
            className="w-full inline-flex items-center justify-center gap-2 px-4 py-3 rounded-lg border border-cyan-500/40 bg-cyan-500/15 text-cyan-200 font-semibold hover:bg-cyan-500/25 disabled:opacity-60"
          >
            {isGenerating ? <Loader2 className="w-4 h-4 animate-spin" /> : <ClipboardList className="w-4 h-4" />}
            {isGenerating ? 'Generating NIST-compliant playbook... (~10-15 seconds)' : 'Generate Playbook'}
          </button>
        </div>

        <div className="2xl:col-span-2 bg-slate-900/45 border border-white/10 rounded-2xl p-5 backdrop-blur-xl">
          <h3 className="text-sm font-semibold text-slate-200 mb-3">Saved Playbooks</h3>
          {savedPlaybooks.length === 0 ? (
            <p className="text-sm text-slate-500">No playbooks yet. Generate your first one above.</p>
          ) : (
            <div className="space-y-3 max-h-[540px] overflow-auto pr-1">
              {savedPlaybooks.map((entry) => (
                <div key={entry.key} className="border border-slate-700 rounded-lg p-3 bg-slate-950/50">
                  <div className="flex items-center justify-between mb-1">
                    <span className="px-2 py-0.5 rounded text-xs bg-slate-800 border border-slate-700 font-mono text-slate-300">{entry.playbook.incidentId}</span>
                    <span className={`px-2 py-0.5 rounded text-xs border ${
                      entry.playbook.severity === 'Critical' ? 'border-red-500/50 text-red-200 bg-red-500/20' :
                      entry.playbook.severity === 'High' ? 'border-orange-500/50 text-orange-200 bg-orange-500/20' :
                      entry.playbook.severity === 'Medium' ? 'border-yellow-500/50 text-yellow-200 bg-yellow-500/20' :
                      'border-blue-500/50 text-blue-200 bg-blue-500/20'
                    }`}>
                      {entry.playbook.severity}
                    </span>
                  </div>
                  <p className="text-sm text-slate-200">{entry.playbook.incidentType}</p>
                  <p className="text-xs text-slate-500 mt-1">{new Date(entry.playbook.createdAt).toLocaleString()}</p>
                  <div className="mt-2 h-2 bg-slate-800 rounded overflow-hidden">
                    <div className="h-2 bg-emerald-500" style={{ width: `${entry.playbook.overallProgress}%` }} />
                  </div>
                  <p className="text-xs text-slate-400 mt-1">{entry.playbook.overallProgress}% completed</p>
                  <div className="mt-3 flex items-center gap-2">
                    <button onClick={() => openSavedPlaybook(entry)} className="px-3 py-1.5 rounded border border-cyan-500/40 bg-cyan-500/10 text-cyan-200 text-xs">
                      Open
                    </button>
                    <button onClick={() => deletePlaybook(entry.key)} className="px-3 py-1.5 rounded border border-red-500/40 bg-red-500/10 text-red-200 text-xs inline-flex items-center gap-1">
                      <Trash2 className="w-3 h-3" />
                      Delete
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {activePlaybook && (
        <div className="space-y-4">
          <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-5 backdrop-blur-xl">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p className="font-mono text-lg text-cyan-200">{activePlaybook.incidentId}</p>
                <h2 className="text-xl font-bold text-slate-100">{activePlaybook.playbookTitle}</h2>
                <p className="text-sm text-slate-400">Created {new Date(activePlaybook.createdAt).toLocaleString()}</p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="px-2 py-1 rounded border border-slate-700 text-slate-200 text-xs">{activePlaybook.incidentType}</span>
                <span className="px-2 py-1 rounded border border-slate-700 text-slate-200 text-xs">{activePlaybook.severity}</span>
              </div>
            </div>

            {playbookStats && (
              <>
                <div className="mt-4 h-3 rounded bg-slate-800 overflow-hidden">
                  <div className="h-3 bg-emerald-500" style={{ width: `${activePlaybook.overallProgress}%` }} />
                </div>
                <p className="text-xs text-slate-400 mt-1">{playbookStats.completed} of {playbookStats.total} steps completed ({activePlaybook.overallProgress}%)</p>
              </>
            )}

            <div className="mt-4 flex flex-wrap gap-2">
              <button onClick={savePlaybookNow} className="px-3 py-2 rounded border border-cyan-500/40 bg-cyan-500/15 text-cyan-200 text-sm inline-flex items-center gap-2">
                <Save className="w-4 h-4" />
                Save Playbook
              </button>
              <button onClick={exportPdf} className="px-3 py-2 rounded border border-purple-500/40 bg-purple-500/15 text-purple-200 text-sm inline-flex items-center gap-2">
                <Download className="w-4 h-4" />
                Export PDF
              </button>
            </div>
          </div>

          <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-5">
            <h3 className="text-sm font-semibold text-slate-200 mb-2">Executive Summary — For Management</h3>
            <div className="p-3 rounded border border-slate-700 bg-slate-950/50 italic text-slate-300 text-sm">{activePlaybook.executiveSummary}</div>
            <div className="mt-3 flex flex-wrap gap-2">
              {activePlaybook.affectedAssets.map((asset) => (
                <span key={asset} className="px-2 py-1 rounded border border-slate-700 bg-slate-900 text-slate-300 text-xs">{asset}</span>
              ))}
            </div>
            <div className="mt-3">
              <div className="flex items-center justify-between">
                <h4 className="text-xs text-slate-400">IOC List</h4>
                <button
                  onClick={async () => {
                    if (!activePlaybook.iocs.length) return;
                    await navigator.clipboard.writeText(activePlaybook.iocs.join('\n'));
                    toast.success('IOC list copied');
                  }}
                  className="px-2 py-1 rounded border border-slate-700 text-xs text-slate-300 inline-flex items-center gap-1"
                >
                  <Copy className="w-3 h-3" />
                  Copy all
                </button>
              </div>
              <ul className="mt-2 text-xs text-slate-300 space-y-1">
                {activePlaybook.iocs.map((ioc) => (
                  <li key={ioc} className="font-mono">{ioc}</li>
                ))}
              </ul>
            </div>
          </div>

          <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-4">
            <h3 className="text-sm font-semibold text-slate-200 mb-3">Phase Progress Navigator</h3>
            <div className="flex flex-wrap gap-2">
              {activePlaybook.phases.map((phase) => {
                const completed = phase.steps.filter((step) => step.status === 'completed').length;
                const ratio = phase.steps.length ? Math.round((completed / phase.steps.length) * 100) : 0;
                return (
                  <button
                    key={phase.phaseId}
                    onClick={() => document.getElementById(`ir-phase-${phase.phaseId}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' })}
                    className="px-3 py-2 rounded-lg border border-slate-700 bg-slate-900 text-left min-w-[180px]"
                  >
                    <p className="text-xs text-slate-400">{phase.phaseId}. {phase.phaseName}</p>
                    <p className="text-xs text-slate-500">{ratio}% · {phase.estimatedDuration}</p>
                    <div className="mt-1 h-1.5 bg-slate-800 rounded overflow-hidden">
                      <div className="h-1.5 bg-emerald-500" style={{ width: `${ratio}%` }} />
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {activePlaybook.phases.map((phase) => {
            const completed = phase.steps.filter((step) => step.status === 'completed').length;
            return (
              <div key={phase.phaseId} id={`ir-phase-${phase.phaseId}`} className="bg-slate-900/45 border border-white/10 rounded-2xl p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <h3 className="text-lg font-semibold text-slate-100">{phase.phaseId}. {phase.phaseName}</h3>
                    <p className="text-xs text-slate-400">Priority: {phase.priority} · Estimated: {phase.estimatedDuration}</p>
                  </div>
                  <button onClick={() => togglePhaseExpanded(phase.phaseId)} className="px-2 py-1 rounded border border-slate-700 text-slate-300 text-xs inline-flex items-center gap-1">
                    {phase.isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                    {phase.isExpanded ? 'Collapse' : 'Expand'}
                  </button>
                </div>

                <div className="mt-2 h-2 bg-slate-800 rounded overflow-hidden">
                  <div className="h-2 bg-emerald-500" style={{ width: `${phase.steps.length ? (completed / phase.steps.length) * 100 : 0}%` }} />
                </div>
                <p className="text-xs text-slate-500 mt-1">{completed}/{phase.steps.length} steps done</p>

                {phase.isExpanded && (
                  <div className="mt-4 space-y-3">
                    {phase.steps.map((step) => (
                      <div key={step.stepId} className={`border rounded-lg p-3 ${statusClass[step.status]}`}>
                        <div className="flex flex-wrap items-start justify-between gap-2">
                          <div className="flex items-start gap-2">
                            <button onClick={() => handleCheckboxCycle(phase, step)} className="mt-0.5">
                              {step.status === 'completed'
                                ? <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                                : <div className="w-5 h-5 rounded border border-slate-500" />}
                            </button>
                            <div>
                              <p className={`font-semibold text-sm ${step.status === 'completed' ? 'line-through text-emerald-200' : step.status === 'skipped' ? 'line-through decoration-2 text-slate-400' : 'text-slate-100'}`}>
                                {step.title}
                              </p>
                              <p className="text-xs text-slate-400">{step.assignedRole}</p>
                            </div>
                          </div>
                          <select
                            value={step.status}
                            onChange={(e) => handleStatusChange(phase, step, e.target.value as StepStatus)}
                            className="px-2 py-1 rounded border border-slate-700 bg-slate-950 text-slate-200 text-xs"
                          >
                            <option value="pending">Pending</option>
                            <option value="in_progress">In Progress</option>
                            <option value="completed">Completed</option>
                            <option value="skipped">Skipped</option>
                          </select>
                        </div>

                        <p className="mt-2 text-sm text-slate-300">{step.description}</p>
                        <p className="mt-1 text-xs text-slate-500 italic">Expected outcome: {step.expectedOutcome}</p>

                        <div className="mt-2 flex flex-wrap gap-2">
                          {step.toolsRequired.map((tool) => (
                            <span key={tool} className="px-2 py-0.5 rounded border border-slate-700 bg-slate-900 text-slate-300 text-xs">{tool}</span>
                          ))}
                        </div>

                        {step.isAutomatable && step.bashCommand && (
                          <div className="mt-2 border border-emerald-500/30 rounded bg-emerald-500/10 p-2">
                            <div className="flex items-center justify-between">
                              <span className="text-xs text-emerald-200">Automatable</span>
                              <button onClick={() => copyCommand(step.bashCommand)} className="text-xs text-emerald-200 border border-emerald-500/40 rounded px-2 py-1 inline-flex items-center gap-1">
                                <Copy className="w-3 h-3" />
                                Copy Command
                              </button>
                            </div>
                            <pre className="mt-2 text-xs text-emerald-100 whitespace-pre-wrap">{step.bashCommand}</pre>
                          </div>
                        )}

                        <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-2">
                          <textarea
                            value={step.notes}
                            onChange={(e) => {
                              const notes = e.target.value;
                              updateStep(phase.phaseId, step.stepId, (old) => ({ ...old, notes }));
                              if (activePlaybook) {
                                sendStepStatusUpdate(activePlaybook.playbookId, step.stepId, step.status, notes, step.completedBy);
                              }
                            }}
                            placeholder="Add analyst notes..."
                            className="w-full px-2 py-1.5 rounded border border-slate-700 bg-slate-950 text-slate-200 text-xs"
                          />
                          <input
                            value={step.completedBy}
                            onChange={(e) => {
                              const completedBy = e.target.value;
                              updateStep(phase.phaseId, step.stepId, (old) => ({ ...old, completedBy }));
                              if (activePlaybook) {
                                sendStepStatusUpdate(activePlaybook.playbookId, step.stepId, step.status, step.notes, completedBy);
                              }
                            }}
                            placeholder="Completed by"
                            className="w-full px-2 py-1.5 rounded border border-slate-700 bg-slate-950 text-slate-200 text-xs"
                          />
                        </div>

                        {step.status === 'completed' && step.completedAt && (
                          <p className="mt-2 text-xs text-emerald-300">Completed at {new Date(step.completedAt).toLocaleString()}</p>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}

          <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-4">
            <h3 className="text-sm font-semibold text-slate-200 mb-3">Communication Plan</h3>
            <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 text-sm">
              {[
                ['Internal Notifications', activePlaybook.communicationPlan.internalNotifications],
                ['External Notifications', activePlaybook.communicationPlan.externalNotifications],
                ['Regulatory Requirements', activePlaybook.communicationPlan.regulatoryRequirements]
              ].map(([title, items]) => (
                <div key={title as string} className="border border-slate-700 rounded-lg p-3 bg-slate-950/40">
                  <p className="font-semibold text-slate-200 mb-2">{title}</p>
                  <ul className="space-y-1">
                    {(items as string[]).map((item) => {
                      const key = `${title}-${item}`;
                      return (
                        <li key={item} className="flex items-start gap-2 text-slate-300">
                          <input
                            type="checkbox"
                            checked={Boolean(commChecks[key])}
                            onChange={(e) => setCommChecks((prev) => ({ ...prev, [key]: e.target.checked }))}
                          />
                          <span>{item}</span>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-4">
            <h3 className="text-sm font-semibold text-slate-200 mb-3">Lessons Learned</h3>
            <ul className="space-y-1 text-sm text-slate-300">
              {activePlaybook.lessonsLearned.map((lesson, idx) => (
                <li key={`${lesson}-${idx}`}>• {lesson}</li>
              ))}
            </ul>
            <div className="mt-3 flex gap-2">
              <input
                value={newLesson}
                onChange={(e) => setNewLesson(e.target.value)}
                placeholder="Add custom lesson"
                className="flex-1 px-3 py-2 rounded border border-slate-700 bg-slate-950 text-slate-200 text-sm"
              />
              <button onClick={addCustomLesson} className="px-3 py-2 rounded border border-cyan-500/40 bg-cyan-500/10 text-cyan-200 text-sm">
                Add Custom Lesson
              </button>
            </div>
          </div>

          <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-4">
            <h3 className="text-sm font-semibold text-slate-200 mb-3">References</h3>
            <div className="flex flex-wrap gap-2">
              {activePlaybook.references.map((ref) => (
                <a key={ref} href={ref} target="_blank" rel="noreferrer" className="px-3 py-1.5 rounded border border-slate-700 bg-slate-900 text-cyan-200 text-xs hover:border-cyan-500/40">
                  {ref}
                </a>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default IncidentResponsePlaybook;
