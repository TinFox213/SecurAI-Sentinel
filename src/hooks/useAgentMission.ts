import { useEffect, useMemo, useRef, useState } from 'react';
import { AgentInterpretation, AgentPlan, AgentReport, AgentState, AgentStep } from '../types/types';
import { logForensicsEvent } from '../utils/forensicsLogger';

type AgentMode = 'passive' | 'active' | 'full';

interface MissionOptions {
  maxSteps: number;
  timeoutPerStepMs: number;
  autoGenerateIR: boolean;
  saveToForensicsTimeline: boolean;
}

interface RunMissionInput {
  target: string;
  mode: AgentMode;
  objectives: string[];
  options: MissionOptions;
}

const API_BASE = 'http://localhost:3001';

const isIpAddress = (value: string) => /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/.test(value.trim());

const timestampPrefix = () => {
  const now = new Date();
  return `[${now.toLocaleTimeString('en-GB', { hour12: false })}]`;
};

const delay = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => resolve(), ms);
    if (signal) {
      signal.addEventListener(
        'abort',
        () => {
          clearTimeout(timer);
          reject(new DOMException('Mission aborted', 'AbortError'));
        },
        { once: true }
      );
    }
  });

const toJsonError = async (response: Response): Promise<Error> => {
  try {
    const data = await response.json();
    return new Error(data?.message || data?.error || `Request failed with status ${response.status}`);
  } catch {
    return new Error(`Request failed with status ${response.status}`);
  }
};

const postJson = async (path: string, body: Record<string, any>, signal: AbortSignal, timeoutMs: number) => {
  const timeoutController = new AbortController();
  const timer = setTimeout(() => timeoutController.abort(), timeoutMs);
  const onAbort = () => timeoutController.abort();
  signal.addEventListener('abort', onAbort, { once: true });

  try {
    const response = await fetch(`${API_BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: timeoutController.signal
    });
    if (!response.ok) {
      throw await toJsonError(response);
    }
    return await response.json();
  } finally {
    clearTimeout(timer);
    signal.removeEventListener('abort', onAbort);
  }
};

const postJsonWithFallback = async (
  paths: string[],
  body: Record<string, any>,
  signal: AbortSignal,
  timeoutMs: number
) => {
  let lastError: Error | null = null;
  for (const path of paths) {
    try {
      return await postJson(path, body, signal, timeoutMs);
    } catch (error: any) {
      lastError = error instanceof Error ? error : new Error(String(error));
      if (!/404|not found/i.test(lastError.message)) {
        throw lastError;
      }
    }
  }
  throw lastError || new Error('No endpoint available for this tool');
};

const riskToSeverity = (score: number): 'Critical' | 'High' | 'Medium' => {
  if (score >= 80) return 'Critical';
  if (score >= 60) return 'High';
  return 'Medium';
};

const makeFallbackPlan = (target: string, mode: AgentMode, objectives: string[], maxSteps: number): AgentPlan => {
  const passiveTools = ['ssl_check', 'headers_check', 'dns_check', 'subdomain_enum', 'cve_search', 'darkweb_domain'];
  const activeTools = [...passiveTools, 'port_scan', 'ip_reputation'];
  const fullTools = [...activeTools, 'attack_classify', 'ir_generate'];
  const toolSet = mode === 'passive' ? passiveTools : mode === 'active' ? activeTools : fullTools;
  const steps = toolSet.slice(0, maxSteps).map((toolName, idx) => ({
    stepNumber: idx + 1,
    toolName,
    toolInput: { target },
    rationale: `Baseline ${toolName.replace('_', ' ')} check for ${target}`,
    dependsOnStep: idx > 0 ? idx : null,
    expectedOutput: 'Structured findings',
    status: 'pending' as const,
    actualOutput: null,
    interpretation: null,
    startedAt: null,
    completedAt: null
  }));

  return {
    planTitle: `${mode.toUpperCase()} assessment for ${target}`,
    estimatedDuration: `${Math.max(steps.length * 4, 15)} seconds`,
    steps,
    agentObjective: objectives.join(', ') || `Assess attack surface for ${target}`,
    riskLevel: 'Medium'
  };
};

const normalizeSteps = (steps: any[], maxSteps: number): AgentStep[] =>
  (Array.isArray(steps) ? steps : [])
    .slice(0, maxSteps)
    .map((step, idx) => ({
      stepNumber: Number(step?.stepNumber || idx + 1),
      toolName: String(step?.toolName || 'headers_check'),
      toolInput: typeof step?.toolInput === 'object' && step?.toolInput ? step.toolInput : {},
      rationale: String(step?.rationale || 'Automated assessment step'),
      dependsOnStep: step?.dependsOnStep == null ? null : Number(step.dependsOnStep),
      expectedOutput: String(step?.expectedOutput || 'Findings'),
      status: 'pending',
      actualOutput: null,
      interpretation: null,
      startedAt: null,
      completedAt: null
    }));

export function useAgentMission() {
  const [agentState, setAgentState] = useState<AgentState>('idle');
  const [plan, setPlan] = useState<AgentPlan | null>(null);
  const [steps, setSteps] = useState<AgentStep[]>([]);
  const [currentStepIndex, setCurrentStepIndex] = useState(-1);
  const [thoughtLog, setThoughtLog] = useState<string[]>([]);
  const [finalReport, setFinalReport] = useState<AgentReport | null>(null);
  const [riskScore, setRiskScore] = useState(0);
  const [elapsedTime, setElapsedTime] = useState(0);
  const [abortController, setAbortController] = useState<AbortController | null>(null);
  const [currentToolName, setCurrentToolName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isAborted, setIsAborted] = useState(false);
  const abortedRef = useRef(false);

  useEffect(() => {
    if (!['planning', 'executing', 'interpreting', 'deciding', 'synthesizing'].includes(agentState)) return;
    const timer = setInterval(() => setElapsedTime((prev) => prev + 1), 1000);
    return () => clearInterval(timer);
  }, [agentState]);

  const isRunning = useMemo(
    () => ['planning', 'executing', 'interpreting', 'deciding', 'synthesizing'].includes(agentState),
    [agentState]
  );

  const appendLog = (entry: string) => {
    setThoughtLog((prev) => [...prev, `${timestampPrefix()} ${entry}`]);
  };

  const updateStep = (index: number, patch: Partial<AgentStep>) => {
    setSteps((prev) => prev.map((step, i) => (i === index ? { ...step, ...patch } : step)));
  };

  const executeTool = async (
    step: AgentStep,
    target: string,
    previousFindings: string,
    signal: AbortSignal,
    timeoutPerStepMs: number,
    liveRiskScore: number
  ): Promise<Record<string, any>> => {
    const toolInput = { ...(step.toolInput || {}) };
    const safeTarget = target.trim();
    const domainTarget = safeTarget.replace(/^https?:\/\//i, '');
    const guessedUrl = /^https?:\/\//i.test(safeTarget) ? safeTarget : `https://${domainTarget}`;

    switch (step.toolName) {
      case 'port_scan': {
        const payload = { ip: toolInput.ip || toolInput.target || safeTarget };
        return await postJsonWithFallback(['/scan', '/scan-ports'], payload, signal, timeoutPerStepMs);
      }
      case 'ssl_check':
        return await postJson('/web/ssl', { domain: toolInput.domain || domainTarget }, signal, timeoutPerStepMs);
      case 'headers_check':
        return await postJson('/web/headers', { url: toolInput.url || guessedUrl }, signal, timeoutPerStepMs);
      case 'dns_check':
        return await postJson('/web/dns', { domain: toolInput.domain || domainTarget }, signal, timeoutPerStepMs);
      case 'subdomain_enum':
        return await postJson('/osint/subdomains', { domain: toolInput.domain || domainTarget }, signal, timeoutPerStepMs);
      case 'cve_search':
        return await postJson('/cve/search', { query: toolInput.query || domainTarget }, signal, timeoutPerStepMs);
      case 'vuln_analyze': {
        try {
          return await postJson('/vuln/analyze', { target: safeTarget, context: previousFindings }, signal, timeoutPerStepMs);
        } catch {
          return {
            simulated: true,
            summary: 'Simulated vulnerability analysis generated due unavailable backend endpoint.',
            findings: [`Potential weaknesses inferred from previous findings for ${safeTarget}`],
            confidence: 0.52
          };
        }
      }
      case 'darkweb_domain':
        return await postJsonWithFallback(
          ['/darkweb/domain', '/darkweb/breach'],
          { domain: toolInput.domain || domainTarget, query: toolInput.domain || domainTarget, type: 'domain' },
          signal,
          timeoutPerStepMs
        );
      case 'attack_classify':
        return await postJson(
          '/attack/classify',
          {
            sourceModule: 'AI Red Team Agent',
            rawFindings: toolInput.rawFindings || previousFindings || `Findings for ${safeTarget}`,
            detectedIndicators: Array.isArray(toolInput.detectedIndicators) ? toolInput.detectedIndicators : []
          },
          signal,
          timeoutPerStepMs
        );
      case 'ip_reputation': {
        const ipCandidate = toolInput.ip || (isIpAddress(safeTarget) ? safeTarget : '');
        return await postJson('/pcap/ip-reputation', { ip: ipCandidate || safeTarget }, signal, timeoutPerStepMs);
      }
      case 'ir_generate':
        return await postJson(
          '/ir/generate',
          {
            incidentType: toolInput.incidentType || 'Automated Red Team Findings',
            severity: toolInput.severity || riskToSeverity(liveRiskScore),
            affectedSystems: Array.isArray(toolInput.affectedSystems) ? toolInput.affectedSystems : [safeTarget],
            findings: toolInput.findings || previousFindings || `Automated findings for ${safeTarget}`,
            organizationContext: 'Generated by AI Red Team Agent'
          },
          signal,
          timeoutPerStepMs
        );
      default:
        throw new Error(`Unknown tool: ${step.toolName}`);
    }
  };

  const abortMission = () => {
    abortedRef.current = true;
    setIsAborted(true);
    appendLog('🛑 Mission abort requested. Finalizing partial findings...');
    if (abortController) {
      abortController.abort();
    }
    setSteps((prev) =>
      prev.map((step, idx) => {
        if (step.status === 'running') {
          return {
            ...step,
            status: 'failed',
            completedAt: Date.now(),
            actualOutput: { error: 'Mission aborted by user' },
            interpretation: {
              interpretation: 'Step aborted by operator.',
              keyFindings: [],
              riskIndicators: [],
              shouldEscalate: false,
              escalationReason: null,
              suggestedNextTools: [],
              confidenceLevel: 0,
              agentThought: 'Operator terminated mission execution.'
            }
          };
        }
        if (idx > currentStepIndex && step.status === 'pending') {
          return { ...step, status: 'skipped' };
        }
        return step;
      })
    );
  };

  const resetMission = () => {
    abortedRef.current = false;
    setAgentState('idle');
    setPlan(null);
    setSteps([]);
    setCurrentStepIndex(-1);
    setThoughtLog([]);
    setFinalReport(null);
    setRiskScore(0);
    setElapsedTime(0);
    setAbortController(null);
    setCurrentToolName('');
    setError(null);
    setIsAborted(false);
  };

  const runMission = async ({ target, mode, objectives, options }: RunMissionInput) => {
    resetMission();
    setError(null);
    setIsAborted(false);
    abortedRef.current = false;

    const controller = new AbortController();
    setAbortController(controller);

    const safeObjectives = objectives.filter((obj) => obj.trim().length > 0);
    appendLog(`🤖 Agent initialized. Target: ${target}`);
    appendLog(`📋 Planning mission in ${mode.toUpperCase()} mode...`);

    try {
      setAgentState('planning');
      let planned: AgentPlan;
      try {
        const plannedRaw = await postJson(
          '/agent/plan',
          {
            target,
            agentMode: mode,
            objectives: safeObjectives
          },
          controller.signal,
          Math.max(options.timeoutPerStepMs, 15000)
        );
        planned = {
          planTitle: String(plannedRaw?.planTitle || `Assessment for ${target}`),
          estimatedDuration: String(plannedRaw?.estimatedDuration || 'Unknown'),
          steps: normalizeSteps(plannedRaw?.steps || [], options.maxSteps),
          agentObjective: String(plannedRaw?.agentObjective || safeObjectives.join(', ') || `Assess ${target}`),
          riskLevel: String(plannedRaw?.riskLevel || 'Medium')
        };
      } catch (planningError) {
        appendLog(`⚠️ Planner unavailable, using fallback plan.`);
        planned = makeFallbackPlan(target, mode, safeObjectives, options.maxSteps);
      }

      setPlan(planned);
      setSteps(planned.steps);
      appendLog(`✅ Plan generated with ${planned.steps.length} steps.`);

      const allInterpretations: AgentInterpretation[] = [];
      const findingsCache: string[] = [];
      const missionSteps: AgentStep[] = planned.steps.map((step) => ({ ...step }));
      let criticalSignal = false;
      let runningRiskScore = 0;

      for (let i = 0; i < planned.steps.length; i += 1) {
        if (controller.signal.aborted || abortedRef.current) break;

        const step = planned.steps[i];
        if (step.toolName === 'ir_generate' && (!options.autoGenerateIR || !criticalSignal)) {
          updateStep(i, { status: 'skipped', completedAt: Date.now() });
          missionSteps[i] = { ...missionSteps[i], status: 'skipped', completedAt: Date.now() };
          appendLog('⏭️ Skipping IR generation (critical threshold not reached or auto-generation disabled).');
          continue;
        }
        setCurrentStepIndex(i);
        setCurrentToolName(step.toolName);
        setAgentState('executing');
        updateStep(i, { status: 'running', startedAt: Date.now() });
        missionSteps[i] = { ...missionSteps[i], status: 'running', startedAt: Date.now() };

        appendLog(`⚡ Step ${step.stepNumber}/${planned.steps.length}: Running ${step.toolName}...`);
        let toolOutput: Record<string, any> = {};
        let toolError: Error | null = null;

        try {
          toolOutput = await executeTool(
            step,
            target,
            findingsCache.join('\n'),
            controller.signal,
            options.timeoutPerStepMs,
            runningRiskScore
          );
          appendLog(`✅ ${step.toolName} completed.`);
        } catch (error: any) {
          toolError = error instanceof Error ? error : new Error(String(error));
          toolOutput = { error: toolError.message };
          appendLog(`❌ ${step.toolName} failed: ${toolError.message}`);
        }

        if (controller.signal.aborted || abortedRef.current) break;

        setAgentState('interpreting');
        appendLog('🔍 Interpreting tool output...');
        let interpretation: AgentInterpretation;
        try {
          const interpreted = await postJson(
            '/agent/interpret',
            {
              stepNumber: step.stepNumber,
              toolName: step.toolName,
              toolInput: step.toolInput,
              toolOutput,
              previousFindings: findingsCache.join('\n')
            },
            controller.signal,
            Math.max(options.timeoutPerStepMs, 12000)
          );
          interpretation = {
            interpretation: String(interpreted?.interpretation || 'No interpretation provided'),
            keyFindings: Array.isArray(interpreted?.keyFindings) ? interpreted.keyFindings.map(String) : [],
            riskIndicators: Array.isArray(interpreted?.riskIndicators) ? interpreted.riskIndicators.map(String) : [],
            shouldEscalate: Boolean(interpreted?.shouldEscalate),
            escalationReason: interpreted?.escalationReason ? String(interpreted.escalationReason) : null,
            suggestedNextTools: Array.isArray(interpreted?.suggestedNextTools) ? interpreted.suggestedNextTools.map(String) : [],
            confidenceLevel: Number.isFinite(Number(interpreted?.confidenceLevel))
              ? Math.max(0, Math.min(1, Number(interpreted.confidenceLevel)))
              : 0.5,
            agentThought: String(interpreted?.agentThought || 'No thought generated')
          };
        } catch (interpretError: any) {
          interpretation = {
            interpretation: `Interpretation fallback: ${interpretError?.message || 'Parser unavailable'}`,
            keyFindings: toolError ? [`Tool failure: ${toolError.message}`] : [],
            riskIndicators: toolError ? ['Tool execution failure'] : [],
            shouldEscalate: Boolean(toolError),
            escalationReason: toolError ? `Failure in ${step.toolName}` : null,
            suggestedNextTools: [],
            confidenceLevel: 0.35,
            agentThought: 'Continuing mission despite interpretation endpoint failure.'
          };
        }

        allInterpretations.push(interpretation);
        findingsCache.push(...interpretation.keyFindings);
        appendLog(`🎯 ${interpretation.agentThought}`);
        interpretation.keyFindings.slice(0, 2).forEach((finding) => appendLog(`• ${finding}`));
        if (interpretation.shouldEscalate) {
          appendLog(`⬆️ ESCALATING: ${interpretation.escalationReason || 'High-risk indicator detected.'}`);
        }

        setAgentState('deciding');
        const riskDelta =
          interpretation.riskIndicators.length * 6 +
          (interpretation.shouldEscalate ? 10 : 0) +
          Math.max(0, Math.round((1 - interpretation.confidenceLevel) * 8));
        runningRiskScore = Math.max(0, Math.min(100, runningRiskScore + riskDelta));
        setRiskScore(runningRiskScore);
        if (interpretation.shouldEscalate || interpretation.riskIndicators.length >= 3) {
          criticalSignal = true;
        }

        updateStep(i, {
          status: toolError ? 'failed' : 'complete',
          actualOutput: toolOutput,
          interpretation,
          completedAt: Date.now()
        });
        missionSteps[i] = {
          ...missionSteps[i],
          status: toolError ? 'failed' : 'complete',
          actualOutput: toolOutput,
          interpretation,
          completedAt: Date.now()
        };

        await delay(500, controller.signal);
      }

      if (controller.signal.aborted || abortedRef.current) {
        appendLog('🧩 Mission stopped early. Building partial report...');
      }

      setAgentState('synthesizing');
      appendLog('📊 Synthesizing final report...');

      const finalSteps = ((): AgentStep[] => {
        return missionSteps.map((step, idx) => ({
          ...step,
          interpretation: allInterpretations[idx] || step.interpretation
        }));
      })();

      let synthesized: AgentReport;
      try {
        const report = await postJson(
          '/agent/synthesize',
          {
            target,
            allSteps: finalSteps.map((step) => ({
              stepNumber: step.stepNumber,
              toolName: step.toolName,
              toolInput: step.toolInput,
              output: step.actualOutput,
              status: step.status
            })),
            allInterpretations,
            agentMode: mode
          },
          controller.signal,
          Math.max(options.timeoutPerStepMs, 15000)
        );
        synthesized = report as AgentReport;
      } catch {
        synthesized = {
          reportTitle: `Automated Assessment Report (${target})`,
          executiveSummary:
            allInterpretations.map((item) => item.interpretation).join(' ') || 'No complete interpretation available.',
          overallRiskRating:
            runningRiskScore >= 81
              ? 'Critical'
              : runningRiskScore >= 61
                ? 'High'
                : runningRiskScore >= 31
                  ? 'Medium'
                  : runningRiskScore > 0
                    ? 'Low'
                    : 'Informational',
          attackSurface: {
            exposedServices: [],
            weakPoints: allInterpretations.flatMap((item) => item.riskIndicators).slice(0, 8),
            strongPoints: allInterpretations.flatMap((item) => item.keyFindings).slice(0, 8)
          },
          criticalFindings: allInterpretations
            .flatMap((item, idx) =>
              item.riskIndicators.map((indicator, jdx) => ({
                finding: indicator,
                evidence: item.interpretation,
                impact: 'Potentially exploitable security weakness',
                recommendation: 'Investigate and apply hardening controls.',
                priority: idx + jdx + 1
              }))
            )
            .slice(0, 8),
          mitreTacticsDetected: [],
          immediateActions: ['Review critical findings', 'Validate exposed services and patch urgent issues'],
          shortTermActions: ['Harden web stack and access controls', 'Enable continuous monitoring'],
          longTermActions: ['Adopt periodic red-team assessments', 'Improve threat-informed defenses'],
          riskScore: runningRiskScore,
          complianceNotes: 'This fallback report is generated when synthesis AI endpoint is unavailable.',
          conclusionStatement: abortedRef.current
            ? 'Mission was manually aborted; findings are partial.'
            : 'Automated assessment completed successfully.'
        };
      }

      setFinalReport(synthesized);
      setAgentState('complete');
      appendLog(`✅ Mission complete. Overall risk: ${synthesized.overallRiskRating}`);

      if (options.saveToForensicsTimeline) {
        try {
          await logForensicsEvent({
            timestamp: Date.now(),
            eventType: 'custom',
            sourceModule: 'AI Red Team Agent',
            severity: synthesized.overallRiskRating === 'Informational' ? 'Info' : (synthesized.overallRiskRating as any),
            title: `AI Red Team mission completed (${synthesized.overallRiskRating})`,
            description: synthesized.executiveSummary,
            details: {
              target,
              mode,
              riskScore: synthesized.riskScore,
              reportTitle: synthesized.reportTitle
            },
            attackPhase: 'Discovery',
            ioc: [target, ...(synthesized.mitreTacticsDetected || [])].slice(0, 20),
            tags: ['ai-agent', 'red-team', abortedRef.current ? 'partial' : 'complete']
          });
        } catch (forensicsError) {
          console.error('Forensics event logging skipped:', forensicsError);
        }
      }
    } catch (missionError: any) {
      const message = missionError instanceof Error ? missionError.message : 'Mission failed unexpectedly';
      setError(message);
      setAgentState(abortedRef.current ? 'complete' : 'error');
      appendLog(`🚨 Mission error: ${message}`);
    } finally {
      setAbortController(null);
      setCurrentToolName('');
    }
  };

  return {
    agentState,
    plan,
    steps,
    currentStepIndex,
    thoughtLog,
    finalReport,
    riskScore,
    elapsedTime,
    abortController,
    currentToolName,
    error,
    isAborted,
    isRunning,
    runMission,
    abortMission,
    resetMission
  };
}
