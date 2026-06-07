import React, { useState, useMemo } from 'react';
import { ScanType, SecurityAnalysis, ThreatLevel } from '../../types/types';
import { AlertTriangle, CheckCircle, ShieldAlert, Info, Terminal, Network, Code, Loader2, Wifi, WifiOff, Server, Globe, Database, Lock, Unlock, Activity } from 'lucide-react';
import RiskGauge from './RiskGauge';
import AttackGraph from './AttackGraph';
import { saveSetting } from '../../services/db';
import { toast } from 'react-hot-toast';

interface AnalysisResultProps {
  analysis: SecurityAnalysis;
  currentType?: ScanType;
  rawData?: string;
  onNavigate?: (type: ScanType) => void;
}

interface PortInfo {
  port: string;
  status: string;
  service: string;
  version?: string;
  protocol?: string;
}

interface VulnInfo {
  name: string;
  severity: string;
  parameter?: string;
  payload?: string;
}

const AnalysisResult: React.FC<AnalysisResultProps> = ({ analysis, currentType, rawData = '', onNavigate }) => {
  const [viewMode, setViewMode] = useState<'text' | 'graph'>('text');
  const [fixScript, setFixScript] = useState<string>('');
  const [generatingScript, setGeneratingScript] = useState(false);
  const [mitigateData, setMitigateData] = useState<{port: string, protocol: string, command: string} | null>(null);
  const [isMitigating, setIsMitigating] = useState(false);

  const normalizedThreatLevel: ThreatLevel = useMemo(() => {
    const value = String((analysis as unknown as Record<string, unknown>)?.threat_level || '').trim().toLowerCase();
    if (value === 'critical') return ThreatLevel.CRITICAL;
    if (value === 'high') return ThreatLevel.HIGH;
    if (value === 'medium') return ThreatLevel.MEDIUM;
    if (value === 'low' || value === 'safe') return ThreatLevel.LOW;
    return ThreatLevel.MEDIUM;
  }, [analysis]);

  const normalizedRiskScore = useMemo(() => {
    const direct = Number((analysis as unknown as Record<string, unknown>)?.risk_score);
    if (Number.isFinite(direct)) {
      return Math.max(0, Math.min(100, Math.round(direct)));
    }
    if (normalizedThreatLevel === ThreatLevel.CRITICAL) return 90;
    if (normalizedThreatLevel === ThreatLevel.HIGH) return 75;
    if (normalizedThreatLevel === ThreatLevel.MEDIUM) return 50;
    return 20;
  }, [analysis, normalizedThreatLevel]);

  const normalizedSummary = useMemo(() => {
    return String((analysis as unknown as Record<string, unknown>)?.summary || '').trim() || 'Data unavailable';
  }, [analysis]);

  const normalizedDetailedAnalysis = useMemo(() => {
    return String((analysis as unknown as Record<string, unknown>)?.detailed_analysis || '').trim() || 'Data unavailable';
  }, [analysis]);

  const normalizedAdditionalNotes = useMemo(() => {
    return String((analysis as unknown as Record<string, unknown>)?.additional_notes || '').trim() || 'Data unavailable';
  }, [analysis]);

  const normalizedRecommendations = useMemo(() => {
    if (Array.isArray(analysis.recommendations) && analysis.recommendations.length > 0) {
      return analysis.recommendations;
    }
    return ['Data unavailable'];
  }, [analysis.recommendations]);

  // Parse structured data from detailed_analysis
  const parsedData = useMemo(() => {
    const text = normalizedDetailedAnalysis;
    const ports: PortInfo[] = [];
    const vulns: VulnInfo[] = [];

    // Parse port information
    const portRegex = /(\d+)\/(tcp|udp)\s+(?:(open|closed|filtered))?\s*(?:\((\w+)\))?\s*[-:]?\s*([^\n]+)?/gi;
    let match;
    while ((match = portRegex.exec(text)) !== null) {
      ports.push({
        port: match[1],
        protocol: match[2],
        status: match[3] || 'open',
        service: match[4] || 'unknown',
        version: match[5]?.trim()
      });
    }

    // Parse vulnerability information
    const vulnRegex = /(?:vulnerability|vuln)[\s:]*([^\n]+)\s+(?:severity|risk)[\s:]*([^\n]+)/gi;
    while ((match = vulnRegex.exec(text)) !== null) {
      vulns.push({
        name: match[1]?.trim(),
        severity: match[2]?.trim()
      });
    }

    return { ports, vulns };
  }, [normalizedDetailedAnalysis]);

  const getServiceIcon = (service: string) => {
    const s = service.toLowerCase();
    if (s.includes('http') || s.includes('web')) return <Globe className="w-4 h-4" />;
    if (s.includes('ssh')) return <Lock className="w-4 h-4" />;
    if (s.includes('ftp')) return <Server className="w-4 h-4" />;
    if (s.includes('mysql') || s.includes('postgres') || s.includes('database')) return <Database className="w-4 h-4" />;
    if (s.includes('telnet')) return <Unlock className="w-4 h-4" />;
    return <Activity className="w-4 h-4" />;
  };

  const getStatusColor = (status: string) => {
    const s = status.toLowerCase();
    if (s.includes('open')) return 'text-red-400 bg-red-500/10 border-red-500/30';
    if (s.includes('closed')) return 'text-slate-400 bg-slate-500/10 border-slate-500/30';
    if (s.includes('filtered')) return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
    return 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30';
  };

  const zeroTrustPrefill = useMemo(() => {
    const rawPorts = (rawData.match(/\b(\d{2,5})\/(?:tcp|udp)\b/gi) || [])
      .map((entry) => Number(entry.split('/')[0]))
      .filter((port) => Number.isFinite(port));

    const openPorts = Array.from(
      new Set(
        [
          ...parsedData.ports
            .filter((p) => p.status.toLowerCase().includes('open'))
            .map((p) => Number(p.port))
            .filter((p) => Number.isFinite(p)),
          ...rawPorts
        ]
      )
    );

    const dangerSet = new Set([21, 23, 135, 137, 138, 139, 445, 1433, 3306, 3389, 5900]);
    const dangerousPorts = openPorts.filter((port) => dangerSet.has(port));
    const domainOrIp = (rawData.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b/) || [])[0] || null;

    return {
      openPorts,
      dangerousPorts,
      domain: domainOrIp
    };
  }, [parsedData.ports, rawData]);

  const openZeroTrustBuilder = async () => {
    if (zeroTrustPrefill.openPorts.length === 0) {
      toast.error('No open ports available for policy generation');
      return;
    }
    try {
      await saveSetting('zerotrust_prefill_payload', {
        sourceModule: 'Port Scanner',
        openPorts: zeroTrustPrefill.openPorts,
        dangerousPorts: zeroTrustPrefill.dangerousPorts,
        missingHeaders: [],
        detectedThreats: normalizedRecommendations.slice(0, 6),
        domain: zeroTrustPrefill.domain,
        internalIPs: [],
        targetEnvironment: 'linux_server',
        createdAt: Date.now()
      });

      if (onNavigate) {
        onNavigate(ScanType.ZERO_TRUST);
        toast.success('Zero Trust Builder opened with port findings');
      } else {
        toast.success('Port findings prepared for Zero Trust Builder');
      }
    } catch (error) {
      console.error('Failed to prefill Zero Trust payload:', error);
      toast.error('Failed to prepare Zero Trust prefill');
    }
  };

  const generateFixScript = async () => {
    setGeneratingScript(true);
    try {
      const response = await fetch('http://localhost:3001/api/generate-script', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          threatLevel: normalizedThreatLevel,
          summary: normalizedSummary,
          recommendations: normalizedRecommendations
        })
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ message: 'Failed to generate script' }));
        throw new Error(errorData.message || 'Failed to generate script');
      }

      const data = await response.json();
      setFixScript(String(data.script || 'Data unavailable'));
    } catch {
      setFixScript('Data unavailable');
    } finally {
      setGeneratingScript(false);
    }
  };

  const handleMitigate = async (port: string, protocol: string = 'tcp') => {
    setIsMitigating(true);
    try {
      const res = await fetch('http://localhost:3001/remediate/firewall', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ port, protocol, os: 'linux' })
      });
      const data = await res.json();
      if (data.success) {
        setMitigateData({ port, protocol, command: data.command });
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsMitigating(false);
    }
  };
  const getThreatColor = (level: ThreatLevel) => {
    switch (level) {
      case ThreatLevel.CRITICAL: return 'text-red-500 border-red-500 bg-red-500/10';
      case ThreatLevel.HIGH: return 'text-orange-500 border-orange-500 bg-orange-500/10';
      case ThreatLevel.MEDIUM: return 'text-yellow-500 border-yellow-500 bg-yellow-500/10';
      case ThreatLevel.LOW: return 'text-emerald-500 border-emerald-500 bg-emerald-500/10';
      default: return 'text-slate-500 border-slate-500 bg-slate-500/10';
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-fade-in">
      
      {/* Left Column: Summary & Metrics */}
      <div className="lg:col-span-1 space-y-6">
        {/* Threat Level Card */}
        <div className={`p-8 rounded-xl border-2 flex flex-col items-center justify-center text-center backdrop-blur-xl shadow-2xl relative overflow-hidden ${getThreatColor(normalizedThreatLevel)}`}>
          <div className="absolute inset-0 bg-gradient-to-br from-transparent to-black/20 z-0"></div>
          <ShieldAlert className="w-16 h-16 mb-4 relative z-10 drop-shadow-lg" />
          <h3 className="text-xs uppercase tracking-widest font-bold text-slate-100/90 relative z-10">Threat Level</h3>
          <p className="text-4xl font-black tracking-wider mt-2 relative z-10 drop-shadow-md text-slate-100">{normalizedThreatLevel || 'Data unavailable'}</p>
          <div className="mt-4 text-xs text-slate-100/75 relative z-10">Security Assessment</div>
        </div>

        {/* Risk Score Gauge */}
        <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-4 shadow-2xl">
          <RiskGauge score={normalizedRiskScore} />
        </div>

        {/* Summary Card */}
        <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-6 shadow-2xl">
          <div className="flex items-center gap-2 mb-4 text-cyan-400">
            <Info className="w-5 h-5" />
            <h3 className="font-bold text-lg">Executive Summary</h3>
          </div>
          <p className="text-slate-300 leading-relaxed text-sm mb-4">
            {normalizedSummary}
          </p>
          
          {/* Quick Stats */}
          {parsedData.ports.length > 0 && (
            <div className="grid grid-cols-2 gap-3 mt-4 pt-4 border-t border-slate-800">
              <div className="bg-slate-950/50 rounded-lg p-3 border border-slate-800">
                <div className="text-xs text-slate-500 font-semibold uppercase tracking-wide">Open Ports</div>
                <div className="text-2xl font-bold text-red-400 mt-1">
                  {parsedData.ports.filter(p => p.status.toLowerCase().includes('open')).length}
                </div>
              </div>
              <div className="bg-slate-950/50 rounded-lg p-3 border border-slate-800">
                <div className="text-xs text-slate-500 font-semibold uppercase tracking-wide">Services</div>
                <div className="text-2xl font-bold text-cyan-400 mt-1">
                  {new Set(parsedData.ports.map(p => p.service)).size}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Right Column: Details & Remediation */}
      <div className="lg:col-span-2 space-y-6">
        
        {/* Technical Analysis */}
        <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-6 shadow-2xl">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2 text-purple-400">
              <Terminal className="w-5 h-5" />
              <h3 className="font-bold text-lg">Technical Analysis</h3>
            </div>
            {/* View Toggle */}
            <div className="flex gap-2 bg-slate-950/50 p-1 rounded-lg">
              <button
                onClick={() => setViewMode('text')}
                className={`px-3 py-1 rounded text-xs font-semibold transition-all ${
                  viewMode === 'text'
                    ? 'bg-purple-500/20 text-purple-400'
                    : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                <Terminal className="w-3 h-3 inline mr-1" />
                Text
              </button>
              <button
                onClick={() => setViewMode('graph')}
                className={`px-3 py-1 rounded text-xs font-semibold transition-all ${
                  viewMode === 'graph'
                    ? 'bg-purple-500/20 text-purple-400'
                    : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                <Network className="w-3 h-3 inline mr-1" />
                Graph
              </button>
            </div>
          </div>
          
          {viewMode === 'text' ? (
            <div className="space-y-6">
              {/* Structured Port Display */}
              {parsedData.ports.length > 0 && (
                <div>
                  <h4 className="text-sm font-bold text-cyan-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                    <Network className="w-4 h-4" />
                    Discovered Ports & Services ({parsedData.ports.length})
                  </h4>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-slate-800">
                          <th className="text-left py-2 px-3 text-slate-400 font-semibold">Port</th>
                          <th className="text-left py-2 px-3 text-slate-400 font-semibold">Protocol</th>
                          <th className="text-left py-2 px-3 text-slate-400 font-semibold">Status</th>
                          <th className="text-left py-2 px-3 text-slate-400 font-semibold">Service</th>
                          <th className="text-left py-2 px-3 text-slate-400 font-semibold">Version</th>
                          <th className="text-left py-2 px-3 text-slate-400 font-semibold">Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {parsedData.ports.map((port, idx) => (
                          <tr key={idx} className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors">
                            <td className="py-3 px-3">
                              <span className="font-mono text-cyan-400 font-bold">{port.port}</span>
                            </td>
                            <td className="py-3 px-3">
                              <span className="text-slate-300 uppercase text-xs font-semibold">{port.protocol}</span>
                            </td>
                            <td className="py-3 px-3">
                              <span className={`px-2 py-1 rounded text-xs font-bold uppercase border ${getStatusColor(port.status)}`}>
                                {port.status}
                              </span>
                            </td>
                            <td className="py-3 px-3">
                              <div className="flex items-center gap-2 text-slate-300">
                                {getServiceIcon(port.service)}
                                <span className="font-medium">{port.service}</span>
                              </div>
                            </td>
                            <td className="py-3 px-3 text-slate-400 font-mono text-xs">
                              {port.version || '-'}
                            </td>
                            <td className="py-3 px-3">
                              {port.status.toLowerCase().includes('open') && (
                                <button 
                                  onClick={() => handleMitigate(port.port, port.protocol)}
                                  disabled={isMitigating}
                                  className="px-2 py-1 text-[10px] font-bold uppercase rounded bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/30 transition-all flex items-center gap-1 disabled:opacity-50"
                                >
                                  <ShieldAlert className="w-3 h-3" /> Auto-Mitigate
                                </button>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Raw Technical Details */}
              <div>
                <h4 className="text-sm font-bold text-purple-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                  <Code className="w-4 h-4" />
                  Detailed Analysis Output
                </h4>
                <div className="prose prose-invert max-w-none">
                  <pre className="text-slate-100 whitespace-pre-wrap font-mono text-xs bg-slate-950/90 p-4 rounded-lg border border-slate-700 leading-relaxed max-h-[360px] overflow-y-auto">
                    {normalizedDetailedAnalysis}
                  </pre>
                </div>
              </div>
            </div>
          ) : (
            <AttackGraph analysis={analysis} />
          )}
          
           {/* Exploitation Notes */}
           <div className="mt-6 p-4 rounded-lg bg-red-950/20 border border-red-500/30 relative z-10">
            <h4 className="text-sm font-bold text-red-400 uppercase tracking-wider mb-2 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4" />
              Exploitation Vector
            </h4>
            <p className="text-slate-100 text-sm leading-relaxed max-h-40 overflow-y-auto">
              {normalizedAdditionalNotes}
            </p>
          </div>
        </div>

        {/* Recommendations */}
        <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-6 shadow-2xl">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-2 text-emerald-400">
              <CheckCircle className="w-5 h-5" />
              <h3 className="font-bold text-lg">Remediation Steps</h3>
              <span className="ml-2 px-2 py-0.5 bg-emerald-500/10 border border-emerald-500/30 rounded-full text-xs font-bold text-emerald-400">
                {normalizedRecommendations.length} Actions
              </span>
            </div>
            <div className="flex items-center gap-2">
              {currentType === ScanType.PORT_SCAN && zeroTrustPrefill.openPorts.length > 0 && (
                <button
                  onClick={openZeroTrustBuilder}
                  className="flex items-center gap-2 px-4 py-2 bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 rounded-lg text-xs font-semibold transition-all border border-cyan-500/20"
                >
                  <ShieldAlert className="w-3 h-3" />
                  Generate Zero Trust Policy
                </button>
              )}
              <button
                onClick={generateFixScript}
                disabled={generatingScript}
                className="flex items-center gap-2 px-4 py-2 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 rounded-lg text-xs font-semibold transition-all border border-emerald-500/20 disabled:opacity-50"
              >
                {generatingScript ? (
                  <>
                    <Loader2 className="w-3 h-3 animate-spin" />
                    Generating...
                  </>
                ) : (
                  <>
                    <Code className="w-3 h-3" />
                    Generate Fix Script
                  </>
                )}
              </button>
            </div>
          </div>
          <div className="space-y-3">
            {normalizedRecommendations.map((rec, index) => (
              <div key={index} className="flex gap-4 p-4 rounded-lg bg-gradient-to-r from-slate-950/50 to-slate-900/30 border border-slate-800/50 hover:border-emerald-500/30 transition-all hover:shadow-lg hover:shadow-emerald-500/5">
                <div className="flex-shrink-0 w-7 h-7 rounded-full bg-gradient-to-br from-emerald-500/20 to-emerald-600/20 text-emerald-400 flex items-center justify-center font-mono text-sm font-bold border border-emerald-500/30 shadow-lg shadow-emerald-500/20">
                  {index + 1}
                </div>
                <p className="text-slate-300 text-sm leading-relaxed flex-1">{rec}</p>
              </div>
            ))}
          </div>
          
          {/* Generated Fix Script */}
          {fixScript && (
            <div className="mt-6 p-5 bg-slate-950/70 rounded-lg border border-emerald-500/30 shadow-lg shadow-emerald-500/5">
              <h4 className="text-xs font-bold text-emerald-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                <Code className="w-4 h-4" />
                Generated Remediation Script
              </h4>
              <pre className="text-xs text-slate-300 font-mono overflow-x-auto whitespace-pre-wrap bg-slate-950 p-4 rounded border border-slate-800">
                {fixScript}
              </pre>
            </div>
          )}
        </div>

      </div>

      {/* Auto-Mitigate Modal */}
      {mitigateData && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-fade-in">
          <div className="bg-slate-900 border border-red-500/50 rounded-xl max-w-lg w-full p-6 shadow-2xl">
            <div className="flex items-center gap-3 mb-4">
              <ShieldAlert className="w-6 h-6 text-red-500" />
              <h3 className="text-xl font-bold text-slate-200">Autonomous Remediation</h3>
            </div>
            <p className="text-sm text-slate-400 mb-4 leading-relaxed">
              The Sentinel AI engine has generated the exact OS-level firewall commands to actively block <strong className="text-red-400 font-mono">Port {mitigateData.port} ({mitigateData.protocol.toUpperCase()})</strong>. Please review carefully before applying.
            </p>
            <div className="bg-slate-950 p-4 rounded-lg font-mono text-xs text-green-400 border border-slate-800 mb-6 overflow-x-auto">
              <pre>{mitigateData.command}</pre>
            </div>
            <div className="flex gap-3 justify-end">
              <button 
                onClick={() => setMitigateData(null)} 
                className="px-4 py-2 rounded font-semibold text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 transition-all text-sm"
              >
                Cancel Action
              </button>
              <button 
                onClick={() => { 
                  navigator.clipboard.writeText(mitigateData.command); 
                  alert('Remediation command copied to clipboard. Execute in your terminal.'); 
                  setMitigateData(null); 
                }} 
                className="px-4 py-2 rounded font-bold text-white bg-red-600 hover:bg-red-700 transition-all flex items-center gap-2 text-sm shadow-lg shadow-red-900/50"
              >
                <CheckCircle className="w-4 h-4" /> Copy & Apply Stack
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AnalysisResult;
