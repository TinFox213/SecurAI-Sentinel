import React, { useState, useEffect, useMemo } from 'react';
import { motion } from 'framer-motion';
import Layout from './src/components/layout/Layout';
import Sidebar from './src/components/layout/Sidebar';
import AnalysisResult from './src/modules/analysis/AnalysisResult';
import AiChatOverlay from './src/components/common/AiChatOverlay';
import LiveAlertToast from './src/components/common/LiveAlertToast';
import DarkWebMonitor from './src/modules/darkweb/DarkWebMonitor';
import SecurityPostureScore from './src/modules/posture/SecurityPostureScore';
import MitreAttackMapper from './src/modules/mitre/MitreMapper';
import ForensicsTimeline from './src/modules/forensics/ForensicsTimeline';
import CryptoVault from './src/modules/crypto/CryptoVault';
import CyberDojo from './src/modules/dojo/CyberDojo';
import CanaryFactory from './src/modules/canary/CanaryFactory';
import NetworkWatchtower from './src/modules/watchtower/NetworkWatchtower';
import WebSecOps from './src/modules/websec/WebSecOps';
import UtilityBelt from './src/modules/utility/UtilityBelt';
import CVEIntelHub from './src/modules/cve/CVEHub';
import FleetEDR from './src/modules/fleet/FleetEDR';
import PacketCaptureAnalyzer from './src/components/PacketCaptureAnalyzer';
import IncidentResponsePlaybook from './src/components/IncidentResponsePlaybook';
import AIRedTeamAgent from './src/components/AIRedTeamAgent';
import ZeroTrustPolicyBuilder from './src/components/ZeroTrustPolicyBuilder';
import HomePage from './src/modules/home/HomePage';
import { ScanType, SecurityAnalysis } from './src/types/types';
import { analyzeSecurityData } from './src/services/geminiService';
import { saveScanToHistory, ScanHistory } from './src/services/db';
import { generatePDF } from './src/services/reportGenerator';
import { logForensicsEvent } from './src/utils/forensicsLogger';
import { Play, RotateCcw, ShieldCheck, Loader2, Copy, AlertCircle, CheckCircle2, HelpCircle, FileDown, Terminal, Search, X, ArrowRight, GitBranch, Tag } from 'lucide-react';
import { toast } from 'react-hot-toast';
import {
  commandModules,
  getModule,
  getModuleGroupConfig,
  getModuleLabel,
  getModuleSecondaryLabels,
  getWorkflowModules,
  moduleRegistry,
  teamModuleGroups,
} from './src/config/modules';

const SAMPLE_DATA: Partial<Record<ScanType, string>> = {
  [ScanType.PORT_SCAN]: `Target: 192.168.1.15
Open Ports:
- 22/tcp (SSH) - OpenSSH 7.2p2 Ubuntu 4ubuntu2.10
- 80/tcp (HTTP) - Apache httpd 2.4.18
- 21/tcp (FTP) - vsftpd 3.0.3
- 3306/tcp (MySQL) - MySQL 5.7.33`,
  [ScanType.VULN_SCAN]: `URL: http://test-site.local/login.php
Vulnerabilities Found:
1. SQL Injection (High)
   Parameter: username
   Payload: ' OR 1=1 --
2. XSS Reflected (Medium)
   Parameter: search
   Payload: <script>alert(1)</script>
3. Missing Security Headers: X-Frame-Options, Content-Security-Policy`,
  [ScanType.PHISHING]: `Subject: URGENT: Account Suspension Notice
From: support@secure-bank-login-verify.com
Links: 
- http://bit.ly/2xk3s (Redirects to http://login-verify-secure.com/auth)
Content: "Your account has been flagged. Click here to verify immediately or lose access."
SPF: Fail
DKIM: None`,
  [ScanType.MALWARE]: `File: invoice_scan.exe
Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Strings Extracted:
- CreateRemoteThread
- VirtualAlloc
- advapi32.dll
- C:\\Windows\\System32\\cmd.exe
- http://c2-server.attacker-site.ru/beacon.php`,
  [ScanType.KEYLOGGER]: `Process List Analysis:
- winlogon.exe (PID: 452) - System
- svchost.exe (PID: 882) - System
- keyhook.dll (Injected into PID 1204 explorer.exe)
- unknown_process.exe (PID: 5521) - User [Suspicious Path: C:\\Temp\\updater.exe]
- Hooks detected: WH_KEYBOARD_LL`,
  [ScanType.GENERAL_LOG]: `Jan 12 14:22:11 server sshd[1202]: Failed password for root from 192.168.1.50 port 4421 ssh2
Jan 12 14:22:13 server sshd[1202]: Failed password for root from 192.168.1.50 port 4421 ssh2
Jan 12 14:22:15 server sshd[1202]: Failed password for root from 192.168.1.50 port 4421 ssh2
Jan 12 14:22:18 server sshd[1202]: Accepted password for root from 192.168.1.50 port 4421 ssh2`
};

const App: React.FC = () => {
  const [currentType, setCurrentType] = useState<ScanType>(ScanType.HOME);
  const [inputData, setInputData] = useState<string>('');
  const [analysis, setAnalysis] = useState<SecurityAnalysis | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false);
  const [commandQuery, setCommandQuery] = useState('');

  // Real-time validation logic
  const validation = useMemo(() => {
    if (!inputData.trim()) return { status: 'empty', message: '' };

    const lower = inputData.toLowerCase();
    
    const patterns = {
      [ScanType.PORT_SCAN]: /(port|tcp|udp|open|closed|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i,
      [ScanType.VULN_SCAN]: /(url|vuln|param|payload|xss|sql|cve|injection|http)/i,
      [ScanType.PHISHING]: /(subject|from|links|spf|dkim|redirect|phish|verify|account)/i,
      [ScanType.MALWARE]: /(hash|strings|md5|sha1|sha256|exe|dll|beacon|payload)/i,
      [ScanType.KEYLOGGER]: /(pid|hook|keyboard|dll|process|injected|winlogon|svchost)/i,
      [ScanType.GENERAL_LOG]: /(\d{4}-\d{2}-\d{2}|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|sshd|failed|accepted|systemd)/i,
    };

    // Check current type's specific pattern
    const activePattern = patterns[currentType as keyof typeof patterns];
    if (!activePattern) {
      return { status: 'uncertain', message: 'This module uses its own data collection flow.' };
    }

    const isValid = activePattern.test(inputData);

    if (isValid) {
      return { status: 'valid', message: 'Input format matches module requirements.' };
    }

    // Heuristic: Check if it matches another type better
    for (const [type, pattern] of Object.entries(patterns)) {
      if (type !== currentType && pattern.test(inputData)) {
        return { 
          status: 'warning', 
          message: `Warning: This data looks more like a ${type}. Double-check your module selection.` 
        };
      }
    }

    return { 
      status: 'uncertain', 
      message: 'Input format is unusual for this module. Results may be less accurate.' 
    };
  }, [inputData, currentType]);

  const handleAnalyze = async () => {
    if (!inputData.trim()) return;
    setLoading(true);
    setError(null);
    setAnalysis(null);

    try {
      const result = await analyzeSecurityData(currentType, inputData);
      setAnalysis(result);
      
      // Save to history
      await saveScanToHistory(currentType, inputData, result);

      // Additive forensic logging for legacy analyzer modules.
      try {
        if (currentType === ScanType.PORT_SCAN) {
          const hasDangerousPort = /\b(21|23|445|3389)\b/.test(inputData) || /danger|critical|high/i.test(result.summary || '');
          if (hasDangerousPort) {
            await logForensicsEvent({
              timestamp: Date.now(),
              eventType: 'port_scan',
              sourceModule: 'Port Scanner',
              severity: result.threat_level === 'Critical' ? 'Critical' : 'High',
              title: 'Dangerous ports identified',
              description: result.summary || 'Port scanner identified high-risk service exposure.',
              details: { scanType: currentType, riskScore: result.risk_score },
              attackPhase: 'Discovery',
              ioc: (inputData.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b|\b\d{2,5}\b/g) || []).slice(0, 10),
              tags: ['port-scan', 'network-exposure']
            });
          }
        }

        if (currentType === ScanType.PHISHING && result.threat_level !== 'Low') {
          await logForensicsEvent({
            timestamp: Date.now(),
            eventType: 'phishing_detected',
            sourceModule: 'Phishing Detect',
            severity: result.threat_level === 'Critical' ? 'Critical' : 'High',
            title: 'Phishing indicators detected',
            description: result.summary || 'Potential phishing campaign indicators identified.',
            details: { scanType: currentType, riskScore: result.risk_score },
            attackPhase: 'Initial Access',
            ioc: (inputData.match(/https?:\/\/\S+|[\w.-]+@[\w.-]+|spf|dkim/gi) || []).slice(0, 10),
            tags: ['phishing', 'email-threat']
          });
        }

        if (currentType === ScanType.MALWARE && (result.threat_level === 'Critical' || result.threat_level === 'High')) {
          await logForensicsEvent({
            timestamp: Date.now(),
            eventType: 'malware_detected',
            sourceModule: 'Malware Analysis',
            severity: result.threat_level === 'Critical' ? 'Critical' : 'High',
            title: 'Malware indicators identified',
            description: result.summary || 'Malware execution and persistence indicators identified.',
            details: { scanType: currentType, riskScore: result.risk_score },
            attackPhase: 'Execution',
            ioc: (inputData.match(/\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b|\.exe|\.dll|beacon/gi) || []).slice(0, 12),
            tags: ['malware', 'endpoint']
          });
        }
      } catch (forensicsErr) {
        console.error('Forensics event logging skipped:', forensicsErr);
      }
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Analysis failed. Please check your API key and try again.';
      console.error('Analysis Error Details:', err);
      setError(errorMessage);
      toast.error(`AI analysis failed: ${errorMessage}`);
    } finally {
      setLoading(false);
    }
  };

  const loadSample = () => {
    const sample = SAMPLE_DATA[currentType];
    if (sample) setInputData(sample);
  };

  const handleLoadHistory = (scan: ScanHistory) => {
    setCurrentType(scan.scanType);
    setInputData(scan.rawData);
    setAnalysis(scan.analysisResult);
    setError(null);
  };

  const handleExportPDF = async () => {
    if (!analysis) return;
    
    try {
      await generatePDF({
        scanType: currentType,
        timestamp: new Date(),
        analysis: analysis,
        rawData: inputData
      });
    } catch (error) {
      console.error('PDF generation failed:', error);
      setError('Failed to generate PDF report');
      toast.error('Failed to generate PDF report');
    }
  };

  const filteredCommandItems = useMemo(() => {
    const query = commandQuery.trim().toLowerCase();
    if (!query) return commandModules;
    return commandModules.filter((item) => {
      const groupLabel = getModuleGroupConfig(item.group)?.label.toLowerCase() || '';
      const secondaryLabels = getModuleSecondaryLabels(item).join(' ').toLowerCase();
      return (
        item.label.toLowerCase().includes(query) ||
        item.type.toLowerCase().includes(query) ||
        item.description.toLowerCase().includes(query) ||
        groupLabel.includes(query) ||
        secondaryLabels.includes(query)
      );
    });
  }, [commandQuery]);

  useEffect(() => {
    const handleShortcut = (event: KeyboardEvent) => {
      const isPaletteShortcut = (event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k';
      if (!isPaletteShortcut) return;
      event.preventDefault();
      setIsCommandPaletteOpen((prev) => !prev);
      setCommandQuery('');
    };

    window.addEventListener('keydown', handleShortcut);
    return () => window.removeEventListener('keydown', handleShortcut);
  }, []);

  const navigateToModule = (type: ScanType) => {
    setCurrentType(type);
    setIsCommandPaletteOpen(false);
    setCommandQuery('');
    setError(null);
  };

  const canExportAnalysis = Boolean(analysis && SAMPLE_DATA[currentType]);
  const workflowModules = useMemo(() => getWorkflowModules(currentType), [currentType]);
  const currentModule = getModule(currentType);
  const currentGroup = currentModule ? getModuleGroupConfig(currentModule.group) : undefined;
  const CurrentGroupIcon = currentGroup?.icon;
  const secondaryLabels = currentModule ? getModuleSecondaryLabels(currentModule) : [];
  const moduleCount = moduleRegistry.filter((item) => item.type !== ScanType.HOME).length;

  return (
    <Layout>
      {/* Sidebar wrapper with fixed width */}
      <div className="w-72 min-w-[288px] h-full flex-shrink-0">
        <Sidebar currentType={currentType} onSelect={navigateToModule} onLoadHistory={handleLoadHistory} />
      </div>
      
      {/* Main content area */}
      <main className="flex-1 flex flex-col h-full overflow-hidden relative">
        {/* Header */}
        <header className="h-14 sm:h-16 glass-topbar flex items-center justify-between px-4 sm:px-8 z-10">
          <div className="flex-1 min-w-0">
            <motion.h2 
              key={currentType}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              className="text-base sm:text-xl font-bold text-slate-100 flex items-center gap-2 truncate"
            >
              <span className="text-cyan-500">/</span> 
              <span className="truncate">{getModuleLabel(currentType)}</span>
            </motion.h2>
          </div>
          <div className="flex items-center gap-2 sm:gap-4 flex-shrink-0">
             {canExportAnalysis && (
               <button
                 onClick={handleExportPDF}
                 className="hidden sm:flex items-center gap-2 px-4 py-2 bg-purple-600/20 hover:bg-purple-600/30 text-purple-400 rounded-lg text-xs font-semibold transition-all border border-purple-500/20"
               >
                 <FileDown className="w-4 h-4" />
                 Export Report
               </button>
             )}
             <div className="text-[10px] sm:text-xs font-mono text-slate-400 glass-control px-2 sm:px-3 py-1 rounded">
                {loading ? <span className="text-yellow-500 animate-pulse">ANALYZING...</span> : <span className="text-emerald-500">READY</span>}
             </div>
          </div>
        </header>

        {/* Content Area */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 scroll-smooth">
          <div className="max-w-7xl mx-auto space-y-6 sm:space-y-8">
            {currentModule && currentType !== ScanType.HOME && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="glass-panel rounded-xl p-4"
              >
                <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      {CurrentGroupIcon && currentGroup && (
                        <span className="inline-flex items-center gap-2 rounded-lg border border-cyan-300/20 bg-cyan-400/10 px-2.5 py-1 text-xs font-semibold text-cyan-100">
                          <CurrentGroupIcon className="h-3.5 w-3.5" />
                          {currentGroup.label}
                        </span>
                      )}
                      {secondaryLabels.map((label) => (
                        <span key={label} className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 bg-white/[0.035] px-2.5 py-1 text-xs font-medium text-slate-300">
                          <Tag className="h-3 w-3 text-slate-500" />
                          {label}
                        </span>
                      ))}
                    </div>
                    <p className="mt-2 text-sm text-slate-400">{currentModule.description}</p>
                  </div>

                  {workflowModules.length > 0 && (
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-slate-500">
                        <GitBranch className="h-3.5 w-3.5 text-cyan-300" />
                        Workflow
                      </span>
                      {workflowModules.map((item) => {
                        const Icon = item.icon;
                        return (
                          <button
                            key={item.type}
                            onClick={() => navigateToModule(item.type)}
                            className="group inline-flex min-h-9 items-center gap-2 rounded-lg border border-white/10 bg-white/[0.035] px-3 py-1.5 text-xs font-semibold text-slate-200 transition-all hover:border-cyan-300/35 hover:bg-cyan-400/10 hover:text-cyan-100"
                          >
                            <Icon className="h-3.5 w-3.5 text-slate-500 group-hover:text-cyan-200" />
                            {item.label}
                            <ArrowRight className="h-3.5 w-3.5 text-slate-600 transition-transform group-hover:translate-x-0.5 group-hover:text-cyan-200" />
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>
              </motion.div>
            )}
            
            {/* Module-specific Components */}
            {currentType === ScanType.HOME ? (
              <HomePage onNavigate={navigateToModule} />
            ) : currentType === ScanType.SECURITY_POSTURE ? (
               <SecurityPostureScore onNavigate={navigateToModule} />
            ) : currentType === ScanType.AI_RED_TEAM ? (
              <AIRedTeamAgent onNavigate={navigateToModule} />
            ) : currentType === ScanType.MITRE_ATTACK ? (
              <MitreAttackMapper />
            ) : currentType === ScanType.DARK_WEB ? (
              <DarkWebMonitor />
            ) : currentType === ScanType.FORENSICS_TIMELINE ? (
              <ForensicsTimeline />
            ) : currentType === ScanType.FILE_CRYPTO ? (
              <CryptoVault />
            ) : currentType === ScanType.CYBER_DOJO ? (
              <CyberDojo />
            ) : currentType === ScanType.PACKET_ANALYZER ? (
              <PacketCaptureAnalyzer onNavigate={navigateToModule} />
            ) : currentType === ScanType.IR_PLAYBOOK ? (
              <IncidentResponsePlaybook />
            ) : currentType === ScanType.CANARY_FACTORY ? (
              <CanaryFactory />
            ) : currentType === ScanType.NETWORK_WATCHTOWER ? (
              <NetworkWatchtower />
            ) : currentType === ScanType.WEBSEC_OPS ? (
              <WebSecOps onNavigate={navigateToModule} />
            ) : currentType === ScanType.ZERO_TRUST ? (
              <ZeroTrustPolicyBuilder onNavigate={navigateToModule} />
            ) : currentType === ScanType.UTILITY_BELT ? (
              <UtilityBelt />
            ) : currentType === ScanType.CVE_INTEL ? (
              <CVEIntelHub />
            ) : currentType === ScanType.EDR_FLEET ? (
              <FleetEDR />
            ) : (
              <>
            {/* Input Section */}
            <motion.div 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="glass-panel rounded-xl p-6"
            >
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-4">
                  <label className="text-sm font-semibold text-slate-300 uppercase tracking-wide flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-cyan-400" />
                    Input Scan Data / Logs
                  </label>
                  
                  {/* Validation Indicator */}
                  {validation.status !== 'empty' && (
                    <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-tighter border animate-fade-in ${
                      validation.status === 'valid' ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500/20' : 
                      validation.status === 'warning' ? 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20' : 
                      'bg-slate-500/10 text-slate-400 border-slate-500/20'
                    }`}>
                      {validation.status === 'valid' ? <CheckCircle2 className="w-3 h-3" /> : 
                       validation.status === 'warning' ? <AlertCircle className="w-3 h-3" /> : 
                       <HelpCircle className="w-3 h-3" />}
                      {validation.status}
                    </div>
                  )}
                </div>

                <button 
                  onClick={loadSample}
                  className="glass-control text-slate-300 hover:text-slate-100 px-4 py-2 rounded-lg flex items-center gap-2 transition-all text-xs"
                >
                  <Copy className="w-3 h-3" /> Load Sample Data
                </button>
              </div>
              
              <div className="relative group">
                <textarea
                  value={inputData}
                  onChange={(e) => setInputData(e.target.value)}
                  placeholder={`Paste your ${currentType.toLowerCase()} output here...`}
                  className="w-full h-48 glass-control rounded-lg p-4 text-slate-300 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/50 transition-all font-mono text-sm resize-y placeholder:text-slate-700"
                />
                
                {/* Real-time Validation Message */}
                {validation.message && (
                  <div className={`mt-2 text-[11px] font-medium flex items-center gap-1.5 transition-all ${
                    validation.status === 'valid' ? 'text-emerald-500' : 
                    validation.status === 'warning' ? 'text-yellow-500' : 'text-slate-500'
                  }`}>
                    {validation.status === 'warning' && <AlertCircle className="w-3.5 h-3.5" />}
                    {validation.message}
                  </div>
                )}

                <div className="absolute bottom-4 right-4 flex gap-2">
                  <button
                    onClick={() => setInputData('')}
                    className="glass-control text-slate-300 hover:text-slate-100 px-4 py-2 rounded-lg flex items-center gap-2 transition-all"
                    title="Clear Input"
                  >
                    <RotateCcw className="w-4 h-4" />
                  </button>
                  <button
                    onClick={handleAnalyze}
                    disabled={loading || !inputData.trim()}
                    className="bg-cyan-500/10 text-cyan-300 border border-cyan-400/30 hover:bg-cyan-500/20 hover:shadow-[0_0_18px_rgba(6,182,212,0.25)] px-4 py-2 rounded-lg flex items-center gap-2 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {loading ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" /> Analyzing
                      </>
                    ) : (
                      <>
                        <Play className="w-4 h-4" /> Run Analysis Engine
                      </>
                    )}
                  </button>
                </div>
              </div>
            </motion.div>

            {/* Error Message */}
            {error && (
              <motion.div 
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                className="bg-red-500/10 backdrop-blur-sm border border-red-500/50 text-red-400 p-4 rounded-lg flex items-center gap-3 shadow-lg"
              >
                <AlertCircle className="w-5 h-5" />
                {error}
              </motion.div>
            )}

            {/* Loading State */}
            {loading && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="flex flex-col items-center justify-center py-20"
              >
                <div className="relative mb-6">
                  <div className="absolute inset-0 bg-cyan-500/30 blur-3xl animate-pulse"></div>
                  <Loader2 className="w-24 h-24 relative text-cyan-400 animate-spin" />
                </div>
                <h3 className="text-xl font-bold text-cyan-400 mb-2 animate-pulse">Analyzing Security Data</h3>
                <p className="text-sm text-slate-500">AI engine processing threat assessment...</p>
                
                <div className="mt-8 flex gap-2">
                  <div className="w-2 h-2 bg-cyan-500 rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></div>
                  <div className="w-2 h-2 bg-cyan-500 rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></div>
                  <div className="w-2 h-2 bg-cyan-500 rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></div>
                </div>
              </motion.div>
            )}

            {/* Results Section */}
            {analysis && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.2 }}
              >
                <AnalysisResult
                  analysis={analysis}
                  currentType={currentType}
                  rawData={inputData}
                  onNavigate={navigateToModule}
                />
              </motion.div>
            )}

            {!analysis && !loading && !error && (
              <div className="flex flex-col items-center justify-center py-20 text-slate-500">
                <div className="relative mb-6">
                  <div className="absolute inset-0 bg-cyan-500/20 blur-2xl animate-pulse"></div>
                  <ShieldCheck className="w-28 h-28 relative text-cyan-500/40" />
                </div>
                <h3 className="text-xl font-bold text-slate-400 mb-2">AI Security Analysis Engine Ready</h3>
                <p className="text-sm text-slate-600 mb-6">Awaiting input data for threat assessment</p>
                
                <div className="grid grid-cols-2 gap-4 max-w-md w-full mt-4">
                  <div className="glass-panel rounded-lg p-4 text-center">
                    <div className="text-2xl font-bold text-cyan-400">{moduleCount}</div>
                    <div className="text-xs text-slate-500 mt-1">Mission Modules</div>
                  </div>
                  <div className="glass-panel rounded-lg p-4 text-center">
                    <div className="text-2xl font-bold text-emerald-400">{teamModuleGroups.length}</div>
                    <div className="text-xs text-slate-500 mt-1">Team Workspaces</div>
                  </div>
                </div>
              </div>
            )}
          </>
        )}

          </div>
        </div>
      </main>
      
      {/* Live Canary Alert Notifications */}
      <LiveAlertToast />

      {isCommandPaletteOpen && (
        <div className="fixed inset-0 z-[120] bg-black/60 backdrop-blur-sm p-4" onClick={() => setIsCommandPaletteOpen(false)}>
          <div
            className="max-w-2xl mx-auto mt-20 glass-panel rounded-xl overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-3 border-b border-white/10 flex items-center gap-2">
              <Search className="w-4 h-4 text-cyan-300" />
              <input
                autoFocus
                value={commandQuery}
                onChange={(e) => setCommandQuery(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Escape') setIsCommandPaletteOpen(false);
                  if (e.key === 'Enter' && filteredCommandItems[0]) {
                    navigateToModule(filteredCommandItems[0].type);
                  }
                }}
                placeholder="Search modules..."
                className="flex-1 bg-transparent text-slate-100 outline-none text-sm"
              />
              <button onClick={() => setIsCommandPaletteOpen(false)} className="text-slate-400 hover:text-slate-200">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="max-h-[420px] overflow-y-auto">
              {filteredCommandItems.map((item) => {
                const Icon = item.icon;
                return (
                  <button
                    key={item.type}
                    onClick={() => navigateToModule(item.type)}
                    className="w-full px-4 py-3 text-left border-b border-white/5 hover:bg-cyan-500/10 text-slate-200 text-sm flex items-center gap-3"
                  >
                    <Icon className="w-4 h-4 text-slate-500" />
                    <span className="min-w-0 flex-1">
                      <span className="block font-semibold">{item.label}</span>
                      <span className="mt-0.5 block truncate text-xs text-slate-500">
                        {getModuleGroupConfig(item.group)?.label}
                        {item.secondaryGroups?.length ? ` / ${getModuleSecondaryLabels(item).join(', ')}` : ''}
                      </span>
                    </span>
                  </button>
                );
              })}
              {filteredCommandItems.length === 0 && (
                <p className="px-4 py-5 text-sm text-slate-500">No modules match your search.</p>
              )}
            </div>
          </div>
        </div>
      )}
      
      {/* AI Chat Assistant */}
      <AiChatOverlay analysisContext={analysis || undefined} />
    </Layout>
  );
};

export default App;
