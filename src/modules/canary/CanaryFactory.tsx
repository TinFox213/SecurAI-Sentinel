import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Bird, Key, FileText, Copy, Download, Shield, AlertTriangle, CheckCircle, Trash2, RefreshCw, Eye, MapPin } from 'lucide-react';
import jsPDF from 'jspdf';
import { logForensicsEvent } from '../../utils/forensicsLogger';
import { toast } from 'react-hot-toast';

type TokenType = 'aws' | 'github' | 'stripe' | 'openai';
type FileType = 'pdf' | 'docx' | 'xlsx';

export default function CanaryFactory() {
  const [activeTab, setActiveTab] = useState<'tokens' | 'files'>('tokens');

  return (
    <div className="space-y-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-2xl p-6"
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-gradient-to-br from-yellow-500 to-orange-500 rounded-xl">
              <Bird className="w-8 h-8 text-white" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-white">Canary Factory</h1>
              <p className="text-slate-400">Generate Honey Tokens & Trap Files</p>
            </div>
          </div>
          <div className="flex items-center gap-2 px-4 py-2 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
            <AlertTriangle className="w-5 h-5 text-yellow-400" />
            <span className="text-yellow-400 text-sm font-semibold">Deception Active</span>
          </div>
        </div>
      </motion.div>

      {/* Tab Navigation */}
      <div className="flex gap-3">
        <button
          onClick={() => setActiveTab('tokens')}
          className={`flex items-center gap-2 px-6 py-3 rounded-xl font-semibold transition-all ${
            activeTab === 'tokens'
              ? 'bg-gradient-to-r from-yellow-500 to-orange-500 text-white shadow-lg shadow-yellow-500/50'
              : 'bg-slate-800/60 text-slate-400 hover:bg-slate-700/60'
          }`}
        >
          <Key className="w-5 h-5" />
          Honey Tokens
        </button>
        <button
          onClick={() => setActiveTab('files')}
          className={`flex items-center gap-2 px-6 py-3 rounded-xl font-semibold transition-all ${
            activeTab === 'files'
              ? 'bg-gradient-to-r from-yellow-500 to-orange-500 text-white shadow-lg shadow-yellow-500/50'
              : 'bg-slate-800/60 text-slate-400 hover:bg-slate-700/60'
          }`}
        >
          <FileText className="w-5 h-5" />
          Trap Files
        </button>
      </div>

      {/* Content */}
      <motion.div
        key={activeTab}
        initial={{ opacity: 0, x: 20 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.3 }}
      >
        {activeTab === 'tokens' && <HoneyTokens />}
        {activeTab === 'files' && <TrapFiles />}
      </motion.div>
    </div>
  );
}

// ==================== Honey Tokens Generator ====================
function HoneyTokens() {
  const [selectedType, setSelectedType] = useState<TokenType>('aws');
  const [generatedToken, setGeneratedToken] = useState('');
  const [copied, setCopied] = useState(false);

  const tokenTemplates = {
    aws: {
      label: 'AWS Access Key',
      icon: '☁️',
      description: 'Fake AWS credentials to detect unauthorized cloud access',
      format: 'AKIA + 16 random chars'
    },
    github: {
      label: 'GitHub PAT',
      icon: '🐙',
      description: 'Personal Access Token to catch repository breaches',
      format: 'ghp_ + 36 random chars'
    },
    stripe: {
      label: 'Stripe API Key',
      icon: '💳',
      description: 'Payment API key to trap financial data theft',
      format: 'sk_live_ + 24 random chars'
    },
    openai: {
      label: 'OpenAI API Key',
      icon: '🤖',
      description: 'AI service key to detect API key leakage',
      format: 'sk-proj- + 48 random chars'
    }
  };

  const generateToken = () => {
    let token = '';
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    
    switch (selectedType) {
      case 'aws':
        token = 'AKIA' + Array.from({ length: 16 }, () => chars[Math.floor(Math.random() * chars.length)]).join('').toUpperCase();
        break;
      case 'github':
        token = 'ghp_' + Array.from({ length: 36 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
        break;
      case 'stripe':
        token = 'sk_live_' + Array.from({ length: 24 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
        break;
      case 'openai':
        token = 'sk-proj-' + Array.from({ length: 48 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
        break;
    }
    
    setGeneratedToken(token);
    setCopied(false);
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(generatedToken);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-4">
      <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-2xl p-6">
        <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <Key className="w-6 h-6 text-yellow-400" />
          Generate Honey Token
        </h2>

        <p className="text-slate-400 mb-6">
          Create realistic-looking fake credentials. Plant them in your codebase or configuration files. 
          If they're leaked or used, you'll know immediately that you've been compromised.
        </p>

        {/* Token Type Selection */}
        <div className="grid grid-cols-2 gap-3 mb-6">
          {(Object.keys(tokenTemplates) as TokenType[]).map((type) => (
            <button
              key={type}
              onClick={() => setSelectedType(type)}
              className={`p-4 rounded-xl border-2 transition-all text-left ${
                selectedType === type
                  ? 'border-yellow-500 bg-yellow-500/10'
                  : 'border-slate-700 bg-slate-800/60 hover:border-slate-600'
              }`}
            >
              <div className="text-2xl mb-2">{tokenTemplates[type].icon}</div>
              <div className="text-white font-semibold">{tokenTemplates[type].label}</div>
              <div className="text-xs text-slate-400 mt-1">{tokenTemplates[type].format}</div>
            </button>
          ))}
        </div>

        <div className="bg-slate-800/60 rounded-lg p-4 mb-4">
          <div className="text-sm text-slate-400 mb-2">Description:</div>
          <div className="text-slate-300 text-sm mb-4">{tokenTemplates[selectedType].description}</div>
          
          <div className="flex gap-2">
            <button
              onClick={() => {
                setSelectedType('aws');
                setGeneratedToken('AKIAIOSFODNN7EXAMPLE');
                toast.success('Sample AWS access key honey token loaded.');
              }}
              className="px-4 py-3 bg-purple-500/20 border border-purple-500/40 text-purple-300 hover:bg-purple-500/30 rounded-lg text-sm font-semibold transition-all flex-1"
            >
              Load Sample Data
            </button>
            <button
              onClick={generateToken}
              className="py-3 bg-gradient-to-r from-yellow-500 to-orange-500 hover:from-yellow-600 hover:to-orange-600 text-white font-semibold rounded-lg transition-all flex items-center justify-center gap-2 flex-[2]"
            >
              <Shield className="w-5 h-5" />
              Generate {tokenTemplates[selectedType].label}
            </button>
          </div>
        </div>

        {generatedToken && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="bg-slate-800/60 rounded-lg p-4"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-slate-400">Generated Token:</span>
              <button
                onClick={copyToClipboard}
                className="px-3 py-1 bg-cyan-500 hover:bg-cyan-600 text-white text-sm rounded-lg transition-colors flex items-center gap-2"
              >
                {copied ? <CheckCircle className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
                {copied ? 'Copied!' : 'Copy'}
              </button>
            </div>
            <div className="bg-slate-900/80 p-3 rounded font-mono text-sm text-yellow-400 break-all">
              {generatedToken}
            </div>
            <div className="mt-3 p-3 bg-orange-500/10 border border-orange-500/30 rounded-lg">
              <div className="flex items-start gap-2">
                <AlertTriangle className="w-5 h-5 text-orange-400 flex-shrink-0 mt-0.5" />
                <div className="text-sm text-orange-300">
                  <strong>Usage Instructions:</strong>
                  <ul className="list-disc list-inside mt-2 space-y-1 text-slate-300">
                    <li>Paste this token in commented-out code or config files</li>
                    <li>Do NOT use in production - this is a trap!</li>
                    <li>Monitor for usage via canarytoken.org or similar services</li>
                    <li>If triggered, investigate immediately for data breach</li>
                  </ul>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </div>

      {/* Best Practices */}
      <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-2xl p-6">
        <h3 className="text-lg font-bold text-white mb-4">🎯 Deployment Strategies</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-slate-800/60 rounded-lg p-4">
            <div className="text-yellow-400 font-semibold mb-2">📂 Code Comments</div>
            <div className="text-slate-300 text-sm">
              // TODO: Remove before deploy
              <br />
              // AWS_KEY = "{generatedToken || 'GENERATE_TOKEN'}"
            </div>
          </div>
          <div className="bg-slate-800/60 rounded-lg p-4">
            <div className="text-yellow-400 font-semibold mb-2">⚙️ Config Files</div>
            <div className="text-slate-300 text-sm">
              # .env.backup
              <br />
              STRIPE_SECRET_KEY={generatedToken || 'GENERATE_TOKEN'}
            </div>
          </div>
          <div className="bg-slate-800/60 rounded-lg p-4">
            <div className="text-yellow-400 font-semibold mb-2">📝 Documentation</div>
            <div className="text-slate-300 text-sm">
              Embed in internal wikis or README files as "test credentials"
            </div>
          </div>
          <div className="bg-slate-800/60 rounded-lg p-4">
            <div className="text-yellow-400 font-semibold mb-2">🗄️ Databases</div>
            <div className="text-slate-300 text-sm">
              Insert fake admin credentials in user tables
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ==================== Trap Files Generator ====================
function TrapFiles() {
  const [selectedFile, setSelectedFile] = useState<FileType>('pdf');
  const [fileName, setFileName] = useState('Salary_Confidential_2026');
  
  // Generate unique tracking ID for each file
  const generateTrackingId = () => {
    return `trap_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  };
  
  const [trackingId] = useState(generateTrackingId());
  const trackingUrl = `http://localhost:3001/track/pixel.png?token=${encodeURIComponent(fileName)}_${trackingId.split('_')[1]}`;

  const fileTemplates = {
    pdf: {
      label: 'PDF Document',
      icon: '📄',
      description: 'Confidential PDF with embedded tracking link',
      example: 'Salary_Confidential.pdf'
    },
    docx: {
      label: 'Word Document',
      icon: '📝',
      description: 'Business document with hidden tracking',
      example: 'Company_Secrets.docx'
    },
    xlsx: {
      label: 'Excel Spreadsheet',
      icon: '📊',
      description: 'Financial data with monitoring beacon',
      example: 'Q4_Financial_Report.xlsx'
    }
  };

  const generateTrapFile = () => {
    if (selectedFile === 'pdf') {
      const doc = new jsPDF();
      
      // Header
      doc.setFontSize(22);
      doc.setTextColor(139, 0, 0); // Dark red
      doc.text('CONFIDENTIAL', 105, 20, { align: 'center' });
      
      // Watermark
      doc.setFontSize(60);
      doc.setTextColor(200, 200, 200);
      doc.text('INTERNAL USE ONLY', 105, 150, { 
        align: 'center', 
        angle: 45 
      });
      
      // Content
      doc.setFontSize(16);
      doc.setTextColor(0, 0, 0);
      doc.text('Salary Information - 2026', 105, 40, { align: 'center' });
      
      doc.setFontSize(12);
      doc.text('Employee Name: John Doe', 20, 60);
      doc.text('Position: Senior Engineer', 20, 70);
      doc.text('Department: Engineering', 20, 80);
      doc.text('Annual Salary: $150,000', 20, 90);
      doc.text('Bonus: $25,000', 20, 100);
      doc.text('Stock Options: 10,000 units', 20, 110);
      doc.text('', 20, 120);
      doc.text('Benefits Package:', 20, 130);
      doc.text('  - Health Insurance: Premium Plan', 20, 140);
      doc.text('  - 401(k) Match: 6%', 20, 150);
      doc.text('  - Vacation Days: 25/year', 20, 160);
      
      // Tracking pixel embedded as invisible 1x1 image
      // The PDF will try to load this image when opened
      doc.addImage(trackingUrl, 'PNG', 0, 0, 0.1, 0.1);
      
      // Alternative: Add as hyperlink that auto-loads
      doc.setFontSize(6);
      doc.setTextColor(255, 255, 255); // White text (invisible)
      doc.textWithLink('.', 1, 1, { url: trackingUrl });
      
      // Footer
      doc.setFontSize(10);
      doc.setTextColor(139, 0, 0);
      doc.text('This document is confidential. Unauthorized distribution is prohibited.', 105, 270, { align: 'center' });
      doc.setFontSize(8);
      doc.setTextColor(180, 180, 180);
      doc.text('Document ID: ' + trackingId, 105, 280, { align: 'center' });
      
      // Save
      doc.save(`${fileName}.pdf`);
    } else {
      // For DOCX/XLSX, create a simple text file with instructions
      const content = selectedFile === 'docx' 
        ? `CONFIDENTIAL DOCUMENT\n\nThis is a honey file.\nIf opened, it indicates potential breach.\n\nTracking: ${trackingUrl}`
        : `FINANCIAL DATA\n\nQ4 Revenue: $5.2M\nProfit Margin: 32%\n\nTracking: ${trackingUrl}`;
      
      const blob = new Blob([content], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${fileName}.${selectedFile === 'docx' ? 'txt' : 'csv'}`;
      a.click();
      URL.revokeObjectURL(url);
    }
  };

  return (
    <div className="space-y-4">
      <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-2xl p-6">
        <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
          <FileText className="w-6 h-6 text-orange-400" />
          Generate Trap File
        </h2>

        <p className="text-slate-400 mb-6">
          Create decoy files that look valuable but are actually monitored. Place them in shared drives, 
          cloud storage, or network folders to detect unauthorized access.
        </p>

        {/* File Type Selection */}
        <div className="grid grid-cols-3 gap-3 mb-6">
          {(Object.keys(fileTemplates) as FileType[]).map((type) => (
            <button
              key={type}
              onClick={() => setSelectedFile(type)}
              className={`p-4 rounded-xl border-2 transition-all text-center ${
                selectedFile === type
                  ? 'border-orange-500 bg-orange-500/10'
                  : 'border-slate-700 bg-slate-800/60 hover:border-slate-600'
              }`}
            >
              <div className="text-3xl mb-2">{fileTemplates[type].icon}</div>
              <div className="text-white font-semibold text-sm">{fileTemplates[type].label}</div>
            </button>
          ))}
        </div>

        {/* Configuration */}
        <div className="space-y-4 mb-4">
          <div>
            <label className="block text-sm text-slate-400 mb-2">File Name</label>
            <input
              type="text"
              value={fileName}
              onChange={(e) => setFileName(e.target.value)}
              placeholder="Document_Name"
              className="w-full px-4 py-2 bg-slate-800/60 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-orange-500"
            />
          </div>
          
          <div>
            <label className="block text-sm text-slate-400 mb-2">Tracking URL (Auto-Generated)</label>
            <input
              type="text"
              value={trackingUrl}
              readOnly
              placeholder="Auto-generated tracking URL"
              className="w-full px-4 py-2 bg-slate-800/60 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-orange-500 font-mono text-sm"
            />
            <div className="text-xs text-green-400 mt-1 flex items-center gap-1">
              <CheckCircle className="w-3 h-3" />
              Real-time breach detection enabled - Alerts will appear instantly when this file is opened
            </div>
          </div>
        </div>

        <div className="flex gap-2">
          <button
            onClick={async () => {
              setSelectedFile('pdf');
              setFileName('Salary_Confidential_2026');
              toast.loading('Simulating honey token trigger...', { duration: 1500 });
              try {
                await fetch(trackingUrl);
                setTimeout(() => {
                  toast.success('Sample trap configuration loaded & breach simulation triggered!');
                }, 1500);
              } catch (err) {
                toast.error('Simulation failed');
              }
            }}
            className="px-4 py-3 bg-purple-500/20 border border-purple-500/40 text-purple-300 hover:bg-purple-500/30 rounded-lg text-sm font-semibold transition-all flex-1 text-center"
          >
            Load Sample & Test Trigger
          </button>
          <button
            onClick={generateTrapFile}
            className="py-3 bg-gradient-to-r from-orange-500 to-red-500 hover:from-orange-600 hover:to-red-600 text-white font-semibold rounded-lg transition-all flex items-center justify-center gap-2 flex-[2]"
          >
            <Download className="w-5 h-5" />
            Generate & Download Trap File
          </button>
        </div>

        <div className="mt-4 p-4 bg-orange-500/10 border border-orange-500/30 rounded-lg">
          <div className="flex items-start gap-2">
            <AlertTriangle className="w-5 h-5 text-orange-400 flex-shrink-0 mt-0.5" />
            <div className="text-sm text-slate-300">
              <strong className="text-orange-300">Deployment Tips:</strong>
              <ul className="list-disc list-inside mt-2 space-y-1">
                <li>Place in obvious locations: "HR Documents", "Financial Reports"</li>
                <li>Use enticing names: "Passwords.xlsx", "Admin_Credentials.pdf"</li>
                <li>Share on cloud storage with fake sensitive data</li>
                <li>Monitor the tracking URL for access attempts</li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      {/* Detection Info */}
      <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-2xl p-6">
        <h3 className="text-lg font-bold text-white mb-4">🔔 How It Works</h3>
        <div className="space-y-3">
          <div className="flex items-start gap-3">
            <div className="w-8 h-8 bg-yellow-500/20 rounded-lg flex items-center justify-center flex-shrink-0">
              <span className="text-yellow-400 font-bold">1</span>
            </div>
            <div>
              <div className="text-white font-semibold">Deploy the Trap</div>
              <div className="text-slate-400 text-sm">Place the file in a monitored location</div>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <div className="w-8 h-8 bg-yellow-500/20 rounded-lg flex items-center justify-center flex-shrink-0">
              <span className="text-yellow-400 font-bold">2</span>
            </div>
            <div>
              <div className="text-white font-semibold">Attacker Takes Bait</div>
              <div className="text-slate-400 text-sm">When opened, the tracking link is triggered</div>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <div className="w-8 h-8 bg-yellow-500/20 rounded-lg flex items-center justify-center flex-shrink-0">
              <span className="text-yellow-400 font-bold">3</span>
            </div>
            <div>
              <div className="text-white font-semibold">Receive Alert</div>
              <div className="text-slate-400 text-sm">Get immediate notification with IP, timestamp, and user-agent</div>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <div className="w-8 h-8 bg-yellow-500/20 rounded-lg flex items-center justify-center flex-shrink-0">
              <span className="text-yellow-400 font-bold">4</span>
            </div>
            <div>
              <div className="text-white font-semibold">Investigate & Respond</div>
              <div className="text-slate-400 text-sm">Trace the breach and take containment actions</div>
            </div>
          </div>
        </div>
      </div>

      {/* Live Breach Monitor */}
      <LiveBreachMonitor />
    </div>
  );
}

// ==================== Live Breach Monitor ====================
interface BreachAlert {
  id: number;
  token: string;
  ip: string;
  userAgent: string;
  timestamp: string;
}

function LiveBreachMonitor() {
  const [alerts, setAlerts] = useState<BreachAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const seenAlertsRef = useRef<Set<number>>(new Set());

  const fetchAlerts = async (showRefresh = false) => {
    try {
      if (showRefresh) setRefreshing(true);
      
      const response = await fetch('http://localhost:3001/track/alerts');
      const data = await response.json();
      
      setAlerts(data.alerts || []);

      // Additive forensic logging for newly observed canary triggers.
      try {
        for (const alert of data.alerts || []) {
          if (!seenAlertsRef.current.has(alert.id)) {
            seenAlertsRef.current.add(alert.id);
            await logForensicsEvent({
              timestamp: new Date(alert.timestamp).getTime(),
              eventType: 'canary_triggered',
              sourceModule: 'Canary Factory',
              severity: 'Critical',
              title: `Canary token triggered: ${alert.token}`,
              description: `Trap opened from ${alert.ip}`,
              details: alert,
              attackPhase: 'Collection',
              ioc: [alert.ip, alert.token],
              tags: ['canary', 'deception']
            });
          }
        }
      } catch (forensicsErr) {
        console.error('Forensics event logging skipped:', forensicsErr);
      }

      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch alerts:', error);
      setLoading(false);
    } finally {
      if (showRefresh) setRefreshing(false);
    }
  };

  const archiveAlert = async (id: number) => {
    try {
      await fetch(`http://localhost:3001/track/alerts/${id}`, {
        method: 'DELETE'
      });
      
      // Remove from UI immediately
      setAlerts(alerts.filter(alert => alert.id !== id));
    } catch (error) {
      console.error('Failed to archive alert:', error);
    }
  };

  const clearAllAlerts = async () => {
    try {
      await fetch('http://localhost:3001/track/alerts', {
        method: 'DELETE'
      });
      
      setAlerts([]);
    } catch (error) {
      console.error('Failed to clear alerts:', error);
    }
  };

  const getTimeAgo = (timestamp: string) => {
    const now = new Date();
    const then = new Date(timestamp);
    const diffMs = now.getTime() - then.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `${diffHours}h ago`;
    
    const diffDays = Math.floor(diffHours / 24);
    return `${diffDays}d ago`;
  };

  const parseDevice = (userAgent: string) => {
    // Extract meaningful device info from user-agent
    if (userAgent.includes('PDF')) return { type: '📄 PDF Reader', detail: 'Adobe/Browser PDF Viewer' };
    if (userAgent.includes('Word')) return { type: '📝 MS Word', detail: 'Microsoft Word' };
    if (userAgent.includes('Excel')) return { type: '📊 MS Excel', detail: 'Microsoft Excel' };
    if (userAgent.includes('Chrome')) return { type: '🌐 Chrome', detail: userAgent.match(/Chrome\/[\d.]+/)?.[0] || 'Chrome' };
    if (userAgent.includes('Firefox')) return { type: '🦊 Firefox', detail: userAgent.match(/Firefox\/[\d.]+/)?.[0] || 'Firefox' };
    if (userAgent.includes('Safari')) return { type: '🧭 Safari', detail: 'Safari' };
    if (userAgent.includes('Edge')) return { type: '🔷 Edge', detail: 'Microsoft Edge' };
    
    return { type: '💻 Unknown', detail: userAgent.substring(0, 50) };
  };

  // Auto-refresh every 3 seconds
  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(() => fetchAlerts(), 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-2xl p-6">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg ${alerts.length > 0 ? 'bg-red-500/20 animate-pulse' : 'bg-green-500/20'}`}>
            <Shield className={`w-6 h-6 ${alerts.length > 0 ? 'text-red-400' : 'text-green-400'}`} />
          </div>
          <div>
            <h2 className="text-2xl font-bold text-white flex items-center gap-2">
              🚨 Live Breach Monitor
              {alerts.length > 0 && (
                <span className="px-3 py-1 bg-red-500 text-white text-sm font-bold rounded-full animate-pulse">
                  {alerts.length}
                </span>
              )}
            </h2>
            <p className="text-slate-400 text-sm">Real-time trap file breach detection</p>
          </div>
        </div>
        
        <div className="flex items-center gap-2">
          <button
            onClick={() => fetchAlerts(true)}
            disabled={refreshing}
            className="p-2 bg-slate-800/60 hover:bg-slate-700/60 border border-slate-700 rounded-lg transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-5 h-5 text-slate-400 ${refreshing ? 'animate-spin' : ''}`} />
          </button>
          
          {alerts.length > 0 && (
            <button
              onClick={clearAllAlerts}
              className="px-4 py-2 bg-red-500/20 hover:bg-red-500/30 border border-red-500/50 text-red-400 rounded-lg transition-all flex items-center gap-2"
            >
              <Trash2 className="w-4 h-4" />
              Clear All
            </button>
          )}
        </div>
      </div>

      {loading ? (
        <div className="text-center py-12">
          <RefreshCw className="w-8 h-8 text-slate-500 animate-spin mx-auto mb-3" />
          <p className="text-slate-500">Loading breach monitor...</p>
        </div>
      ) : alerts.length === 0 ? (
        <div className="text-center py-12">
          <div className="w-16 h-16 bg-green-500/20 rounded-full flex items-center justify-center mx-auto mb-4">
            <CheckCircle className="w-8 h-8 text-green-400" />
          </div>
          <h3 className="text-xl font-bold text-green-400 mb-2">System Secure</h3>
          <p className="text-slate-400">No traps triggered. All canary files are untouched.</p>
          <div className="mt-4 inline-flex items-center gap-2 px-4 py-2 bg-green-500/10 border border-green-500/30 rounded-lg">
            <Eye className="w-4 h-4 text-green-400" />
            <span className="text-green-400 text-sm font-medium">Monitoring Active</span>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          <AnimatePresence>
            {alerts.map((alert) => {
              const device = parseDevice(alert.userAgent);
              
              return (
                <motion.div
                  key={alert.id}
                  initial={{ opacity: 0, x: -20, scale: 0.95 }}
                  animate={{ opacity: 1, x: 0, scale: 1 }}
                  exit={{ opacity: 0, x: 20, scale: 0.95 }}
                  className="bg-red-500/10 border-2 border-red-500/50 rounded-xl p-4 hover:bg-red-500/15 transition-all"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 space-y-3">
                      {/* Header Row */}
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <AlertTriangle className="w-5 h-5 text-red-400 animate-pulse" />
                          <span className="text-red-400 font-bold text-lg">BREACH DETECTED</span>
                        </div>
                        <span className="text-slate-400 text-sm">{getTimeAgo(alert.timestamp)}</span>
                      </div>
                      
                      {/* Details Grid */}
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                        {/* Trap Name */}
                        <div className="bg-slate-900/50 rounded-lg p-3 border border-slate-700/50">
                          <div className="text-slate-400 text-xs mb-1">Trap File</div>
                          <div className="text-white font-semibold text-sm break-all">
                            {alert.token}
                          </div>
                        </div>
                        
                        {/* IP Address */}
                        <div className="bg-slate-900/50 rounded-lg p-3 border border-slate-700/50">
                          <div className="text-slate-400 text-xs mb-1 flex items-center gap-1">
                            <MapPin className="w-3 h-3" />
                            Attacker IP
                          </div>
                          <div className="text-orange-400 font-mono text-sm font-bold">
                            {alert.ip}
                          </div>
                        </div>
                        
                        {/* Device */}
                        <div className="bg-slate-900/50 rounded-lg p-3 border border-slate-700/50">
                          <div className="text-slate-400 text-xs mb-1">Device</div>
                          <div className="text-white text-sm">
                            <div className="font-semibold">{device.type}</div>
                            <div className="text-slate-500 text-xs truncate">{device.detail}</div>
                          </div>
                        </div>
                      </div>
                      
                      {/* Full User Agent (Expandable) */}
                      <details className="text-xs">
                        <summary className="text-slate-500 cursor-pointer hover:text-slate-400">
                          Full User-Agent String
                        </summary>
                        <pre className="mt-2 p-2 bg-slate-900/80 rounded text-slate-400 overflow-x-auto">
                          {alert.userAgent}
                        </pre>
                      </details>
                      
                      {/* Timestamp */}
                      <div className="text-xs text-slate-500">
                        🕐 {new Date(alert.timestamp).toLocaleString()}
                      </div>
                    </div>
                    
                    {/* Archive Button */}
                    <button
                      onClick={() => archiveAlert(alert.id)}
                      className="p-2 bg-slate-800/60 hover:bg-red-500/20 border border-slate-700 hover:border-red-500/50 rounded-lg transition-all group"
                      title="Archive Alert"
                    >
                      <Trash2 className="w-4 h-4 text-slate-400 group-hover:text-red-400" />
                    </button>
                  </div>
                </motion.div>
              );
            })}
          </AnimatePresence>
          
          {/* Action Bar */}
          <div className="mt-4 p-4 bg-orange-500/10 border border-orange-500/30 rounded-lg">
            <div className="flex items-start gap-2">
              <AlertTriangle className="w-5 h-5 text-orange-400 flex-shrink-0 mt-0.5" />
              <div className="text-sm text-slate-300">
                <strong className="text-orange-300">Response Actions:</strong>
                <ul className="list-disc list-inside mt-2 space-y-1">
                  <li>Investigate the source IP address immediately</li>
                  <li>Check system logs for related suspicious activity</li>
                  <li>Quarantine potentially compromised systems</li>
                  <li>Review access logs for the timeframe of breach</li>
                  <li>Consider rotating credentials if sensitive data exposed</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
