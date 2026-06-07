import React, { useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import {
  AlertTriangle,
  Box,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Cloud,
  Copy,
  Download,
  FileDown,
  Filter,
  Globe,
  Monitor,
  Server,
  Shield,
  Sparkles,
  Terminal
} from 'lucide-react';
import { toast } from 'react-hot-toast';
import { ScanType, PolicyConfig, SecurityRule, ZeroTrustPolicy } from '../types/types';
import { deleteSetting, getAllScans, getSetting } from '../services/db';
import { logForensicsEvent } from '../utils/forensicsLogger';

interface ZeroTrustPolicyBuilderProps {
  onNavigate?: (type: ScanType) => void;
}

type InputTab = 'load' | 'manual';
type Environment = 'linux_server' | 'nginx' | 'apache' | 'aws' | 'docker' | 'windows';

const environmentCards: Array<{
  key: Environment;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  { key: 'linux_server', label: 'Linux Server', icon: Terminal, description: 'iptables, ufw, fail2ban rules' },
  { key: 'nginx', label: 'Nginx', icon: Globe, description: 'nginx.conf security blocks, CSP headers' },
  { key: 'apache', label: 'Apache', icon: Server, description: '.htaccess, mod_security, headers' },
  { key: 'aws', label: 'AWS Cloud', icon: Cloud, description: 'Security Group rules, NACLs, WAF rules' },
  { key: 'docker', label: 'Docker', icon: Box, description: 'docker-compose security, network policies' },
  { key: 'windows', label: 'Windows Server', icon: Monitor, description: 'Windows Firewall, PowerShell hardening' }
];

const headerOptions = [
  'Content-Security-Policy',
  'Strict-Transport-Security (HSTS)',
  'X-Frame-Options',
  'X-Content-Type-Options',
  'Referrer-Policy',
  'Permissions-Policy',
  'X-XSS-Protection'
];

const templateLibrary: Array<{
  name: string;
  description: string;
  environment: Environment;
  config: Omit<PolicyConfig, 'isValidated' | 'validationErrors' | 'validationWarnings'>;
  suggestedPorts?: number[];
  suggestedDangerous?: number[];
  suggestedHeaders?: string[];
  suggestedThreats?: string[];
}> = [
  {
    name: 'Harden SSH Access',
    description: 'Allow SSH only from trusted IPs and rate limit brute-force attempts.',
    environment: 'linux_server',
    suggestedPorts: [22],
    suggestedDangerous: [22],
    config: {
      configType: 'iptables',
      fileName: 'iptables-ssh-harden.sh',
      language: 'bash',
      description: 'Restrict SSH access and throttle repeated attempts.',
      warningNote: 'Test this in staging before applying to production hosts.',
      testCommand: 'sudo iptables -S',
      content: `#!/bin/bash
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH only from trusted admin subnet
iptables -A INPUT -p tcp -s 10.10.10.0/24 --dport 22 -m conntrack --ctstate NEW -j ACCEPT

# Rate-limit SSH attempts
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP`
    }
  },
  {
    name: 'Block Common Attack Ports',
    description: 'Drop traffic to high-risk service ports commonly abused by worms and ransomware.',
    environment: 'linux_server',
    suggestedDangerous: [23, 135, 137, 138, 139, 445, 3389],
    config: {
      configType: 'iptables',
      fileName: 'iptables-block-common-attack-ports.sh',
      language: 'bash',
      description: 'Explicitly block legacy and high-risk exposed ports.',
      warningNote: null,
      testCommand: 'sudo iptables -L INPUT -n --line-numbers',
      content: `#!/bin/bash
for PORT in 23 135 137 138 139 445 3389; do
  iptables -A INPUT -p tcp --dport "$PORT" -j DROP
  iptables -A INPUT -p udp --dport "$PORT" -j DROP
done`
    }
  },
  {
    name: 'Complete Security Headers',
    description: 'Apply full baseline secure headers for web applications.',
    environment: 'nginx',
    suggestedHeaders: headerOptions,
    config: {
      configType: 'nginx',
      fileName: 'nginx-security-headers.conf',
      language: 'nginx',
      description: 'Recommended secure header baseline for reverse proxy/web app.',
      warningNote: 'Validate with staging and browser compatibility checks.',
      testCommand: 'nginx -t',
      content: `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none';" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
add_header X-XSS-Protection "1; mode=block" always;`
    }
  },
  {
    name: 'Strict Content Security Policy',
    description: 'A strict CSP baseline for modern single-page applications.',
    environment: 'nginx',
    config: {
      configType: 'csp',
      fileName: 'csp-headers.txt',
      language: 'nginx',
      description: 'Strict CSP policy with minimal allowed origins.',
      warningNote: 'Adjust script-src/style-src for required trusted CDNs if needed.',
      testCommand: 'curl -I https://yourdomain.example | findstr /I "content-security-policy"',
      content: `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests`
    }
  },
  {
    name: 'Rate Limiting Rules',
    description: 'Protect login and API endpoints from brute force and flooding.',
    environment: 'nginx',
    config: {
      configType: 'nginx',
      fileName: 'nginx-rate-limit.conf',
      language: 'nginx',
      description: 'Request rate controls for sensitive endpoints.',
      warningNote: null,
      testCommand: 'nginx -t',
      content: `limit_req_zone $binary_remote_addr zone=api_rl:10m rate=20r/m;
limit_req_zone $binary_remote_addr zone=login_rl:10m rate=5r/m;

location /api/ {
  limit_req zone=api_rl burst=20 nodelay;
}

location /login {
  limit_req zone=login_rl burst=5 nodelay;
}`
    }
  },
  {
    name: 'Docker Network Isolation',
    description: 'Segment containers and deny direct internet-facing lateral movement.',
    environment: 'docker',
    config: {
      configType: 'docker-compose',
      fileName: 'docker-compose.security.yml',
      language: 'yaml',
      description: 'Dual-network model with internal network isolation.',
      warningNote: 'Ensure application services do not require direct host networking.',
      testCommand: 'docker compose -f docker-compose.security.yml config',
      content: `version: "3.9"
services:
  app:
    image: your-app:latest
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    networks:
      - frontend
      - backend

  db:
    image: postgres:16
    networks:
      - backend

networks:
  frontend:
    driver: bridge
  backend:
    internal: true`
    }
  }
];

const actionBadge = (action: SecurityRule['action']) => {
  if (action === 'ALLOW') return 'bg-emerald-500/20 border-emerald-500/40 text-emerald-300';
  if (action === 'DENY') return 'bg-red-500/20 border-red-500/40 text-red-300';
  if (action === 'LOG') return 'bg-blue-500/20 border-blue-500/40 text-blue-300';
  return 'bg-yellow-500/20 border-yellow-500/40 text-yellow-300';
};

const normalizeHeaderName = (header: string): string => {
  const map: Record<string, string> = {
    HSTS: 'Strict-Transport-Security (HSTS)',
    CSP: 'Content-Security-Policy'
  };
  return map[header] || header;
};

const parsePortsFromText = (text: string): number[] => {
  const matches = text.match(/\b(\d{2,5})\/(?:tcp|udp)\b/gi) || [];
  const ports = matches
    .map((m) => Number(m.split('/')[0]))
    .filter((port) => Number.isFinite(port) && port > 0 && port <= 65535);
  return Array.from(new Set(ports));
};

const parseDangerousPorts = (ports: number[]) => {
  const risky = new Set([21, 23, 135, 137, 138, 139, 445, 1433, 3306, 3389, 5900]);
  return ports.filter((port) => risky.has(port));
};

const languageClass = (language: string) => {
  const lower = language.toLowerCase();
  if (lower.includes('bash')) return 'text-green-300';
  if (lower.includes('nginx')) return 'text-sky-300';
  if (lower.includes('yaml')) return 'text-purple-300';
  return 'text-slate-200';
};

const defaultPolicy = (template: typeof templateLibrary[number]): ZeroTrustPolicy => ({
  policyTitle: template.name,
  riskReduction: `Template profile: ${template.description}`,
  estimatedRiskReduction: 35,
  immediateWins: ['Review generated configuration', 'Test in staging', 'Apply change windows with rollback'],
  implementationOrder: ['Create backup', 'Deploy policy in staging', 'Validate application health', 'Promote to production'],
  securityRules: [],
  configs: [
    {
      ...template.config,
      isValidated: false,
      validationErrors: [],
      validationWarnings: []
    }
  ]
});

const TagInput: React.FC<{
  value: string;
  setValue: (value: string) => void;
  tags: string[];
  setTags: (tags: string[]) => void;
  placeholder: string;
  numeric?: boolean;
}> = ({ value, setValue, tags, setTags, placeholder, numeric }) => {
  const addTag = () => {
    const clean = value.trim();
    if (!clean) return;
    if (numeric && !/^\d{1,5}$/.test(clean)) return;
    if (tags.includes(clean)) return;
    setTags([...tags, clean]);
    setValue('');
  };

  return (
    <div className="space-y-2">
      <input
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter') {
            e.preventDefault();
            addTag();
          }
        }}
        placeholder={placeholder}
        className="w-full px-3 py-2.5 rounded-lg bg-slate-950/60 border border-white/10 text-slate-100 focus:outline-none focus:border-cyan-500/50"
      />
      <div className="flex flex-wrap gap-2">
        {tags.map((tag) => (
          <button
            key={tag}
            onClick={() => setTags(tags.filter((item) => item !== tag))}
            className="px-2 py-1 rounded-full text-xs border border-cyan-500/40 bg-cyan-500/10 text-cyan-300"
          >
            {tag} ×
          </button>
        ))}
      </div>
    </div>
  );
};

const ZeroTrustPolicyBuilder: React.FC<ZeroTrustPolicyBuilderProps> = ({ onNavigate }) => {
  const [activeTab, setActiveTab] = useState<InputTab>('load');
  const [sourceModule, setSourceModule] = useState<string>(ScanType.PORT_SCAN);
  const [openPorts, setOpenPorts] = useState<string[]>([]);
  const [openPortInput, setOpenPortInput] = useState('');
  const [dangerousPorts, setDangerousPorts] = useState<string[]>([]);
  const [dangerousPortInput, setDangerousPortInput] = useState('');
  const [missingHeaders, setMissingHeaders] = useState<string[]>([]);
  const [detectedThreats, setDetectedThreats] = useState<string[]>([]);
  const [threatInput, setThreatInput] = useState('');
  const [domain, setDomain] = useState('');
  const [internalIps, setInternalIps] = useState<string[]>([]);
  const [internalIpInput, setInternalIpInput] = useState('');
  const [targetEnvironment, setTargetEnvironment] = useState<Environment | null>(null);
  const [policy, setPolicy] = useState<ZeroTrustPolicy | null>(null);
  const [loading, setLoading] = useState(false);
  const [selectedConfigIndex, setSelectedConfigIndex] = useState(0);
  const [sortColumn, setSortColumn] = useState<keyof SecurityRule>('ruleId');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('asc');
  const [actionFilter, setActionFilter] = useState<'ALL' | SecurityRule['action']>('ALL');
  const [implementationChecks, setImplementationChecks] = useState<Record<number, boolean>>({});
  const [showTemplates, setShowTemplates] = useState(false);

  useEffect(() => {
    const loadPrefill = async () => {
      try {
        const payload = await getSetting('zerotrust_prefill_payload');
        if (!payload?.value) return;
        const value = payload.value as any;
        if (Array.isArray(value.openPorts)) setOpenPorts(value.openPorts.map((item: any) => String(item)));
        if (Array.isArray(value.dangerousPorts)) setDangerousPorts(value.dangerousPorts.map((item: any) => String(item)));
        if (Array.isArray(value.missingHeaders)) setMissingHeaders(value.missingHeaders.map((item: any) => normalizeHeaderName(String(item))));
        if (Array.isArray(value.detectedThreats)) setDetectedThreats(value.detectedThreats.map((item: any) => String(item)));
        if (Array.isArray(value.internalIPs)) setInternalIps(value.internalIPs.map((item: any) => String(item)));
        if (value.domain) setDomain(String(value.domain));
        if (value.targetEnvironment && environmentCards.some((env) => env.key === value.targetEnvironment)) {
          setTargetEnvironment(value.targetEnvironment);
        }
        await deleteSetting('zerotrust_prefill_payload');
      } catch (prefillErr) {
        console.error('Failed to load Zero Trust prefill:', prefillErr);
      }
    };
    loadPrefill();
  }, []);

  const loadLatestScan = async () => {
    try {
      const scans = await getAllScans();
      if (sourceModule === ScanType.PORT_SCAN) {
        const latest = scans.find((scan) => scan.scanType === ScanType.PORT_SCAN);
        if (!latest) {
          toast.error('No Port Scanner history found');
          return;
        }
        const mergedText = `${latest.rawData}\n${latest.analysisResult?.detailed_analysis || ''}`;
        const parsedPorts = parsePortsFromText(mergedText);
        setOpenPorts(parsedPorts.map((p) => String(p)));
        setDangerousPorts(parseDangerousPorts(parsedPorts).map((p) => String(p)));
        setDetectedThreats(latest.analysisResult?.recommendations?.slice(0, 5) || []);
        toast.success('Loaded latest Port Scanner result');
        return;
      }

      if (sourceModule === ScanType.WEBSEC_OPS) {
        const websecPayload = await getSetting('websec_latest_result');
        if (!websecPayload?.value) {
          toast.error('No WebSec Ops result found');
          return;
        }
        const value = websecPayload.value as any;
        setMissingHeaders((Array.isArray(value?.missingHeaders) ? value.missingHeaders : []).map((h: any) => normalizeHeaderName(String(h))));
        setDomain(String(value?.domain || ''));
        setDetectedThreats((Array.isArray(value?.missingHeaders) ? value.missingHeaders : []).map((h: any) => `Missing ${normalizeHeaderName(String(h))}`));
        toast.success('Loaded latest WebSec Ops result');
        return;
      }

      const latest = scans.find((scan) => scan.scanType === sourceModule);
      if (!latest) {
        toast.error('No scan history found for selected module');
        return;
      }

      setDetectedThreats(
        [
          latest.analysisResult?.summary || '',
          ...(latest.analysisResult?.recommendations || [])
        ]
          .filter(Boolean)
          .slice(0, 6)
      );
      toast.success('Loaded latest module summary');
    } catch (error: any) {
      toast.error(error?.message || 'Failed to load latest scan');
    }
  };

  const loadSamplePolicyData = () => {
    setActiveTab('manual');
    setTargetEnvironment('nginx');
    setSourceModule(ScanType.WEBSEC_OPS);
    setOpenPorts(['80', '443', '22', '8080']);
    setDangerousPorts(['22', '8080']);
    setMissingHeaders(['Strict-Transport-Security (HSTS)', 'Content-Security-Policy', 'X-Frame-Options']);
    setDetectedThreats([
      'Insecure SSH exposed on WAN',
      'Missing standard HTTP Security Headers',
      'Sensitive development endpoint exposed on port 8080'
    ]);
    setDomain('staging.securai-sentinel.local');
    setInternalIps(['192.168.1.5', '192.168.1.10']);
    toast.success('Sample requirements loaded. Click "Generate Policies" to build.');
  };

  const generatePolicies = async () => {
    if (!targetEnvironment) {
      toast.error('Select target environment');
      return;
    }

    setLoading(true);
    try {
      const response = await fetch('http://localhost:3001/zerotrust/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scanResults: {
            sourceModule,
            mode: activeTab
          },
          targetEnvironment,
          openPorts: openPorts.map(Number).filter(Number.isFinite),
          dangerousPorts: dangerousPorts.map(Number).filter(Number.isFinite),
          missingHeaders,
          detectedThreats,
          domain: domain.trim() || null,
          internalIPs: internalIps
        })
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(data?.message || 'Failed to generate policies');
      }

      const normalized: ZeroTrustPolicy = {
        ...data,
        configs: (Array.isArray(data?.configs) ? data.configs : []).map((config: any) => ({
          ...config,
          isValidated: false,
          validationErrors: [],
          validationWarnings: []
        }))
      };
      setPolicy(normalized);
      setSelectedConfigIndex(0);
      setImplementationChecks(
        (normalized.implementationOrder || []).reduce((acc, _value, idx) => {
          acc[idx] = false;
          return acc;
        }, {} as Record<number, boolean>)
      );
      toast.success('Zero Trust policy generated');
    } catch (error: any) {
      toast.error(error?.message || 'Generation failed');
    } finally {
      setLoading(false);
    }
  };

  const validateConfig = async (index: number) => {
    if (!policy) return;
    const config = policy.configs[index];
    try {
      const response = await fetch('http://localhost:3001/zerotrust/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          configType: config.configType,
          content: config.content
        })
      });
      const result = await response.json();
      if (!response.ok) {
        throw new Error(result?.message || 'Validation failed');
      }

      const nextConfigs = [...policy.configs];
      nextConfigs[index] = {
        ...nextConfigs[index],
        isValidated: Boolean(result.valid),
        validationErrors: Array.isArray(result.errors) ? result.errors : [],
        validationWarnings: Array.isArray(result.warnings) ? result.warnings : []
      };
      setPolicy({ ...policy, configs: nextConfigs });
      toast.success(result.valid ? 'Syntax valid' : 'Validation completed with errors');
    } catch (error: any) {
      toast.error(error?.message || 'Validation failed');
    }
  };

  const exportRulesCsv = () => {
    if (!policy?.securityRules?.length) return;
    const headers = ['Rule ID', 'Rule Name', 'Action', 'Source', 'Destination', 'Protocol', 'Port', 'Rationale'];
    const rows = policy.securityRules.map((rule) =>
      [
        rule.ruleId,
        rule.ruleName,
        rule.action,
        rule.source,
        rule.destination,
        rule.protocol,
        rule.port,
        rule.rationale
      ].map((value) => `"${String(value).replace(/"/g, '""')}"`)
    );
    const csv = [headers.join(','), ...rows.map((row) => row.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `zero-trust-rules-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadTextFile = (fileName: string, content: string) => {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(url);
  };

  const buildInstallerScript = () => {
    if (!policy) return '';
    const timestamp = new Date().toISOString();
    return [
      '#!/bin/bash',
      '# SecurAI Sentinel - Zero Trust Policy Installer',
      `# Generated: ${timestamp}`,
      '# WARNING: Review before executing',
      'set -e',
      '',
      'BACKUP_DIR="./securai-backups-$(date +%s)"',
      'mkdir -p "$BACKUP_DIR"',
      'echo "Backups stored at: $BACKUP_DIR"',
      '',
      ...policy.configs.flatMap((cfg, idx) => [
        `# ---- ${cfg.fileName} (${cfg.configType}) ----`,
        `cat <<'EOF_${idx}' > "${cfg.fileName}"`,
        cfg.content,
        `EOF_${idx}`,
        'echo "Wrote file: ' + cfg.fileName + '"',
        ''
      ]),
      'echo "Policy files generated. Validate before deployment."'
    ].join('\n');
  };

  const exportPolicyPdf = () => {
    if (!policy) return;
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    const writeBlock = (title: string, text: string, yStart: number) => {
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(13);
      doc.text(title, 14, yStart);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(10);
      doc.text(doc.splitTextToSize(text, pageWidth - 28), 14, yStart + 7);
    };

    writeBlock('Zero Trust Policy Report', policy.policyTitle, 20);
    writeBlock('Risk Reduction', `${policy.riskReduction} (${policy.estimatedRiskReduction}%)`, 45);
    writeBlock('Implementation Order', policy.implementationOrder.map((item, idx) => `${idx + 1}. ${item}`).join('\n'), 65);

    doc.addPage();
    autoTable(doc, {
      startY: 16,
      head: [['Rule ID', 'Rule Name', 'Action', 'Source', 'Destination', 'Protocol', 'Port']],
      body: (policy.securityRules || []).map((rule) => [
        rule.ruleId,
        rule.ruleName,
        rule.action,
        rule.source,
        rule.destination,
        rule.protocol,
        rule.port
      ]),
      styles: { fontSize: 8 },
      headStyles: { fillColor: [6, 182, 212] }
    });

    policy.configs.forEach((cfg) => {
      doc.addPage();
      doc.setFontSize(14);
      doc.setFont('helvetica', 'bold');
      doc.text(cfg.fileName, 14, 16);
      doc.setFontSize(9);
      doc.setFont('courier', 'normal');
      const lines = doc.splitTextToSize(cfg.content, pageWidth - 28);
      doc.text(lines, 14, 24);
    });

    doc.save(`zero-trust-policy-${Date.now()}.pdf`);
  };

  const saveToForensics = async () => {
    if (!policy) return;
    try {
      await logForensicsEvent({
        timestamp: Date.now(),
        eventType: 'custom',
        sourceModule: 'Zero Trust Builder',
        severity: policy.estimatedRiskReduction >= 70 ? 'High' : policy.estimatedRiskReduction >= 40 ? 'Medium' : 'Low',
        title: `Zero Trust policy generated (${policy.estimatedRiskReduction}% reduction)`,
        description: policy.riskReduction,
        details: {
          policyTitle: policy.policyTitle,
          environment: targetEnvironment,
          configs: policy.configs.map((cfg) => cfg.fileName),
          ruleCount: policy.securityRules.length
        },
        attackPhase: 'Defense Evasion',
        ioc: (policy.securityRules || []).map((rule) => `${rule.protocol}/${rule.port}`).slice(0, 25),
        tags: ['zero-trust', 'policy-builder']
      });
      toast.success('Saved to Forensics Timeline');
      if (onNavigate) onNavigate(ScanType.FORENSICS_TIMELINE);
    } catch (error) {
      console.error('Forensics save failed:', error);
      toast.error('Failed to save to Forensics Timeline');
    }
  };

  const visibleRules = useMemo(() => {
    if (!policy?.securityRules) return [];
    const filtered = actionFilter === 'ALL' ? policy.securityRules : policy.securityRules.filter((rule) => rule.action === actionFilter);
    const sorted = [...filtered].sort((a, b) => {
      const left = String(a[sortColumn] || '');
      const right = String(b[sortColumn] || '');
      return sortDirection === 'asc' ? left.localeCompare(right) : right.localeCompare(left);
    });
    return sorted;
  }, [policy, actionFilter, sortColumn, sortDirection]);

  const selectedConfig = policy?.configs?.[selectedConfigIndex];

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="bg-slate-900/55 border border-cyan-500/20 rounded-2xl p-6 backdrop-blur-xl">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-cyan-500/20 border border-cyan-500/40">
              <Shield className="w-7 h-7 text-cyan-300" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-slate-100">Zero Trust Policy Builder</h1>
              <p className="text-sm text-slate-400">Generate production-ready firewall rules, configs, and security policies</p>
            </div>
          </div>
          <div className="flex gap-2">
            {['Never Trust', 'Always Verify', 'Least Privilege'].map((label) => (
              <span key={label} className="px-2.5 py-1 rounded-full border border-cyan-500/30 bg-cyan-500/10 text-cyan-200 text-xs">
                {label}
              </span>
            ))}
          </div>
        </div>
      </motion.div>

      <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-6 backdrop-blur-xl space-y-6">
        <div className="flex justify-between items-center flex-wrap gap-2">
          <div className="flex gap-2">
            <button
              onClick={() => setActiveTab('load')}
              className={`px-3 py-2 rounded-lg text-sm border ${activeTab === 'load' ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-200' : 'border-white/10 text-slate-300'}`}
            >
              Load from Module Results
            </button>
            <button
              onClick={() => setActiveTab('manual')}
              className={`px-3 py-2 rounded-lg text-sm border ${activeTab === 'manual' ? 'border-cyan-500/40 bg-cyan-500/10 text-cyan-200' : 'border-white/10 text-slate-300'}`}
            >
              Manual Input
            </button>
          </div>
          <button
            onClick={loadSamplePolicyData}
            className="glass-control text-slate-300 hover:text-slate-100 px-4 py-2 rounded-lg flex items-center gap-2 transition-all text-xs"
          >
            <Sparkles className="w-4 h-4 text-cyan-400" />
            <span>Load Sample Data</span>
          </button>
        </div>

        {activeTab === 'load' ? (
          <div className="space-y-4">
            <div>
              <label className="text-sm text-slate-300 font-semibold mb-2 block">Select source module</label>
              <select
                value={sourceModule}
                onChange={(e) => setSourceModule(e.target.value)}
                className="w-full px-3 py-2.5 rounded-lg bg-slate-950/60 border border-white/10 text-slate-100 focus:outline-none focus:border-cyan-500/50"
              >
                {Object.values(ScanType).map((type) => (
                  <option key={type} value={type}>
                    {type}
                  </option>
                ))}
              </select>
            </div>
            <button onClick={loadLatestScan} className="px-4 py-2 rounded-lg border border-cyan-500/40 bg-cyan-500/10 text-cyan-200 text-sm">
              Load Latest Scan
            </button>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div className="bg-slate-950/50 border border-white/10 rounded-lg p-3">
                <p className="text-slate-400 mb-1">Open Ports</p>
                <p className="text-slate-200">{openPorts.join(', ') || 'None loaded'}</p>
              </div>
              <div className="bg-slate-950/50 border border-white/10 rounded-lg p-3">
                <p className="text-slate-400 mb-1">Missing Headers</p>
                <p className="text-slate-200">{missingHeaders.join(', ') || 'None loaded'}</p>
              </div>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div>
                <label className="text-sm text-slate-300 font-semibold mb-2 block">Open Ports</label>
                <TagInput
                  value={openPortInput}
                  setValue={setOpenPortInput}
                  tags={openPorts}
                  setTags={setOpenPorts}
                  placeholder="Type port number and press Enter"
                  numeric
                />
              </div>
              <div>
                <label className="text-sm text-slate-300 font-semibold mb-2 block">Dangerous Ports</label>
                <TagInput
                  value={dangerousPortInput}
                  setValue={setDangerousPortInput}
                  tags={dangerousPorts}
                  setTags={setDangerousPorts}
                  placeholder="Add dangerous ports"
                  numeric
                />
              </div>
            </div>

            <div>
              <label className="text-sm text-slate-300 font-semibold mb-2 block">Missing Security Headers</label>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {headerOptions.map((header) => (
                  <label key={header} className="inline-flex items-center gap-2 text-sm text-slate-300">
                    <input
                      type="checkbox"
                      checked={missingHeaders.includes(header)}
                      onChange={(e) => {
                        if (e.target.checked) setMissingHeaders((prev) => [...prev, header]);
                        else setMissingHeaders((prev) => prev.filter((item) => item !== header));
                      }}
                      className="accent-cyan-500"
                    />
                    {header}
                  </label>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div>
                <label className="text-sm text-slate-300 font-semibold mb-2 block">Detected Threats</label>
                <TagInput value={threatInput} setValue={setThreatInput} tags={detectedThreats} setTags={setDetectedThreats} placeholder="Add threat and press Enter" />
              </div>
              <div>
                <label className="text-sm text-slate-300 font-semibold mb-2 block">Internal IP Ranges</label>
                <TagInput value={internalIpInput} setValue={setInternalIpInput} tags={internalIps} setTags={setInternalIps} placeholder="e.g. 10.0.0.0/24" />
              </div>
            </div>

            <div>
              <label className="text-sm text-slate-300 font-semibold mb-2 block">Domain/IP</label>
              <input
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="example.com or 192.168.1.10"
                className="w-full px-3 py-2.5 rounded-lg bg-slate-950/60 border border-white/10 text-slate-100 focus:outline-none focus:border-cyan-500/50"
              />
            </div>
          </div>
        )}

        <div>
          <label className="text-sm text-slate-300 font-semibold mb-3 block">Target Environment</label>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
            {environmentCards.map((env) => (
              <button
                key={env.key}
                onClick={() => setTargetEnvironment(env.key)}
                className={`text-left p-4 rounded-xl border transition-all ${
                  targetEnvironment === env.key ? 'border-cyan-500/50 bg-cyan-500/10' : 'border-white/10 bg-slate-950/40 hover:border-cyan-500/30'
                }`}
              >
                <div className="inline-flex items-center gap-2 text-slate-100 font-semibold">
                  <env.icon className="w-4 h-4 text-cyan-300" />
                  {env.label}
                </div>
                <p className="text-xs text-slate-400 mt-1">{env.description}</p>
              </button>
            ))}
          </div>
        </div>

        <button
          onClick={generatePolicies}
          disabled={loading || !targetEnvironment}
          className="w-full py-3 rounded-xl border border-cyan-500/40 bg-gradient-to-r from-cyan-500/20 to-purple-500/20 text-cyan-200 font-bold hover:from-cyan-500/30 hover:to-purple-500/30 disabled:opacity-50"
        >
          {loading ? 'Generating Policies...' : 'Generate Zero Trust Policies'}
        </button>
      </div>

      {policy && (
        <div className="space-y-5">
          <div className="bg-emerald-500/10 border border-emerald-500/40 rounded-2xl p-5">
            <h2 className="text-2xl font-bold text-emerald-300">Estimated Risk Reduction: {policy.estimatedRiskReduction}%</h2>
            <div className="mt-4 space-y-2">
              <div>
                <p className="text-xs text-slate-400 mb-1">Before</p>
                <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
                  <div className="h-full bg-gradient-to-r from-red-500 to-orange-500" style={{ width: `${Math.max(10, 100 - policy.estimatedRiskReduction)}%` }} />
                </div>
              </div>
              <div>
                <p className="text-xs text-slate-400 mb-1">After</p>
                <div className="h-2 rounded-full bg-slate-800 overflow-hidden">
                  <div className="h-full bg-gradient-to-r from-emerald-500 to-cyan-500" style={{ width: `${Math.max(10, policy.estimatedRiskReduction)}%` }} />
                </div>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
            <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-4">
              <h3 className="text-lg font-bold text-slate-100 mb-2">Follow this order for safe deployment</h3>
              <div className="space-y-2">
                {policy.implementationOrder.map((item, idx) => (
                  <label key={`${item}-${idx}`} className="flex items-start gap-2 text-sm text-slate-300">
                    <input
                      type="checkbox"
                      checked={Boolean(implementationChecks[idx])}
                      onChange={(e) => setImplementationChecks({ ...implementationChecks, [idx]: e.target.checked })}
                      className="accent-cyan-500 mt-0.5"
                    />
                    <span>{idx + 1}. {item}</span>
                  </label>
                ))}
              </div>
            </div>

            <div className="xl:col-span-2 bg-emerald-500/10 border border-emerald-500/40 rounded-2xl p-4">
              <h3 className="text-lg font-bold text-emerald-300 mb-2">⚡ Quick Wins — Implement These First</h3>
              <ul className="list-disc list-inside text-sm text-slate-200 space-y-1">
                {policy.immediateWins.map((item, idx) => <li key={idx}>{item}</li>)}
              </ul>
            </div>
          </div>

          <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-4">
            <div className="flex flex-wrap justify-between items-center gap-2 mb-3">
              <h3 className="text-lg font-bold text-slate-100">Security Rules</h3>
              <div className="flex gap-2 items-center">
                <Filter className="w-4 h-4 text-slate-400" />
                <select
                  value={actionFilter}
                  onChange={(e) => setActionFilter(e.target.value as any)}
                  className="px-2 py-1 rounded bg-slate-950 border border-white/10 text-slate-200 text-xs"
                >
                  <option value="ALL">Filter by action...</option>
                  <option value="ALLOW">ALLOW</option>
                  <option value="DENY">DENY</option>
                  <option value="LOG">LOG</option>
                  <option value="RATE_LIMIT">RATE_LIMIT</option>
                </select>
                <button onClick={exportRulesCsv} className="px-2.5 py-1.5 rounded border border-cyan-500/40 bg-cyan-500/10 text-cyan-200 text-xs">
                  Export Rules as CSV
                </button>
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-white/10 text-slate-400">
                    {(['ruleId', 'ruleName', 'action', 'source', 'destination', 'protocol', 'port', 'rationale'] as Array<keyof SecurityRule>).map((key) => (
                      <th
                        key={key}
                        className="text-left px-2 py-2 cursor-pointer"
                        onClick={() => {
                          if (sortColumn === key) setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
                          else {
                            setSortColumn(key);
                            setSortDirection('asc');
                          }
                        }}
                      >
                        {key}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {visibleRules.map((rule) => (
                    <tr key={rule.ruleId} className="border-b border-white/5">
                      <td className="px-2 py-2 font-mono text-cyan-300">{rule.ruleId}</td>
                      <td className="px-2 py-2 text-slate-200">{rule.ruleName}</td>
                      <td className="px-2 py-2">
                        <span className={`px-2 py-0.5 rounded-full border text-[10px] ${actionBadge(rule.action)}`}>{rule.action}</span>
                      </td>
                      <td className="px-2 py-2 text-slate-300">{rule.source}</td>
                      <td className="px-2 py-2 text-slate-300">{rule.destination}</td>
                      <td className="px-2 py-2 text-slate-300">{rule.protocol}</td>
                      <td className="px-2 py-2 text-slate-300">{rule.port}</td>
                      <td className="px-2 py-2 text-slate-400">{rule.rationale}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-4 space-y-4">
            <div className="flex flex-wrap gap-2 border-b border-white/10 pb-2">
              {policy.configs.map((cfg, idx) => (
                <button
                  key={`${cfg.fileName}-${idx}`}
                  onClick={() => setSelectedConfigIndex(idx)}
                  className={`px-2.5 py-1 text-xs rounded border ${
                    selectedConfigIndex === idx
                      ? 'border-cyan-500/50 text-cyan-200 bg-cyan-500/10'
                      : 'border-white/10 text-slate-300 bg-slate-950/50'
                  }`}
                >
                  {cfg.fileName}
                </button>
              ))}
            </div>

            {selectedConfig && (
              <div className="space-y-3">
                <div className="flex flex-wrap justify-between gap-2">
                  <div>
                    <h3 className="font-mono text-sm text-slate-100">{selectedConfig.fileName}</h3>
                    <p className="text-xs text-slate-400 mt-1">{selectedConfig.description}</p>
                  </div>
                  <div className="flex gap-2">
                    <span className="px-2 py-1 rounded border border-cyan-500/30 bg-cyan-500/10 text-cyan-200 text-[10px] uppercase">
                      {selectedConfig.configType}
                    </span>
                    <span className="px-2 py-1 rounded border border-purple-500/30 bg-purple-500/10 text-purple-200 text-[10px] uppercase">
                      {selectedConfig.language}
                    </span>
                  </div>
                </div>

                {selectedConfig.warningNote && (
                  <div className="p-3 rounded-lg border border-amber-500/30 bg-amber-500/10 text-amber-200 text-xs">
                    ⚠️ {selectedConfig.warningNote}
                  </div>
                )}

                <div className="border border-white/10 rounded-xl overflow-hidden">
                  <div className="flex justify-end gap-2 p-2 border-b border-white/10 bg-slate-950/60">
                    <button
                      onClick={async () => {
                        await navigator.clipboard.writeText(selectedConfig.content);
                        toast.success('Copied config');
                      }}
                      className="px-2 py-1 rounded border border-white/10 text-slate-300 text-xs inline-flex items-center gap-1"
                    >
                      <Copy className="w-3 h-3" /> Copy
                    </button>
                    <button
                      onClick={() => downloadTextFile(selectedConfig.fileName, selectedConfig.content)}
                      className="px-2 py-1 rounded border border-white/10 text-slate-300 text-xs inline-flex items-center gap-1"
                    >
                      <Download className="w-3 h-3" /> Download
                    </button>
                    <button
                      onClick={() => validateConfig(selectedConfigIndex)}
                      className="px-2 py-1 rounded border border-cyan-500/30 text-cyan-200 text-xs inline-flex items-center gap-1"
                    >
                      <CheckCircle2 className="w-3 h-3" /> Validate Syntax
                    </button>
                  </div>
                  <div className="max-h-[380px] overflow-auto bg-black/70">
                    <table className="w-full font-mono text-xs">
                      <tbody>
                        {selectedConfig.content.split('\n').map((line, idx) => (
                          <tr key={idx} className="hover:bg-white/5">
                            <td className="w-10 text-right pr-2 text-slate-600 select-none">{idx + 1}</td>
                            <td className={`py-0.5 ${languageClass(selectedConfig.language)}`}>{line || ' '}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {(selectedConfig.validationErrors.length > 0 || selectedConfig.validationWarnings.length > 0 || selectedConfig.isValidated) && (
                  <div className="space-y-2 text-xs">
                    {selectedConfig.isValidated && (
                      <div className="p-2 rounded border border-emerald-500/40 bg-emerald-500/10 text-emerald-300">✅ Syntax Valid</div>
                    )}
                    {selectedConfig.validationErrors.map((error, idx) => (
                      <div key={idx} className="p-2 rounded border border-red-500/40 bg-red-500/10 text-red-300">
                        ❌ {error}
                      </div>
                    ))}
                    {selectedConfig.validationWarnings.map((warning, idx) => (
                      <div key={idx} className="p-2 rounded border border-amber-500/40 bg-amber-500/10 text-amber-200">
                        ⚠️ {warning}
                      </div>
                    ))}
                  </div>
                )}

                {selectedConfig.testCommand && (
                  <div className="p-3 rounded-lg border border-white/10 bg-slate-950/60">
                    <p className="text-xs text-slate-400">Test with:</p>
                    <div className="flex justify-between items-center mt-1 gap-2">
                      <code className="text-xs text-slate-200 break-all">{selectedConfig.testCommand}</code>
                      <button
                        onClick={async () => {
                          await navigator.clipboard.writeText(selectedConfig.testCommand || '');
                          toast.success('Copied test command');
                        }}
                        className="px-2 py-1 rounded border border-white/10 text-slate-300 text-xs"
                      >
                        Copy
                      </button>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-4">
            <h3 className="text-lg font-bold text-slate-100 mb-3">Policy Export Options</h3>
            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => downloadTextFile(`zero-trust-installer-${Date.now()}.sh`, buildInstallerScript())}
                className="px-3 py-2 rounded-lg border border-cyan-500/40 bg-cyan-500/10 text-cyan-200 text-sm inline-flex items-center gap-2"
              >
                <Download className="w-4 h-4" /> Download Installer Script
              </button>
              <button
                onClick={exportPolicyPdf}
                className="px-3 py-2 rounded-lg border border-purple-500/40 bg-purple-500/10 text-purple-200 text-sm inline-flex items-center gap-2"
              >
                <FileDown className="w-4 h-4" /> Export Policy Report PDF
              </button>
              <button
                onClick={saveToForensics}
                className="px-3 py-2 rounded-lg border border-emerald-500/40 bg-emerald-500/10 text-emerald-200 text-sm"
              >
                Save to Forensics Timeline
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="bg-slate-900/35 border border-white/10 rounded-2xl p-4">
        <button
          onClick={() => setShowTemplates((prev) => !prev)}
          className="w-full flex items-center justify-between text-slate-200 font-semibold"
        >
          <span className="inline-flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-cyan-300" />
            Quick Start Templates
          </span>
          {showTemplates ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </button>

        {showTemplates && (
          <div className="mt-4 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
            {templateLibrary.map((template) => (
              <div key={template.name} className="border border-white/10 rounded-xl p-3 bg-slate-950/50">
                <h4 className="font-semibold text-slate-100">{template.name}</h4>
                <p className="text-xs text-slate-400 mt-1">{template.description}</p>
                <div className="flex gap-2 mt-3">
                  <button
                    onClick={() => {
                      setPolicy(defaultPolicy(template));
                      setSelectedConfigIndex(0);
                    }}
                    className="px-2 py-1 rounded border border-cyan-500/40 bg-cyan-500/10 text-cyan-200 text-xs"
                  >
                    Use Template
                  </button>
                  <button
                    onClick={() => {
                      setActiveTab('manual');
                      setTargetEnvironment(template.environment);
                      if (template.suggestedPorts) setOpenPorts(template.suggestedPorts.map((p) => String(p)));
                      if (template.suggestedDangerous) setDangerousPorts(template.suggestedDangerous.map((p) => String(p)));
                      if (template.suggestedHeaders) setMissingHeaders(template.suggestedHeaders);
                      if (template.suggestedThreats) setDetectedThreats(template.suggestedThreats);
                      toast.success('Template context loaded. Generate with AI to customize.');
                    }}
                    className="px-2 py-1 rounded border border-purple-500/40 bg-purple-500/10 text-purple-200 text-xs"
                  >
                    Customize with AI
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default ZeroTrustPolicyBuilder;
