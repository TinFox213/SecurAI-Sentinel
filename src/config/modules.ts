import type { LucideIcon } from 'lucide-react';
import {
  Activity,
  BarChart3,
  Bot,
  Bug,
  ClipboardList,
  Crosshair,
  Eye,
  FileText,
  FileWarning,
  Fish,
  Gamepad2,
  GitBranch,
  Globe,
  Home,
  Keyboard,
  Network,
  PackageSearch,
  Radar,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Wrench,
} from 'lucide-react';
import { ScanType } from '../types/types';

export type ModuleGroup =
  | 'command'
  | 'red'
  | 'blue'
  | 'threatIntel'
  | 'dfir'
  | 'deception'
  | 'appsec'
  | 'governance'
  | 'training'
  | 'utility';

export type ModuleAccent = 'cyan' | 'emerald' | 'amber' | 'rose' | 'violet' | 'sky';

export interface ModuleGroupConfig {
  id: ModuleGroup;
  label: string;
  description: string;
  icon: LucideIcon;
  accent: ModuleAccent;
}

export interface ModuleNavItem {
  type: ScanType;
  icon: LucideIcon;
  label: string;
  description: string;
  group: ModuleGroup;
  secondaryGroups?: ModuleGroup[];
  workflow?: ScanType[];
  accent: ModuleAccent;
  featured?: boolean;
  agent?: boolean;
}

export const moduleGroups: ModuleGroupConfig[] = [
  {
    id: 'command',
    label: 'Command Center',
    description: 'Executive and operator overview.',
    icon: Activity,
    accent: 'cyan',
  },
  {
    id: 'red',
    label: 'Red Team',
    description: 'Authorized offensive assessment and attack-surface discovery.',
    icon: Crosshair,
    accent: 'rose',
  },
  {
    id: 'blue',
    label: 'Blue Team / SOC',
    description: 'Monitoring, detection, endpoint triage, and alert handling.',
    icon: ShieldCheck,
    accent: 'sky',
  },
  {
    id: 'threatIntel',
    label: 'Threat Intelligence',
    description: 'External exposure and vulnerability intelligence.',
    icon: Eye,
    accent: 'violet',
  },
  {
    id: 'dfir',
    label: 'DFIR',
    description: 'Incident response, evidence handling, and timeline reconstruction.',
    icon: FileWarning,
    accent: 'amber',
  },
  {
    id: 'deception',
    label: 'Deception Engineering',
    description: 'Tripwires, trap files, ghost ports, and early-warning signals.',
    icon: Radar,
    accent: 'rose',
  },
  {
    id: 'appsec',
    label: 'AppSec / DevSecOps',
    description: 'Application, code, container, and infrastructure security.',
    icon: Globe,
    accent: 'emerald',
  },
  {
    id: 'governance',
    label: 'Governance and Resilience',
    description: 'Risk, control mapping, compliance hints, and hardening plans.',
    icon: ClipboardList,
    accent: 'cyan',
  },
  {
    id: 'training',
    label: 'Training Lab',
    description: 'Practice and education.',
    icon: Gamepad2,
    accent: 'violet',
  },
  {
    id: 'utility',
    label: 'Utility Bench',
    description: 'Small analyst tools for focused tasks.',
    icon: Wrench,
    accent: 'amber',
  },
];

export const moduleRegistry: ModuleNavItem[] = [
  {
    type: ScanType.HOME,
    icon: Home,
    label: 'Home',
    description: 'Unified command view for AI security operations.',
    group: 'command',
    secondaryGroups: ['governance'],
    workflow: [ScanType.SECURITY_POSTURE, ScanType.AI_RED_TEAM, ScanType.WEBSEC_OPS],
    accent: 'cyan',
    featured: true,
  },
  {
    type: ScanType.SECURITY_POSTURE,
    icon: BarChart3,
    label: 'Security Posture Score',
    description: 'Score network, web, endpoint, data, and incident readiness.',
    group: 'command',
    secondaryGroups: ['governance', 'blue'],
    workflow: [ScanType.ZERO_TRUST, ScanType.WEBSEC_OPS, ScanType.FORENSICS_TIMELINE],
    accent: 'emerald',
    featured: true,
  },
  {
    type: ScanType.AI_RED_TEAM,
    icon: Bot,
    label: 'AI Red Team Agent',
    description: 'Plan and run guided assessment missions.',
    group: 'red',
    secondaryGroups: ['threatIntel', 'blue', 'governance'],
    workflow: [ScanType.MITRE_ATTACK, ScanType.IR_PLAYBOOK, ScanType.ZERO_TRUST, ScanType.SECURITY_POSTURE],
    accent: 'violet',
    featured: true,
    agent: true,
  },
  {
    type: ScanType.PORT_SCAN,
    icon: Network,
    label: 'Port Scanner',
    description: 'Analyze exposed services and risky port posture.',
    group: 'red',
    secondaryGroups: ['blue', 'governance'],
    workflow: [ScanType.VULN_SCAN, ScanType.ZERO_TRUST, ScanType.SECURITY_POSTURE],
    accent: 'sky',
  },
  {
    type: ScanType.VULN_SCAN,
    icon: Bug,
    label: 'Vulnerability Analysis',
    description: 'Review vulnerability scan output and remediation paths.',
    group: 'red',
    secondaryGroups: ['appsec', 'governance'],
    workflow: [ScanType.CVE_INTEL, ScanType.WEBSEC_OPS, ScanType.ZERO_TRUST],
    accent: 'rose',
  },
  {
    type: ScanType.MITRE_ATTACK,
    icon: Crosshair,
    label: 'MITRE ATT&CK Mapper',
    description: 'Map findings to tactics, techniques, and detections.',
    group: 'red',
    secondaryGroups: ['blue', 'dfir'],
    workflow: [ScanType.GENERAL_LOG, ScanType.EDR_FLEET, ScanType.PACKET_ANALYZER, ScanType.IR_PLAYBOOK],
    accent: 'amber',
    featured: true,
  },
  {
    type: ScanType.CVE_INTEL,
    icon: ShieldAlert,
    label: 'CVE Intel Hub',
    description: 'Search CVEs and summarize exploitation risk.',
    group: 'threatIntel',
    secondaryGroups: ['appsec', 'red'],
    workflow: [ScanType.VULN_SCAN, ScanType.WEBSEC_OPS, ScanType.ZERO_TRUST],
    accent: 'rose',
  },
  {
    type: ScanType.PHISHING,
    icon: Fish,
    label: 'Phishing Detection',
    description: 'Inspect suspicious messages, links, and sender signals.',
    group: 'blue',
    secondaryGroups: ['training', 'dfir'],
    workflow: [ScanType.GENERAL_LOG, ScanType.FORENSICS_TIMELINE, ScanType.IR_PLAYBOOK],
    accent: 'amber',
  },
  {
    type: ScanType.DARK_WEB,
    icon: Eye,
    label: 'Dark Web Monitor',
    description: 'Check exposed identifiers and breach intelligence.',
    group: 'threatIntel',
    secondaryGroups: ['command', 'dfir'],
    workflow: [ScanType.IR_PLAYBOOK, ScanType.SECURITY_POSTURE],
    accent: 'violet',
  },
  {
    type: ScanType.MALWARE,
    icon: FileWarning,
    label: 'Malware Analysis',
    description: 'Assess hashes, strings, process traces, and indicators.',
    group: 'dfir',
    secondaryGroups: ['blue'],
    workflow: [ScanType.FORENSICS_TIMELINE, ScanType.IR_PLAYBOOK, ScanType.ZERO_TRUST],
    accent: 'rose',
  },
  {
    type: ScanType.KEYLOGGER,
    icon: Keyboard,
    label: 'Keylogger Detection',
    description: 'Review process and hook evidence for credential theft.',
    group: 'dfir',
    secondaryGroups: ['blue'],
    workflow: [ScanType.FORENSICS_TIMELINE, ScanType.IR_PLAYBOOK],
    accent: 'amber',
  },
  {
    type: ScanType.GENERAL_LOG,
    icon: FileText,
    label: 'General Log Analysis',
    description: 'Turn raw logs into anomaly findings and next actions.',
    group: 'blue',
    secondaryGroups: ['dfir'],
    workflow: [ScanType.MITRE_ATTACK, ScanType.FORENSICS_TIMELINE, ScanType.IR_PLAYBOOK],
    accent: 'sky',
  },
  {
    type: ScanType.PACKET_ANALYZER,
    icon: PackageSearch,
    label: 'Packet Capture Analyzer',
    description: 'Inspect packet captures for suspicious flows.',
    group: 'dfir',
    secondaryGroups: ['blue', 'red'],
    workflow: [ScanType.MITRE_ATTACK, ScanType.FORENSICS_TIMELINE, ScanType.IR_PLAYBOOK],
    accent: 'cyan',
    featured: true,
  },
  {
    type: ScanType.FILE_CRYPTO,
    icon: ShieldCheck,
    label: 'CryptoVault',
    description: 'Protect files, analyze code, and strip risky metadata.',
    group: 'dfir',
    secondaryGroups: ['appsec', 'utility'],
    workflow: [ScanType.UTILITY_BELT, ScanType.FORENSICS_TIMELINE],
    accent: 'emerald',
  },
  {
    type: ScanType.CYBER_DOJO,
    icon: Gamepad2,
    label: 'Cyber Dojo',
    description: 'Practice security recognition and response drills.',
    group: 'training',
    secondaryGroups: ['red', 'blue'],
    workflow: [ScanType.PHISHING, ScanType.MITRE_ATTACK],
    accent: 'violet',
  },
  {
    type: ScanType.IR_PLAYBOOK,
    icon: ClipboardList,
    label: 'Incident Response Playbook',
    description: 'Generate and track incident response phases.',
    group: 'dfir',
    secondaryGroups: ['command', 'governance'],
    workflow: [ScanType.FORENSICS_TIMELINE, ScanType.ZERO_TRUST, ScanType.SECURITY_POSTURE],
    accent: 'amber',
    featured: true,
  },
  {
    type: ScanType.CANARY_FACTORY,
    icon: Activity,
    label: 'Canary Factory',
    description: 'Deploy tripwires and monitor triggered alerts.',
    group: 'deception',
    secondaryGroups: ['blue'],
    workflow: [ScanType.NETWORK_WATCHTOWER, ScanType.FORENSICS_TIMELINE, ScanType.IR_PLAYBOOK],
    accent: 'rose',
  },
  {
    type: ScanType.NETWORK_WATCHTOWER,
    icon: Radar,
    label: 'Network Watchtower',
    description: 'Monitor local network devices and live alerts.',
    group: 'blue',
    secondaryGroups: ['deception'],
    workflow: [ScanType.CANARY_FACTORY, ScanType.FORENSICS_TIMELINE, ScanType.IR_PLAYBOOK],
    accent: 'cyan',
  },
  {
    type: ScanType.FORENSICS_TIMELINE,
    icon: GitBranch,
    label: 'Forensics Timeline',
    description: 'Correlate events into a forensic investigation trail.',
    group: 'dfir',
    secondaryGroups: ['blue', 'command'],
    workflow: [ScanType.IR_PLAYBOOK, ScanType.ZERO_TRUST, ScanType.SECURITY_POSTURE],
    accent: 'sky',
  },
  {
    type: ScanType.WEBSEC_OPS,
    icon: Globe,
    label: 'WebSec Ops',
    description: 'Assess headers, SSL, DNS, and web exposure.',
    group: 'appsec',
    secondaryGroups: ['red', 'threatIntel'],
    workflow: [ScanType.AI_RED_TEAM, ScanType.ZERO_TRUST, ScanType.SECURITY_POSTURE],
    accent: 'emerald',
    featured: true,
  },
  {
    type: ScanType.ZERO_TRUST,
    icon: Shield,
    label: 'Zero Trust Policy Builder',
    description: 'Produce policy packages and control recommendations.',
    group: 'governance',
    secondaryGroups: ['appsec', 'blue'],
    workflow: [ScanType.SECURITY_POSTURE, ScanType.IR_PLAYBOOK],
    accent: 'cyan',
  },
  {
    type: ScanType.UTILITY_BELT,
    icon: Wrench,
    label: 'Utility Belt',
    description: 'Run small security utilities from one work surface.',
    group: 'utility',
    secondaryGroups: ['appsec', 'dfir'],
    accent: 'amber',
  },
  {
    type: ScanType.EDR_FLEET,
    icon: Server,
    label: 'Fleet EDR',
    description: 'Review endpoint fleet status and response actions.',
    group: 'blue',
    secondaryGroups: ['dfir'],
    workflow: [ScanType.GENERAL_LOG, ScanType.FORENSICS_TIMELINE, ScanType.IR_PLAYBOOK],
    accent: 'sky',
  },
];

export const groupById = new Map(moduleGroups.map((group) => [group.id, group]));

export const teamModuleGroups = moduleGroups
  .map((group) => ({
    ...group,
    modules: moduleRegistry.filter((item) => item.group === group.id),
  }))
  .filter((group) => group.modules.length > 0);

export const commandModules = moduleRegistry;
export const commandCenterModules = moduleRegistry.filter((item) => item.group === 'command');
export const redTeamModules = moduleRegistry.filter((item) => item.group === 'red');
export const blueTeamModules = moduleRegistry.filter((item) => item.group === 'blue');
export const threatIntelModules = moduleRegistry.filter((item) => item.group === 'threatIntel');
export const dfirModules = moduleRegistry.filter((item) => item.group === 'dfir');
export const deceptionModules = moduleRegistry.filter((item) => item.group === 'deception');
export const appSecModules = moduleRegistry.filter((item) => item.group === 'appsec');
export const governanceModules = moduleRegistry.filter((item) => item.group === 'governance');
export const trainingModules = moduleRegistry.filter((item) => item.group === 'training');
export const utilityModules = moduleRegistry.filter((item) => item.group === 'utility');

// Compatibility exports for older module surfaces.
export const homeModules = commandCenterModules;
export const analysisModules = moduleRegistry.filter((item) =>
  ['red', 'blue', 'threatIntel', 'dfir', 'appsec'].includes(item.group)
);
export const operationsModules = moduleRegistry.filter((item) =>
  ['deception', 'governance', 'training', 'utility'].includes(item.group)
);

export const featuredModules = moduleRegistry.filter((item) => item.featured && item.type !== ScanType.HOME);

export const getModule = (type: ScanType) => moduleRegistry.find((item) => item.type === type);
export const getModuleLabel = (type: ScanType) => getModule(type)?.label || type;
export const getModuleGroupConfig = (group: ModuleGroup) => groupById.get(group);
export const getModuleGroupLabel = (group: ModuleGroup) => getModuleGroupConfig(group)?.label || group;
export const getModuleSecondaryLabels = (item: ModuleNavItem) =>
  (item.secondaryGroups || []).map((group) => getModuleGroupLabel(group));
export const getWorkflowModules = (type: ScanType) =>
  (getModule(type)?.workflow || [])
    .map((workflowType) => getModule(workflowType))
    .filter((item): item is ModuleNavItem => Boolean(item));
