export enum ThreatLevel {
  LOW = 'Low',
  MEDIUM = 'Medium',
  HIGH = 'High',
  CRITICAL = 'Critical'
}

export enum ScanType {
  HOME = 'Home',
  SECURITY_POSTURE = 'Security Posture Score',
  AI_RED_TEAM = 'AI Red Team Agent',
  PORT_SCAN = 'Port Scan',
  VULN_SCAN = 'Vulnerability Scan',
  MITRE_ATTACK = 'MITRE ATT&CK Mapper',
  CVE_INTEL = 'CVE Intelligence Hub',
  PHISHING = 'Phishing Detection',
  DARK_WEB = 'Dark Web Monitor',
  MALWARE = 'Malware Analysis',
  KEYLOGGER = 'Keylogger Detection',
  GENERAL_LOG = 'General Log Analysis',
  PACKET_ANALYZER = 'Packet Capture Analyzer',
  FILE_CRYPTO = 'CryptoVault & Sanitizer',
  CYBER_DOJO = 'Cyber Dojo',
  IR_PLAYBOOK = 'Incident Response Playbook',
  CANARY_FACTORY = 'Canary Factory',
  NETWORK_WATCHTOWER = 'Network Watchtower',
  FORENSICS_TIMELINE = 'Forensics Timeline',
  WEBSEC_OPS = 'WebSec Ops',
  ZERO_TRUST = 'Zero Trust Policy Builder',
  UTILITY_BELT = 'Utility Belt',
  EDR_FLEET = 'Fleet EDR Management',
}

export interface SecurityAnalysis {
  threat_level: ThreatLevel;
  risk_score: number;
  summary: string;
  detailed_analysis: string;
  recommendations: string[];
  additional_notes: string;
}

export interface ScanHistoryItem {
  id: string;
  timestamp: Date;
  type: ScanType;
  result: SecurityAnalysis;
}

export interface AutoRemediationResult {
  is_vulnerable: boolean;
  fixed_content: string | null;
  analysis: SecurityAnalysis;
}

export interface NVDVulnerability {
  id: string;
  sourceIdentifier: string;
  published: string;
  lastModified: string;
  vulnStatus: string;
  descriptions: { lang: string; value: string }[];
  metrics?: {
    cvssMetricV31?: {
      cvssData: {
        baseScore: number;
        baseSeverity: string;
        vectorString: string;
        attackVector: string;
        attackComplexity: string;
        privilegesRequired: string;
        userInteraction: string;
      };
    }[];
    cvssMetricV2?: { cvssData: { baseScore: number; baseSeverity: string } }[];
  };
  weaknesses?: { description: { lang: string; value: string }[] }[];
  configurations?: any[];
  references?: { url: string; source: string; tags?: string[] }[];
}

export interface CVEAIAnalysis {
  plainEnglish: string;
  attackVector: string;
  impact: string;
  remediationSteps: string[];
  urgency: 'Critical' | 'High' | 'Medium' | 'Low';
  affectedPortsWarning: string | null;
}

export interface CVERecord {
  vulnerability: NVDVulnerability;
  aiAnalysis: CVEAIAnalysis | null;
  isAnalyzing: boolean;
  analysisError: string | null;
}

export interface HIBPBreach {
  Name: string;
  Title: string;
  Domain: string;
  BreachDate: string;
  AddedDate: string;
  ModifiedDate: string;
  PwnCount: number;
  Description: string;
  LogoPath: string;
  DataClasses: string[];
  IsVerified: boolean;
  IsFabricated: boolean;
  IsSensitive: boolean;
  IsRetired: boolean;
  IsSpamList: boolean;
  IsMalware: boolean;
}

export interface DarkWebAIAnalysis {
  riskScore: number;
  riskLevel: 'Critical' | 'High' | 'Medium' | 'Low' | 'Clean';
  summary: string;
  exposedDataTypes: string[];
  oldestBreach: string;
  mostRecentBreach: string;
  immediateActions: string[];
  longTermRecommendations: string[];
  passwordChangeUrgency: 'Immediate' | 'Soon' | 'Optional' | 'N/A';
}

export interface PasteExposure {
  Source?: string;
  Id?: string;
  Title?: string;
  Date?: string;
  EmailCount?: number;
}

export interface AbuseReport {
  reportedAt?: string;
  categories?: number[];
  comment?: string;
  reporterCountryCode?: string;
}

export interface AbuseData {
  abuseConfidenceScore?: number;
  totalReports?: number;
  countryCode?: string;
  isp?: string;
  usageType?: string;
  reports?: AbuseReport[];
}

export interface DarkWebScanResult {
  query: string;
  type: 'email' | 'domain' | 'ip' | 'username';
  breaches: HIBPBreach[];
  pasteExposures: PasteExposure[];
  abuseData?: AbuseData;
  aiAnalysis: DarkWebAIAnalysis | null;
  isDemoMode: boolean;
  timestamp: string;
}

export interface PostureReport {
  overallScore: number;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  categoryScores: {
    networkSecurity: number;
    webSecurity: number;
    endpointSecurity: number;
    dataProtection: number;
    threatIntelligence: number;
    incidentReadiness: number;
  };
  criticalFindings: string[];
  strengths: string[];
  improvementAreas: string[];
  complianceHints: {
    cisLevel1: 'Pass' | 'Partial' | 'Fail';
    cisLevel2: 'Pass' | 'Partial' | 'Fail';
    gdprReadiness: 'Pass' | 'Partial' | 'Fail';
    iso27001Hints: string;
  };
  nextScanRecommendations: string[];
  trendDirection: 'Improving' | 'Stable' | 'Declining' | 'New';
}

export interface PostureHistoryEntry {
  id?: number;
  score: number;
  grade: string;
  categoryScores: PostureReport['categoryScores'];
  timestamp: string;
}

export interface AttackTechnique {
  techniqueId: string;
  techniqueName: string;
  subTechniqueId: string | null;
  subTechniqueName: string | null;
  confidence: number;
  evidence: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  mitigation: string;
  detectionTip: string;
}

export interface AttackTactic {
  tacticId: string;
  tacticName: string;
  tacticPhase: number;
  confidence: number;
  techniques: AttackTechnique[];
}

export interface AttackClassification {
  tactics: AttackTactic[];
  killChainStage: string;
  attackSummary: string;
  threatActorProfile: string;
  overallSeverity: 'Critical' | 'High' | 'Medium' | 'Low';
}

export type ForensicsEventType =
  | 'port_scan'
  | 'vuln_detected'
  | 'phishing_detected'
  | 'malware_detected'
  | 'canary_triggered'
  | 'ghost_port_triggered'
  | 'arp_spoof_detected'
  | 'new_device_detected'
  | 'breach_found'
  | 'cve_added'
  | 'attack_classified'
  | 'ssl_expired'
  | 'dns_anomaly'
  | 'log_anomaly'
  | 'custom';

export interface ForensicsEvent {
  id: string;
  timestamp: number;
  eventType: ForensicsEventType;
  sourceModule: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  title: string;
  description: string;
  details: Record<string, any>;
  attackPhase?: string;
  ioc?: string[];
  relatedEventIds?: string[];
  isBookmarked: boolean;
  tags: string[];
}

export interface ParsedPacket {
  index: number;
  timestamp: number;
  length: number;
  srcIP: string | null;
  dstIP: string | null;
  srcPort: number | null;
  dstPort: number | null;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'ARP' | 'Other';
  tcpFlags: string[] | null;
  service: string | null;
  isSuspicious: boolean;
  suspicionReason: string | null;
}

export interface PCAPAnomaly {
  type: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  description: string;
  affectedIPs: string[];
  packetCount: number;
}

export interface PCAPAIResult {
  threatLevel: 'Critical' | 'High' | 'Medium' | 'Low' | 'Clean';
  verdict: string;
  detectedAttacks: {
    attackType: string;
    confidence: number;
    description: string;
    affectedHosts: string[];
    mitreTechnique: string | null;
    evidence: string;
  }[];
  suspiciousFlows: {
    srcIP: string;
    dstIP: string;
    port: number;
    protocol: string;
    reason: string;
    severity: 'Critical' | 'High' | 'Medium' | 'Low';
  }[];
  c2Indicators: string[];
  exfiltrationRisk: 'High' | 'Medium' | 'Low' | 'None';
  recommendations: string[];
  iocs: string[];
}

export type StepStatus = 'pending' | 'in_progress' | 'completed' | 'skipped';

export interface IRStep {
  stepId: string;
  title: string;
  description: string;
  assignedRole: string;
  toolsRequired: string[];
  expectedOutcome: string;
  isAutomatable: boolean;
  bashCommand: string | null;
  status: StepStatus;
  completedAt: number | null;
  completedBy: string;
  notes: string;
}

export interface IRPhase {
  phaseId: number;
  phaseName: string;
  phaseIcon: string;
  estimatedDuration: string;
  priority: 'Immediate' | 'High' | 'Medium' | 'Low';
  steps: IRStep[];
  isExpanded: boolean;
}

export interface IRPlaybook {
  playbookId: string;
  playbookTitle: string;
  incidentId: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  incidentType: string;
  createdAt: number;
  lastUpdated: number;
  executiveSummary: string;
  affectedAssets: string[];
  iocs: string[];
  phases: IRPhase[];
  communicationPlan: {
    internalNotifications: string[];
    externalNotifications: string[];
    regulatoryRequirements: string[];
  };
  lessonsLearned: string[];
  references: string[];
  overallProgress: number;
}

export type AgentState =
  | 'idle'
  | 'planning'
  | 'executing'
  | 'interpreting'
  | 'deciding'
  | 'synthesizing'
  | 'complete'
  | 'error';

export interface AgentInterpretation {
  interpretation: string;
  keyFindings: string[];
  riskIndicators: string[];
  shouldEscalate: boolean;
  escalationReason: string | null;
  suggestedNextTools: string[];
  confidenceLevel: number;
  agentThought: string;
}

export interface AgentStep {
  stepNumber: number;
  toolName: string;
  toolInput: Record<string, any>;
  rationale: string;
  dependsOnStep: number | null;
  expectedOutput: string;
  status: 'pending' | 'running' | 'complete' | 'failed' | 'skipped';
  actualOutput: Record<string, any> | null;
  interpretation: AgentInterpretation | null;
  startedAt: number | null;
  completedAt: number | null;
}

export interface AgentPlan {
  planTitle: string;
  estimatedDuration: string;
  steps: AgentStep[];
  agentObjective: string;
  riskLevel: string;
}

export interface AgentReport {
  reportTitle: string;
  executiveSummary: string;
  overallRiskRating: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
  attackSurface: {
    exposedServices: string[];
    weakPoints: string[];
    strongPoints: string[];
  };
  criticalFindings: {
    finding: string;
    evidence: string;
    impact: string;
    recommendation: string;
    priority: number;
  }[];
  mitreTacticsDetected: string[];
  immediateActions: string[];
  shortTermActions: string[];
  longTermActions: string[];
  riskScore: number;
  complianceNotes: string;
  conclusionStatement: string;
}

export interface PolicyConfig {
  configType: string;
  fileName: string;
  language: string;
  description: string;
  content: string;
  warningNote: string | null;
  testCommand: string | null;
  isValidated: boolean;
  validationErrors: string[];
  validationWarnings: string[];
}

export interface SecurityRule {
  ruleId: string;
  ruleName: string;
  action: 'ALLOW' | 'DENY' | 'LOG' | 'RATE_LIMIT';
  source: string;
  destination: string;
  protocol: string;
  port: string;
  rationale: string;
}

export interface ZeroTrustPolicy {
  policyTitle: string;
  riskReduction: string;
  configs: PolicyConfig[];
  securityRules: SecurityRule[];
  immediateWins: string[];
  estimatedRiskReduction: number;
  implementationOrder: string[];
}
