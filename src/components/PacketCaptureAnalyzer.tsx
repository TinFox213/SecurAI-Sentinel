import React, { useMemo, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import jsPDF from 'jspdf';
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  Download,
  FileDown,
  Filter,
  Loader2,
  PackageSearch,
  Shield,
  Target,
  Upload,
  X
} from 'lucide-react';
import { toast } from 'react-hot-toast';
import { ParsedPacket, PCAPAIResult, PCAPAnomaly, ScanType } from '../types/types';
import { saveSetting } from '../services/db';
import { logForensicsEvent } from '../utils/forensicsLogger';

type AnalysisDepth = 'quick' | 'deep';
type ProgressStatus = 'pending' | 'active' | 'done';
type TabKey = 'overview' | 'inspector' | 'anomalies' | 'ai' | 'conversations';

interface PacketCaptureAnalyzerProps {
  onNavigate?: (type: ScanType) => void;
}

interface CaptureTopProtocol {
  protocol: string;
  count: number;
  percentage: number;
}

interface CaptureTopIP {
  ip: string;
  count: number;
}

interface CaptureTopPort {
  port: number;
  count: number;
  service: string;
}

interface CaptureStats {
  totalPackets: number;
  parsedPackets: number;
  captureStart: number;
  captureEnd: number;
  captureDuration: number;
  topProtocols: CaptureTopProtocol[];
  topSrcIPs: CaptureTopIP[];
  topDstIPs: CaptureTopIP[];
  topPorts: CaptureTopPort[];
  packets: ParsedPacket[];
}

interface ProtocolDistributionRow {
  protocol: string;
  count: number;
  percentage: number;
}

interface ConversationRow {
  srcIP: string;
  dstIP: string;
  protocol: string;
  packets: number;
  bytes: number;
  duration: number;
  flags: string[];
  risk: 'High' | 'Low';
}

interface ProtocolStats {
  protocolDistribution: ProtocolDistributionRow[];
  conversations: ConversationRow[];
  tcpFlagDistribution: { flag: string; count: number }[];
  packetSizeDistribution: { small: number; medium: number; large: number };
}

const severityClass: Record<string, string> = {
  Critical: 'bg-red-500/20 border-red-500/40 text-red-200',
  High: 'bg-orange-500/20 border-orange-500/40 text-orange-200',
  Medium: 'bg-yellow-500/20 border-yellow-500/40 text-yellow-200',
  Low: 'bg-blue-500/20 border-blue-500/40 text-blue-200',
  Clean: 'bg-emerald-500/20 border-emerald-500/40 text-emerald-200'
};

const protocolColors: Record<string, string> = {
  TCP: 'bg-blue-500',
  UDP: 'bg-purple-500',
  ICMP: 'bg-emerald-500',
  ARP: 'bg-yellow-500',
  Other: 'bg-slate-500'
};

function ipToBytes(ip: string): number[] {
  return ip.split('.').map((octet) => Math.max(0, Math.min(255, Number(octet) || 0)));
}

function writeUInt16BE(buffer: Uint8Array, offset: number, value: number) {
  buffer[offset] = (value >> 8) & 0xff;
  buffer[offset + 1] = value & 0xff;
}

function writeUInt16LE(buffer: Uint8Array, offset: number, value: number) {
  buffer[offset] = value & 0xff;
  buffer[offset + 1] = (value >> 8) & 0xff;
}

function writeUInt32LE(buffer: Uint8Array, offset: number, value: number) {
  buffer[offset] = value & 0xff;
  buffer[offset + 1] = (value >> 8) & 0xff;
  buffer[offset + 2] = (value >> 16) & 0xff;
  buffer[offset + 3] = (value >> 24) & 0xff;
}

function buildSyntheticEthernetIPv4Packet(
  srcIP: string,
  dstIP: string,
  srcPort: number,
  dstPort: number,
  protocol: 'TCP' | 'UDP' = 'TCP',
  tcpFlags = 0x18,
  payloadSize = 24
): Uint8Array {
  const payload = new Uint8Array(payloadSize);
  for (let i = 0; i < payload.length; i += 1) payload[i] = (i * 13) & 0xff;

  const ethernetHeaderLength = 14;
  const ipHeaderLength = 20;
  const l4HeaderLength = protocol === 'TCP' ? 20 : 8;
  const totalLength = ethernetHeaderLength + ipHeaderLength + l4HeaderLength + payload.length;
  const packet = new Uint8Array(totalLength);

  // Ethernet header (dst MAC + src MAC + IPv4 ethertype)
  const dstMac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
  const srcMac = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
  packet.set(dstMac, 0);
  packet.set(srcMac, 6);
  packet[12] = 0x08;
  packet[13] = 0x00;

  // IPv4 header
  const ipOffset = ethernetHeaderLength;
  packet[ipOffset] = 0x45;
  packet[ipOffset + 1] = 0x00;
  writeUInt16BE(packet, ipOffset + 2, ipHeaderLength + l4HeaderLength + payload.length);
  writeUInt16BE(packet, ipOffset + 4, 0x1234);
  writeUInt16BE(packet, ipOffset + 6, 0x4000);
  packet[ipOffset + 8] = 64;
  packet[ipOffset + 9] = protocol === 'TCP' ? 6 : 17;
  writeUInt16BE(packet, ipOffset + 10, 0);
  packet.set(ipToBytes(srcIP), ipOffset + 12);
  packet.set(ipToBytes(dstIP), ipOffset + 16);

  // L4 header
  const l4Offset = ipOffset + ipHeaderLength;
  writeUInt16BE(packet, l4Offset, srcPort);
  writeUInt16BE(packet, l4Offset + 2, dstPort);

  if (protocol === 'TCP') {
    writeUInt16BE(packet, l4Offset + 4, 0x1111);
    writeUInt16BE(packet, l4Offset + 6, 0x2222);
    packet[l4Offset + 12] = 0x50;
    packet[l4Offset + 13] = tcpFlags & 0xff;
    writeUInt16BE(packet, l4Offset + 14, 65535);
  } else {
    writeUInt16BE(packet, l4Offset + 4, l4HeaderLength + payload.length);
    writeUInt16BE(packet, l4Offset + 6, 0);
  }

  packet.set(payload, l4Offset + l4HeaderLength);
  return packet;
}

function buildSamplePcapBase64(): string {
  const globalHeader = new Uint8Array(24);
  globalHeader.set([0xd4, 0xc3, 0xb2, 0xa1], 0); // little-endian magic
  writeUInt16LE(globalHeader, 4, 2);
  writeUInt16LE(globalHeader, 6, 4);
  writeUInt32LE(globalHeader, 8, 0);
  writeUInt32LE(globalHeader, 12, 0);
  writeUInt32LE(globalHeader, 16, 65535);
  writeUInt32LE(globalHeader, 20, 1); // Ethernet

  const packetDefs = [
    ['10.0.0.5', '10.0.0.10', 51120, 443, 'TCP', 0x18, 40],
    ['10.0.0.5', '10.0.0.10', 51120, 443, 'TCP', 0x18, 40],
    ['10.0.0.5', '10.0.0.10', 51120, 443, 'TCP', 0x18, 40],
    ['10.0.0.5', '10.0.0.10', 51120, 443, 'TCP', 0x18, 40],
    ['10.0.0.5', '10.0.0.10', 51120, 443, 'TCP', 0x18, 40],
    ['10.0.0.5', '10.0.0.10', 51120, 443, 'TCP', 0x18, 40],
    ['10.0.0.7', '8.8.8.8', 53000, 53, 'UDP', 0, 620],
    ['10.0.0.7', '8.8.8.8', 53001, 53, 'UDP', 0, 580],
    ['10.0.0.11', '10.0.0.20', 44001, 4444, 'TCP', 0x02, 12],
    ['10.0.0.11', '10.0.0.20', 44002, 1337, 'TCP', 0x02, 12],
    ['10.0.0.11', '10.0.0.20', 44003, 31337, 'TCP', 0x02, 12],
    ['10.0.0.11', '10.0.0.20', 44004, 6666, 'TCP', 0x02, 12],
    ['10.0.0.11', '10.0.0.20', 44005, 9999, 'TCP', 0x02, 12],
    ['10.0.0.12', '10.0.0.25', 61000, 80, 'TCP', 0x02, 20],
    ['10.0.0.12', '10.0.0.25', 61001, 81, 'TCP', 0x02, 20],
    ['10.0.0.12', '10.0.0.25', 61002, 82, 'TCP', 0x02, 20],
    ['10.0.0.12', '10.0.0.25', 61003, 83, 'TCP', 0x02, 20],
    ['10.0.0.12', '10.0.0.25', 61004, 84, 'TCP', 0x02, 20],
    ['10.0.0.12', '10.0.0.25', 61005, 85, 'TCP', 0x02, 20],
    ['10.0.0.12', '10.0.0.25', 61006, 86, 'TCP', 0x02, 20],
    ['10.0.0.12', '10.0.0.25', 61007, 87, 'TCP', 0x02, 20],
    ['10.0.0.12', '10.0.0.25', 61008, 88, 'TCP', 0x02, 20],
    ['10.0.0.12', '10.0.0.25', 61009, 89, 'TCP', 0x02, 20],
    ['10.0.0.12', '10.0.0.25', 61010, 90, 'TCP', 0x02, 20]
  ] as const;

  const chunks: Uint8Array[] = [globalHeader];
  let tsBase = Math.floor(Date.now() / 1000);

  packetDefs.forEach((row, idx) => {
    const [srcIP, dstIP, srcPort, dstPort, proto, flags, payloadLen] = row;
    const packetData = buildSyntheticEthernetIPv4Packet(srcIP, dstIP, srcPort, dstPort, proto, flags, payloadLen);
    const recordHeader = new Uint8Array(16);
    writeUInt32LE(recordHeader, 0, tsBase + idx * (idx < 6 ? 5 : 1));
    writeUInt32LE(recordHeader, 4, 1200);
    writeUInt32LE(recordHeader, 8, packetData.length);
    writeUInt32LE(recordHeader, 12, packetData.length);
    chunks.push(recordHeader, packetData);
  });

  const total = chunks.reduce((acc, c) => acc + c.length, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  chunks.forEach((chunk) => {
    output.set(chunk, offset);
    offset += chunk.length;
  });

  let binary = '';
  output.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

const SAMPLE_PCAP_BASE64 = buildSamplePcapBase64();

function bytesToHuman(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

const PacketCaptureAnalyzer: React.FC<PacketCaptureAnalyzerProps> = ({ onNavigate }) => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [analysisDepth, setAnalysisDepth] = useState<AnalysisDepth>('quick');
  const [isDragOver, setIsDragOver] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [activeTab, setActiveTab] = useState<TabKey>('overview');
  const [error, setError] = useState<string | null>(null);
  const [summary, setSummary] = useState('');
  const [captureStats, setCaptureStats] = useState<CaptureStats | null>(null);
  const [anomalies, setAnomalies] = useState<PCAPAnomaly[]>([]);
  const [aiResult, setAiResult] = useState<PCAPAIResult | null>(null);
  const [protocolStats, setProtocolStats] = useState<ProtocolStats | null>(null);
  const [selectedPacket, setSelectedPacket] = useState<ParsedPacket | null>(null);
  const [filterProtocol, setFilterProtocol] = useState<string>('All');
  const [filterIP, setFilterIP] = useState('');
  const [filterPort, setFilterPort] = useState('');
  const [suspiciousOnly, setSuspiciousOnly] = useState(false);
  const [conversationSort, setConversationSort] = useState<{ key: keyof ConversationRow; direction: 'asc' | 'desc' }>({
    key: 'bytes',
    direction: 'desc'
  });
  const [progress, setProgress] = useState<Record<'validate' | 'parse' | 'anomaly' | 'ai', ProgressStatus>>({
    validate: 'pending',
    parse: 'pending',
    anomaly: 'pending',
    ai: 'pending'
  });

  const protocolTotals = useMemo(() => {
    const base = { TCP: 0, UDP: 0, ICMP: 0, ARP: 0, Other: 0 };
    (captureStats?.topProtocols || []).forEach((item) => {
      if (item.protocol in base) {
        base[item.protocol as keyof typeof base] += item.percentage;
      } else {
        base.Other += item.percentage;
      }
    });
    return base;
  }, [captureStats]);

  const filteredPackets = useMemo(() => {
    const rows = captureStats?.packets || [];
    return rows.filter((packet) => {
      if (filterProtocol !== 'All' && packet.protocol !== filterProtocol) return false;
      if (suspiciousOnly && !packet.isSuspicious) return false;

      const ipQuery = filterIP.trim();
      if (ipQuery) {
        const inSrc = packet.srcIP?.includes(ipQuery);
        const inDst = packet.dstIP?.includes(ipQuery);
        if (!inSrc && !inDst) return false;
      }

      const portQuery = Number(filterPort);
      if (filterPort.trim() && Number.isFinite(portQuery)) {
        if (packet.srcPort !== portQuery && packet.dstPort !== portQuery) return false;
      }

      return true;
    });
  }, [captureStats, filterProtocol, filterIP, filterPort, suspiciousOnly]);

  const sortedConversations = useMemo(() => {
    const rows = [...(protocolStats?.conversations || [])];
    rows.sort((a, b) => {
      const left = a[conversationSort.key];
      const right = b[conversationSort.key];
      if (typeof left === 'number' && typeof right === 'number') {
        return conversationSort.direction === 'asc' ? left - right : right - left;
      }
      const leftStr = String(left ?? '');
      const rightStr = String(right ?? '');
      return conversationSort.direction === 'asc'
        ? leftStr.localeCompare(rightStr)
        : rightStr.localeCompare(leftStr);
    });
    return rows;
  }, [protocolStats, conversationSort]);

  const threatLevel = useMemo(() => {
    if (aiResult?.threatLevel) return aiResult.threatLevel;
    const hasCritical = anomalies.some((a) => a.severity === 'Critical');
    if (hasCritical) return 'Critical';
    const hasHigh = anomalies.some((a) => a.severity === 'High');
    if (hasHigh) return 'High';
    const hasMedium = anomalies.some((a) => a.severity === 'Medium');
    if (hasMedium) return 'Medium';
    if (anomalies.length > 0) return 'Low';
    return 'Clean';
  }, [aiResult, anomalies]);

  const exfilRisk = useMemo(() => {
    if (aiResult?.exfiltrationRisk) return aiResult.exfiltrationRisk;
    const hasExfil = anomalies.some((a) => /exfil|large data transfer/i.test(a.type) || /transferred/i.test(a.description));
    return hasExfil ? 'Medium' : 'None';
  }, [aiResult, anomalies]);

  const verdict = useMemo(() => {
    if (aiResult?.verdict) return aiResult.verdict;
    if (anomalies.length === 0) return 'No significant network anomalies were detected in the parsed packet sample.';
    return `${anomalies.length} anomaly signature(s) detected during packet inspection.`;
  }, [aiResult, anomalies]);

  const uniqueIpCount = useMemo(() => {
    const set = new Set<string>();
    (captureStats?.packets || []).forEach((packet) => {
      if (packet.srcIP) set.add(packet.srcIP);
      if (packet.dstIP) set.add(packet.dstIP);
    });
    return set.size;
  }, [captureStats]);

  const suspiciousFlowCount = useMemo(() => {
    if (aiResult?.suspiciousFlows) return aiResult.suspiciousFlows.length;
    return (protocolStats?.conversations || []).filter((row) => row.risk === 'High').length;
  }, [aiResult, protocolStats]);

  const c2Count = useMemo(() => {
    if (aiResult?.c2Indicators) return aiResult.c2Indicators.length;
    return anomalies.filter((a) => /beacon|c2/i.test(a.type) || /beacon|c2/i.test(a.description)).length;
  }, [aiResult, anomalies]);

  const resetProgress = () => {
    setProgress({
      validate: 'pending',
      parse: 'pending',
      anomaly: 'pending',
      ai: 'pending'
    });
  };

  const applyFile = (file: File | null) => {
    setSelectedFile(file);
    setError(null);
  };

  const removeFile = () => {
    setSelectedFile(null);
    setCaptureStats(null);
    setAnomalies([]);
    setAiResult(null);
    setProtocolStats(null);
    setSelectedPacket(null);
    setSummary('');
    setError(null);
    resetProgress();
  };

  const handleDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.stopPropagation();
    setIsDragOver(false);
    const file = event.dataTransfer.files?.[0];
    if (!file) return;
    applyFile(file);
  };

  const useSamplePcap = () => {
    try {
      const bytes = Uint8Array.from(atob(SAMPLE_PCAP_BASE64), (char) => char.charCodeAt(0));
      const blob = new Blob([bytes], { type: 'application/vnd.tcpdump.pcap' });
      const file = new File([blob], 'sample-network-traffic.pcap', { type: 'application/vnd.tcpdump.pcap' });
      applyFile(file);
      toast.success('Loaded sample PCAP with synthetic traffic');
    } catch {
      toast.error('Unable to generate sample PCAP');
    }
  };

  const analyzeCapture = async () => {
    if (!selectedFile) return;
    setError(null);
    setIsAnalyzing(true);
    setCaptureStats(null);
    setAnomalies([]);
    setAiResult(null);
    setProtocolStats(null);
    setSummary('');
    setSelectedPacket(null);
    setActiveTab('overview');
    resetProgress();
    setProgress((prev) => ({ ...prev, validate: 'active' }));

    try {
      const formData = new FormData();
      formData.append('file', selectedFile);
      formData.append('analysisDepth', analysisDepth);

      const parseResponse = await fetch('http://localhost:3001/pcap/analyze', {
        method: 'POST',
        body: formData
      });
      const parseData = await parseResponse.json();
      if (!parseResponse.ok) {
        throw new Error(parseData?.message || 'PCAP analysis failed');
      }

      const nextStats: CaptureStats = parseData.captureStats;
      const nextAnomalies: PCAPAnomaly[] = Array.isArray(parseData.anomalies) ? parseData.anomalies : [];
      const nextSummary = String(parseData.summary || '');
      setCaptureStats(nextStats);
      setAnomalies(nextAnomalies);
      setSummary(nextSummary);
      setProgress({
        validate: 'done',
        parse: 'done',
        anomaly: 'done',
        ai: analysisDepth === 'deep' ? 'active' : 'pending'
      });

      const protocolPromise = fetch('http://localhost:3001/pcap/protocols', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ packets: nextStats?.packets || [] })
      }).then(async (response) => {
        const data = await response.json();
        if (!response.ok) throw new Error(data?.message || 'Protocol statistics failed');
        return data as ProtocolStats;
      });

      let nextAI: PCAPAIResult | null = null;
      if (analysisDepth === 'deep') {
        const aiResponse = await fetch('http://localhost:3001/pcap/ai-analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ summary: nextSummary, anomalies: nextAnomalies, captureStats: nextStats })
        });
        const aiData = await aiResponse.json();
        if (!aiResponse.ok) {
          throw new Error(aiData?.message || 'AI packet intelligence failed');
        }
        nextAI = aiData as PCAPAIResult;
        setAiResult(nextAI);
        setProgress((prev) => ({ ...prev, ai: 'done' }));
      }

      const pStats = await protocolPromise;
      setProtocolStats(pStats);

      try {
        const eventThreat = nextAI?.threatLevel
          || (nextAnomalies.some((a) => a.severity === 'Critical')
            ? 'Critical'
            : nextAnomalies.some((a) => a.severity === 'High')
              ? 'High'
              : nextAnomalies.some((a) => a.severity === 'Medium')
                ? 'Medium'
                : nextAnomalies.length > 0
                  ? 'Low'
                  : 'Clean');
        await logForensicsEvent({
          timestamp: Date.now(),
          eventType: 'custom',
          sourceModule: 'Packet Analyzer',
          severity: eventThreat === 'Clean' ? 'Info' : (eventThreat as 'Critical' | 'High' | 'Medium' | 'Low'),
          title: `Packet capture analyzed: ${selectedFile.name}`,
          description: nextAI?.verdict || (nextAnomalies[0]?.description || 'Packet capture analysis completed'),
          details: {
            fileName: selectedFile.name,
            totalPackets: nextStats.totalPackets,
            anomalies: nextAnomalies
          },
          attackPhase: nextAnomalies.some((a) => /c2|beacon/i.test(a.type)) ? 'Command and Control' : 'Discovery',
          ioc: nextAI?.iocs || [],
          tags: ['packet-capture', 'network-forensics']
        });
      } catch (forensicsErr) {
        console.error('Forensics event logging skipped:', forensicsErr);
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to analyze packet capture';
      setError(message);
      toast.error(message);
      resetProgress();
    } finally {
      setIsAnalyzing(false);
    }
  };

  const exportPacketCsv = () => {
    const rows = filteredPackets;
    if (rows.length === 0) {
      toast.error('No packet rows to export');
      return;
    }

    const header = ['index', 'timestamp', 'src', 'dst', 'protocol', 'length', 'flags', 'service', 'status'];
    const lines = rows.map((packet) => [
      packet.index,
      packet.timestamp,
      `${packet.srcIP || 'N/A'}${packet.srcPort ? `:${packet.srcPort}` : ''}`,
      `${packet.dstIP || 'N/A'}${packet.dstPort ? `:${packet.dstPort}` : ''}`,
      packet.protocol,
      packet.length,
      packet.tcpFlags?.join('|') || '',
      packet.service || '',
      packet.isSuspicious ? 'Suspicious' : 'Normal'
    ].join(','));
    downloadBlob(new Blob([[header.join(','), ...lines].join('\n')], { type: 'text/csv;charset=utf-8' }), `packet-list-${Date.now()}.csv`);
  };

  const exportIOCList = () => {
    const iocs = aiResult?.iocs || [];
    if (iocs.length === 0) {
      toast.error('No IOCs available');
      return;
    }
    downloadBlob(new Blob([iocs.join('\n')], { type: 'text/plain;charset=utf-8' }), `ioc-list-${Date.now()}.txt`);
  };

  const copyAllIocs = async () => {
    const iocs = aiResult?.iocs || [];
    if (iocs.length === 0) {
      toast.error('No IOCs available');
      return;
    }
    await navigator.clipboard.writeText(iocs.join('\n'));
    toast.success('IOC list copied to clipboard');
  };

  const exportPdf = () => {
    if (!captureStats) return;
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    let y = 16;
    const lineHeight = 6;

    const addHeading = (title: string) => {
      if (y > pageHeight - 25) {
        doc.addPage();
        y = 16;
      }
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(14);
      doc.text(title, 14, y);
      y += 8;
      doc.setLineWidth(0.2);
      doc.line(14, y - 4, pageWidth - 14, y - 4);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(11);
    };

    const addTextBlock = (label: string, text: string) => {
      if (y > pageHeight - 25) {
        doc.addPage();
        y = 16;
      }
      doc.setFont('helvetica', 'bold');
      doc.text(`${label}:`, 14, y);
      doc.setFont('helvetica', 'normal');
      const wrapped = doc.splitTextToSize(text || 'N/A', pageWidth - 32);
      doc.text(wrapped, 38, y);
      y += Math.max(lineHeight, wrapped.length * lineHeight);
    };

    doc.setFontSize(18);
    doc.setFont('helvetica', 'bold');
    doc.text('Packet Capture Forensics Report', 14, y);
    y += 9;
    doc.setFontSize(11);
    doc.setFont('helvetica', 'normal');
    doc.text(`Generated: ${new Date().toLocaleString()}`, 14, y);
    y += 9;

    addHeading('Capture Statistics');
    addTextBlock('Threat Level', threatLevel);
    addTextBlock('Verdict', verdict);
    addTextBlock('Exfiltration Risk', exfilRisk);
    addTextBlock('Total Packets', String(captureStats.totalPackets));
    addTextBlock('Capture Duration', `${captureStats.captureDuration} seconds`);
    addTextBlock('Top Protocols', captureStats.topProtocols.map((row) => `${row.protocol} (${row.percentage}%)`).join(', '));

    addHeading('Detected Anomalies');
    if (anomalies.length === 0) {
      addTextBlock('Status', 'No anomalies detected');
    } else {
      anomalies.forEach((anomaly, index) => {
        addTextBlock(`Anomaly ${index + 1}`, `[${anomaly.severity}] ${anomaly.type} — ${anomaly.description}`);
      });
    }

    addHeading('AI Intelligence');
    addTextBlock('Summary', aiResult?.verdict || 'AI deep analysis not executed');
    addTextBlock('IOCs', (aiResult?.iocs || []).join(', ') || 'None');
    addTextBlock('Recommendations', (aiResult?.recommendations || []).join(' | ') || 'None');

    const totalPages = doc.getNumberOfPages();
    for (let page = 1; page <= totalPages; page += 1) {
      doc.setPage(page);
      doc.setFontSize(9);
      doc.text(`Page ${page}/${totalPages}`, pageWidth / 2, pageHeight - 8, { align: 'center' });
    }
    doc.save(`pcap-forensics-report-${Date.now()}.pdf`);
  };

  const sendToForensicsTimeline = async () => {
    if (!captureStats) return;
    try {
      await logForensicsEvent({
        timestamp: Date.now(),
        eventType: 'custom',
        sourceModule: 'Packet Analyzer',
        severity: threatLevel === 'Clean' ? 'Info' : (threatLevel as 'Critical' | 'High' | 'Medium' | 'Low'),
        title: `Packet analysis findings exported`,
        description: verdict,
        details: {
          captureStats,
          anomalies,
          ai: aiResult
        },
        attackPhase: aiResult?.c2Indicators?.length ? 'Command and Control' : 'Discovery',
        ioc: aiResult?.iocs || [],
        tags: ['packet-capture', 'timeline-export']
      });
      toast.success('Findings sent to Forensics Timeline');
    } catch (forensicsErr) {
      console.error('Forensics event logging skipped:', forensicsErr);
      toast.error('Failed to send to Forensics Timeline');
    }
  };

  const mapToAttack = async () => {
    if (!captureStats) return;
    try {
      await saveSetting('mitre_prefill_payload', {
        sourceModule: 'Packet Analyzer',
        findings: summary,
        indicators: aiResult?.iocs || [],
        createdAt: Date.now()
      });
    } catch (err) {
      console.error('Failed to persist ATT&CK prefill payload:', err);
    }

    if (onNavigate) {
      onNavigate(ScanType.MITRE_ATTACK);
      toast.success('ATT&CK Mapper opened with packet findings prefill');
    } else {
      toast.error('ATT&CK Mapper navigation unavailable');
    }
  };

  const protocolOptions = ['All', 'TCP', 'UDP', 'ICMP', 'ARP', 'Other'];

  const toggleConversationSort = (key: keyof ConversationRow) => {
    setConversationSort((prev) => ({
      key,
      direction: prev.key === key && prev.direction === 'desc' ? 'asc' : 'desc'
    }));
  };

  const showAITab = analysisDepth === 'deep' || Boolean(aiResult);

  return (
    <div className="space-y-6">
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="bg-slate-900/50 border border-white/10 rounded-2xl p-6 backdrop-blur-xl">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/20 border border-cyan-500/30">
              <PackageSearch className="w-6 h-6 text-cyan-300" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-slate-100">Packet Capture Analyzer</h1>
              <p className="text-sm text-slate-400">Upload .pcap files for AI-powered network forensics</p>
            </div>
          </div>
          <span className="text-xs px-3 py-1 rounded-full border border-slate-700 bg-slate-800/80 text-slate-300">Supports .pcap / .pcapng up to 50MB</span>
        </div>
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="bg-slate-900/45 border border-white/10 rounded-2xl p-6 backdrop-blur-xl">
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setIsDragOver(true);
          }}
          onDragLeave={(e) => {
            e.preventDefault();
            setIsDragOver(false);
          }}
          onDrop={handleDrop}
          className={`border-2 border-dashed rounded-2xl p-8 text-center transition-all ${isDragOver ? 'border-cyan-400 bg-cyan-500/10' : 'border-slate-700 bg-slate-950/40'}`}
        >
          <motion.div animate={{ y: isDragOver ? [0, -4, 0] : 0 }} transition={{ duration: 0.6, repeat: isDragOver ? Infinity : 0 }} className="mx-auto w-16 h-16 rounded-full bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center mb-4">
            <PackageSearch className="w-8 h-8 text-cyan-300" />
          </motion.div>
          <p className="text-lg font-semibold text-slate-100">Drop .pcap or .pcapng file here</p>
          <p className="text-sm text-slate-400 mb-4">or click to browse files</p>
          <label className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-cyan-500/30 bg-cyan-500/10 text-cyan-300 cursor-pointer hover:bg-cyan-500/20 transition">
            <Upload className="w-4 h-4" />
            Select Capture File
            <input
              type="file"
              accept=".pcap,.pcapng,application/vnd.tcpdump.pcap,application/octet-stream"
              className="hidden"
              onChange={(e) => applyFile(e.target.files?.[0] || null)}
            />
          </label>
          <div className="mt-4 text-xs text-slate-500">
            <span className="px-2 py-1 rounded border border-slate-700 bg-slate-900">.pcap .pcapng</span>
          </div>

          {selectedFile && (
            <div className="mt-6 p-3 rounded-lg bg-slate-900/60 border border-slate-700 flex flex-wrap items-center justify-between gap-3">
              <div className="text-left">
                <p className="text-sm text-slate-200 font-medium">{selectedFile.name}</p>
                <p className="text-xs text-slate-400">{bytesToHuman(selectedFile.size)}</p>
              </div>
              <button onClick={removeFile} className="inline-flex items-center gap-1 text-red-300 hover:text-red-200 text-xs border border-red-500/40 bg-red-500/10 px-2 py-1 rounded">
                <X className="w-3 h-3" /> Remove
              </button>
            </div>
          )}
        </div>

        <div className="mt-5 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2 p-1 rounded-lg bg-slate-950/50 border border-slate-700">
            <button
              onClick={() => setAnalysisDepth('quick')}
              className={`px-3 py-1.5 rounded text-sm ${analysisDepth === 'quick' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-slate-400'}`}
            >
              Quick Analysis
            </button>
            <button
              onClick={() => setAnalysisDepth('deep')}
              className={`px-3 py-1.5 rounded text-sm ${analysisDepth === 'deep' ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30' : 'text-slate-400'}`}
            >
              Deep Analysis
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button onClick={useSamplePcap} className="inline-flex items-center gap-2 px-3 py-2 rounded-lg border border-slate-600 bg-slate-800/60 text-slate-200 hover:bg-slate-700/60 transition text-sm">
              Use Sample PCAP
            </button>
            <button
              disabled={!selectedFile || isAnalyzing}
              onClick={analyzeCapture}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-cyan-500/40 bg-cyan-500/15 text-cyan-300 hover:bg-cyan-500/25 disabled:opacity-50 disabled:cursor-not-allowed transition"
            >
              {isAnalyzing ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
              Analyze Capture
            </button>
          </div>
        </div>

        {error && (
          <div className="mt-4 text-sm text-red-300 bg-red-500/10 border border-red-500/30 rounded-lg px-3 py-2 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" />
            {error}
          </div>
        )}
      </motion.div>

      {(isAnalyzing || progress.validate === 'done' || progress.parse === 'done' || progress.anomaly === 'done' || progress.ai === 'done') && (
        <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="bg-slate-900/40 border border-white/10 rounded-2xl p-5 backdrop-blur-xl">
          <h3 className="text-sm font-semibold text-slate-200 mb-3">Analysis Progress</h3>
          <div className="space-y-2">
            {[
              ['validate', 'Validating file format...'],
              ['parse', 'Parsing packet headers...'],
              ['anomaly', 'Running anomaly detection...'],
              ['ai', 'Generating AI intelligence...']
            ].filter(([key]) => key !== 'ai' || analysisDepth === 'deep')
              .map(([key, label]) => {
                const status = progress[key as keyof typeof progress];
                return (
                  <div key={key} className="flex items-center gap-3 text-sm">
                    {status === 'done' ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    ) : status === 'active' ? (
                      <Loader2 className="w-4 h-4 text-cyan-300 animate-spin" />
                    ) : (
                      <div className="w-4 h-4 rounded-full border border-slate-600" />
                    )}
                    <span className={status === 'done' ? 'text-emerald-300' : status === 'active' ? 'text-cyan-300' : 'text-slate-500'}>{label}</span>
                  </div>
                );
              })}
          </div>
        </motion.div>
      )}

      {captureStats && (
        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-5">
          <div className={`rounded-2xl border p-5 ${severityClass[threatLevel] || severityClass.Medium}`}>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-xs uppercase tracking-wide">Threat Level</p>
                <h2 className="text-2xl font-bold">{threatLevel}</h2>
                <p className="text-sm opacity-90 mt-1">{verdict}</p>
              </div>
              <div className="px-3 py-1 rounded-full border border-white/20 bg-black/20 text-sm font-semibold">
                Exfiltration Risk: {exfilRisk}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-2 lg:grid-cols-6 gap-3">
            {[
              ['Total Packets', String(captureStats.totalPackets)],
              ['Capture Duration', `${captureStats.captureDuration}s`],
              ['Unique IPs', String(uniqueIpCount)],
              ['Suspicious Flows', String(suspiciousFlowCount)],
              ['Anomalies Detected', String(anomalies.length)],
              ['C2 Indicators', String(c2Count)]
            ].map(([label, value]) => (
              <div key={label} className="bg-slate-900/45 border border-white/10 rounded-xl p-3">
                <p className="text-xs text-slate-400">{label}</p>
                <p className="text-xl font-bold text-slate-100">{value}</p>
              </div>
            ))}
          </div>

          <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-4">
            <div className="flex flex-wrap gap-2">
              {[
                ['overview', 'Overview'],
                ['inspector', 'Packet Inspector'],
                ['anomalies', 'Anomalies'],
                ...(showAITab ? ([['ai', 'AI Intelligence']] as const) : []),
                ['conversations', 'Conversations']
              ].map(([key, label]) => (
                <button
                  key={key}
                  onClick={() => setActiveTab(key as TabKey)}
                  className={`px-3 py-2 rounded-lg text-sm border transition ${
                    activeTab === key ? 'bg-cyan-500/20 border-cyan-500/40 text-cyan-300' : 'bg-slate-900 border-slate-700 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          <AnimatePresence mode="wait">
            {activeTab === 'overview' && (
              <motion.div key="overview" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-4">
                <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-5">
                  <h3 className="text-sm font-semibold text-slate-200 mb-3">Protocol Distribution</h3>
                  <div className="h-8 w-full rounded overflow-hidden flex border border-slate-700 bg-slate-950">
                    {Object.entries(protocolTotals).map(([name, value]) => (
                      <div
                        key={name}
                        className={`${protocolColors[name] || protocolColors.Other} h-full text-[10px] text-white flex items-center justify-center font-semibold`}
                        style={{ width: `${Math.max(value, 0)}%` }}
                        title={`${name}: ${value.toFixed(2)}%`}
                      >
                        {value > 8 ? `${name} ${value.toFixed(1)}%` : ''}
                      </div>
                    ))}
                  </div>
                </div>

                <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                  <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-4 overflow-auto">
                    <h4 className="text-sm font-semibold text-slate-200 mb-3">Top 5 Source IPs</h4>
                    <table className="w-full text-sm">
                      <thead className="text-slate-400">
                        <tr>
                          <th className="text-left py-2">IP</th>
                          <th className="text-right py-2">Packet Count</th>
                          <th className="text-right py-2">% Traffic</th>
                          <th className="text-right py-2">Suspicious</th>
                        </tr>
                      </thead>
                      <tbody>
                        {captureStats.topSrcIPs.slice(0, 5).map((row) => {
                          const suspicious = anomalies.some((a) => a.affectedIPs.includes(row.ip));
                          return (
                            <tr key={row.ip} className="border-t border-slate-800">
                              <td className="py-2 text-slate-200">{row.ip}</td>
                              <td className="py-2 text-right text-slate-200">{row.count}</td>
                              <td className="py-2 text-right text-slate-300">{((row.count / Math.max(captureStats.parsedPackets, 1)) * 100).toFixed(1)}%</td>
                              <td className="py-2 text-right">{suspicious ? <span className="text-red-300">Flagged</span> : <span className="text-emerald-300">No</span>}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>

                  <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-4 overflow-auto">
                    <h4 className="text-sm font-semibold text-slate-200 mb-3">Top 5 Destination IPs</h4>
                    <table className="w-full text-sm">
                      <thead className="text-slate-400">
                        <tr>
                          <th className="text-left py-2">IP</th>
                          <th className="text-right py-2">Packet Count</th>
                          <th className="text-right py-2">% Traffic</th>
                          <th className="text-right py-2">Suspicious</th>
                        </tr>
                      </thead>
                      <tbody>
                        {captureStats.topDstIPs.slice(0, 5).map((row) => {
                          const suspicious = anomalies.some((a) => a.affectedIPs.includes(row.ip));
                          return (
                            <tr key={row.ip} className="border-t border-slate-800">
                              <td className="py-2 text-slate-200">{row.ip}</td>
                              <td className="py-2 text-right text-slate-200">{row.count}</td>
                              <td className="py-2 text-right text-slate-300">{((row.count / Math.max(captureStats.parsedPackets, 1)) * 100).toFixed(1)}%</td>
                              <td className="py-2 text-right">{suspicious ? <span className="text-red-300">Flagged</span> : <span className="text-emerald-300">No</span>}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                  <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-4 overflow-auto">
                    <h4 className="text-sm font-semibold text-slate-200 mb-3">Top 10 Ports</h4>
                    <table className="w-full text-sm">
                      <thead className="text-slate-400">
                        <tr>
                          <th className="text-left py-2">Port</th>
                          <th className="text-left py-2">Service Name</th>
                          <th className="text-right py-2">Count</th>
                          <th className="text-right py-2">Risk</th>
                        </tr>
                      </thead>
                      <tbody>
                        {captureStats.topPorts.slice(0, 10).map((row) => {
                          const risk = [4444, 1337, 31337, 6666, 9999].includes(row.port) ? 'High' : row.port < 1024 ? 'Medium' : 'Low';
                          return (
                            <tr key={`${row.port}-${row.count}`} className="border-t border-slate-800">
                              <td className="py-2 text-slate-200">{row.port}</td>
                              <td className="py-2 text-slate-300">{row.service}</td>
                              <td className="py-2 text-right text-slate-200">{row.count}</td>
                              <td className="py-2 text-right">
                                <span className={`px-2 py-0.5 rounded text-xs border ${risk === 'High' ? 'bg-red-500/20 border-red-500/40 text-red-200' : risk === 'Medium' ? 'bg-yellow-500/20 border-yellow-500/40 text-yellow-200' : 'bg-blue-500/20 border-blue-500/40 text-blue-200'}`}>
                                  {risk}
                                </span>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>

                  <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-4">
                    <h4 className="text-sm font-semibold text-slate-200 mb-3">Packet Size Distribution</h4>
                    {protocolStats ? (
                      <div className="space-y-3">
                        {[
                          ['Small (<64)', protocolStats.packetSizeDistribution.small, 'bg-blue-500'],
                          ['Medium (64-1024)', protocolStats.packetSizeDistribution.medium, 'bg-purple-500'],
                          ['Large (>1024)', protocolStats.packetSizeDistribution.large, 'bg-red-500']
                        ].map(([label, value, color]) => (
                          <div key={label as string}>
                            <div className="flex justify-between text-xs text-slate-400 mb-1">
                              <span>{label}</span>
                              <span>{value}</span>
                            </div>
                            <div className="h-3 rounded bg-slate-800 overflow-hidden">
                              <div className={`${color} h-3`} style={{ width: `${(Number(value) / Math.max(captureStats.parsedPackets, 1)) * 100}%` }} />
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-slate-500">Statistics unavailable</p>
                    )}
                  </div>
                </div>
              </motion.div>
            )}

            {activeTab === 'inspector' && (
              <motion.div key="inspector" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-4">
                <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-4">
                  <div className="flex flex-wrap items-center gap-2 mb-3">
                    <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-700">
                      <Filter className="w-3.5 h-3.5 text-slate-400" />
                      <select value={filterProtocol} onChange={(e) => setFilterProtocol(e.target.value)} className="bg-transparent text-sm text-slate-200 outline-none">
                        {protocolOptions.map((option) => (
                          <option key={option} value={option} className="bg-slate-900">
                            {option}
                          </option>
                        ))}
                      </select>
                    </div>
                    <input
                      value={filterIP}
                      onChange={(e) => setFilterIP(e.target.value)}
                      placeholder="Filter by IP"
                      className="px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-950 text-sm text-slate-200"
                    />
                    <input
                      value={filterPort}
                      onChange={(e) => setFilterPort(e.target.value)}
                      placeholder="Port"
                      className="w-24 px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-950 text-sm text-slate-200"
                    />
                    <label className="inline-flex items-center gap-2 text-sm text-slate-300">
                      <input type="checkbox" checked={suspiciousOnly} onChange={(e) => setSuspiciousOnly(e.target.checked)} />
                      Suspicious only
                    </label>
                    <button onClick={exportPacketCsv} className="ml-auto inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/15 text-cyan-300 text-sm">
                      <Download className="w-4 h-4" />
                      Export Packet List
                    </button>
                  </div>

                  <div className="max-h-[420px] overflow-auto border border-slate-800 rounded-lg">
                    <table className="w-full text-sm">
                      <thead className="sticky top-0 bg-slate-950 text-slate-400">
                        <tr>
                          <th className="text-left px-3 py-2">#</th>
                          <th className="text-left px-3 py-2">Timestamp</th>
                          <th className="text-left px-3 py-2">Src IP:Port</th>
                          <th className="text-left px-3 py-2">Dst IP:Port</th>
                          <th className="text-left px-3 py-2">Protocol</th>
                          <th className="text-right px-3 py-2">Length</th>
                          <th className="text-left px-3 py-2">Flags</th>
                          <th className="text-left px-3 py-2">Service</th>
                          <th className="text-left px-3 py-2">Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredPackets.map((packet) => (
                          <tr
                            key={packet.index}
                            className={`border-t border-slate-900 cursor-pointer ${packet.isSuspicious ? 'bg-red-500/10 hover:bg-red-500/15' : 'hover:bg-slate-800/50'}`}
                            onClick={() => setSelectedPacket(packet)}
                          >
                            <td className="px-3 py-2 text-slate-300">{packet.index}</td>
                            <td className="px-3 py-2 text-slate-300">{new Date(packet.timestamp * 1000).toLocaleTimeString()}</td>
                            <td className="px-3 py-2 text-slate-200">{packet.srcIP || 'N/A'}{packet.srcPort ? `:${packet.srcPort}` : ''}</td>
                            <td className="px-3 py-2 text-slate-200">{packet.dstIP || 'N/A'}{packet.dstPort ? `:${packet.dstPort}` : ''}</td>
                            <td className="px-3 py-2 text-slate-300">{packet.protocol}</td>
                            <td className="px-3 py-2 text-right text-slate-300">{packet.length}</td>
                            <td className="px-3 py-2 text-slate-300">{packet.tcpFlags?.join(', ') || '-'}</td>
                            <td className="px-3 py-2 text-slate-300">{packet.service || '-'}</td>
                            <td className="px-3 py-2">
                              <span className={`px-2 py-0.5 rounded text-xs border ${packet.isSuspicious ? 'bg-red-500/20 border-red-500/40 text-red-200' : 'bg-emerald-500/20 border-emerald-500/40 text-emerald-200'}`}>
                                {packet.isSuspicious ? 'Suspicious' : 'Normal'}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {selectedPacket && (
                  <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-4">
                    <h4 className="text-sm font-semibold text-slate-200 mb-2">Packet Details #{selectedPacket.index}</h4>
                    <pre className="text-xs text-slate-300 whitespace-pre-wrap">
{JSON.stringify(selectedPacket, null, 2)}
                    </pre>
                  </div>
                )}
              </motion.div>
            )}

            {activeTab === 'anomalies' && (
              <motion.div key="anomalies" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                {anomalies.length === 0 ? (
                  <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-2xl p-6 text-emerald-200">No anomalies detected</div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {anomalies.map((anomaly, idx) => (
                      <div key={`${anomaly.type}-${idx}`} className={`rounded-2xl border p-4 ${severityClass[anomaly.severity] || severityClass.Medium}`}>
                        <div className="flex items-center justify-between mb-2">
                          <span className="px-2 py-0.5 rounded border border-white/30 text-xs uppercase">{anomaly.type}</span>
                          <span className="text-sm font-semibold">{anomaly.severity}</span>
                        </div>
                        <p className="text-sm mb-2">{anomaly.description}</p>
                        <p className="text-xs opacity-90">Affected IPs: {anomaly.affectedIPs.join(', ') || 'N/A'}</p>
                        <p className="text-xs opacity-90 mt-1">Packet Count: {anomaly.packetCount}</p>
                      </div>
                    ))}
                  </div>
                )}
              </motion.div>
            )}

            {activeTab === 'ai' && showAITab && (
              <motion.div key="ai" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-4">
                <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-4">
                  <h3 className="text-sm font-semibold text-slate-200 mb-3">Detected Attacks</h3>
                  {(aiResult?.detectedAttacks || []).length === 0 ? (
                    <p className="text-sm text-slate-500">No AI attack signatures were returned.</p>
                  ) : (
                    <div className="space-y-3">
                      {aiResult?.detectedAttacks.map((attack, idx) => (
                        <div key={`${attack.attackType}-${idx}`} className="border border-slate-700 rounded-lg p-3 bg-slate-950/40">
                          <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                            <span className="px-2 py-1 rounded border border-purple-500/40 bg-purple-500/15 text-purple-200 text-xs">{attack.attackType}</span>
                            <span className="text-xs text-slate-400">Confidence: {attack.confidence}%</span>
                          </div>
                          <div className="h-2 rounded bg-slate-800 overflow-hidden mb-2">
                            <div className="h-2 bg-purple-500" style={{ width: `${Math.max(0, Math.min(100, attack.confidence))}%` }} />
                          </div>
                          <p className="text-sm text-slate-300">{attack.description}</p>
                          <p className="text-xs text-slate-400 mt-1">Affected Hosts: {attack.affectedHosts?.join(', ') || 'N/A'}</p>
                          {attack.mitreTechnique && (
                            <a className="text-xs text-cyan-300 hover:underline mt-1 inline-block" href={`https://attack.mitre.org/search/?q=${encodeURIComponent(attack.mitreTechnique)}`} target="_blank" rel="noreferrer">
                              MITRE: {attack.mitreTechnique}
                            </a>
                          )}
                          <p className="text-xs text-slate-500 mt-1">Evidence: {attack.evidence}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-4 overflow-auto">
                  <h3 className="text-sm font-semibold text-slate-200 mb-3">Suspicious Flows</h3>
                  <table className="w-full text-sm">
                    <thead className="text-slate-400">
                      <tr>
                        <th className="text-left py-2">Src → Dst</th>
                        <th className="text-left py-2">Port</th>
                        <th className="text-left py-2">Protocol</th>
                        <th className="text-left py-2">Reason</th>
                        <th className="text-left py-2">Severity</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(aiResult?.suspiciousFlows || []).map((flow, idx) => (
                        <tr key={`${flow.srcIP}-${flow.dstIP}-${idx}`} className="border-t border-slate-800">
                          <td className="py-2 text-slate-200">{flow.srcIP} → {flow.dstIP}</td>
                          <td className="py-2 text-slate-300">{flow.port}</td>
                          <td className="py-2 text-slate-300">{flow.protocol}</td>
                          <td className="py-2 text-slate-300">{flow.reason}</td>
                          <td className="py-2">
                            <span className={`px-2 py-0.5 rounded text-xs border ${severityClass[flow.severity] || severityClass.Medium}`}>{flow.severity}</span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                  <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-4">
                    <h3 className="text-sm font-semibold text-slate-200 mb-2">C2 Indicators</h3>
                    <ul className="text-sm text-slate-300 space-y-1">
                      {(aiResult?.c2Indicators || []).map((item, idx) => (
                        <li key={`${item}-${idx}`}>• {item}</li>
                      ))}
                      {(aiResult?.c2Indicators || []).length === 0 && <li className="text-slate-500">No C2 indicators returned.</li>}
                    </ul>
                  </div>
                  <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-4">
                    <div className="flex items-center justify-between mb-2">
                      <h3 className="text-sm font-semibold text-slate-200">IOC List</h3>
                      <button onClick={copyAllIocs} className="inline-flex items-center gap-1 px-2 py-1 rounded border border-slate-600 text-xs text-slate-200">
                        <Copy className="w-3 h-3" />
                        Copy all
                      </button>
                    </div>
                    <ul className="text-sm text-slate-300 space-y-1 max-h-36 overflow-auto">
                      {(aiResult?.iocs || []).map((ioc, idx) => (
                        <li key={`${ioc}-${idx}`} className="font-mono text-xs">{ioc}</li>
                      ))}
                      {(aiResult?.iocs || []).length === 0 && <li className="text-slate-500">No IOCs generated.</li>}
                    </ul>
                  </div>
                </div>

                <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-4">
                  <h3 className="text-sm font-semibold text-slate-200 mb-2">Recommendations</h3>
                  <ol className="text-sm text-slate-300 space-y-1 list-decimal pl-5">
                    {(aiResult?.recommendations || []).map((rec, idx) => (
                      <li key={`${rec}-${idx}`}>{rec}</li>
                    ))}
                    {(aiResult?.recommendations || []).length === 0 && <li className="text-slate-500">No recommendations returned.</li>}
                  </ol>
                </div>
              </motion.div>
            )}

            {activeTab === 'conversations' && (
              <motion.div key="conversations" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="bg-slate-900/45 border border-white/10 rounded-2xl p-4 overflow-auto">
                <table className="w-full text-sm min-w-[860px]">
                  <thead className="text-slate-400">
                    <tr>
                      {[
                        ['srcIP', 'Src IP'],
                        ['dstIP', 'Dst IP'],
                        ['protocol', 'Protocol'],
                        ['packets', 'Packets'],
                        ['bytes', 'Est. Bytes'],
                        ['duration', 'Duration'],
                        ['flags', 'Flags'],
                        ['risk', 'Risk']
                      ].map(([key, label]) => (
                        <th key={key} className="text-left py-2 cursor-pointer" onClick={() => toggleConversationSort(key as keyof ConversationRow)}>
                          {label}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {sortedConversations.map((row, idx) => (
                      <tr key={`${row.srcIP}-${row.dstIP}-${idx}`} className={`border-t border-slate-800 ${row.risk === 'High' ? 'bg-red-500/8' : ''}`}>
                        <td className="py-2 text-slate-200">{row.srcIP}</td>
                        <td className="py-2 text-slate-200">{row.dstIP}</td>
                        <td className="py-2 text-slate-300">{row.protocol}</td>
                        <td className="py-2 text-slate-300">{row.packets}</td>
                        <td className="py-2 text-slate-300">{bytesToHuman(row.bytes)}</td>
                        <td className="py-2 text-slate-300">{row.duration}s</td>
                        <td className="py-2 text-slate-300">{row.flags.join(', ') || '-'}</td>
                        <td className="py-2">
                          <span className={`px-2 py-0.5 rounded text-xs border ${row.risk === 'High' ? 'bg-red-500/20 border-red-500/40 text-red-200' : 'bg-emerald-500/20 border-emerald-500/40 text-emerald-200'}`}>
                            {row.risk}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </motion.div>
            )}
          </AnimatePresence>

          <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-4">
            <div className="flex flex-wrap items-center gap-2">
              <button onClick={exportPdf} className="inline-flex items-center gap-2 px-3 py-2 rounded-lg border border-purple-500/40 bg-purple-500/15 text-purple-200 text-sm">
                <FileDown className="w-4 h-4" />
                Export Full Report PDF
              </button>
              <button onClick={exportIOCList} className="inline-flex items-center gap-2 px-3 py-2 rounded-lg border border-slate-600 bg-slate-800/60 text-slate-200 text-sm">
                <Download className="w-4 h-4" />
                Export IOC List
              </button>
              <button onClick={sendToForensicsTimeline} className="inline-flex items-center gap-2 px-3 py-2 rounded-lg border border-cyan-500/40 bg-cyan-500/15 text-cyan-200 text-sm">
                <Target className="w-4 h-4" />
                Send to Forensics Timeline
              </button>
              <button onClick={mapToAttack} className="inline-flex items-center gap-2 px-3 py-2 rounded-lg border border-emerald-500/40 bg-emerald-500/15 text-emerald-200 text-sm">
                <PackageSearch className="w-4 h-4" />
                Map to ATT&amp;CK
              </button>
            </div>
          </div>
        </motion.div>
      )}
    </div>
  );
};

export default PacketCaptureAnalyzer;
