import Dexie, { Table } from 'dexie';
import { ScanType, SecurityAnalysis, DarkWebScanResult, PostureHistoryEntry, ForensicsEvent } from '../types/types';

export interface ScanHistory {
  id?: number;
  timestamp: Date;
  scanType: ScanType;
  rawData: string;
  analysisResult: SecurityAnalysis;
}

export interface NetworkDevice {
  id?: number;
  ip: string;
  mac: string;
  name: string;
  vendor: string;
  firstSeen: Date;
  lastSeen: Date;
  status: 'online' | 'offline';
  isRogue: boolean;
}

export interface AppSettings {
  id: string;
  value: any;
  timestamp: number;
}

export interface EDRTelemetry {
  id?: number;
  endpointId: string;
  hostname: string;
  os: string;
  health: 'Healthy' | 'Warning' | 'Critical';
  lastSeen: number;
  cpu: number;
  memory: number;
  processes: { pid: number; name: string; user: string; cpu: number; mem: number; path: string; status: string }[];
  network: { proto: string; local: string; remote: string; state: string; pid: number }[];
  alerts: { id: string; severity: string; message: string; timestamp: number }[];
}

export interface DarkWebScanSummary {
  id?: number;
  query: string;
  type: 'email' | 'domain' | 'ip' | 'username';
  riskScore: number;
  riskLevel: 'Critical' | 'High' | 'Medium' | 'Low' | 'Clean';
  breachCount: number;
  timestamp: string;
}

export class SecurAIDatabase extends Dexie {
  scanHistory!: Table<ScanHistory>;
  knownDevices!: Table<NetworkDevice>;
  settings!: Table<AppSettings, string>;
  edrTelemetry!: Table<EDRTelemetry>;
  darkwebScans!: Table<DarkWebScanSummary>;
  postureHistory!: Table<PostureHistoryEntry>;
  forensicsEvents!: Table<ForensicsEvent, string>;

  constructor() {
    super('SecurAIDatabase');
    this.version(1).stores({
      scanHistory: '++id, timestamp, scanType'
    });
    this.version(2).stores({
      scanHistory: '++id, timestamp, scanType',
      knownDevices: '++id, mac, ip, lastSeen'
    });
    this.version(3).stores({
      scanHistory: '++id, timestamp, scanType',
      knownDevices: '++id, mac, ip, lastSeen',
      settings: 'id, timestamp'
    });
    this.version(4).stores({
      scanHistory: '++id, timestamp, scanType',
      knownDevices: '++id, mac, ip, lastSeen',
      settings: 'id, timestamp',
      edrTelemetry: '++id, endpointId, lastSeen'
    });
    this.version(5).stores({
      scanHistory: '++id, timestamp, scanType',
      knownDevices: '++id, mac, ip, lastSeen',
      settings: 'id, timestamp',
      edrTelemetry: '++id, endpointId, lastSeen',
      darkwebScans: '++id, timestamp, type, riskScore, riskLevel',
      postureHistory: '++id, timestamp, score, grade'
    });
    this.version(6).stores({
      scanHistory: '++id, timestamp, scanType',
      knownDevices: '++id, mac, ip, lastSeen',
      settings: 'id, timestamp',
      edrTelemetry: '++id, endpointId, lastSeen',
      darkwebScans: '++id, timestamp, type, riskScore, riskLevel',
      postureHistory: '++id, timestamp, score, grade',
      forensicsEvents: 'id, timestamp, eventType, sourceModule, severity, attackPhase, isBookmarked'
    });
  }
}

export const db = new SecurAIDatabase();

// Helper functions
export const saveScanToHistory = async (
  scanType: ScanType,
  rawData: string,
  analysisResult: SecurityAnalysis
): Promise<number> => {
  return await db.scanHistory.add({
    timestamp: new Date(),
    scanType,
    rawData,
    analysisResult
  });
};

export const getAllScans = async (): Promise<ScanHistory[]> => {
  return await db.scanHistory.orderBy('timestamp').reverse().toArray();
};

export const getScansByType = async (scanType: ScanType): Promise<ScanHistory[]> => {
  return await db.scanHistory
    .where('scanType')
    .equals(scanType)
    .reverse()
    .sortBy('timestamp');
};

export const deleteScan = async (id: number): Promise<void> => {
  await db.scanHistory.delete(id);
};

export const clearAllHistory = async (): Promise<void> => {
  await db.scanHistory.clear();
};

// Network Device Management
export const saveDevice = async (device: Omit<NetworkDevice, 'id'>): Promise<number> => {
  // Check if device already exists by MAC address
  const existing = await db.knownDevices.where('mac').equals(device.mac).first();
  
  if (existing) {
    // Update existing device
    await db.knownDevices.update(existing.id!, {
      ...device,
      lastSeen: new Date()
    });
    return existing.id!;
  } else {
    // Add new device
    return await db.knownDevices.add({
      ...device,
      firstSeen: new Date(),
      lastSeen: new Date()
    });
  }
};

export const getAllDevices = async (): Promise<NetworkDevice[]> => {
  return await db.knownDevices.orderBy('lastSeen').reverse().toArray();
};

export const markDeviceAsKnown = async (mac: string): Promise<void> => {
  const device = await db.knownDevices.where('mac').equals(mac).first();
  if (device) {
    await db.knownDevices.update(device.id!, { isRogue: false });
  }
};

export const deleteDevice = async (id: number): Promise<void> => {
  await db.knownDevices.delete(id);
};

export const clearAllDevices = async (): Promise<void> => {
  await db.knownDevices.clear();
};

// Settings Management
export const saveSetting = async (id: string, value: any): Promise<void> => {
  await db.settings.put({
    id,
    value,
    timestamp: Date.now()
  });
};

export const getSetting = async (id: string): Promise<AppSettings | undefined> => {
  return await db.settings.get(id);
};

export const deleteSetting = async (id: string): Promise<void> => {
  await db.settings.delete(id);
};

export const clearExpiredSettings = async (expiryMs: number): Promise<void> => {
  const now = Date.now();
  const expired = await db.settings.filter(s => (now - s.timestamp) > expiryMs).toArray();
  await Promise.all(expired.map(s => db.settings.delete(s.id)));
};

// EDR Management
export const saveEDRTelemetry = async (telemetry: Omit<EDRTelemetry, 'id'>): Promise<number> => {
  const existing = await db.edrTelemetry.where('endpointId').equals(telemetry.endpointId).first();
  if (existing) {
    await db.edrTelemetry.update(existing.id!, telemetry);
    return existing.id!;
  }
  return await db.edrTelemetry.add(telemetry);
};

export const getEDRTelemetries = async (): Promise<EDRTelemetry[]> => {
  return await db.edrTelemetry.orderBy('lastSeen').reverse().toArray();
};

// Dark Web Monitor persistence
export const saveDarkWebScan = async (scan: DarkWebScanResult): Promise<number> => {
  const storageKey = `darkweb_scan_${scan.timestamp}`;
  await saveSetting(storageKey, scan);

  return await db.darkwebScans.add({
    query: scan.query,
    type: scan.type,
    riskScore: scan.aiAnalysis?.riskScore ?? 0,
    riskLevel: scan.aiAnalysis?.riskLevel ?? 'Clean',
    breachCount: scan.breaches.length,
    timestamp: scan.timestamp
  });
};

export const getDarkWebScans = async (): Promise<DarkWebScanSummary[]> => {
  return await db.darkwebScans.orderBy('timestamp').reverse().toArray();
};

export const getDarkWebScanResultByTimestamp = async (timestamp: string): Promise<DarkWebScanResult | null> => {
  const storageKey = `darkweb_scan_${timestamp}`;
  const saved = await getSetting(storageKey);
  return (saved?.value as DarkWebScanResult) || null;
};

export const clearDarkWebScans = async (): Promise<void> => {
  await db.darkwebScans.clear();
  const darkWebSettings = await db.settings.where('id').startsWith('darkweb_scan_').toArray();
  await Promise.all(darkWebSettings.map((entry) => db.settings.delete(entry.id)));
};

// Security Posture persistence
export const savePostureHistory = async (entry: PostureHistoryEntry): Promise<number> => {
  return await db.postureHistory.add(entry);
};

export const getPostureHistory = async (): Promise<PostureHistoryEntry[]> => {
  return await db.postureHistory.orderBy('timestamp').toArray();
};

// Forensics Timeline persistence
export const saveForensicsEvent = async (event: ForensicsEvent): Promise<void> => {
  await db.forensicsEvents.put(event);
};

export const getForensicsEvents = async (): Promise<ForensicsEvent[]> => {
  return await db.forensicsEvents.orderBy('timestamp').reverse().toArray();
};

export const deleteForensicsEvent = async (id: string): Promise<void> => {
  await db.forensicsEvents.delete(id);
};

export const clearForensicsEvents = async (): Promise<void> => {
  await db.forensicsEvents.clear();
};
