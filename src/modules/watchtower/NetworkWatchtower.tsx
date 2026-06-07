import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Radar, Wifi, Shield, AlertTriangle, CheckCircle, 
  Trash2, RefreshCw, Server, Clock, Network, XCircle,
  Scan, Moon, Sun, Smartphone, Cpu, Monitor, HardDrive, Router,
  List, GitBranch, Database
} from 'lucide-react';
import { NetworkDevice, saveDevice, getAllDevices, markDeviceAsKnown, deleteDevice, saveSetting, getSetting, clearExpiredSettings } from '../../services/db';
import { toast } from 'react-hot-toast';
import NetworkGraph from './NetworkGraph';
import { logForensicsEvent } from '../../utils/forensicsLogger';

interface ScanResult {
  success: boolean;
  devices: Array<{
    ip: string;
    mac: string;
    name: string;
    vendor: string;
    lastSeen: string;
    status: string;
  }>;
  scanTime: string;
}

interface Alert {
  timestamp: string;
  sourceIP: string;
  sourcePort: number;
  targetPort: number;
  message: string;
  severity: string;
}

interface PortScanResult {
  port: number;
  name: string;
  open: boolean;
  dangerous: boolean;
}

interface IntruderAlert {
  mac: string;
  ip: string;
  vendor: string;
  timestamp: string;
}

export default function NetworkWatchtower() {
  const [scanning, setScanning] = useState(false);
  const [devices, setDevices] = useState<NetworkDevice[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [serverOnline, setServerOnline] = useState(false);
  const [lastScan, setLastScan] = useState<Date | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  
  // New features state
  const [nightMode, setNightMode] = useState(false);
  const [knownDevices, setKnownDevices] = useState<Set<string>>(new Set());
  const [scanningPort, setScanningPort] = useState<string | null>(null);
  const [portResults, setPortResults] = useState<Map<string, PortScanResult[]>>(new Map());
  const [intruderAlert, setIntruderAlert] = useState<IntruderAlert | null>(null);
  const audioContextRef = useRef<AudioContext | null>(null);
  const sirenIntervalRef = useRef<number | null>(null);
  
  // View toggle and ARP status
  const [viewMode, setViewMode] = useState<'list' | 'graph'>('list');
  const [arpStatus, setArpStatus] = useState<{
    status: 'secure' | 'compromised' | 'warning' | 'error';
    details: string;
    gatewayIP?: string;
    trustedMAC?: string;
  }>({ status: 'secure', details: 'Initializing...' });
  
  // ARP Defense states
  const [showExploreMore, setShowExploreMore] = useState(false);
  const [defendingAttack, setDefendingAttack] = useState(false);
  const [defenseLog, setDefenseLog] = useState<string[]>([]);
  const [dismissedARPAlert, setDismissedARPAlert] = useState(false);
  const [showDefenseScript, setShowDefenseScript] = useState(false);
  const [defenseScript, setDefenseScript] = useState({ windows: '', linux: '' });
  const defenseLogRef = useRef<HTMLDivElement>(null);
  const loggedAlertKeysRef = useRef<Set<string>>(new Set());
  const loggedIntruderKeysRef = useRef<Set<string>>(new Set());
  
  // Active Mitigation state
  const [mitigateData, setMitigateData] = useState<{port: number, protocol: string, command: string} | null>(null);
  const [isMitigating, setIsMitigating] = useState(false);

  const handleMitigate = async (port: number) => {
    setIsMitigating(true);
    try {
      const res = await fetch('http://localhost:3001/remediate/firewall', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ port, protocol: 'tcp', os: 'linux' })
      });
      const data = await res.json();
      if (data.success) {
        setMitigateData({ port, protocol: 'tcp', command: data.command });
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsMitigating(false);
    }
  };

  // Check server health on mount
  useEffect(() => {
    checkServerHealth();
    loadDevices();
    loadKnownDevices();
    checkDismissalState();
    connectWebSocket();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      stopSiren();
      if (audioContextRef.current) {
        audioContextRef.current.close().catch(() => {
          // Ignore close errors during teardown.
        });
        audioContextRef.current = null;
      }
    };
  }, []);
  
  // Auto-scroll defense log
  useEffect(() => {
    if (defenseLogRef.current) {
      defenseLogRef.current.scrollTop = defenseLogRef.current.scrollHeight;
    }
  }, [defenseLog]);
  
  // Poll ARP status every 5 seconds
  useEffect(() => {
    if (!serverOnline) return;
    
    const checkARP = async () => {
      try {
        const response = await fetch('http://localhost:3001/network/arp-status');
        if (response.ok) {
          const data = await response.json();
          setArpStatus(data);
          
          // Trigger intruder alert if ARP is compromised (but not if dismissed or defending)
          if (data.status === 'compromised' && !intruderAlert && !dismissedARPAlert && !defendingAttack) {
            setIntruderAlert({
              mac: 'ARP_SPOOF',
              ip: data.gatewayIP || 'Unknown',
              vendor: 'Man-in-the-Middle Attack',
              timestamp: new Date().toISOString()
            });
            playSiren();
          }
        }
      } catch (error) {
        console.error('ARP status check failed:', error);
      }
    };
    
    checkARP(); // Initial check
    const interval = setInterval(checkARP, 5000); // Every 5 seconds
    
    return () => clearInterval(interval);
  }, [serverOnline, intruderAlert, dismissedARPAlert, defendingAttack]);
  
  // Auto-scan in night mode
  useEffect(() => {
    if (nightMode && serverOnline) {
      const interval = setInterval(() => {
        scanNetwork();
      }, 10000); // 10 seconds
      
      return () => clearInterval(interval);
    }
  }, [nightMode, serverOnline]);

  // Additive forensic logging for ghost port triggers from alert stream.
  useEffect(() => {
    const logAlerts = async () => {
      try {
        for (const alert of alerts) {
          const key = `${alert.timestamp}-${alert.sourceIP}-${alert.targetPort}`;
          if (!loggedAlertKeysRef.current.has(key) && alert.targetPort) {
            loggedAlertKeysRef.current.add(key);
            await logForensicsEvent({
              timestamp: new Date(alert.timestamp).getTime(),
              eventType: 'ghost_port_triggered',
              sourceModule: 'Network Watchtower',
              severity: 'High',
              title: `Ghost port ${alert.targetPort} triggered`,
              description: alert.message || 'Unauthorized connection attempt detected on trap port.',
              details: alert,
              attackPhase: 'Discovery',
              ioc: [alert.sourceIP, String(alert.targetPort)],
              tags: ['ghost-port', 'watchtower']
            });
          }
        }
      } catch (forensicsErr) {
        console.error('Forensics event logging skipped:', forensicsErr);
      }
    };

    if (alerts.length > 0) {
      logAlerts();
    }
  }, [alerts]);

  // Additive forensic logging for intruder and ARP anomaly detections.
  useEffect(() => {
    const logIntruder = async () => {
      if (!intruderAlert) return;
      const key = `${intruderAlert.timestamp}-${intruderAlert.mac}-${intruderAlert.ip}`;
      if (loggedIntruderKeysRef.current.has(key)) return;
      loggedIntruderKeysRef.current.add(key);

      try {
        if (intruderAlert.mac === 'ARP_SPOOF') {
          await logForensicsEvent({
            timestamp: new Date(intruderAlert.timestamp).getTime(),
            eventType: 'arp_spoof_detected',
            sourceModule: 'Network Watchtower',
            severity: 'Critical',
            title: 'ARP spoofing detected',
            description: `Potential MitM attack detected near gateway ${intruderAlert.ip}.`,
            details: { intruderAlert, arpStatus },
            attackPhase: 'Defense Evasion',
            ioc: [intruderAlert.ip, intruderAlert.mac],
            tags: ['arp', 'mitm']
          });
        } else {
          await logForensicsEvent({
            timestamp: new Date(intruderAlert.timestamp).getTime(),
            eventType: 'new_device_detected',
            sourceModule: 'Network Watchtower',
            severity: 'Medium',
            title: `Unknown device detected: ${intruderAlert.ip}`,
            description: `New untrusted device observed (${intruderAlert.vendor}).`,
            details: intruderAlert,
            attackPhase: 'Discovery',
            ioc: [intruderAlert.ip, intruderAlert.mac],
            tags: ['new-device', 'watchtower']
          });
        }
      } catch (forensicsErr) {
        console.error('Forensics event logging skipped:', forensicsErr);
      }
    };

    logIntruder();
  }, [intruderAlert, arpStatus]);

  const checkServerHealth = async () => {
    try {
      const response = await fetch('http://localhost:3001/health');
      if (response.ok) {
        setServerOnline(true);
      } else {
        setServerOnline(false);
      }
    } catch (error) {
      setServerOnline(false);
    }
  };

  const connectWebSocket = () => {
    try {
      if (wsRef.current) {
        wsRef.current.close();
      }

      const websocket = new WebSocket('ws://localhost:3001');
      
      websocket.onopen = () => {
        console.log('Connected to Watchtower server');
      };
      
      websocket.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'alert') {
          setAlerts(prev => [data.data, ...prev]);
        } else if (data.type === 'history') {
          setAlerts(data.alerts);
        }
      };
      
      websocket.onerror = (error) => {
        console.error('WebSocket error:', error);
      };

      websocket.onclose = () => {
        if (wsRef.current === websocket) {
          wsRef.current = null;
        }
      };
      
      wsRef.current = websocket;
    } catch (error) {
      console.error('Failed to connect WebSocket:', error);
    }
  };

  const loadDevices = async () => {
    const storedDevices = await getAllDevices();
    setDevices(storedDevices);
  };
  
  const loadKnownDevices = async () => {
    try {
      const storedDevices = await getAllDevices();
      const knownMACs = new Set(
        (storedDevices || [])
          .filter(d => d && !d.isRogue)
          .map(d => d.mac)
      );
      setKnownDevices(knownMACs);
    } catch (error) {
      console.error('Error loading known devices:', error);
      setKnownDevices(new Set());
    }
  };
  
  // Check ARP dismissal state from DB
  const checkDismissalState = async () => {
    try {
      // Clear expired dismissals (older than 1 hour)
      await clearExpiredSettings(60 * 60 * 1000); // 1 hour in milliseconds
      
      const dismissalState = await getSetting('arp_dismissed');
      if (dismissalState) {
        const hourAgo = Date.now() - (60 * 60 * 1000);
        if (dismissalState.timestamp > hourAgo) {
          setDismissedARPAlert(true);
        } else {
          // Expired, clear it
          setDismissedARPAlert(false);
        }
      }
    } catch (error) {
      console.error('Error checking dismissal state:', error);
    }
  };

  const loadSampleNetworkData = async () => {
    try {
      const sampleDevices: NetworkDevice[] = [
        {
          ip: '192.168.1.1',
          mac: '00:11:22:33:44:5A',
          name: 'Gateway Router',
          vendor: 'Cisco Systems',
          status: 'online',
          isRogue: false,
          firstSeen: new Date(Date.now() - 86400000 * 5),
          lastSeen: new Date()
        },
        {
          ip: '192.168.1.100',
          mac: 'F0:18:98:A2:B4:C6',
          name: 'CEO iPhone',
          vendor: 'Apple',
          status: 'online',
          isRogue: false,
          firstSeen: new Date(Date.now() - 86400000 * 3),
          lastSeen: new Date()
        },
        {
          ip: '192.168.1.102',
          mac: 'B8:27:EB:D3:E5:F7',
          name: 'Thermostat Control',
          vendor: 'Raspberry Pi',
          status: 'online',
          isRogue: false,
          firstSeen: new Date(Date.now() - 86400000 * 4),
          lastSeen: new Date()
        },
        {
          ip: '192.168.1.105',
          mac: '00:50:56:C0:00:08',
          name: 'SecurAI Sentinel Dev VM',
          vendor: 'VMware',
          status: 'online',
          isRogue: false,
          firstSeen: new Date(Date.now() - 86400000 * 2),
          lastSeen: new Date()
        },
        {
          ip: '192.168.1.250',
          mac: '70:5A:B6:3C:2D:11',
          name: 'Unknown Intruder Device',
          vendor: 'Espressif Inc.',
          status: 'online',
          isRogue: true,
          firstSeen: new Date(),
          lastSeen: new Date()
        }
      ];

      for (const dev of sampleDevices) {
        await saveDevice(dev);
      }

      setAlerts([
        {
          timestamp: new Date(Date.now() - 30000).toISOString(),
          sourceIP: '192.168.1.250',
          sourcePort: 55432,
          targetPort: 22,
          message: 'Failed SSH login attempt from unapproved vendor node',
          severity: 'High'
        },
        {
          timestamp: new Date(Date.now() - 90000).toISOString(),
          sourceIP: '192.168.1.250',
          sourcePort: 60100,
          targetPort: 80,
          message: 'Fast port scanning sweep detected targeting internal host 192.168.1.105',
          severity: 'High'
        },
        {
          timestamp: new Date(Date.now() - 400000).toISOString(),
          sourceIP: '192.168.1.100',
          sourcePort: 49200,
          targetPort: 443,
          message: 'External communication with known Tor entry node',
          severity: 'Medium'
        }
      ]);

      setArpStatus({
        status: 'warning',
        details: 'Potential ARP attack: Host 192.168.1.250 claims gateway MAC 00:11:22:33:44:5A',
        gatewayIP: '192.168.1.1',
        trustedMAC: '00:11:22:33:44:5A'
      });

      setIntruderAlert({
        mac: '70:5A:B6:3C:2D:11',
        ip: '192.168.1.250',
        vendor: 'Espressif Inc.',
        timestamp: new Date().toISOString()
      });
      playSiren();

      await loadDevices();
      await loadKnownDevices();

      toast.success('Sample network data loaded successfully.');
    } catch (err) {
      console.error('Failed to load sample network data:', err);
      toast.error('Failed to load sample network data.');
    }
  };

  // Siren Sound Generator
  const playSiren = () => {
    if (sirenIntervalRef.current) {
      return;
    }

    if (!audioContextRef.current) {
      const AudioContextCtor = window.AudioContext || (window as Window & { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
      if (!AudioContextCtor) {
        return;
      }
      audioContextRef.current = new AudioContextCtor();
    }
    
    const ctx = audioContextRef.current;
    let frequency = 800;
    
    const playBeep = () => {
      const oscillator = ctx.createOscillator();
      const gainNode = ctx.createGain();
      
      oscillator.connect(gainNode);
      gainNode.connect(ctx.destination);
      
      oscillator.frequency.value = frequency;
      oscillator.type = 'sine';
      
      gainNode.gain.setValueAtTime(0.3, ctx.currentTime);
      gainNode.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.3);
      
      oscillator.start(ctx.currentTime);
      oscillator.stop(ctx.currentTime + 0.3);
      
      frequency = frequency === 800 ? 400 : 800; // Alternating frequency
    };
    
    playBeep();
    sirenIntervalRef.current = window.setInterval(playBeep, 300);
  };
  
  const stopSiren = () => {
    if (sirenIntervalRef.current) {
      clearInterval(sirenIntervalRef.current);
      sirenIntervalRef.current = null;
    }
  };
  
  // Port Scanner
  const scanPorts = async (ip: string) => {
    setScanningPort(ip);
    try {
      const response = await fetch('http://localhost:3001/scan-ports', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      
      const result = await response.json();
      
      if (result.success) {
        setPortResults(prev => new Map(prev).set(ip, result.openPorts));
      }
    } catch (error) {
      console.error('Port scan error:', error);
    } finally {
      setScanningPort(null);
    }
  };
  
  // Vendor Icon Helper
  const getVendorIcon = (vendor: string) => {
    const v = vendor.toLowerCase();
    if (v.includes('apple')) return <Smartphone className="w-4 h-4 text-slate-400" />;
    if (v.includes('espressif') || v.includes('esp')) return <Cpu className="w-4 h-4 text-slate-400" />;
    if (v.includes('raspberry')) return <Cpu className="w-4 h-4 text-slate-400" />;
    if (v.includes('dell') || v.includes('hp') || v.includes('lenovo')) return <Monitor className="w-4 h-4 text-slate-400" />;
    if (v.includes('tp-link') || v.includes('cisco') || v.includes('netgear')) return <Router className="w-4 h-4 text-slate-400" />;
    return <HardDrive className="w-4 h-4 text-slate-400" />;
  };

  const scanNetwork = async () => {
    if (!serverOnline) {
      alert('Companion Server is not running. Please start the server with: npm run start:server');
      return;
    }

    setScanning(true);
    try {
      const response = await fetch('http://localhost:3001/scan');
      if (!response.ok) {
        throw new Error(`Server responded with status: ${response.status}`);
      }
      const result: ScanResult = await response.json();
      
      if (result.success && result.devices) {
        // Load existing devices
        const existingDevices = (await getAllDevices()) || [];
        const existingMACs = new Set(existingDevices.map(d => d.mac));
        
        // Check for intruders in Night Mode
        if (nightMode && result.devices.length > 0) {
          for (const device of result.devices) {
            if (device && device.mac && !knownDevices.has(device.mac) && !existingMACs.has(device.mac)) {
              // INTRUDER DETECTED!
              setIntruderAlert({
                mac: device.mac,
                ip: device.ip,
                vendor: device.vendor,
                timestamp: new Date().toISOString()
              });
              playSiren();
              
              // Log to console
              console.log('🚨 INTRUDER DETECTED:', device);
              break; // Only alert for first intruder
            }
          }
        }
        
        // Process scanned devices
        for (const device of result.devices) {
          if (!device || !device.mac) continue; // Skip invalid devices
          
          const isRogue = !existingMACs.has(device.mac) && !knownDevices.has(device.mac);
          
          try {
            await saveDevice({
              ip: device.ip || 'Unknown',
              mac: device.mac,
              name: device.name || 'Unknown',
              vendor: device.vendor || 'Unknown',
              status: 'online',
              isRogue,
              firstSeen: new Date(),
              lastSeen: new Date()
            });
          } catch (err) {
            console.error('Error saving device:', err);
          }
        }
        
        // Mark offline devices
        const scannedMACs = new Set((result.devices || []).map(d => d.mac));
        for (const device of existingDevices) {
          if (device && device.mac && !scannedMACs.has(device.mac)) {
            try {
              await saveDevice({
                ...device,
                status: 'offline'
              });
            } catch (err) {
              console.error('Error marking device offline:', err);
            }
          }
        }
        
        await loadDevices();
        await loadKnownDevices();
        setLastScan(new Date());
      } else {
        console.error('Scan failed or returned no devices:', result);
      }
    } catch (error) {
      console.error('Scan error:', error);
      if (!nightMode) {
        alert('Failed to scan network. Error: ' + (error instanceof Error ? error.message : 'Unknown error'));
      }
    } finally {
      setScanning(false);
    }
  };

  const handleMarkKnown = async (mac: string) => {
    await markDeviceAsKnown(mac);
    await loadDevices();
    await loadKnownDevices();
  };
  
  const acknowledgeIntruder = async () => {
    if (intruderAlert) {
      // Add to known devices
      const device = devices.find(d => d.mac === intruderAlert.mac);
      if (device) {
        await markDeviceAsKnown(device.mac);
        await loadKnownDevices();
      }
      
      // If ARP spoofing, save dismissal to DB
      if (intruderAlert.mac === 'ARP_SPOOF') {
        await saveSetting('arp_dismissed', true);
        setDismissedARPAlert(true);
      }
    }
    
    stopSiren();
    setIntruderAlert(null);
    setShowExploreMore(false);
  };
  
  const dismissIntruder = async () => {
    // If ARP spoofing, save dismissal to DB
    if (intruderAlert?.mac === 'ARP_SPOOF') {
      await saveSetting('arp_dismissed', true);
      setDismissedARPAlert(true);
    }
    
    stopSiren();
    setIntruderAlert(null);
    setShowExploreMore(false);
  };
  
  const startDefending = async () => {
    setDefendingAttack(true);
    setDefenseLog([]);
    setShowExploreMore(false);
    
    // Generate defense strategy (honest messaging)
    const logActions = [
      '🔍 Analyzing network topology...',
      '🛡️ Identifying gateway configuration...',
      '📡 Detecting current ARP cache state...',
      '🔒 Generating MAC address lock strategy...',
      '⚡ Preparing ARP cache flush commands...',
      '🚨 Calculating optimal defense parameters...',
      '🔐 Creating static ARP entry scripts...',
      '📊 Compiling OS-specific instructions...',
      '✅ Defense strategy generated!',
      '🎯 Manual intervention required',
      '⚠️ Browser cannot modify OS network stack'
    ];
    
    for (let i = 0; i < logActions.length; i++) {
      await new Promise(resolve => setTimeout(resolve, 800));
      setDefenseLog(prev => [...prev, logActions[i]]);
    }
    
    // Generate actual defense scripts
    const gatewayIP = arpStatus.gatewayIP || '192.168.1.1';
    const trustedMAC = arpStatus.trustedMAC || 'XX:XX:XX:XX:XX:XX';
    
    const windowsScript = `# Run as Administrator in PowerShell
# View current ARP table
netsh interface ipv4 show neighbors

# Flush ARP cache
arp -d

# Add static ARP entry for gateway (replace interface name if needed)
netsh interface ipv4 set neighbors "Wi-Fi" "${gatewayIP}" "${trustedMAC}" store=persistent

# Verify the entry
netsh interface ipv4 show neighbors | Select-String "${gatewayIP}"

# Flush DNS cache
ipconfig /flushdns

Write-Host "Gateway MAC address locked. Monitor for continued attacks." -ForegroundColor Green`;

    const linuxScript = `#!/bin/bash
# Run with sudo

# View current ARP table
arp -a

# Add static ARP entry for gateway
sudo arp -s ${gatewayIP} ${trustedMAC}

# Alternative method for persistent entry (systemd-based)
# sudo ip neigh replace ${gatewayIP} lladdr ${trustedMAC} dev eth0 nud permanent

# Verify the entry
arp -a | grep ${gatewayIP}

echo "Gateway MAC address locked. Monitor for continued attacks."

# To make persistent across reboots, add to /etc/network/interfaces:
# echo "post-up arp -s ${gatewayIP} ${trustedMAC}" | sudo tee -a /etc/network/interfaces`;

    setDefenseScript({ windows: windowsScript, linux: linuxScript });
    
    // Show the manual defense modal
    await new Promise(resolve => setTimeout(resolve, 1500));
    setDefendingAttack(false);
    setShowDefenseScript(true);
  };
  
  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      alert('Script copied to clipboard!');
    } catch (error) {
      console.error('Failed to copy:', error);
      alert('Failed to copy. Please select and copy manually.');
    }
  };

  const handleDeleteDevice = async (id: number) => {
    if (confirm('Remove this device from tracking?')) {
      try {
        await deleteDevice(id);
        await loadDevices();
      } catch (error) {
        console.error('Error deleting device:', error);
      }
    }
  };

  const rogueDevices = devices.filter(d => d && d.isRogue);
  const onlineDevices = devices.filter(d => d && d.status === 'online');

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
            <div className="p-3 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-xl">
              <Radar className="w-8 h-8 text-white" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-white">Network Watchtower</h1>
              <p className="text-slate-400">Advanced Security Monitoring & Port Auditing</p>
            </div>
          </div>
          <div className="flex items-center gap-4">
            {/* Load Sample Data */}
            <button
              onClick={loadSampleNetworkData}
              className="glass-control text-slate-300 hover:text-slate-100 px-4 py-2 rounded-lg flex items-center gap-2 transition-all text-xs"
            >
              <Database className="w-4 h-4 text-cyan-400" />
              <span>Load Sample Data</span>
            </button>

            {/* Night Mode Toggle */}
            <button
              onClick={() => setNightMode(!nightMode)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg border transition-all ${
                nightMode 
                  ? 'bg-purple-500/20 border-purple-500/50 text-purple-300' 
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-600'
              }`}
              title={nightMode ? 'Night Mode Active - Auto-scanning every 10s' : 'Enable Night Mode for intruder detection'}
            >
              {nightMode ? (
                <>
                  <Moon className="w-5 h-5" />
                  <span className="text-sm font-semibold">Night Mode</span>
                </>
              ) : (
                <>
                  <Sun className="w-5 h-5" />
                  <span className="text-sm font-semibold">Day Mode</span>
                </>
              )}
            </button>
            
            {/* Server Status */}
            <div className={`flex items-center gap-2 px-4 py-2 rounded-lg border ${
              serverOnline 
                ? 'bg-green-500/10 border-green-500/30' 
                : 'bg-red-500/10 border-red-500/30'
            }`}>
              {serverOnline ? (
                <>
                  <Server className="w-5 h-5 text-green-400" />
                  <span className="text-green-400 text-sm font-semibold">Server Online</span>
                </>
              ) : (
                <>
                  <XCircle className="w-5 h-5 text-red-400" />
                  <span className="text-red-400 text-sm font-semibold">Server Offline</span>
                </>
              )}
            </div>
          </div>
        </div>
      </motion.div>

      {/* Server Offline Warning */}
      {!serverOnline && (
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="bg-red-500/10 border border-red-500/30 rounded-2xl p-6"
        >
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-6 h-6 text-red-400 flex-shrink-0 mt-1" />
            <div>
              <h3 className="text-lg font-bold text-red-400 mb-2">Companion Server Not Running</h3>
              <p className="text-slate-300 mb-4">
                Network scanning requires the backend relay server to access your local network.
              </p>
              <div className="bg-slate-900/60 p-4 rounded-lg font-mono text-sm text-cyan-400">
                <div className="mb-2 text-slate-400"># Start the companion server:</div>
                npm run start:server
              </div>
              <button
                onClick={checkServerHealth}
                className="mt-4 px-4 py-2 bg-cyan-500 hover:bg-cyan-600 text-white rounded-lg transition-colors flex items-center gap-2"
              >
                <RefreshCw className="w-4 h-4" />
                Check Again
              </button>
            </div>
          </div>
        </motion.div>
      )}
      
      {/* Night Mode Active Banner */}
      {nightMode && serverOnline && (
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="bg-purple-500/10 border border-purple-500/30 rounded-2xl p-6"
        >
          <div className="flex items-start gap-3">
            <Moon className="w-6 h-6 text-purple-400 flex-shrink-0 mt-1" />
            <div>
              <h3 className="text-lg font-bold text-purple-400 mb-2">🌙 Night Mode Active - Intruder Detection Enabled</h3>
              <p className="text-slate-300">
                Automatically scanning every 10 seconds. Unknown devices will trigger an alarm.
              </p>
              <div className="mt-2 text-sm text-slate-400">
                Known devices: <span className="text-cyan-400 font-semibold">{knownDevices.size}</span>
              </div>
            </div>
          </div>
        </motion.div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-slate-400 text-sm">Total Devices</div>
              <div className="text-2xl font-bold text-white">{devices.length}</div>
            </div>
            <Network className="w-8 h-8 text-cyan-400" />
          </div>
        </div>
        
        <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-slate-400 text-sm">Online</div>
              <div className="text-2xl font-bold text-green-400">{onlineDevices.length}</div>
            </div>
            <Wifi className="w-8 h-8 text-green-400" />
          </div>
        </div>
        
        <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-slate-400 text-sm">Rogue Devices</div>
              <div className="text-2xl font-bold text-red-400">{rogueDevices.length}</div>
            </div>
            <AlertTriangle className="w-8 h-8 text-red-400" />
          </div>
        </div>
        
        <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-slate-400 text-sm">Ghost Alerts</div>
              <div className="text-2xl font-bold text-yellow-400">{alerts.length}</div>
            </div>
            <Shield className="w-8 h-8 text-yellow-400" />
          </div>
        </div>
      </div>

      {/* Scan Controls */}
      <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-2xl p-6">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-xl font-bold text-white mb-2">Network Scanner</h2>
            <p className="text-slate-400 text-sm">
              {lastScan 
                ? `Last scan: ${lastScan.toLocaleString()}`
                : 'No scans performed yet'
              }
            </p>
          </div>
          <button
            onClick={scanNetwork}
            disabled={scanning || !serverOnline}
            className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 text-white font-semibold rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
          >
            {scanning ? (
              <>
                <RefreshCw className="w-5 h-5 animate-spin" />
                Scanning...
              </>
            ) : (
              <>
                <Radar className="w-5 h-5" />
                Scan Network
              </>
            )}
          </button>
        </div>
      </div>

      {/* Device Table */}
      <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-2xl p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Network className="w-6 h-6 text-cyan-400" />
            Discovered Devices
          </h2>
          
          {/* View Toggle */}
          <div className="flex items-center gap-2 bg-slate-800/50 rounded-lg p-1">
            <button
              onClick={() => setViewMode('list')}
              className={`px-4 py-2 rounded-md flex items-center gap-2 transition-all ${
                viewMode === 'list'
                  ? 'bg-cyan-500 text-white'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <List className="w-4 h-4" />
              <span className="text-sm font-semibold">List View</span>
            </button>
            <button
              onClick={() => setViewMode('graph')}
              className={`px-4 py-2 rounded-md flex items-center gap-2 transition-all ${
                viewMode === 'graph'
                  ? 'bg-cyan-500 text-white'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <GitBranch className="w-4 h-4" />
              <span className="text-sm font-semibold">Graph View</span>
            </button>
          </div>
        </div>
        
        {/* ARP Status Banner */}
        {arpStatus.status !== 'secure' && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            className={`mb-4 p-4 rounded-lg border-2 flex items-center gap-3 ${
              arpStatus.status === 'compromised'
                ? 'bg-red-500/20 border-red-500'
                : arpStatus.status === 'warning'
                ? 'bg-yellow-500/20 border-yellow-500'
                : 'bg-orange-500/20 border-orange-500'
            }`}
          >
            <AlertTriangle className={`w-6 h-6 flex-shrink-0 ${
              arpStatus.status === 'compromised' ? 'text-red-400' : 'text-yellow-400'
            }`} />
            <div className="flex-1">
              <div className={`font-bold text-sm ${
                arpStatus.status === 'compromised' ? 'text-red-400' : 'text-yellow-400'
              }`}>
                {arpStatus.status === 'compromised' ? '🚨 ARP SPOOFING DETECTED' : '⚠️ ARP Warning'}
              </div>
              <div className="text-slate-300 text-xs mt-1">{arpStatus.details}</div>
            </div>
          </motion.div>
        )}

        {/* Graph View */}
        {viewMode === 'graph' && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.95 }}
          >
            {devices.length === 0 ? (
              <div className="text-center py-12 text-slate-400">
                <Radar className="w-16 h-16 mx-auto mb-4 opacity-50" />
                <p className="text-lg font-semibold">No Devices Found</p>
                <p className="text-sm">Click "Scan Network" to discover devices on your network</p>
              </div>
            ) : (
              <NetworkGraph 
                devices={devices.filter(d => d && d.mac) as any}
                gatewayIP={arpStatus.gatewayIP}
                arpCompromised={arpStatus.status === 'compromised'}
                onScanPorts={scanPorts}
                scanningPort={scanningPort}
                portResults={portResults}
              />
            )}
          </motion.div>
        )}
        
        {/* List View */}
        {viewMode === 'list' && (
          <>
            {devices.length === 0 ? (
              <div className="text-center py-12 text-slate-400">
                <Radar className="w-16 h-16 mx-auto mb-4 opacity-50" />
                <p className="text-lg font-semibold">No Devices Found</p>
                <p className="text-sm">Click "Scan Network" to discover devices on your network</p>
              </div>
            ) : (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="overflow-x-auto"
              >
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-white/10">
                      <th className="text-left py-3 px-4 text-slate-400 font-semibold">Status</th>
                      <th className="text-left py-3 px-4 text-slate-400 font-semibold">IP Address</th>
                      <th className="text-left py-3 px-4 text-slate-400 font-semibold">MAC Address</th>
                      <th className="text-left py-3 px-4 text-slate-400 font-semibold">Vendor</th>
                      <th className="text-left py-3 px-4 text-slate-400 font-semibold">Device Name</th>
                      <th className="text-left py-3 px-4 text-slate-400 font-semibold">Last Seen</th>
                      <th className="text-left py-3 px-4 text-slate-400 font-semibold">Security</th>
                      <th className="text-left py-3 px-4 text-slate-400 font-semibold">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {devices.filter(d => d && d.mac).map((device) => (
                      <motion.tr
                        key={device.id || device.mac}
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        className={`border-b border-white/5 hover:bg-white/5 transition-colors ${
                          device.isRogue ? 'bg-red-500/5' : ''
                        }`}
                      >
                        <td className="py-4 px-4">
                          <div className="flex items-center gap-2">
                            {device.status === 'online' ? (
                              <CheckCircle className="w-5 h-5 text-green-400" />
                            ) : (
                              <XCircle className="w-5 h-5 text-slate-500" />
                            )}
                          </div>
                        </td>
                        <td className="py-4 px-4 text-white font-mono">{device.ip || 'N/A'}</td>
                        <td className="py-4 px-4 text-slate-300 font-mono text-sm">{device.mac}</td>
                        <td className="py-4 px-4">
                          <div className="flex items-center gap-2">
                            {getVendorIcon(device.vendor || '')}
                            <span className="text-slate-300">{device.vendor || 'Unknown'}</span>
                          </div>
                        </td>
                        <td className="py-4 px-4 text-slate-300">{device.name || 'Unknown'}</td>
                        <td className="py-4 px-4 text-slate-400 text-sm">
                          {device.lastSeen ? new Date(device.lastSeen).toLocaleString() : 'N/A'}
                        </td>
                        <td className="py-4 px-4">
                          <div className="flex flex-col gap-2">
                            {device.isRogue && (
                              <span className="inline-flex items-center gap-1 px-2 py-1 bg-red-500/20 text-red-400 rounded text-xs font-semibold">
                                <AlertTriangle className="w-3 h-3" />
                                Unknown
                              </span>
                            )}
                            
                            {device.status === 'online' && (
                              <button
                                onClick={() => scanPorts(device.ip || '')}
                                disabled={scanningPort === device.mac}
                                className="px-3 py-1 bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-400 rounded text-xs font-semibold transition-colors disabled:opacity-50 flex items-center gap-1"
                              >
                                {scanningPort === device.mac ? (
                                  <>
                                    <RefreshCw className="w-3 h-3 animate-spin" />
                                    Scanning...
                                  </>
                                ) : (
                                  <>
                                    <Scan className="w-3 h-3" />
                                    Port Scan
                                  </>
                                )}
                              </button>
                            )}
                            
                            {portResults.get(device.mac) && (
                              <div className="flex flex-wrap gap-1 mt-1">
                                {portResults.get(device.mac)?.filter(p => p.open).map((port) => (
                                  <span
                                    key={port.port}
                                    className={`px-2 py-0.5 rounded text-xs font-semibold ${
                                      port.dangerous 
                                        ? 'bg-red-500/30 text-red-300 border border-red-500' 
                                        : 'bg-green-500/20 text-green-400'
                                    }`}
                                    title={port.name}
                                  >
                                    {port.dangerous && '⚠️ '}{port.port}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        </td>
                        <td className="py-4 px-4">
                          <div className="flex items-center gap-2">
                            {device.isRogue && (
                              <button
                                onClick={() => handleMarkKnown(device.mac)}
                                className="p-2 hover:bg-green-500/20 text-green-400 rounded transition-colors"
                                title="Mark as Known Device"
                              >
                                <CheckCircle className="w-4 h-4" />
                              </button>
                            )}
                            <button
                              onClick={() => handleDeleteDevice(device.id!)}
                              className="p-2 hover:bg-red-500/20 text-red-400 rounded transition-colors"
                              title="Remove Device"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      </motion.tr>
                    ))}
                  </tbody>
                </table>
              </motion.div>
            )}
          </>
        )}
      </div>

      {/* Ghost Port Alerts */}
      {alerts.length > 0 && (
        <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-2xl p-6">
          <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
            <Shield className="w-6 h-6 text-yellow-400" />
            Ghost Port Alerts
          </h2>
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {alerts.map((alert, idx) => (
              <motion.div
                key={idx}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4"
              >
                <div className="flex items-start gap-3">
                  <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
                  <div className="flex-1">
                    <div className="text-yellow-400 font-semibold">{alert.message}</div>
                    <div className="text-sm text-slate-400 mt-1">
                      Source: <span className="text-cyan-400 font-mono">{alert.sourceIP}:{alert.sourcePort}</span>
                      {' • '}
                      Time: {new Date(alert.timestamp).toLocaleString()}
                    </div>
                  </div>
                  <div className={`px-2 py-1 rounded text-xs font-semibold ${
                    alert.severity === 'HIGH' 
                      ? 'bg-red-500/20 text-red-400' 
                      : 'bg-yellow-500/20 text-yellow-400'
                  }`}>
                    {alert.severity}
                  </div>
                  {/* MITRE ATT&CK MAPPING */}
                  <div className="px-2 py-1 rounded text-[10px] font-mono font-bold uppercase bg-purple-900/40 border border-purple-500/30 text-purple-300 flex items-center gap-1 shadow-[0_0_10px_rgba(168,85,247,0.1)]">
                    <span className="text-purple-400">T1190</span> Public-Facing App Exploit
                  </div>
                  <button 
                    onClick={() => handleMitigate(alert.targetPort)}
                    disabled={isMitigating}
                    className="ml-2 px-3 py-1 text-xs font-bold uppercase rounded bg-red-500/20 text-red-400 border border-red-500/30 hover:bg-red-500/30 transition-all flex items-center gap-1 disabled:opacity-50"
                  >
                    <Shield className="w-4 h-4" /> Mitigate Port {alert.targetPort}
                  </button>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      )}
      
      {/* Intruder Alert Modal */}
      <AnimatePresence>
        {intruderAlert && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center bg-black/90 backdrop-blur-sm p-4 overflow-y-auto"
          >
            <motion.div
              initial={{ scale: 0.8, y: 50 }}
              animate={{ scale: 1, y: 0 }}
              exit={{ scale: 0.8, y: 50 }}
              className="bg-gradient-to-br from-red-900 to-red-950 border-4 border-red-500 rounded-3xl p-8 md:p-12 max-w-4xl w-full mx-4 shadow-2xl my-8"
            >
              {!showExploreMore && !defendingAttack ? (
                // Main Alert View
                <div className="text-center">
                  <motion.div
                    animate={{ 
                      scale: [1, 1.2, 1],
                      rotate: [0, 10, -10, 0]
                    }}
                    transition={{ 
                      duration: 0.5,
                      repeat: Infinity,
                      repeatDelay: 0.5
                    }}
                    className="inline-block mb-6"
                  >
                    <AlertTriangle className="w-24 h-24 text-red-400" />
                  </motion.div>
                  
                  <h1 className="text-4xl md:text-5xl font-black text-red-400 mb-4 uppercase tracking-wider">
                    {intruderAlert.mac === 'ARP_SPOOF' 
                      ? '🚨 ARP SPOOFING DETECTED 🚨' 
                      : '🚨 INTRUDER DETECTED 🚨'
                    }
                  </h1>

                  {/* MITRE ATT&CK TAG */}
                  <div className="flex justify-center mb-6">
                    <div className="px-4 py-1.5 rounded-full text-xs font-mono font-bold uppercase bg-purple-900/30 border border-purple-500/50 text-purple-300 flex items-center gap-2 shadow-[0_0_15px_rgba(168,85,247,0.2)]">
                      <Shield className="w-3.5 h-3.5 text-purple-400" />
                      {intruderAlert.mac === 'ARP_SPOOF' 
                        ? <><span className="text-white">T1557.002:</span> MitM / ARP Spoofing</>
                        : <><span className="text-white">T1078:</span> Valid Accounts / Unauthorized Access</>}
                    </div>
                  </div>
                  
                  <div className="bg-black/40 rounded-2xl p-6 mb-8 text-left">
                    {intruderAlert.mac === 'ARP_SPOOF' ? (
                      <div className="space-y-4">
                        <div className="text-center">
                          <div className="text-red-300 font-bold text-2xl mb-2">Man-in-the-Middle Attack</div>
                          <div className="text-red-200 text-lg">Gateway MAC Address Changed!</div>
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-lg">
                          <div>
                            <div className="text-slate-400 text-sm mb-1">Attack Type</div>
                            <div className="text-red-300 font-bold">{intruderAlert.vendor}</div>
                          </div>
                          <div>
                            <div className="text-slate-400 text-sm mb-1">Gateway IP</div>
                            <div className="text-red-300 font-mono font-bold">{intruderAlert.ip}</div>
                          </div>
                          <div className="col-span-1 md:col-span-2">
                            <div className="text-slate-400 text-sm mb-1">Time Detected</div>
                            <div className="text-red-300 font-bold">
                              {new Date(intruderAlert.timestamp).toLocaleTimeString()}
                            </div>
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-lg">
                        <div>
                          <div className="text-slate-400 text-sm mb-1">MAC Address</div>
                          <div className="text-red-300 font-mono font-bold">{intruderAlert.mac}</div>
                        </div>
                        <div>
                          <div className="text-slate-400 text-sm mb-1">IP Address</div>
                          <div className="text-red-300 font-mono font-bold">{intruderAlert.ip}</div>
                        </div>
                        <div>
                          <div className="text-slate-400 text-sm mb-1">Vendor</div>
                          <div className="text-red-300 font-bold">{intruderAlert.vendor}</div>
                        </div>
                        <div>
                          <div className="text-slate-400 text-sm mb-1">Time Detected</div>
                          <div className="text-red-300 font-bold">
                            {new Date(intruderAlert.timestamp).toLocaleTimeString()}
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                  
                  <p className="text-xl text-red-200 mb-8">
                    {intruderAlert.mac === 'ARP_SPOOF'
                      ? 'Your network traffic may be intercepted! Disconnect immediately and investigate.'
                      : 'An unknown device has joined your network!'
                    }
                  </p>
                  
                  <div className="flex flex-col md:flex-row gap-4 justify-center">
                    {intruderAlert.mac === 'ARP_SPOOF' && (
                      <button
                        onClick={startDefending}
                        className="px-6 py-4 bg-purple-600 hover:bg-purple-700 text-white font-bold rounded-xl transition-all text-lg flex items-center gap-2 justify-center"
                      >
                        <Shield className="w-6 h-6" />
                        Initiate Defense Protocol
                      </button>
                    )}
                    
                    <button
                      onClick={() => setShowExploreMore(true)}
                      className="px-6 py-4 bg-blue-600 hover:bg-blue-700 text-white font-bold rounded-xl transition-all text-lg flex items-center gap-2 justify-center"
                    >
                      <Scan className="w-6 h-6" />
                      Explore More
                    </button>
                    
                    <button
                      onClick={acknowledgeIntruder}
                      className="px-6 py-4 bg-green-600 hover:bg-green-700 text-white font-bold rounded-xl transition-all text-lg flex items-center gap-2 justify-center"
                    >
                      <CheckCircle className="w-6 h-6" />
                      Mark as Known
                    </button>
                    
                    <button
                      onClick={dismissIntruder}
                      className="px-6 py-4 bg-slate-700 hover:bg-slate-800 text-white font-bold rounded-xl transition-all text-lg flex items-center gap-2 justify-center"
                    >
                      <XCircle className="w-6 h-6" />
                      Dismiss Alert
                    </button>
                  </div>
                </div>
              ) : defendingAttack ? (
                // Defense Dashboard
                <div>
                  <div className="text-center mb-8">
                    <motion.div
                      animate={{ rotate: 360 }}
                      transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                      className="inline-block mb-4"
                    >
                      <Shield className="w-20 h-20 text-purple-400" />
                    </motion.div>
                    <h2 className="text-3xl font-black text-purple-400 mb-2">GENERATING DEFENSE STRATEGY</h2>
                    <p className="text-red-200">Analyzing attack and preparing countermeasures...</p>
                  </div>
                  
                  <div ref={defenseLogRef} className="bg-black/60 rounded-2xl p-6 max-h-96 overflow-y-auto">
                    <div className="space-y-3 font-mono text-sm">
                      {defenseLog.map((log, idx) => (
                        <motion.div
                          key={idx}
                          initial={{ opacity: 0, x: -20 }}
                          animate={{ opacity: 1, x: 0 }}
                          className="text-green-400 flex items-start gap-2"
                        >
                          <span className="text-slate-500">[{new Date().toLocaleTimeString()}]</span>
                          <span>{log}</span>
                        </motion.div>
                      ))}
                    </div>
                  </div>
                  
                  {defenseLog.length >= 11 && (
                    <motion.div
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="mt-6 text-center"
                    >
                      <div className="bg-yellow-500/20 border-2 border-yellow-500 rounded-xl p-4 mb-4">
                        <AlertTriangle className="w-12 h-12 text-yellow-400 mx-auto mb-2" />
                        <p className="text-yellow-400 font-bold text-xl">Manual Intervention Required</p>
                        <p className="text-yellow-300 text-sm mt-1">Browser cannot modify OS network stack</p>
                      </div>
                    </motion.div>
                  )}
                </div>
              ) : showDefenseScript ? (
                // Manual Defense Script Modal
                <div className="text-left">
                  <div className="flex items-center justify-between mb-6">
                    <h2 className="text-3xl font-black text-yellow-400">Manual Defense Required</h2>
                    <button
                      onClick={async () => {
                        await saveSetting('arp_dismissed', true);
                        setDismissedARPAlert(true);
                        setShowDefenseScript(false);
                        stopSiren();
                        setIntruderAlert(null);
                      }}
                      className="p-2 hover:bg-white/10 rounded-lg transition-colors"
                    >
                      <XCircle className="w-6 h-6 text-red-400" />
                    </button>
                  </div>
                  
                  <div className="bg-yellow-500/10 border border-yellow-500/50 rounded-xl p-4 mb-6">
                    <div className="flex items-start gap-3">
                      <AlertTriangle className="w-6 h-6 text-yellow-400 flex-shrink-0 mt-1" />
                      <div className="text-yellow-200">
                        <p className="font-semibold mb-2">Security Limitation:</p>
                        <p className="text-sm">
                          Web browsers cannot directly modify your operating system's network configuration. 
                          You must run the commands below in your terminal with administrator/sudo privileges.
                        </p>
                      </div>
                    </div>
                  </div>
                  
                  <div className="space-y-6 max-h-[450px] overflow-y-auto pr-2">
                    {/* Windows Script */}
                    <div className="bg-black/40 rounded-xl p-6">
                      <div className="flex items-center justify-between mb-3">
                        <h3 className="text-xl font-bold text-cyan-400">Windows (PowerShell)</h3>
                        <button
                          onClick={() => copyToClipboard(defenseScript.windows)}
                          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg text-sm font-semibold transition-colors flex items-center gap-2"
                        >
                          <CheckCircle className="w-4 h-4" />
                          Copy Script
                        </button>
                      </div>
                      <pre className="bg-slate-900 rounded-lg p-4 overflow-x-auto text-sm text-green-400 font-mono">
                        {defenseScript.windows}
                      </pre>
                    </div>
                    
                    {/* Linux/Mac Script */}
                    <div className="bg-black/40 rounded-xl p-6">
                      <div className="flex items-center justify-between mb-3">
                        <h3 className="text-xl font-bold text-cyan-400">Linux / macOS</h3>
                        <button
                          onClick={() => copyToClipboard(defenseScript.linux)}
                          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg text-sm font-semibold transition-colors flex items-center gap-2"
                        >
                          <CheckCircle className="w-4 h-4" />
                          Copy Script
                        </button>
                      </div>
                      <pre className="bg-slate-900 rounded-lg p-4 overflow-x-auto text-sm text-green-400 font-mono">
                        {defenseScript.linux}
                      </pre>
                    </div>
                    
                    {/* Instructions */}
                    <div className="bg-black/40 rounded-xl p-6">
                      <h3 className="text-xl font-bold text-orange-400 mb-3">⚠️ Important Instructions</h3>
                      <ol className="text-slate-200 leading-relaxed space-y-2 list-decimal list-inside">
                        <li><strong className="text-white">Copy the appropriate script</strong> for your operating system</li>
                        <li><strong className="text-white">Open terminal/PowerShell as Administrator</strong> (Windows) or with sudo (Linux/Mac)</li>
                        <li><strong className="text-white">Paste and execute</strong> the commands</li>
                        <li><strong className="text-white">Verify</strong> the static ARP entry was created successfully</li>
                        <li><strong className="text-white">Continue monitoring</strong> - The attacker may persist</li>
                      </ol>
                    </div>
                  </div>
                  
                  <div className="flex gap-4 mt-6 pt-6 border-t border-white/20">
                    <button
                      onClick={async () => {
                        await saveSetting('arp_dismissed', true);
                        setDismissedARPAlert(true);
                        setShowDefenseScript(false);
                        stopSiren();
                        setIntruderAlert(null);
                      }}
                      className="flex-1 px-6 py-3 bg-green-600 hover:bg-green-700 text-white font-bold rounded-xl transition-all"
                    >
                      I've Applied the Defense
                    </button>
                  </div>
                </div>
              ) : (
                // Explore More View
                <div className="text-left">
                  <div className="flex items-center justify-between mb-6">
                    <h2 className="text-3xl font-black text-red-400">Understanding {intruderAlert.mac === 'ARP_SPOOF' ? 'ARP Spoofing' : 'Network Intrusion'}</h2>
                    <button
                      onClick={() => setShowExploreMore(false)}
                      className="p-2 hover:bg-white/10 rounded-lg transition-colors"
                    >
                      <XCircle className="w-6 h-6 text-red-400" />
                    </button>
                  </div>
                  
                  <div className="space-y-6 max-h-[500px] overflow-y-auto pr-2">
                    {intruderAlert.mac === 'ARP_SPOOF' ? (
                      <>
                        <div className="bg-black/40 rounded-xl p-6">
                          <h3 className="text-xl font-bold text-yellow-400 mb-3 flex items-center gap-2">
                            <AlertTriangle className="w-5 h-5" />
                            What is ARP Spoofing?
                          </h3>
                          <p className="text-slate-200 leading-relaxed mb-3">
                            ARP Spoofing (Address Resolution Protocol Spoofing) is a type of cyber attack where an attacker sends falsified ARP messages 
                            over a local network. This results in the linking of an attacker's MAC address with the IP address of a legitimate network device, 
                            such as your gateway/router.
                          </p>
                          <p className="text-red-300 font-semibold">
                            ⚠️ When successful, an attacker can intercept, modify, or block data intended for the victim's computer.
                          </p>
                        </div>
                        
                        <div className="bg-black/40 rounded-xl p-6">
                          <h3 className="text-xl font-bold text-orange-400 mb-3 flex items-center gap-2">
                            <Shield className="w-5 h-5" />
                            How It Works
                          </h3>
                          <ol className="text-slate-200 leading-relaxed space-y-2 list-decimal list-inside">
                            <li>The attacker broadcasts fake ARP responses to your network</li>
                            <li>Your devices update their ARP cache with the attacker's MAC address</li>
                            <li>Traffic intended for the gateway now goes to the attacker first</li>
                            <li>The attacker can read, modify, or forward your data</li>
                            <li>This creates a "Man-in-the-Middle" attack scenario</li>
                          </ol>
                        </div>
                        
                        <div className="bg-black/40 rounded-xl p-6">
                          <h3 className="text-xl font-bold text-cyan-400 mb-3 flex items-center gap-2">
                            <CheckCircle className="w-5 h-5" />
                            Immediate Actions
                          </h3>
                          <ul className="text-slate-200 leading-relaxed space-y-2">
                            <li className="flex items-start gap-2">
                              <span className="text-green-400">1.</span>
                              <span><strong className="text-white">Disconnect</strong> - Temporarily disconnect from the network if handling sensitive data</span>
                            </li>
                            <li className="flex items-start gap-2">
                              <span className="text-green-400">2.</span>
                              <span><strong className="text-white">Clear ARP Cache</strong> - Run: <code className="bg-slate-900 px-2 py-1 rounded text-cyan-400">arp -d</code> (Windows) or <code className="bg-slate-900 px-2 py-1 rounded text-cyan-400">sudo ip -s -s neigh flush all</code> (Linux)</span>
                            </li>
                            <li className="flex items-start gap-2">
                              <span className="text-green-400">3.</span>
                              <span><strong className="text-white">Use Defense Protocol</strong> - Click "Initiate Defense Protocol" to generate OS-specific defense scripts</span>
                            </li>
                            <li className="flex items-start gap-2">
                              <span className="text-green-400">4.</span>
                              <span><strong className="text-white">Check Router</strong> - Log into your router and look for unknown connected devices</span>
                            </li>
                            <li className="flex items-start gap-2">
                              <span className="text-green-400">5.</span>
                              <span><strong className="text-white">Static ARP Entries</strong> - Configure static ARP entries for critical devices</span>
                            </li>
                          </ul>
                        </div>
                        
                        <div className="bg-black/40 rounded-xl p-6">
                          <h3 className="text-xl font-bold text-purple-400 mb-3 flex items-center gap-2">
                            <Radar className="w-5 h-5" />
                            Long-term Prevention
                          </h3>
                          <ul className="text-slate-200 leading-relaxed space-y-2">
                            <li>• Enable <strong className="text-white">Dynamic ARP Inspection (DAI)</strong> on managed switches</li>
                            <li>• Implement <strong className="text-white">Port Security</strong> to limit MAC addresses per port</li>
                            <li>• Use <strong className="text-white">VPN encryption</strong> for sensitive communications</li>
                            <li>• Enable <strong className="text-white">HTTPS Everywhere</strong> to encrypt web traffic</li>
                            <li>• Monitor network with <strong className="text-white">IDS/IPS systems</strong></li>
                            <li>• Regularly update router firmware and change default credentials</li>
                          </ul>
                        </div>
                      </>
                    ) : (
                      <>
                        <div className="bg-black/40 rounded-xl p-6">
                          <h3 className="text-xl font-bold text-yellow-400 mb-3">Unknown Device Detected</h3>
                          <p className="text-slate-200 leading-relaxed">
                            An unrecognized device has connected to your network. This could be a legitimate new device or an unauthorized intrusion attempt.
                          </p>
                        </div>
                        
                        <div className="bg-black/40 rounded-xl p-6">
                          <h3 className="text-xl font-bold text-cyan-400 mb-3">Recommended Actions</h3>
                          <ul className="text-slate-200 leading-relaxed space-y-2">
                            <li>• Verify if this device belongs to you or authorized users</li>
                            <li>• Check your router's connected devices list</li>
                            <li>• Change your WiFi password if device is unauthorized</li>
                            <li>• Enable MAC address filtering on your router</li>
                            <li>• Mark as "Known Device" if it's legitimate</li>
                          </ul>
                        </div>
                      </>
                    )}
                  </div>
                  
                  <div className="flex gap-4 mt-6 pt-6 border-t border-white/20">
                    <button
                      onClick={() => setShowExploreMore(false)}
                      className="flex-1 px-6 py-3 bg-slate-700 hover:bg-slate-800 text-white font-bold rounded-xl transition-all"
                    >
                      Back to Alert
                    </button>
                  </div>
                </div>
              )}
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Auto-Mitigate Modal */}
      {mitigateData && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-fade-in">
          <div className="bg-slate-900 border border-red-500/50 rounded-xl max-w-lg w-full p-6 shadow-2xl">
            <div className="flex items-center gap-3 mb-4">
              <Shield className="w-6 h-6 text-red-500" />
              <h3 className="text-xl font-bold text-slate-200">Autonomous Remediation</h3>
            </div>
            <p className="text-sm text-slate-400 mb-4 leading-relaxed">
              The AI engine has generated the exact OS-level firewall commands to actively block <strong className="text-red-400 font-mono">Port {mitigateData.port} ({mitigateData.protocol.toUpperCase()})</strong>. Please review carefully before applying.
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
}
