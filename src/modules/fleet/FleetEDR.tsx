import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Server, Activity, Cpu, HardDrive, Network, AlertTriangle, ShieldAlert, CheckCircle, RefreshCw, XCircle, Code, Loader2, Sparkles } from 'lucide-react';
import { getEDRTelemetries, saveEDRTelemetry, EDRTelemetry } from '../../services/db';
import { toast } from 'react-hot-toast';

export default function FleetEDR() {
  const [telemetry, setTelemetry] = useState<EDRTelemetry[]>([]);
  const [selectedEndpoint, setSelectedEndpoint] = useState<EDRTelemetry | null>(null);
  const [isSimulating, setIsSimulating] = useState(false);
  
  // Isolation State
  const [isolationData, setIsolationData] = useState<{endpointId: string, command: string} | null>(null);
  const [isIsolating, setIsIsolating] = useState(false);

  useEffect(() => {
    loadData();
    // Refresh every 5 seconds to simulate real-time
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, []);

  const loadData = async () => {
    const data = await getEDRTelemetries();
    setTelemetry(data);
    if (selectedEndpoint) {
      const updated = data.find(d => d.endpointId === selectedEndpoint.endpointId);
      if (updated) setSelectedEndpoint(updated);
    }
  };

  const handleSimulateAgent = async () => {
    setIsSimulating(true);
    
    // Generate mock agent telemetry
    const newAgent: Omit<EDRTelemetry, 'id'> = {
      endpointId: `WEB-SRV-${Math.floor(Math.random() * 1000)}`,
      hostname: 'production-web-01.securai.local',
      os: 'Ubuntu 22.04 LTS',
      health: Math.random() > 0.7 ? 'Warning' : 'Healthy',
      lastSeen: Date.now(),
      cpu: Math.floor(Math.random() * 80) + 10,
      memory: Math.floor(Math.random() * 60) + 20,
      processes: [
        { pid: 1, name: 'systemd', user: 'root', cpu: 0.1, mem: 5.2, path: '/sbin/init', status: 'running' },
        { pid: 1422, name: 'nginx', user: 'www-data', cpu: 2.5, mem: 15.4, path: '/usr/sbin/nginx', status: 'running' },
        { pid: 3511, name: 'python3', user: 'root', cpu: 45.2, mem: 8.1, path: '/usr/bin/python3', status: 'running' }
      ],
      network: [
        { proto: 'TCP', local: '0.0.0.0:80', remote: '0.0.0.0:0', state: 'LISTEN', pid: 1422 },
        { proto: 'TCP', local: '192.168.1.15:443', remote: '10.0.0.5:54321', state: 'ESTABLISHED', pid: 1422 },
        { proto: 'TCP', local: '192.168.1.15:3511', remote: '185.15.x.x:443', state: 'SYN_SENT', pid: 3511 }
      ],
      alerts: []
    };

    if (newAgent.health === 'Warning') {
      newAgent.alerts.push({
        id: `ALT-${Date.now()}`,
        severity: 'HIGH',
        message: 'Suspicious outbound connection detected from python3 process to known malicious IP',
        timestamp: Date.now()
      });
    }

    await saveEDRTelemetry(newAgent);
    await loadData();
    setIsSimulating(false);
  };

  const loadSampleFleetData = async () => {
    setIsSimulating(true);
    try {
      const sampleEndpoints: Omit<EDRTelemetry, 'id'>[] = [
        {
          endpointId: 'DB-SRV-01',
          hostname: 'production-db-01.securai.local',
          os: 'Red Hat Enterprise Linux 9.2',
          health: 'Warning',
          lastSeen: Date.now(),
          cpu: 76,
          memory: 89,
          processes: [
            { pid: 1, name: 'systemd', user: 'root', cpu: 0.1, mem: 2.1, path: '/sbin/init', status: 'running' },
            { pid: 3306, name: 'mysqld', user: 'mysql', cpu: 15.4, mem: 45.2, path: '/usr/sbin/mysqld', status: 'running' },
            { pid: 9988, name: 'nc', user: 'nobody', cpu: 60.5, mem: 41.7, path: '/usr/bin/nc', status: 'running' }
          ],
          network: [
            { proto: 'TCP', local: '0.0.0.0:3306', remote: '0.0.0.0:0', state: 'LISTEN', pid: 3306 },
            { proto: 'TCP', local: '192.168.1.20:3306', remote: '192.168.1.15:48552', state: 'ESTABLISHED', pid: 3306 },
            { proto: 'TCP', local: '192.168.1.20:54321', remote: '45.80.x.x:443', state: 'ESTABLISHED', pid: 9988 }
          ],
          alerts: [
            {
              id: 'ALT-1002',
              severity: 'CRITICAL',
              message: 'Active reverse shell detected: netcat (nc) spawning shell back to rogue IP 45.80.x.x',
              timestamp: Date.now() - 15000
            }
          ]
        },
        {
          endpointId: 'DC-SRV-01',
          hostname: 'securai-dc-01.securai.local',
          os: 'Windows Server 2022',
          health: 'Healthy',
          lastSeen: Date.now(),
          cpu: 12,
          memory: 42,
          processes: [
            { pid: 4, name: 'System', user: 'SYSTEM', cpu: 0.5, mem: 1.2, path: 'System', status: 'running' },
            { pid: 504, name: 'lsass.exe', user: 'SYSTEM', cpu: 1.2, mem: 12.4, path: 'C:\\Windows\\System32\\lsass.exe', status: 'running' },
            { pid: 912, name: 'dns.exe', user: 'SYSTEM', cpu: 2.1, mem: 8.5, path: 'C:\\Windows\\System32\\dns.exe', status: 'running' }
          ],
          network: [
            { proto: 'TCP', local: '0.0.0.0:53', remote: '0.0.0.0:0', state: 'LISTEN', pid: 912 },
            { proto: 'TCP', local: '0.0.0.0:389', remote: '0.0.0.0:0', state: 'LISTEN', pid: 504 }
          ],
          alerts: []
        },
        {
          endpointId: 'WEB-SRV-01',
          hostname: 'production-web-01.securai.local',
          os: 'Ubuntu 22.04 LTS',
          health: 'Healthy',
          lastSeen: Date.now(),
          cpu: 24,
          memory: 55,
          processes: [
            { pid: 1, name: 'systemd', user: 'root', cpu: 0.1, mem: 1.5, path: '/sbin/init', status: 'running' },
            { pid: 80, name: 'nginx', user: 'www-data', cpu: 4.2, mem: 22.1, path: '/usr/sbin/nginx', status: 'running' }
          ],
          network: [
            { proto: 'TCP', local: '0.0.0.0:80', remote: '0.0.0.0:0', state: 'LISTEN', pid: 80 }
          ],
          alerts: []
        }
      ];

      for (const ep of sampleEndpoints) {
        await saveEDRTelemetry(ep);
      }
      
      const data = await getEDRTelemetries();
      setTelemetry(data);
      const target = data.find(d => d.endpointId === 'DB-SRV-01');
      if (target) setSelectedEndpoint(target);
      
      toast.success('Sample endpoint agents loaded successfully.');
    } catch (err) {
      console.error(err);
      toast.error('Failed to load sample fleet data');
    } finally {
      setIsSimulating(false);
    }
  };

  const handleIsolate = async (endpointId: string, os: string) => {
    setIsIsolating(true);
    try {
      const res = await fetch('http://localhost:3001/edr/isolate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ endpointId, os, reason: 'Administrator initiated isolation via Fleet EDR' })
      });
      const data = await res.json();
      if (data.success) {
        setIsolationData({ endpointId, command: data.command });
      }
    } catch (e) {
      console.error(e);
      alert('Failed to connect to EDR control server.');
    } finally {
      setIsIsolating(false);
    }
  };

  return (
    <div className="flex flex-col h-full overflow-hidden relative">
      <div className="bg-slate-900/60 backdrop-blur-xl border border-white/10 rounded-xl p-6 mb-6 shadow-2xl flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-blue-500/20 rounded-lg">
            <Server className="w-6 h-6 text-blue-500" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-100 tracking-tight">Fleet EDR Management</h1>
            <p className="text-sm text-slate-400">Endpoint Detection and Response Telemetry Dashboard</p>
          </div>
        </div>
        <div className="flex gap-2">
          <button 
            onClick={loadSampleFleetData}
            disabled={isSimulating}
            className="px-4 py-2 bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 rounded-lg text-sm font-semibold transition-all border border-blue-500/30 flex items-center gap-2 disabled:opacity-50"
          >
            <Sparkles className="w-4 h-4 text-cyan-400" />
            Load Sample Data
          </button>
          <button 
            onClick={handleSimulateAgent}
            disabled={isSimulating}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-sm font-semibold transition-all border border-slate-700 flex items-center gap-2 disabled:opacity-50"
          >
            {isSimulating ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
            Simulate Endpoint Agent
          </button>
        </div>
      </div>

      <div className="flex-1 flex gap-6 overflow-hidden">
        {/* Fleet List Sidebar */}
        <div className="w-80 flex-shrink-0 bg-slate-900/40 border border-white/10 rounded-xl flex flex-col overflow-hidden">
          <div className="p-4 border-b border-white/10 bg-slate-900/60 font-semibold text-slate-200 flex items-center gap-2">
            <Activity className="w-4 h-4 text-slate-400" /> Monitored Endpoints
          </div>
          <div className="flex-1 overflow-y-auto p-2 space-y-2">
            {telemetry.length === 0 ? (
              <div className="text-center p-6 text-slate-500 text-sm">
                No endpoint telemetry received. <br/>Deploy agents or click Simulate to test.
              </div>
            ) : (
              telemetry.map(ep => (
                <button
                  key={ep.endpointId}
                  onClick={() => setSelectedEndpoint(ep)}
                  className={`w-full text-left p-3 rounded-lg border transition-all ${selectedEndpoint?.endpointId === ep.endpointId ? 'bg-blue-600/20 border-blue-500/50' : 'bg-slate-950/40 border-slate-800 hover:border-slate-600'}`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-bold font-mono text-slate-200 text-sm">{ep.endpointId}</span>
                    <span className={`w-2 h-2 rounded-full ${ep.health === 'Healthy' ? 'bg-emerald-500' : ep.health === 'Warning' ? 'bg-yellow-500 animate-pulse' : 'bg-red-500 animate-pulse'}`}></span>
                  </div>
                  <div className="text-xs text-slate-400">{ep.hostname}</div>
                  <div className="mt-2 flex items-center gap-3 text-[10px] text-slate-500 uppercase font-semibold">
                    <span className="flex items-center gap-1"><Cpu className="w-3 h-3 text-slate-400"/> {ep.cpu}%</span>
                    <span className="flex items-center gap-1"><Server className="w-3 h-3 text-slate-400"/> {ep.memory}%</span>
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        {/* Endpoint Details Area */}
        <div className="flex-1 bg-slate-900/40 border border-white/10 rounded-xl overflow-y-auto scrollbar-hide">
          {selectedEndpoint ? (
            <div className="p-6 space-y-6">
              {/* Header Info */}
              <div className="flex flex-col lg:flex-row justify-between gap-4 bg-slate-950/50 p-6 rounded-xl border border-white/5">
                <div>
                  <h2 className="text-2xl font-bold text-white font-mono flex items-center gap-3">
                    {selectedEndpoint.endpointId}
                    {selectedEndpoint.health !== 'Healthy' && (
                      <span className="px-2 py-0.5 rounded text-xs bg-red-500/20 text-red-500 font-sans border border-red-500/30 uppercase tracking-widest flex items-center gap-1">
                        <AlertTriangle className="w-3 h-3" /> {selectedEndpoint.health}
                      </span>
                    )}
                  </h2>
                  <div className="text-slate-400 text-sm mt-1">{selectedEndpoint.hostname} • {selectedEndpoint.os}</div>
                </div>
                <div className="flex items-center gap-3">
                  <div className="px-4 py-2 bg-slate-900 rounded-lg border border-slate-800 text-center">
                    <div className="text-xs text-slate-500 uppercase font-bold mb-1">CPU Usage</div>
                    <div className={`text-lg font-bold font-mono ${selectedEndpoint.cpu > 80 ? 'text-red-400' : 'text-emerald-400'}`}>{selectedEndpoint.cpu}%</div>
                  </div>
                  <div className="px-4 py-2 bg-slate-900 rounded-lg border border-slate-800 text-center">
                    <div className="text-xs text-slate-500 uppercase font-bold mb-1">Memory</div>
                    <div className={`text-lg font-bold font-mono ${selectedEndpoint.memory > 80 ? 'text-red-400' : 'text-emerald-400'}`}>{selectedEndpoint.memory}%</div>
                  </div>
                  <button 
                    onClick={() => handleIsolate(selectedEndpoint.endpointId, selectedEndpoint.os)}
                    className="h-full px-4 py-2 bg-red-600/20 hover:bg-red-600/30 text-red-500 border border-red-500/30 rounded-lg font-semibold transition-all flex items-center gap-2 flex-col justify-center text-xs ml-2"
                  >
                    <ShieldAlert className="w-5 h-5" />
                    ISOLATE MACHINE
                  </button>
                </div>
              </div>

              {/* Alerts if any */}
              {selectedEndpoint.alerts.length > 0 && (
                <div className="space-y-3">
                  <h3 className="text-sm font-bold text-red-400 uppercase tracking-wider flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4" /> Active EDR Alerts
                  </h3>
                  {selectedEndpoint.alerts.map(a => (
                    <div key={a.id} className="bg-red-950/40 border border-red-500/30 p-4 rounded-lg flex items-start gap-3">
                      <ShieldAlert className="w-5 h-5 text-red-500 shrink-0 mt-0.5" />
                      <div>
                        <div className="font-semibold text-red-200">{a.message}</div>
                        <div className="text-xs text-red-400/60 mt-1 font-mono">{a.id} • {new Date(a.timestamp).toLocaleString()}</div>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* Process Tree */}
              <div>
                <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-2">
                  <Server className="w-4 h-4" /> Active Processes
                </h3>
                <div className="bg-slate-950 rounded-xl border border-slate-800 overflow-hidden">
                  <table className="w-full text-left font-mono text-xs">
                    <thead className="bg-slate-900 text-slate-400">
                      <tr>
                        <th className="p-3 font-semibold">PID</th>
                        <th className="p-3 font-semibold">Name</th>
                        <th className="p-3 font-semibold">User</th>
                        <th className="p-3 font-semibold">CPU%</th>
                        <th className="p-3 font-semibold">MEM%</th>
                        <th className="p-3 font-semibold">Path</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {selectedEndpoint.processes.map(p => (
                        <tr key={p.pid} className="hover:bg-slate-900/50 text-slate-300">
                          <td className="p-3 text-cyan-400">{p.pid}</td>
                          <td className="p-3 font-bold">{p.name}</td>
                          <td className="p-3 text-slate-500">{p.user}</td>
                          <td className={`p-3 ${p.cpu > 30 ? 'text-red-400' : ''}`}>{p.cpu.toFixed(1)}</td>
                          <td className="p-3">{p.mem.toFixed(1)}</td>
                          <td className="p-3 text-slate-500 truncate max-w-xs" title={p.path}>{p.path}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Network Connections */}
              <div>
                <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center gap-2">
                  <Network className="w-4 h-4" /> Network Connections
                </h3>
                <div className="bg-slate-950 rounded-xl border border-slate-800 overflow-hidden">
                  <table className="w-full text-left font-mono text-xs">
                    <thead className="bg-slate-900 text-slate-400">
                      <tr>
                        <th className="p-3 font-semibold">Proto</th>
                        <th className="p-3 font-semibold">Local Address</th>
                        <th className="p-3 font-semibold">Foreign Address</th>
                        <th className="p-3 font-semibold">State</th>
                        <th className="p-3 font-semibold">PID</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                      {selectedEndpoint.network.map((n, i) => (
                        <tr key={i} className="hover:bg-slate-900/50 text-slate-300">
                          <td className="p-3">{n.proto}</td>
                          <td className="p-3 text-cyan-400">{n.local}</td>
                          <td className="p-3 text-purple-400">{n.remote}</td>
                          <td className="p-3 text-slate-500">{n.state}</td>
                          <td className="p-3 text-emerald-400">{n.pid}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-slate-500">
              <Server className="w-20 h-20 mb-4 opacity-20" />
              <p>Select an endpoint from the fleet menu to view telemetry.</p>
            </div>
          )}
        </div>
      </div>

      {/* Network Isolation Modal */}
      {isolationData && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-fade-in">
          <div className="bg-slate-900 border border-red-500/50 rounded-xl max-w-lg w-full p-6 shadow-2xl">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-3">
                <ShieldAlert className="w-6 h-6 text-red-500" />
                <h3 className="text-xl font-bold text-slate-200">Network Isolation</h3>
              </div>
              <button onClick={() => setIsolationData(null)} className="text-slate-500 hover:text-white"><XCircle className="w-6 h-6"/></button>
            </div>
            <p className="text-sm text-slate-400 mb-4 leading-relaxed">
              To immediately contain endpoint <strong className="text-red-400 font-mono">{isolationData.endpointId}</strong> without disrupting the EDR agent connection (for forensic collection), deploy the following OS-level firewall rules.
            </p>
            <div className="bg-slate-950 p-4 rounded-lg font-mono text-xs text-red-400 border border-red-900/50 mb-6 overflow-x-auto shadow-inner">
              <pre>{isolationData.command}</pre>
            </div>
            <div className="flex gap-3 justify-end">
              <button 
                onClick={() => setIsolationData(null)} 
                className="px-4 py-2 rounded font-semibold text-slate-400 hover:text-white bg-slate-800 transition-all text-sm"
              >
                Cancel
              </button>
              <button 
                onClick={() => { 
                  navigator.clipboard.writeText(isolationData.command); 
                  alert('Isolation script copied to your clipboard/management tool.'); 
                  setIsolationData(null); 
                }} 
                className="px-4 py-2 rounded font-bold text-white bg-red-600 hover:bg-red-700 transition-all flex items-center gap-2 text-sm shadow-lg shadow-red-900/50"
              >
                <Code className="w-4 h-4" /> Copy Isolation Script
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
