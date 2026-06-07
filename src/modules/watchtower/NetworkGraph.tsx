import React, { useEffect, useMemo, useState } from 'react';
import ReactFlow, {
  Node,
  Edge,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  MarkerType,
  Position,
  NodeProps
} from 'reactflow';
import 'reactflow/dist/style.css';
import { 
  Router, 
  Smartphone, 
  Monitor, 
  Cpu, 
  HardDrive,
  AlertTriangle,
  Shield,
  Wifi,
  X,
  Scan,
  RefreshCw
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

interface Device {
  id?: string;
  ip: string;
  mac: string;
  vendor: string;
  name?: string;
  status?: string;
  isRogue?: boolean;
  lastSeen?: string;
  openPorts?: number;
  portScanResults?: Array<{
    port: number;
    name: string;
    open: boolean;
    dangerous: boolean;
  }>;
}

interface NetworkGraphProps {
  devices: Device[];
  gatewayIP?: string;
  arpCompromised?: boolean;
  onScanPorts?: (ip: string, mac: string) => Promise<void>;
  scanningPort?: string | null;
  portResults?: Map<string, Array<{
    port: number;
    name: string;
    open: boolean;
    dangerous: boolean;
  }>>;
}

interface DeviceNodeData {
  label: string;
  sublabel: string;
  vendor?: string;
  icon: React.ComponentType<{ className?: string }>;
  isDangerous: boolean;
  isGateway: boolean;
  openPorts: number;
  onClick: () => void;
}

// Custom node component for devices
const DeviceNode: React.FC<NodeProps<DeviceNodeData>> = ({ data }) => {
  const Icon = data.icon;
  const isDangerous = data.isDangerous;
  const isGateway = data.isGateway;
  const hasOpenPorts = data.openPorts > 0;
  
  return (
    <div
      onClick={data.onClick}
      className={`
        relative p-4 rounded-xl border-2 backdrop-blur-md cursor-pointer
        transition-all duration-300 hover:scale-110 hover:shadow-2xl
        ${isGateway 
          ? 'bg-cyan-500/20 border-cyan-400 shadow-cyan-500/50' 
          : isDangerous 
            ? 'bg-red-500/20 border-red-500 shadow-red-500/50 animate-pulse' 
            : 'bg-green-500/10 border-green-400/50 shadow-green-500/30'
        }
      `}
      style={{
        boxShadow: isGateway 
          ? '0 0 30px rgba(34, 211, 238, 0.6)' 
          : isDangerous 
            ? '0 0 30px rgba(239, 68, 68, 0.6)' 
            : '0 0 20px rgba(34, 197, 94, 0.4)',
        minWidth: '180px'
      }}
    >
      {/* Red Shield Badge for Open Ports */}
      {hasOpenPorts && !isGateway && (
        <div className="absolute -top-2 -right-2 bg-red-500 rounded-full p-2 border-2 border-red-600 shadow-lg z-20 animate-pulse">
          <Shield className="w-4 h-4 text-white" />
        </div>
      )}
      
      {/* Glow effect */}
      <div className={`absolute inset-0 rounded-xl opacity-50 blur-xl ${
        isGateway ? 'bg-cyan-400' : isDangerous ? 'bg-red-500' : 'bg-green-400'
      }`} />
      
      <div className="relative z-10 flex flex-col items-center space-y-2">
        {/* Icon */}
        <div className={`p-3 rounded-full ${
          isGateway ? 'bg-cyan-500/30' : isDangerous ? 'bg-red-500/30' : 'bg-green-500/20'
        }`}>
          <Icon 
            className={`w-8 h-8 ${
              isGateway ? 'text-cyan-300' : isDangerous ? 'text-red-400' : 'text-green-400'
            }`} 
          />
        </div>
        
        {/* Label */}
        <div className="text-center">
          <div className="font-bold text-white text-sm">{data.label}</div>
          <div className="text-xs text-gray-300">{data.sublabel}</div>
          {data.vendor && (
            <div className="text-xs text-gray-400 mt-1">{data.vendor}</div>
          )}
        </div>
        
        {/* Status badges */}
        {isDangerous && !isGateway && (
          <div className="flex items-center space-x-1 text-xs text-red-400">
            <AlertTriangle className="w-3 h-3" />
            <span>Threat Detected</span>
          </div>
        )}
        
        {data.openPorts > 0 && !isGateway && (
          <div className="text-xs bg-orange-500/30 px-2 py-1 rounded border border-orange-400">
            {data.openPorts} open ports
          </div>
        )}
      </div>
    </div>
  );
};

const nodeTypes = {
  device: DeviceNode,
};

export default function NetworkGraph({ 
  devices, 
  gatewayIP, 
  arpCompromised,
  onScanPorts,
  scanningPort,
  portResults 
}: NetworkGraphProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState<Node<DeviceNodeData>>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null);
  const [isScanning, setIsScanning] = useState(false);

  // Get vendor icon
  const getVendorIcon = (vendor: string) => {
    const v = vendor?.toLowerCase() || '';
    if (v.includes('apple') || v.includes('iphone') || v.includes('ipad')) return Smartphone;
    if (v.includes('raspberry') || v.includes('pi')) return Cpu;
    if (v.includes('dell') || v.includes('hp') || v.includes('lenovo')) return Monitor;
    if (v.includes('intel') || v.includes('realtek') || v.includes('broadcom')) return Cpu;
    if (v.includes('synology') || v.includes('nas')) return HardDrive;
    return Wifi; // Default
  };

  // Transform devices to nodes and edges
  useEffect(() => {
    if (!devices || devices.length === 0) {
      setNodes([]);
      setEdges([]);
      return;
    }

    // Calculate radial layout
    const centerX = 400;
    const centerY = 300;
    const radius = 250;
    
    const newNodes: Node[] = [];
    const newEdges: Edge[] = [];

    // Gateway/Router node (center)
    newNodes.push({
      id: 'gateway',
      type: 'device',
      position: { x: centerX, y: centerY },
      data: {
        label: gatewayIP || 'Gateway',
        sublabel: 'Router',
        icon: Router,
        isGateway: true,
        isDangerous: arpCompromised || false,
        openPorts: 0,
        onClick: () => {}, // No action for gateway
      },
      draggable: true,
    });

    // Device nodes (radial layout)
    devices.forEach((device, index) => {
      if (!device || !device.mac) return;

      const angle = (2 * Math.PI * index) / devices.length;
      const x = centerX + radius * Math.cos(angle);
      const y = centerY + radius * Math.sin(angle);

      const deviceResults = portResults?.get(device.mac);
      const openPortsCount = deviceResults?.filter(p => p.open).length || 0;
      const hasDangerousPorts = deviceResults?.some(p => p.open && p.dangerous) || false;
      const isDangerous = device.isRogue || hasDangerousPorts;
      const deviceId = device.id || device.mac;

      newNodes.push({
        id: deviceId,
        type: 'device',
        position: { x, y },
        data: {
          label: device.ip,
          sublabel: device.name || 'Device',
          vendor: device.vendor,
          icon: getVendorIcon(device.vendor),
          isDangerous,
          isGateway: false,
          openPorts: openPortsCount,
          onClick: () => setSelectedDevice(device), // Click handler
        },
        draggable: true,
      });

      // Edge from gateway to device
      newEdges.push({
        id: `e-gateway-${deviceId}`,
        source: 'gateway',
        target: deviceId,
        animated: true,
        style: {
          stroke: isDangerous ? '#ef4444' : arpCompromised ? '#f59e0b' : '#22c55e',
          strokeWidth: 2,
        },
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: isDangerous ? '#ef4444' : arpCompromised ? '#f59e0b' : '#22c55e',
        },
      });
    });

    setNodes(newNodes);
    setEdges(newEdges);
  }, [devices, gatewayIP, arpCompromised, portResults, setNodes, setEdges]);

  return (
    <div className="w-full h-[600px] rounded-lg border border-cyan-500/30 overflow-hidden relative">
      {/* Background overlay */}
      <div className="absolute inset-0 bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 opacity-95" />
      
      {/* ARP Compromised Alert Banner */}
      {arpCompromised && (
        <div className="absolute top-4 left-1/2 transform -translate-x-1/2 z-50 bg-red-500/90 backdrop-blur-md px-6 py-3 rounded-lg border-2 border-red-400 shadow-2xl animate-pulse">
          <div className="flex items-center space-x-3">
            <AlertTriangle className="w-6 h-6 text-white" />
            <div>
              <div className="font-bold text-white text-sm">ARP SPOOFING DETECTED</div>
              <div className="text-xs text-red-100">Network may be compromised - Review gateway</div>
            </div>
          </div>
        </div>
      )}

      {/* React Flow */}
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        fitView
        className="relative z-10"
        minZoom={0.5}
        maxZoom={2}
        defaultViewport={{ x: 0, y: 0, zoom: 1 }}
      >
        <Background 
          color="#0ea5e9" 
          gap={20} 
          size={1} 
          className="opacity-20"
        />
        <Controls 
          className="bg-slate-800/80 backdrop-blur-md border border-cyan-500/30 rounded-lg"
        />
        <MiniMap 
          nodeColor={(node) => {
            if (node.data.isGateway) return '#22d3ee';
            if (node.data.isDangerous) return '#ef4444';
            return '#22c55e';
          }}
          className="bg-slate-800/80 backdrop-blur-md border border-cyan-500/30 rounded-lg"
        />
      </ReactFlow>

      {/* Legend */}
      <div className="absolute bottom-4 right-4 bg-slate-800/80 backdrop-blur-md border border-cyan-500/30 rounded-lg p-4 z-20">
        <div className="text-xs font-bold text-cyan-400 mb-2">Legend</div>
        <div className="space-y-1 text-xs">
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 rounded-full bg-cyan-400" />
            <span className="text-gray-300">Gateway/Router</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 rounded-full bg-green-400" />
            <span className="text-gray-300">Secure Device</span>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 rounded-full bg-red-500" />
            <span className="text-gray-300">Threat/Unknown</span>
          </div>
        </div>
      </div>

      {/* Device count */}
      <div className="absolute top-4 left-4 bg-slate-800/80 backdrop-blur-md border border-cyan-500/30 rounded-lg px-4 py-2 z-20">
        <div className="flex items-center space-x-2">
          <Shield className="w-4 h-4 text-cyan-400" />
          <span className="text-sm font-bold text-white">{devices.length} Devices</span>
        </div>
      </div>

      {/* Device Detail Panel */}
      <AnimatePresence>
        {selectedDevice && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="absolute inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center"
            onClick={() => setSelectedDevice(null)}
          >
            <motion.div
              initial={{ scale: 0.9, y: 20 }}
              animate={{ scale: 1, y: 0 }}
              exit={{ scale: 0.9, y: 20 }}
              onClick={(e) => e.stopPropagation()}
              className="bg-slate-900/95 backdrop-blur-xl border-2 border-cyan-500/50 rounded-2xl p-6 max-w-lg w-full mx-4 shadow-2xl"
              style={{ boxShadow: '0 0 40px rgba(34, 211, 238, 0.4)' }}
            >
              {/* Header */}
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                  <div className="p-3 bg-cyan-500/20 rounded-xl">
                    {React.createElement(getVendorIcon(selectedDevice.vendor), {
                      className: 'w-8 h-8 text-cyan-400'
                    })}
                  </div>
                  <div>
                    <h3 className="text-xl font-bold text-white">Device Details</h3>
                    <p className="text-sm text-slate-400">{selectedDevice.name || 'Unknown Device'}</p>
                  </div>
                </div>
                <button
                  onClick={() => setSelectedDevice(null)}
                  className="p-2 hover:bg-slate-800 rounded-lg transition-colors"
                >
                  <X className="w-5 h-5 text-slate-400" />
                </button>
              </div>

              {/* Device Info Grid */}
              <div className="grid grid-cols-2 gap-4 mb-6">
                <div className="bg-slate-800/50 rounded-lg p-3">
                  <div className="text-xs text-slate-400 mb-1">IP Address</div>
                  <div className="text-white font-mono font-bold">{selectedDevice.ip}</div>
                </div>
                <div className="bg-slate-800/50 rounded-lg p-3">
                  <div className="text-xs text-slate-400 mb-1">MAC Address</div>
                  <div className="text-white font-mono text-sm">{selectedDevice.mac}</div>
                </div>
                <div className="bg-slate-800/50 rounded-lg p-3">
                  <div className="text-xs text-slate-400 mb-1">Vendor</div>
                  <div className="text-white font-semibold">{selectedDevice.vendor}</div>
                </div>
                <div className="bg-slate-800/50 rounded-lg p-3">
                  <div className="text-xs text-slate-400 mb-1">Status</div>
                  <div className={`font-semibold ${
                    selectedDevice.status === 'online' ? 'text-green-400' : 'text-slate-400'
                  }`}>
                    {selectedDevice.status?.toUpperCase() || 'UNKNOWN'}
                  </div>
                </div>
              </div>

              {/* Security Status */}
              {selectedDevice.isRogue && (
                <div className="bg-red-500/20 border border-red-500/50 rounded-lg p-3 mb-4">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-5 h-5 text-red-400" />
                    <span className="text-red-400 font-semibold">Unknown/Rogue Device</span>
                  </div>
                </div>
              )}

              {/* Port Scan Results */}
              {portResults?.get(selectedDevice.mac) && (
                <div className="bg-slate-800/50 rounded-lg p-4 mb-4">
                  <div className="text-sm font-semibold text-white mb-3">Port Scan Results</div>
                  <div className="flex flex-wrap gap-2">
                    {portResults.get(selectedDevice.mac)?.filter(p => p.open).map((port) => (
                      <div
                        key={port.port}
                        className={`px-3 py-1 rounded text-xs font-semibold ${
                          port.dangerous
                            ? 'bg-red-500/30 text-red-300 border border-red-500'
                            : 'bg-green-500/20 text-green-400'
                        }`}
                      >
                        {port.dangerous && '⚠️ '}
                        {port.port} - {port.name}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Deep Scan Button */}
              {selectedDevice.status === 'online' && onScanPorts && (
                <button
                  onClick={async () => {
                    setIsScanning(true);
                    await onScanPorts(selectedDevice.ip, selectedDevice.mac);
                    setIsScanning(false);
                  }}
                  disabled={scanningPort === selectedDevice.mac || isScanning}
                  className="w-full py-3 bg-gradient-to-r from-cyan-500 to-blue-500 hover:from-cyan-600 hover:to-blue-600 text-white font-bold rounded-xl transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                >
                  {scanningPort === selectedDevice.mac || isScanning ? (
                    <>
                      <RefreshCw className="w-5 h-5 animate-spin" />
                      Scanning Ports...
                    </>
                  ) : (
                    <>
                      <Scan className="w-5 h-5" />
                      RUN DEEP SCAN
                    </>
                  )}
                </button>
              )}

              {selectedDevice.status !== 'online' && (
                <div className="text-center py-3 text-slate-400 text-sm">
                  Device is offline. Deep scan not available.
                </div>
              )}
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
