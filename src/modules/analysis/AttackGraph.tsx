import React, { useMemo } from 'react';
import ReactFlow, {
  Node,
  Edge,
  Background,
  Controls,
  MiniMap,
  NodeTypes,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { SecurityAnalysis, ThreatLevel } from '../../types/types';

interface AttackGraphProps {
  analysis: SecurityAnalysis;
}

interface AttackNodeData {
  label: string;
  description: string;
  type: 'attacker' | 'vector' | 'target' | 'impact';
}

const AttackNode: React.FC<{ data: AttackNodeData }> = ({ data }) => {
  const getNodeStyle = () => {
    switch (data.type) {
      case 'attacker':
        return 'bg-red-500/20 border-red-500 text-red-400';
      case 'vector':
        return 'bg-orange-500/20 border-orange-500 text-orange-400';
      case 'target':
        return 'bg-yellow-500/20 border-yellow-500 text-yellow-400';
      case 'impact':
        return 'bg-purple-500/20 border-purple-500 text-purple-400';
      default:
        return 'bg-slate-500/20 border-slate-500 text-slate-400';
    }
  };

  return (
    <div className={`px-4 py-3 rounded-lg border-2 backdrop-blur-sm shadow-lg min-w-[150px] ${getNodeStyle()}`}>
      <div className="font-bold text-sm mb-1">{data.label}</div>
      <div className="text-xs opacity-80">{data.description}</div>
    </div>
  );
};

const nodeTypes: NodeTypes = {
  attackNode: AttackNode,
};

const AttackGraph: React.FC<AttackGraphProps> = ({ analysis }) => {
  const { nodes, edges } = useMemo(() => {
    // Parse the detailed analysis to extract attack chain
    const analysisText = analysis.detailed_analysis.toLowerCase();
    
    // Create nodes based on threat level and analysis
    const attackNodes: Node<AttackNodeData>[] = [
      {
        id: '1',
        type: 'attackNode',
        position: { x: 50, y: 100 },
        data: {
          label: 'Threat Actor',
          description: analysis.threat_level === ThreatLevel.CRITICAL || analysis.threat_level === ThreatLevel.HIGH 
            ? 'Advanced Attacker' 
            : 'Opportunistic Actor',
          type: 'attacker',
        },
      },
      {
        id: '2',
        type: 'attackNode',
        position: { x: 300, y: 100 },
        data: {
          label: 'Attack Vector',
          description: analysisText.includes('sql') ? 'SQL Injection' :
                      analysisText.includes('xss') ? 'XSS' :
                      analysisText.includes('port') ? 'Exposed Services' :
                      analysisText.includes('phish') ? 'Social Engineering' :
                      analysisText.includes('malware') ? 'Malware Delivery' :
                      'Vulnerability Exploit',
          type: 'vector',
        },
      },
      {
        id: '3',
        type: 'attackNode',
        position: { x: 550, y: 100 },
        data: {
          label: 'Target System',
          description: analysisText.includes('database') ? 'Database Server' :
                      analysisText.includes('web') || analysisText.includes('http') ? 'Web Application' :
                      analysisText.includes('network') ? 'Network Infrastructure' :
                      'System Resources',
          type: 'target',
        },
      },
      {
        id: '4',
        type: 'attackNode',
        position: { x: 300, y: 250 },
        data: {
          label: 'Impact',
          description: `Risk Score: ${analysis.risk_score}/100\n${analysis.threat_level} Threat`,
          type: 'impact',
        },
      },
    ];

    const attackEdges: Edge[] = [
      {
        id: 'e1-2',
        source: '1',
        target: '2',
        animated: true,
        style: { stroke: '#ef4444', strokeWidth: 2 },
        label: 'Initiates',
      },
      {
        id: 'e2-3',
        source: '2',
        target: '3',
        animated: true,
        style: { stroke: '#f97316', strokeWidth: 2 },
        label: 'Exploits',
      },
      {
        id: 'e3-4',
        source: '3',
        target: '4',
        animated: true,
        style: { stroke: '#a855f7', strokeWidth: 2 },
        label: 'Results in',
      },
    ];

    return { nodes: attackNodes, edges: attackEdges };
  }, [analysis]);

  return (
    <div className="h-[400px] w-full bg-slate-950/50 backdrop-blur-sm rounded-lg border border-white/10 overflow-hidden">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        attributionPosition="bottom-left"
      >
        <Background color="#334155" gap={16} />
        <Controls className="bg-slate-900/80 backdrop-blur-sm border border-white/10 rounded-lg" />
        <MiniMap 
          className="bg-slate-900/80 backdrop-blur-sm border border-white/10 rounded-lg" 
          nodeColor={(node) => {
            const data = node.data as AttackNodeData;
            switch (data.type) {
              case 'attacker': return '#ef4444';
              case 'vector': return '#f97316';
              case 'target': return '#eab308';
              case 'impact': return '#a855f7';
              default: return '#64748b';
            }
          }}
        />
      </ReactFlow>
    </div>
  );
};

export default AttackGraph;
