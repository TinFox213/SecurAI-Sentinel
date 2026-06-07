import React, { useState, useEffect } from 'react';
import { ScanType } from '../../types/types';
import {
  Activity,
  BrainCircuit,
  History,
  Trash2,
  TrendingUp,
} from 'lucide-react';
import { getAllScans, deleteScan, ScanHistory } from '../../services/db';
import {
  ModuleGroupConfig,
  ModuleNavItem,
  teamModuleGroups,
} from '../../config/modules';
import { useAiProviders } from '../../hooks/useAiProviders';

interface SidebarProps {
  currentType: ScanType;
  onSelect: (type: ScanType) => void;
  onLoadHistory?: (scan: ScanHistory) => void;
}

type TeamModuleGroup = ModuleGroupConfig & { modules: ModuleNavItem[] };

const Sidebar: React.FC<SidebarProps> = ({ currentType, onSelect, onLoadHistory }) => {
  const [historyScans, setHistoryScans] = useState<ScanHistory[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const { status: aiStatus } = useAiProviders(45000);
  const activeProvider = aiStatus.providers.find((provider) => provider.selected);

  useEffect(() => {
    if (showHistory) {
      loadHistory();
    }
  }, [showHistory]);

  const loadHistory = async () => {
    const scans = await getAllScans();
    setHistoryScans(scans);
  };

  const handleDeleteScan = async (id: number, e: React.MouseEvent) => {
    e.stopPropagation();
    await deleteScan(id);
    loadHistory();
  };

  const handleSelect = (type: ScanType) => {
    setShowHistory(false);
    onSelect(type);
  };

  const renderNavButton = (item: ModuleNavItem, extraClassName = '') => {
    const Icon = item.icon;
    const isActive = currentType === item.type && !showHistory;

    return (
      <button
        key={item.type}
        onClick={() => handleSelect(item.type)}
        className={`${extraClassName} group w-full min-h-10 flex items-center justify-between gap-2 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 ${
          isActive
            ? 'bg-cyan-400/12 text-cyan-100 border border-cyan-300/30 shadow-[inset_3px_0_0_0_rgba(34,211,238,0.95),0_10px_24px_rgba(6,182,212,0.08)]'
            : 'border border-transparent text-slate-400 hover:text-slate-100 hover:bg-white/[0.055] hover:border-white/10'
        }`}
      >
        <span className="inline-flex min-w-0 items-center gap-3">
          <span className={`flex h-7 w-7 items-center justify-center rounded-lg border ${
            isActive
              ? 'border-cyan-300/25 bg-cyan-300/10 text-cyan-200'
              : 'border-white/5 bg-white/[0.035] text-slate-500 group-hover:text-slate-300'
          }`}>
            <Icon className="w-3.5 h-3.5 flex-shrink-0" />
          </span>
          <span className="truncate">{item.label}</span>
        </span>
        {item.agent && (
          <span className="inline-flex flex-shrink-0 items-center gap-1 px-1.5 py-0.5 rounded-full text-[9px] font-bold border border-cyan-400/40 bg-cyan-500/10 text-cyan-200">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-300 animate-pulse" />
            AI
          </span>
        )}
      </button>
    );
  };

  const renderHistoryButton = () => (
    <div className="mt-2 border-t border-white/10 pt-2">
      <button
        onClick={() => setShowHistory(!showHistory)}
        className={`w-full min-h-10 flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200 ${
          showHistory
            ? 'bg-cyan-400/12 text-cyan-100 border border-cyan-300/30 shadow-[inset_3px_0_0_0_rgba(34,211,238,0.95)]'
            : 'border border-transparent text-slate-400 hover:text-slate-100 hover:bg-white/[0.055] hover:border-white/10'
        }`}
      >
        <span className={`flex h-7 w-7 items-center justify-center rounded-lg border ${
          showHistory
            ? 'border-cyan-300/25 bg-cyan-300/10 text-cyan-200'
            : 'border-white/5 bg-white/[0.035] text-slate-500'
        }`}>
          <TrendingUp className="w-3.5 h-3.5 flex-shrink-0" />
        </span>
        <span className="truncate">Scan History & Reports</span>
      </button>

      {showHistory && (
        <div className="px-2 py-3">
          <p className="mb-2 text-xs font-semibold text-slate-500 uppercase tracking-wider flex items-center gap-2">
            <History className="w-3 h-3" /> Recent Scans
          </p>
          <div className="space-y-2">
            {historyScans.length === 0 ? (
              <div className="py-5 text-center text-slate-600 text-xs">
                No scans yet
              </div>
            ) : (
              historyScans.map((scan) => (
                <button
                  key={scan.id}
                  onClick={() => onLoadHistory?.(scan)}
                  className="w-full flex items-center justify-between gap-2 px-3 py-2.5 rounded-lg text-xs border border-white/5 bg-white/[0.025] hover:bg-white/[0.06] transition-all group"
                >
                  <div className="flex-1 text-left min-w-0">
                    <div className="text-slate-300 font-medium truncate">{scan.scanType}</div>
                    <div className="text-slate-600 font-mono text-[10px]">
                      {new Date(scan.timestamp).toLocaleDateString()} {new Date(scan.timestamp).toLocaleTimeString()}
                    </div>
                  </div>
                  <button
                    onClick={(e) => handleDeleteScan(scan.id!, e)}
                    className="opacity-0 group-hover:opacity-100 text-red-500 hover:text-red-400 transition-opacity flex-shrink-0"
                    title="Delete scan"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                </button>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );

  const renderGroup = (group: TeamModuleGroup) => {
    const GroupIcon = group.icon;
    return (
      <section key={group.id} className="mb-4" title={group.description}>
        <div className="px-2 mb-2 flex items-center gap-2 text-xs font-semibold text-slate-500 uppercase tracking-wider">
          <GroupIcon className="h-3.5 w-3.5 text-slate-600" />
          <span className="truncate">{group.label}</span>
        </div>
        <div className="space-y-1.5">
          {group.modules.map((item) => renderNavButton(item))}
          {group.id === 'command' && renderHistoryButton()}
        </div>
      </section>
    );
  };

  return (
    <div className="flex flex-col h-full w-full glass-sidebar relative z-50">
      <div className="p-5 border-b border-white/10 flex items-center gap-3 flex-shrink-0">
        <div className="w-9 h-9 rounded-lg border border-cyan-300/25 bg-cyan-400/10 text-cyan-200 flex items-center justify-center shadow-[0_10px_28px_rgba(6,182,212,0.12)]">
          <Activity className="w-5 h-5" />
        </div>
        <div className="min-w-0">
          <h1 className="font-bold text-slate-100 tracking-tight">SecurAI</h1>
          <p className="text-xs text-slate-500 font-mono">SENTINEL V2.0</p>
        </div>
      </div>

      <div className="flex-1 min-h-0 overflow-y-auto p-3.5">
        {teamModuleGroups.map(renderGroup)}
      </div>

      <div className="p-4 border-t border-white/10 flex-shrink-0">
        <div className="rounded-lg p-3 border border-white/10 bg-slate-950/35 backdrop-blur-xl shadow-[0_18px_45px_rgba(2,6,23,0.22)]">
          <div className="flex items-center justify-between gap-2 mb-2">
            <div className="flex items-center gap-2 min-w-0">
              <div className={`w-2 h-2 rounded-full ${aiStatus.healthy ? 'bg-emerald-400 shadow-[0_0_12px_rgba(52,211,153,0.8)]' : 'bg-amber-400 shadow-[0_0_12px_rgba(251,191,36,0.65)]'}`}></div>
              <span className={`text-xs font-mono truncate ${aiStatus.healthy ? 'text-emerald-400' : 'text-amber-400'}`}>
                {aiStatus.healthy ? 'AI ROUTING ONLINE' : 'AI ROUTING LIMITED'}
              </span>
            </div>
            <BrainCircuit className="w-3.5 h-3.5 text-slate-500" />
          </div>
          <p className="text-[10px] text-slate-500 truncate">
            {activeProvider ? `${activeProvider.label}: ${activeProvider.model}` : aiStatus.message}
          </p>
        </div>
      </div>
    </div>
  );
};

export default Sidebar;
