import React from 'react';
import { motion } from 'framer-motion';
import {
  ArrowRight,
  BrainCircuit,
  Gauge,
  Layers3,
  LockKeyhole,
  Radio,
  ShieldCheck,
} from 'lucide-react';
import { ScanType } from '../../types/types';
import { featuredModules, getModule, moduleRegistry, teamModuleGroups } from '../../config/modules';
import { useAiProviders } from '../../hooks/useAiProviders';

interface HomePageProps {
  onNavigate: (type: ScanType) => void;
}

const accentClasses = {
  cyan: 'border-cyan-400/25 text-cyan-200 bg-cyan-500/10',
  emerald: 'border-emerald-400/25 text-emerald-200 bg-emerald-500/10',
  amber: 'border-amber-400/25 text-amber-200 bg-amber-500/10',
  rose: 'border-rose-400/25 text-rose-200 bg-rose-500/10',
  violet: 'border-violet-400/25 text-violet-200 bg-violet-500/10',
  sky: 'border-sky-400/25 text-sky-200 bg-sky-500/10',
};

const HomePage: React.FC<HomePageProps> = ({ onNavigate }) => {
  const { status } = useAiProviders(45000);
  const activeProvider = status.providers.find((provider) => provider.selected);
  const posture = getModule(ScanType.SECURITY_POSTURE);
  const agent = getModule(ScanType.AI_RED_TEAM);
  const moduleCount = moduleRegistry.filter((item) => item.type !== ScanType.HOME).length;

  const stats = [
    { label: 'Mission Modules', value: moduleCount, icon: Layers3, tone: 'text-cyan-300' },
    { label: 'Team Workspaces', value: teamModuleGroups.length, icon: Radio, tone: 'text-emerald-300' },
    { label: 'AI Providers', value: `${status.configuredCount}/${status.totalCount}`, icon: BrainCircuit, tone: 'text-violet-300' },
    { label: 'Security Mode', value: status.healthy ? 'Ready' : 'Local', icon: LockKeyhole, tone: status.healthy ? 'text-emerald-300' : 'text-amber-300' },
  ];

  return (
    <div className="space-y-6 sm:space-y-8">
      <motion.section
        initial={{ opacity: 0, y: 18 }}
        animate={{ opacity: 1, y: 0 }}
        className="relative overflow-hidden rounded-xl glass-panel"
      >
        <div className="absolute inset-0 bg-[linear-gradient(rgba(148,163,184,0.06)_1px,transparent_1px),linear-gradient(90deg,rgba(148,163,184,0.06)_1px,transparent_1px)] bg-[size:36px_36px]" />
        <div className="absolute inset-0 bg-[linear-gradient(135deg,rgba(6,182,212,0.16),transparent_36%,rgba(16,185,129,0.08)_68%,transparent)]" />

        <div className="relative grid min-h-[500px] gap-8 p-5 sm:p-8 lg:grid-cols-[1.05fr_0.95fr] lg:p-10">
          <div className="flex flex-col justify-between gap-8">
            <div>
              <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-cyan-400/25 bg-cyan-500/10 px-3 py-1.5 text-xs font-semibold text-cyan-200">
                <ShieldCheck className="h-3.5 w-3.5" />
                AI Security Operations
              </div>
              <h1 className="max-w-3xl text-4xl font-black leading-tight tracking-normal text-slate-50 sm:text-5xl lg:text-6xl">
                SecurAI Sentinel
              </h1>
              <p className="mt-5 max-w-2xl text-base leading-7 text-slate-300 sm:text-lg">
                A unified cyber command surface for posture, threat analysis, response, forensics, and AI-assisted security work.
              </p>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              {[posture, agent].filter(Boolean).map((item) => {
                const Icon = item!.icon;
                return (
                  <button
                    key={item!.type}
                    onClick={() => onNavigate(item!.type)}
                    className="group flex min-h-[96px] items-center justify-between rounded-lg border border-white/10 bg-white/[0.045] p-4 text-left transition-all hover:border-cyan-400/40 hover:bg-white/[0.075]"
                  >
                    <span className="flex items-center gap-3">
                      <span className={`flex h-11 w-11 items-center justify-center rounded-lg border ${accentClasses[item!.accent]}`}>
                        <Icon className="h-5 w-5" />
                      </span>
                      <span>
                        <span className="block text-sm font-bold text-slate-100">{item!.label}</span>
                        <span className="mt-1 block text-xs text-slate-500">{item!.type}</span>
                      </span>
                    </span>
                    <ArrowRight className="h-4 w-4 text-slate-500 transition-transform group-hover:translate-x-1 group-hover:text-cyan-300" />
                  </button>
                );
              })}
            </div>
          </div>

          <div className="relative flex items-center justify-center">
            <div className="relative aspect-square w-full max-w-[460px]">
              <div className="absolute inset-0 rounded-full border border-cyan-400/20" />
              <div className="absolute inset-[10%] rounded-full border border-emerald-400/15" />
              <div className="absolute inset-[20%] rounded-full border border-violet-400/15" />
              <div className="absolute left-1/2 top-1/2 h-[2px] w-[44%] origin-left animate-spin bg-gradient-to-r from-cyan-300/80 to-transparent" style={{ animationDuration: '7s' }} />
              <div className="absolute left-1/2 top-1/2 h-24 w-24 -translate-x-1/2 -translate-y-1/2 rounded-2xl border border-cyan-400/30 bg-slate-950/90 shadow-[0_0_45px_rgba(6,182,212,0.22)]">
                <div className="flex h-full w-full items-center justify-center">
                  <ShieldCheck className="h-11 w-11 text-cyan-200" />
                </div>
              </div>

              {featuredModules.slice(0, 6).map((item, index) => {
                const Icon = item.icon;
                const positions = [
                  'left-[8%] top-[22%]',
                  'right-[5%] top-[18%]',
                  'right-[12%] bottom-[18%]',
                  'left-[14%] bottom-[14%]',
                  'left-[42%] top-[2%]',
                  'left-[45%] bottom-[3%]',
                ];
                return (
                  <button
                    key={item.type}
                    onClick={() => onNavigate(item.type)}
                    className={`absolute ${positions[index]} flex h-14 w-14 items-center justify-center rounded-xl border bg-slate-950/85 shadow-lg transition-all hover:scale-105 ${accentClasses[item.accent]}`}
                    title={item.label}
                  >
                    <Icon className="h-6 w-6" />
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      </motion.section>

      <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        {stats.map((item) => {
          const Icon = item.icon;
          return (
            <div key={item.label} className="glass-panel rounded-lg p-4">
              <div className="mb-4 flex items-center justify-between">
                <Icon className={`h-5 w-5 ${item.tone}`} />
                <Gauge className="h-4 w-4 text-slate-600" />
              </div>
              <div className="text-2xl font-black text-slate-50">{item.value}</div>
              <div className="mt-1 text-xs font-semibold uppercase tracking-wider text-slate-500">{item.label}</div>
            </div>
          );
        })}
      </section>

      <section className="grid gap-5 xl:grid-cols-[1.3fr_0.7fr]">
        <div className="glass-panel rounded-lg p-5">
          <div className="mb-4 flex items-center justify-between gap-3">
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300">Mission Modules</h2>
            <span className="rounded-full border border-cyan-400/20 bg-cyan-500/10 px-2.5 py-1 text-[10px] font-bold text-cyan-200">
              {featuredModules.length} pinned
            </span>
          </div>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {featuredModules.map((item) => {
              const Icon = item.icon;
              return (
                <button
                  key={item.type}
                  onClick={() => onNavigate(item.type)}
                  className="group min-h-[132px] rounded-lg border border-white/10 bg-white/[0.035] p-4 text-left transition-all hover:border-cyan-400/35 hover:bg-white/[0.065]"
                >
                  <div className="flex items-center justify-between">
                    <span className={`flex h-10 w-10 items-center justify-center rounded-lg border ${accentClasses[item.accent]}`}>
                      <Icon className="h-5 w-5" />
                    </span>
                    <ArrowRight className="h-4 w-4 text-slate-600 transition-transform group-hover:translate-x-1 group-hover:text-cyan-300" />
                  </div>
                  <div className="mt-4 text-sm font-bold text-slate-100">{item.label}</div>
                  <div className="mt-2 text-xs leading-5 text-slate-500">{item.description}</div>
                </button>
              );
            })}
          </div>
        </div>

        <div className="glass-panel rounded-lg p-5">
          <div className="mb-4 flex items-center justify-between gap-3">
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-300">AI Routing</h2>
            <span className={`rounded-full border px-2.5 py-1 text-[10px] font-bold ${status.healthy ? 'border-emerald-400/25 bg-emerald-500/10 text-emerald-200' : 'border-amber-400/25 bg-amber-500/10 text-amber-200'}`}>
              {status.mode.toUpperCase()}
            </span>
          </div>
          <div className="space-y-3">
            {status.providers.length > 0 ? status.providers.map((provider) => (
              <div key={provider.id} className="flex items-center justify-between rounded-lg border border-white/10 bg-slate-950/45 px-3 py-3">
                <div className="min-w-0">
                  <div className="text-sm font-semibold text-slate-100">{provider.label}</div>
                  <div className="truncate text-xs text-slate-500">{provider.model}</div>
                </div>
                <div className={`ml-3 h-2.5 w-2.5 rounded-full ${provider.configured ? 'bg-emerald-400' : 'bg-slate-700'}`} />
              </div>
            )) : (
              <div className="rounded-lg border border-amber-400/15 bg-amber-500/10 p-4 text-sm text-amber-100">
                {status.message}
              </div>
            )}
          </div>
          <div className="mt-4 rounded-lg border border-white/10 bg-slate-950/40 p-4">
            <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">Active Provider</div>
            <div className="mt-2 text-lg font-black text-slate-50">{activeProvider?.label || 'None'}</div>
            <div className="mt-1 text-xs text-slate-500">{activeProvider?.model || status.message}</div>
          </div>
        </div>
      </section>
    </div>
  );
};

export default HomePage;
