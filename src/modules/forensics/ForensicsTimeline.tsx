import React, { useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  AlertTriangle,
  Bookmark,
  BookmarkCheck,
  Calendar,
  Download,
  GitBranch,
  Plus,
  Search,
  Star,
  Trash2,
  X,
  ZoomIn,
  ZoomOut
} from 'lucide-react';
import { ForensicsEvent, ForensicsEventType } from '../../types/types';
import {
  clearForensicsEvents,
  deleteForensicsEvent,
  getForensicsEvents,
  saveForensicsEvent
} from '../../services/db';
import { logForensicsEvent } from '../../utils/forensicsLogger';
import { toast } from 'react-hot-toast';

type SeverityFilter = 'All' | 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

const severities: SeverityFilter[] = ['All', 'Critical', 'High', 'Medium', 'Low', 'Info'];

const eventTypeOptions: ForensicsEventType[] = [
  'port_scan',
  'vuln_detected',
  'phishing_detected',
  'malware_detected',
  'canary_triggered',
  'ghost_port_triggered',
  'arp_spoof_detected',
  'new_device_detected',
  'breach_found',
  'cve_added',
  'attack_classified',
  'ssl_expired',
  'dns_anomaly',
  'log_anomaly',
  'custom'
];

const attackPhases = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact'
];

const severityClass = (severity: ForensicsEvent['severity']) => {
  if (severity === 'Critical') return 'bg-red-500/20 text-red-300 border-red-500/40';
  if (severity === 'High') return 'bg-orange-500/20 text-orange-300 border-orange-500/40';
  if (severity === 'Medium') return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40';
  if (severity === 'Low') return 'bg-blue-500/20 text-blue-300 border-blue-500/40';
  return 'bg-slate-500/20 text-slate-300 border-slate-500/40';
};

const dotColor = (severity: ForensicsEvent['severity']) => {
  if (severity === 'Critical') return '#ef4444';
  if (severity === 'High') return '#f97316';
  if (severity === 'Medium') return '#eab308';
  if (severity === 'Low') return '#38bdf8';
  return '#94a3b8';
};

const ForensicsTimeline: React.FC = () => {
  const [events, setEvents] = useState<ForensicsEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');
  const [severity, setSeverity] = useState<SeverityFilter>('All');
  const [moduleFilter, setModuleFilter] = useState('All');
  const [eventTypeFilter, setEventTypeFilter] = useState<'All' | ForensicsEventType>('All');
  const [search, setSearch] = useState('');
  const [sortNewest, setSortNewest] = useState(true);
  const [viewMode, setViewMode] = useState<'vertical' | 'gantt'>('vertical');
  const [zoom, setZoom] = useState(1);
  const [selectedEvent, setSelectedEvent] = useState<ForensicsEvent | null>(null);
  const [expandedJsonId, setExpandedJsonId] = useState<string | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [reconstruction, setReconstruction] = useState<string>('');
  const [tagInput, setTagInput] = useState('');

  const [manual, setManual] = useState({
    title: '',
    description: '',
    severity: 'Medium' as ForensicsEvent['severity'],
    eventType: 'custom' as ForensicsEventType,
    sourceModule: 'Manual',
    iocInput: '',
    iocs: [] as string[],
    attackPhase: '',
    tagsInput: '',
    tags: [] as string[]
  });

  const loadEvents = async () => {
    setLoading(true);
    const data = await getForensicsEvents();
    setEvents(data);
    setLoading(false);
  };

  React.useEffect(() => {
    loadEvents();
  }, []);

  const modules = useMemo(() => {
    const set = new Set(events.map((e) => e.sourceModule));
    return ['All', ...Array.from(set).sort()];
  }, [events]);

  const filtered = useMemo(() => {
    let rows = [...events];
    if (fromDate) {
      const from = new Date(fromDate).getTime();
      rows = rows.filter((e) => e.timestamp >= from);
    }
    if (toDate) {
      const to = new Date(toDate).getTime() + 86399999;
      rows = rows.filter((e) => e.timestamp <= to);
    }
    if (severity !== 'All') rows = rows.filter((e) => e.severity === severity);
    if (moduleFilter !== 'All') rows = rows.filter((e) => e.sourceModule === moduleFilter);
    if (eventTypeFilter !== 'All') rows = rows.filter((e) => e.eventType === eventTypeFilter);
    if (search.trim()) {
      const q = search.toLowerCase();
      rows = rows.filter((e) => `${e.title} ${e.description}`.toLowerCase().includes(q));
    }
    rows.sort((a, b) => (sortNewest ? b.timestamp - a.timestamp : a.timestamp - b.timestamp));
    return rows;
  }, [events, fromDate, toDate, severity, moduleFilter, eventTypeFilter, search, sortNewest]);

  const groupedByDay = useMemo(() => {
    const groups: Record<string, ForensicsEvent[]> = {};
    filtered.forEach((event) => {
      const day = new Date(event.timestamp).toDateString();
      if (!groups[day]) groups[day] = [];
      groups[day].push(event);
    });
    return groups;
  }, [filtered]);

  const exportTimeline = () => {
    const jsonBlob = new Blob([JSON.stringify(filtered, null, 2)], { type: 'application/json' });
    const jsonUrl = URL.createObjectURL(jsonBlob);
    const jsonA = document.createElement('a');
    jsonA.href = jsonUrl;
    jsonA.download = `forensics-timeline-${Date.now()}.json`;
    jsonA.click();
    URL.revokeObjectURL(jsonUrl);

    const csvHeader = 'timestamp,eventType,sourceModule,severity,title,description,attackPhase,tags';
    const csvRows = filtered.map((e) => {
      const row = [
        new Date(e.timestamp).toISOString(),
        e.eventType,
        e.sourceModule,
        e.severity,
        e.title.replace(/,/g, ';'),
        e.description.replace(/,/g, ';'),
        (e.attackPhase || '').replace(/,/g, ';'),
        (e.tags || []).join('|')
      ];
      return row.join(',');
    });
    const csvBlob = new Blob([`${csvHeader}\n${csvRows.join('\n')}`], { type: 'text/csv' });
    const csvUrl = URL.createObjectURL(csvBlob);
    const csvA = document.createElement('a');
    csvA.href = csvUrl;
    csvA.download = `forensics-timeline-${Date.now()}.csv`;
    csvA.click();
    URL.revokeObjectURL(csvUrl);
  };

  const toggleBookmark = async (id: string) => {
    const event = events.find((e) => e.id === id);
    if (!event) return;
    await saveForensicsEvent({ ...event, isBookmarked: !event.isBookmarked });
    await loadEvents();
  };

  const addTagToEvent = async (id: string, tag: string) => {
    const event = events.find((e) => e.id === id);
    if (!event || !tag.trim()) return;
    const nextTags = Array.from(new Set([...(event.tags || []), tag.trim()]));
    await saveForensicsEvent({ ...event, tags: nextTags });
    setTagInput('');
    await loadEvents();
  };

  const reconstructChain = () => {
    const now = Date.now();
    const last24h = filtered
      .filter((e) => e.timestamp >= now - 24 * 60 * 60 * 1000)
      .sort((a, b) => a.timestamp - b.timestamp);

    if (last24h.length === 0) {
      setReconstruction('No events in selected range to reconstruct.');
      return;
    }

    const lines = last24h.map((e) => {
      const time = new Date(e.timestamp).toLocaleTimeString();
      const phase = e.attackPhase ? ` (${e.attackPhase} phase)` : '';
      return `At ${time}, ${e.sourceModule} recorded: ${e.title}${phase}.`;
    });

    setReconstruction(lines.join(' '));
  };

  const saveManualEvent = async () => {
    if (!manual.title.trim() || !manual.description.trim()) return;
    await logForensicsEvent({
      timestamp: Date.now(),
      eventType: manual.eventType,
      sourceModule: manual.sourceModule || 'Manual',
      severity: manual.severity,
      title: manual.title.trim(),
      description: manual.description.trim(),
      details: { entry: 'manual' },
      attackPhase: manual.attackPhase || undefined,
      ioc: manual.iocs,
      tags: manual.tags
    });

    setManual({
      title: '',
      description: '',
      severity: 'Medium',
      eventType: 'custom',
      sourceModule: 'Manual',
      iocInput: '',
      iocs: [],
      attackPhase: '',
      tagsInput: '',
      tags: []
    });
    setShowModal(false);
    await loadEvents();
  };

  const seedEvents = async () => {
    const samples: Omit<ForensicsEvent, 'id' | 'isBookmarked'>[] = [
      {
        timestamp: Date.now() - 45 * 60 * 1000,
        eventType: 'port_scan',
        sourceModule: 'Port Scanner',
        severity: 'High',
        title: 'Dangerous port 445 detected',
        description: 'Host 192.168.1.5 exposed SMB on 445/tcp.',
        details: { ip: '192.168.1.5', port: 445 },
        attackPhase: 'Discovery',
        ioc: ['192.168.1.5', '445/tcp'],
        tags: ['seed', 'network']
      },
      {
        timestamp: Date.now() - 37 * 60 * 1000,
        eventType: 'canary_triggered',
        sourceModule: 'Canary Factory',
        severity: 'Critical',
        title: 'Canary token triggered',
        description: 'Confidential trap file was opened from external IP.',
        details: { ip: '203.0.113.10' },
        attackPhase: 'Collection',
        ioc: ['203.0.113.10'],
        tags: ['seed', 'deception']
      },
      {
        timestamp: Date.now() - 29 * 60 * 1000,
        eventType: 'malware_detected',
        sourceModule: 'Malware Analysis',
        severity: 'Critical',
        title: 'Ransomware-like behavior detected',
        description: 'Process chain matched known encryption-for-impact patterns.',
        details: { family: 'WannaCry-like' },
        attackPhase: 'Impact',
        ioc: ['CreateRemoteThread', 'beacon.php'],
        tags: ['seed', 'malware']
      },
      {
        timestamp: Date.now() - 20 * 60 * 1000,
        eventType: 'dns_anomaly',
        sourceModule: 'WebSec Ops',
        severity: 'Medium',
        title: 'DNS resolver mismatch',
        description: 'System DNS differs from trusted resolver response.',
        details: { domain: 'example.com' },
        attackPhase: 'Command and Control',
        ioc: ['example.com'],
        tags: ['seed', 'dns']
      },
      {
        timestamp: Date.now() - 8 * 60 * 1000,
        eventType: 'attack_classified',
        sourceModule: 'MITRE ATT&CK Mapper',
        severity: 'High',
        title: 'ATT&CK chain classified',
        description: 'Mapped findings to Initial Access, Credential Access, and Discovery.',
        details: { tactics: ['Initial Access', 'Credential Access', 'Discovery'] },
        attackPhase: 'Discovery',
        ioc: ['T1190', 'T1110'],
        tags: ['seed', 'mitre']
      }
    ];

    for (const sample of samples) {
      await logForensicsEvent(sample);
    }
    await loadEvents();
    toast.success('Sample forensics events loaded.');
  };

  const minTs = Math.min(...filtered.map((e) => e.timestamp), Date.now() - 60 * 60 * 1000);
  const maxTs = Math.max(...filtered.map((e) => e.timestamp), Date.now());
  const span = Math.max(maxTs - minTs, 1);

  return (
    <div className="space-y-6">
      <div className="bg-slate-900/50 border border-white/10 rounded-2xl p-6 backdrop-blur-xl">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/20 border border-cyan-500/40">
              <GitBranch className="w-6 h-6 text-cyan-300" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-slate-100">Forensics Timeline</h1>
              <p className="text-sm text-slate-400">Chronological reconstruction of all detected security events</p>
            </div>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <span className="px-3 py-1 rounded-full border border-white/10 text-sm text-slate-300">{events.length} events recorded</span>
            <button onClick={seedEvents} className="px-3 py-2 rounded-lg border border-cyan-500/40 text-cyan-300 bg-cyan-500/15 inline-flex items-center gap-2 font-semibold">
              Load Sample Data
            </button>
            <button onClick={() => setShowModal(true)} className="px-3 py-2 rounded-lg border border-cyan-500/40 text-cyan-300 bg-cyan-500/15 inline-flex items-center gap-2">
              <Plus className="w-4 h-4" /> Add Manual Event
            </button>
          </div>
        </div>
      </div>

      <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-4 space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-6 gap-3">
          <input type="date" value={fromDate} onChange={(e) => setFromDate(e.target.value)} className="bg-slate-950/60 border border-white/10 rounded-lg p-2 text-slate-200" />
          <input type="date" value={toDate} onChange={(e) => setToDate(e.target.value)} className="bg-slate-950/60 border border-white/10 rounded-lg p-2 text-slate-200" />
          <select value={moduleFilter} onChange={(e) => setModuleFilter(e.target.value)} className="bg-slate-950/60 border border-white/10 rounded-lg p-2 text-slate-200">
            {modules.map((m) => <option key={m} value={m}>{m}</option>)}
          </select>
          <select value={eventTypeFilter} onChange={(e) => setEventTypeFilter(e.target.value as any)} className="bg-slate-950/60 border border-white/10 rounded-lg p-2 text-slate-200">
            <option value="All">All event types</option>
            {eventTypeOptions.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <div className="xl:col-span-2 flex items-center gap-2 bg-slate-950/60 border border-white/10 rounded-lg px-2">
            <Search className="w-4 h-4 text-slate-500" />
            <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search title/description..." className="w-full bg-transparent p-2 text-slate-200 outline-none" />
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            {severities.map((s) => (
              <button key={s} onClick={() => setSeverity(s)} className={`px-2.5 py-1 rounded-full border text-xs ${severity === s ? 'border-cyan-500/40 text-cyan-300 bg-cyan-500/15' : 'border-white/10 text-slate-400'}`}>
                {s}
              </button>
            ))}
            <button onClick={() => setSortNewest((v) => !v)} className="px-2.5 py-1 rounded border border-white/10 text-xs text-slate-300">
              {sortNewest ? 'Newest First' : 'Oldest First'}
            </button>
            <button onClick={() => setViewMode((v) => (v === 'vertical' ? 'gantt' : 'vertical'))} className="px-2.5 py-1 rounded border border-white/10 text-xs text-slate-300">
              View: {viewMode === 'vertical' ? 'Vertical' : 'Gantt'}
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button onClick={reconstructChain} className="px-3 py-1.5 rounded border border-purple-500/40 text-purple-300 bg-purple-500/15 text-xs">
              Reconstruct Attack Chain
            </button>
            <button onClick={exportTimeline} className="px-3 py-1.5 rounded border border-cyan-500/40 text-cyan-300 bg-cyan-500/15 text-xs inline-flex items-center gap-1">
              <Download className="w-3 h-3" /> Export Timeline
            </button>
            <button
              onClick={async () => {
                if (!confirm('Clear all events?')) return;
                await clearForensicsEvents();
                await loadEvents();
              }}
              className="px-3 py-1.5 rounded border border-red-500/40 text-red-300 bg-red-500/15 text-xs"
            >
              Clear All Events
            </button>
          </div>
        </div>
      </div>

      {reconstruction && (
        <div className="bg-purple-500/10 border border-purple-500/30 rounded-xl p-4 text-sm text-slate-200">
          {reconstruction}
        </div>
      )}

      {loading ? (
        <div className="text-slate-400">Loading timeline...</div>
      ) : filtered.length === 0 ? (
        <div className="bg-slate-900/40 border border-white/10 rounded-2xl p-10 text-center">
          <GitBranch className="w-16 h-16 mx-auto text-cyan-400 animate-pulse" />
          <h3 className="text-2xl font-bold text-slate-100 mt-4">No events recorded yet</h3>
          <p className="text-slate-400 mt-2">Events are automatically captured as you use other modules.</p>
          <button onClick={seedEvents} className="mt-4 px-4 py-2 rounded-lg border border-cyan-500/40 bg-cyan-500/15 text-cyan-300">
            Add Test Event
          </button>
        </div>
      ) : viewMode === 'vertical' ? (
        <div className="space-y-4">
          {Object.entries(groupedByDay).map(([day, dayEvents]) => (
            <div key={day}>
              <div className="sticky top-0 z-10 bg-slate-950/85 border border-white/10 rounded-lg px-3 py-1 text-xs text-slate-400 inline-flex items-center gap-1">
                <Calendar className="w-3 h-3" /> {day}
              </div>

              <div className="mt-3 space-y-3">
                {dayEvents.map((event) => (
                  <div key={event.id} className="grid grid-cols-1 lg:grid-cols-12 gap-3">
                    <div className="lg:col-span-3 text-xs text-slate-400">
                      <div>{new Date(event.timestamp).toLocaleDateString()}</div>
                      <div>{new Date(event.timestamp).toLocaleTimeString()}</div>
                      <div className="mt-1 px-2 py-1 rounded-full border border-white/10 inline-block">{event.sourceModule}</div>
                    </div>
                    <div className="lg:col-span-1 flex justify-center">
                      <div className="w-0.5 bg-white/10 relative">
                        <span className="absolute -left-1.5 top-2 w-3 h-3 rounded-full" style={{ backgroundColor: dotColor(event.severity) }} />
                      </div>
                    </div>
                    <div className="lg:col-span-8 bg-slate-900/45 border border-white/10 rounded-xl p-4">
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className={`px-2 py-1 rounded-full border text-xs ${severityClass(event.severity)}`}>{event.severity}</span>
                          <span className="text-xs text-slate-400">{event.eventType}</span>
                        </div>
                        <button onClick={() => toggleBookmark(event.id)} className="text-slate-300">
                          {event.isBookmarked ? <BookmarkCheck className="w-4 h-4 text-yellow-300" /> : <Bookmark className="w-4 h-4" />}
                        </button>
                      </div>
                      <h3 className="text-slate-100 font-semibold mt-2">{event.title}</h3>
                      <p className="text-sm text-slate-300 mt-1">{event.description}</p>
                      {(event.ioc || []).length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-2">
                          {event.ioc!.map((ioc) => <span key={ioc} className="text-xs px-2 py-1 rounded border border-white/10 bg-slate-950/60 text-slate-300 font-mono">{ioc}</span>)}
                        </div>
                      )}
                      {event.attackPhase && <div className="mt-2 text-xs text-cyan-300">{event.attackPhase}</div>}
                      {(event.relatedEventIds || []).length > 0 && (
                        <div className="mt-2 text-xs text-slate-400">Related Events: {event.relatedEventIds?.length}</div>
                      )}
                      {(event.tags || []).length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-2">
                          {event.tags.map((tag) => <span key={tag} className="text-xs px-2 py-1 rounded-full border border-purple-500/30 text-purple-300">#{tag}</span>)}
                        </div>
                      )}
                      <div className="mt-3 flex items-center gap-2">
                        <button onClick={() => setExpandedJsonId(expandedJsonId === event.id ? null : event.id)} className="text-xs text-cyan-300 border border-cyan-500/30 rounded px-2 py-1">{expandedJsonId === event.id ? 'Collapse' : 'Expand'} Details</button>
                        <button onClick={() => setSelectedEvent(event)} className="text-xs text-slate-300 border border-white/10 rounded px-2 py-1">Open Drawer</button>
                      </div>
                      {expandedJsonId === event.id && (
                        <pre className="mt-2 text-xs bg-slate-950/70 border border-white/10 rounded p-2 overflow-x-auto text-emerald-300">{JSON.stringify(event.details, null, 2)}</pre>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="bg-slate-900/45 border border-white/10 rounded-2xl p-4">
          <div className="flex justify-end gap-2 mb-3">
            <button onClick={() => setZoom((z) => Math.max(0.5, z - 0.25))} className="p-1.5 rounded border border-white/10 text-slate-300"><ZoomOut className="w-4 h-4" /></button>
            <button onClick={() => setZoom((z) => Math.min(3, z + 0.25))} className="p-1.5 rounded border border-white/10 text-slate-300"><ZoomIn className="w-4 h-4" /></button>
          </div>
          <div className="overflow-auto">
            <svg width={Math.max(900, 900 * zoom)} height={Math.max(260, modules.length * 42 + 60)}>
              {modules.filter((m) => m !== 'All').map((module, idx) => (
                <g key={module}>
                  <text x="8" y={50 + idx * 40} fill="#94a3b8" fontSize="11">{module}</text>
                  <line x1="140" x2={Math.max(860, 860 * zoom)} y1={45 + idx * 40} y2={45 + idx * 40} stroke="rgba(148,163,184,0.2)" />
                </g>
              ))}

              {filtered.map((event) => {
                const yIndex = Math.max(0, modules.filter((m) => m !== 'All').indexOf(event.sourceModule));
                const x = 140 + ((event.timestamp - minTs) / span) * (Math.max(720, 720 * zoom));
                const y = 45 + yIndex * 40;
                return (
                  <g key={event.id} onClick={() => setSelectedEvent(event)}>
                    <circle cx={x} cy={y} r={6} fill={dotColor(event.severity)} style={{ cursor: 'pointer' }}>
                      <title>{`${event.title} (${event.severity})`}</title>
                    </circle>
                  </g>
                );
              })}
            </svg>
          </div>
        </div>
      )}

      <AnimatePresence>
        {selectedEvent && (
          <motion.div
            initial={{ x: 420, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: 420, opacity: 0 }}
            className="fixed top-0 right-0 h-full w-full max-w-md bg-slate-950/95 border-l border-white/10 z-50 p-5 overflow-y-auto"
          >
            <div className="flex items-start justify-between gap-2">
              <h3 className="text-lg font-bold text-slate-100">Event Details</h3>
              <button onClick={() => setSelectedEvent(null)} className="text-slate-300"><X className="w-5 h-5" /></button>
            </div>
            <div className="mt-4 space-y-3 text-sm">
              <div className={`inline-flex px-2 py-1 rounded border ${severityClass(selectedEvent.severity)}`}>{selectedEvent.severity}</div>
              <div className="text-slate-100 font-semibold">{selectedEvent.title}</div>
              <div className="text-slate-300">{selectedEvent.description}</div>
              <div className="text-slate-400">{new Date(selectedEvent.timestamp).toLocaleString()}</div>
              {selectedEvent.attackPhase && (
                <button className="text-cyan-300 underline">Link to ATT&CK: {selectedEvent.attackPhase}</button>
              )}
              <div>
                <div className="text-slate-400 mb-1">IOCs</div>
                <div className="space-y-2">
                  {(selectedEvent.ioc || []).map((ioc) => (
                    <div key={ioc} className="flex items-center justify-between bg-slate-900/70 border border-white/10 rounded p-2 text-xs font-mono text-slate-200">
                      <span>{ioc}</span>
                      <button onClick={() => navigator.clipboard.writeText(ioc)} className="text-cyan-300">Copy</button>
                    </div>
                  ))}
                </div>
              </div>

              <details className="bg-slate-900/70 border border-white/10 rounded p-2">
                <summary className="cursor-pointer text-slate-300">Details JSON</summary>
                <pre className="mt-2 text-xs text-emerald-300 overflow-x-auto">{JSON.stringify(selectedEvent.details, null, 2)}</pre>
              </details>

              <div className="flex items-center gap-2">
                <input value={tagInput} onChange={(e) => setTagInput(e.target.value)} placeholder="Add tag" className="flex-1 bg-slate-900/70 border border-white/10 rounded p-2 text-slate-200" />
                <button onClick={() => addTagToEvent(selectedEvent.id, tagInput)} className="px-2 py-2 border border-cyan-500/40 text-cyan-300 rounded">Add Tag</button>
              </div>

              <div className="flex gap-2">
                <button onClick={() => toggleBookmark(selectedEvent.id)} className="px-3 py-1.5 rounded border border-yellow-500/40 text-yellow-300 bg-yellow-500/10 inline-flex items-center gap-1">
                  <Star className="w-3 h-3" /> Bookmark
                </button>
                <button
                  onClick={async () => {
                    if (!confirm('Delete this event?')) return;
                    await deleteForensicsEvent(selectedEvent.id);
                    setSelectedEvent(null);
                    await loadEvents();
                  }}
                  className="px-3 py-1.5 rounded border border-red-500/40 text-red-300 bg-red-500/10 inline-flex items-center gap-1"
                >
                  <Trash2 className="w-3 h-3" /> Delete Event
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      <AnimatePresence>
        {showModal && (
          <motion.div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
            <motion.div className="w-full max-w-2xl bg-slate-950 border border-white/10 rounded-2xl p-5" initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: 20, opacity: 0 }}>
              <div className="flex justify-between items-center">
                <h3 className="text-lg font-bold text-slate-100">Add Manual Event</h3>
                <button onClick={() => setShowModal(false)} className="text-slate-300"><X className="w-4 h-4" /></button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-4">
                <input value={manual.title} onChange={(e) => setManual((m) => ({ ...m, title: e.target.value }))} placeholder="Title" className="bg-slate-900/70 border border-white/10 rounded p-2 text-slate-200" />
                <input value={manual.sourceModule} onChange={(e) => setManual((m) => ({ ...m, sourceModule: e.target.value }))} placeholder="Source Module" className="bg-slate-900/70 border border-white/10 rounded p-2 text-slate-200" />
                <select value={manual.severity} onChange={(e) => setManual((m) => ({ ...m, severity: e.target.value as any }))} className="bg-slate-900/70 border border-white/10 rounded p-2 text-slate-200">
                  {severities.filter((s) => s !== 'All').map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
                <select value={manual.eventType} onChange={(e) => setManual((m) => ({ ...m, eventType: e.target.value as ForensicsEventType }))} className="bg-slate-900/70 border border-white/10 rounded p-2 text-slate-200">
                  {eventTypeOptions.map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>

              <textarea value={manual.description} onChange={(e) => setManual((m) => ({ ...m, description: e.target.value }))} placeholder="Description" className="w-full mt-3 h-20 bg-slate-900/70 border border-white/10 rounded p-2 text-slate-200" />

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">
                <div className="bg-slate-900/70 border border-white/10 rounded p-2">
                  <input
                    value={manual.iocInput}
                    onChange={(e) => setManual((m) => ({ ...m, iocInput: e.target.value }))}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && manual.iocInput.trim()) {
                        e.preventDefault();
                        setManual((m) => ({ ...m, iocs: Array.from(new Set([...m.iocs, m.iocInput.trim()])), iocInput: '' }));
                      }
                    }}
                    placeholder="IOCs (press Enter)"
                    className="w-full bg-transparent outline-none text-slate-200"
                  />
                  <div className="flex flex-wrap gap-1 mt-2">
                    {manual.iocs.map((i) => <span key={i} className="text-xs px-2 py-1 rounded border border-white/10 text-slate-300">{i}</span>)}
                  </div>
                </div>

                <div className="bg-slate-900/70 border border-white/10 rounded p-2">
                  <select value={manual.attackPhase} onChange={(e) => setManual((m) => ({ ...m, attackPhase: e.target.value }))} className="w-full bg-transparent outline-none text-slate-200">
                    <option value="">Attack Phase (optional)</option>
                    {attackPhases.map((p) => <option key={p} value={p}>{p}</option>)}
                  </select>
                </div>
              </div>

              <div className="bg-slate-900/70 border border-white/10 rounded p-2 mt-3">
                <input
                  value={manual.tagsInput}
                  onChange={(e) => setManual((m) => ({ ...m, tagsInput: e.target.value }))}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && manual.tagsInput.trim()) {
                      e.preventDefault();
                      setManual((m) => ({ ...m, tags: Array.from(new Set([...m.tags, m.tagsInput.trim()])), tagsInput: '' }));
                    }
                  }}
                  placeholder="Tags (press Enter)"
                  className="w-full bg-transparent outline-none text-slate-200"
                />
                <div className="flex flex-wrap gap-1 mt-2">
                  {manual.tags.map((t) => <span key={t} className="text-xs px-2 py-1 rounded-full border border-purple-500/30 text-purple-300">#{t}</span>)}
                </div>
              </div>

              <div className="mt-4 flex justify-end gap-2">
                <button onClick={() => setShowModal(false)} className="px-3 py-2 rounded border border-white/10 text-slate-300">Cancel</button>
                <button onClick={saveManualEvent} className="px-3 py-2 rounded border border-cyan-500/40 text-cyan-300 bg-cyan-500/15">Save Event</button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default ForensicsTimeline;
