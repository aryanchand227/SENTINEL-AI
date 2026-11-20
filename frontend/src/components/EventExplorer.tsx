import React, { useState, useMemo } from 'react'
import {
  Search,
  Filter,
  Eye,
  X,
  Terminal,
  Shield,
  Layers,
} from 'lucide-react'
import type { CanonicalSecurityEvent } from '../types'

interface EventExplorerProps {
  events: CanonicalSecurityEvent[]
  loading: boolean
  onInvestigateEvent: (eventId: string, details: string) => void
}

export const EventExplorer: React.FC<EventExplorerProps> = ({
  events,
  loading,
  onInvestigateEvent,
}) => {
  const [searchTerm, setSearchTerm] = useState('')
  const [severityFilter, setSeverityFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all')
  const [categoryFilter, setCategoryFilter] = useState<string>('all')
  const [selectedEvent, setSelectedEvent] = useState<CanonicalSecurityEvent | null>(null)

  // Extract unique categories
  const categories = useMemo(() => {
    const set = new Set<string>()
    events.forEach((e) => {
      if (e.event.category) set.add(e.event.category)
    })
    return Array.from(set).sort()
  }, [events])

  // Filtered events
  const filteredEvents = useMemo(() => {
    return events.filter((ev) => {
      // Severity filter
      const sev = ev.event.severity
      if (severityFilter === 'critical' && sev < 100) return false
      if (severityFilter === 'high' && (sev < 75 || sev >= 100)) return false
      if (severityFilter === 'medium' && (sev < 50 || sev >= 75)) return false
      if (severityFilter === 'low' && sev >= 50) return false

      // Category filter
      if (categoryFilter !== 'all' && ev.event.category !== categoryFilter) return false

      // Search term
      if (searchTerm.trim()) {
        const term = searchTerm.toLowerCase()
        const text = [
          ev.event.id,
          ev.event.action,
          ev.event.category,
          ev.message,
          ev.user?.name,
          ev.host?.name,
          ev.source?.ip,
          ev.destination?.ip,
          ev.process?.name,
          ev.process?.command_line,
        ]
          .filter(Boolean)
          .join(' ')
          .toLowerCase()

        if (!text.includes(term)) return false
      }

      return true
    })
  }, [events, severityFilter, categoryFilter, searchTerm])

  return (
    <div className="flex flex-col h-full bg-slate-950 overflow-hidden">
      {/* Top Controls Bar */}
      <div className="p-4 bg-slate-900 border-b border-slate-800 space-y-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Layers className="w-5 h-5 text-sky-400" />
            <div>
              <h1 className="text-sm font-bold text-slate-100">Security Event Explorer</h1>
              <span className="text-[11px] text-slate-400">
                Direct read-only access to canonical security telemetry ({events.length} events loaded)
              </span>
            </div>
          </div>

          {/* Search Box */}
          <div className="relative w-full md:w-80">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search by IP, user, action, host, process..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 transition"
            />
          </div>
        </div>

        {/* Filter Pills */}
        <div className="flex flex-wrap items-center gap-2 text-xs pt-1 border-t border-slate-800/80">
          <div className="flex items-center gap-1 text-slate-400 text-[11px] mr-1">
            <Filter className="w-3.5 h-3.5" />
            <span>Severity:</span>
          </div>

          {(['all', 'critical', 'high', 'medium', 'low'] as const).map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-2.5 py-1 rounded-md text-[11px] font-semibold uppercase tracking-wider transition ${
                severityFilter === sev
                  ? 'bg-sky-500 text-white shadow-sm'
                  : 'bg-slate-800 text-slate-400 hover:text-slate-200'
              }`}
            >
              {sev}
            </button>
          ))}

          <div className="h-4 w-px bg-slate-800 mx-1" />

          {/* Category Dropdown */}
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="bg-slate-800 border border-slate-700 text-slate-300 text-xs px-2.5 py-1 rounded-md focus:outline-none"
          >
            <option value="all">All Categories</option>
            {categories.map((c) => (
              <option key={c} value={c}>
                {c.toUpperCase()}
              </option>
            ))}
          </select>

          <span className="text-[11px] text-slate-400 ml-auto font-mono">
            Showing {filteredEvents.length} of {events.length}
          </span>
        </div>
      </div>

      {/* Main Table Area */}
      <div className="flex-1 overflow-auto p-4">
        {loading ? (
          <div className="text-center py-20 text-slate-400 text-xs">
            Querying SIEM provider for security events...
          </div>
        ) : filteredEvents.length === 0 ? (
          <div className="text-center py-20 text-slate-400 text-xs">
            No events match the current search filters.
          </div>
        ) : (
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-md">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-950 border-b border-slate-800 text-slate-400 font-mono text-[11px] uppercase tracking-wider">
                  <th className="p-3">Event ID</th>
                  <th className="p-3">Timestamp</th>
                  <th className="p-3">Severity</th>
                  <th className="p-3">Category</th>
                  <th className="p-3">Action / Outcome</th>
                  <th className="p-3">User</th>
                  <th className="p-3">Source IP</th>
                  <th className="p-3">Destination IP</th>
                  <th className="p-3 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-300 font-sans">
                {filteredEvents.map((ev) => {
                  const sev = ev.event.severity
                  const sevBadge =
                    sev >= 100
                      ? 'bg-red-950/80 text-red-400 border-red-800'
                      : sev >= 75
                      ? 'bg-orange-950/80 text-orange-400 border-orange-800'
                      : sev >= 50
                      ? 'bg-amber-950/80 text-amber-400 border-amber-800'
                      : 'bg-slate-800 text-slate-400 border-slate-700'

                  return (
                    <tr
                      key={ev.event.id}
                      onClick={() => setSelectedEvent(ev)}
                      className="hover:bg-slate-800/60 cursor-pointer transition"
                    >
                      <td className="p-3 font-mono text-sky-400 font-semibold">{ev.event.id}</td>
                      <td className="p-3 font-mono text-slate-400 text-[11px]">
                        {new Date(ev['@timestamp']).toLocaleString()}
                      </td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${sevBadge}`}>
                          {sev}
                        </span>
                      </td>
                      <td className="p-3 capitalize font-mono text-slate-300">
                        {ev.event.category}
                      </td>
                      <td className="p-3">
                        <span className="font-mono text-slate-200">{ev.event.action || '-'}</span>
                        {ev.event.outcome && (
                          <span
                            className={`ml-1.5 text-[10px] font-mono uppercase px-1 py-0.2 rounded ${
                              ev.event.outcome === 'success'
                                ? 'text-emerald-400 bg-emerald-950'
                                : 'text-red-400 bg-red-950'
                            }`}
                          >
                            {ev.event.outcome}
                          </span>
                        )}
                      </td>
                      <td className="p-3 font-medium text-slate-200">
                        {ev.user?.name || '-'}
                      </td>
                      <td className="p-3 font-mono text-[11px] text-slate-400">
                        {ev.source?.ip || '-'}
                      </td>
                      <td className="p-3 font-mono text-[11px] text-slate-400">
                        {ev.destination?.ip || '-'}
                      </td>
                      <td className="p-3 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            setSelectedEvent(ev)
                          }}
                          className="p-1 hover:text-sky-400 text-slate-400 rounded transition"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Event Detail Modal / Drawer */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-3xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden">
            {/* Modal Header */}
            <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-sky-400" />
                <h3 className="text-sm font-bold text-slate-100">
                  Forensic Event Details: <span className="font-mono text-sky-400">{selectedEvent.event.id}</span>
                </h3>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-slate-100 p-1 rounded transition"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-5 overflow-y-auto space-y-4 text-xs">
              {/* Key metadata grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 bg-slate-950 p-3 rounded-lg border border-slate-800">
                <div>
                  <span className="text-[10px] text-slate-400 block">Category</span>
                  <span className="font-mono text-slate-200 capitalize">{selectedEvent.event.category}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-400 block">Severity</span>
                  <span className="font-mono font-bold text-orange-400">{selectedEvent.event.severity}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-400 block">Action</span>
                  <span className="font-mono text-slate-200">{selectedEvent.event.action || '-'}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-400 block">Outcome</span>
                  <span className="font-mono text-slate-200 uppercase">{selectedEvent.event.outcome || '-'}</span>
                </div>
              </div>

              {/* Host & User & Network Details */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
                  <span className="text-[10px] text-slate-400 font-bold uppercase block">Identity & User</span>
                  <div>Name: <span className="font-mono text-slate-200">{selectedEvent.user?.name || 'N/A'}</span></div>
                  <div>ID: <span className="font-mono text-slate-400">{selectedEvent.user?.id || 'N/A'}</span></div>
                </div>

                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
                  <span className="text-[10px] text-slate-400 font-bold uppercase block">Network Endpoints</span>
                  <div>Source: <span className="font-mono text-slate-200">{selectedEvent.source?.ip || 'N/A'}:{selectedEvent.source?.port || ''}</span></div>
                  <div>Destination: <span className="font-mono text-slate-200">{selectedEvent.destination?.ip || 'N/A'}:{selectedEvent.destination?.port || ''}</span></div>
                </div>

                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
                  <span className="text-[10px] text-slate-400 font-bold uppercase block">Host Information</span>
                  <div>Host Name: <span className="font-mono text-slate-200">{selectedEvent.host?.name || 'N/A'}</span></div>
                  <div>OS: <span className="text-slate-400">{selectedEvent.host?.os?.name || 'N/A'}</span></div>
                </div>
              </div>

              {/* Process & Command Line (if applicable) */}
              {selectedEvent.process && (
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1.5">
                  <span className="text-[10px] text-slate-400 font-bold uppercase block">Process Execution</span>
                  <div>Process Name: <span className="font-mono text-sky-300">{selectedEvent.process.name}</span> (PID: {selectedEvent.process.pid})</div>
                  {selectedEvent.process.command_line && (
                    <div>
                      <span className="text-slate-400 block mb-1">Command Line:</span>
                      <pre className="bg-slate-900 p-2 rounded text-[11px] font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap">
                        {selectedEvent.process.command_line}
                      </pre>
                    </div>
                  )}
                </div>
              )}

              {/* Message */}
              {selectedEvent.message && (
                <div>
                  <span className="text-[10px] text-slate-400 font-bold uppercase block mb-1">Event Message</span>
                  <div className="bg-slate-950 p-3 rounded border border-slate-800 text-slate-300 font-mono text-xs">
                    {selectedEvent.message}
                  </div>
                </div>
              )}

              {/* Raw Canonical ECS JSON */}
              <div>
                <span className="text-[10px] text-slate-400 font-bold uppercase block mb-1">
                  Raw Canonical ECS JSON (Zero Hallucination Verified)
                </span>
                <pre className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-[11px] font-mono text-slate-300 max-h-48 overflow-y-auto">
                  {JSON.stringify(selectedEvent, null, 2)}
                </pre>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-4 border-t border-slate-800 flex justify-between items-center bg-slate-950">
              <span className="text-[11px] text-slate-400">
                Provenance: <span className="font-mono text-slate-300">{selectedEvent.sentinel.source.provider}</span> ({selectedEvent.sentinel.data_mode})
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => {
                    const id = selectedEvent.event.id
                    setSelectedEvent(null)
                    onInvestigateEvent(id, `Investigate security event ${id} (${selectedEvent.event.category} - ${selectedEvent.event.action})`)
                  }}
                  className="flex items-center gap-1.5 bg-sky-600 hover:bg-sky-500 text-white px-3 py-1.5 rounded-lg text-xs font-semibold transition"
                >
                  <Terminal className="w-3.5 h-3.5" />
                  <span>Send to AI Investigation</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
