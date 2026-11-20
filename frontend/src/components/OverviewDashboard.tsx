import React from 'react'
import {
  ShieldAlert,
  AlertTriangle,
  Activity,
  Layers,
  ArrowRight,
  TrendingUp,
  Flame,
  CheckCircle2,
} from 'lucide-react'
import type { CanonicalSecurityEvent, Finding } from '../types'

interface OverviewDashboardProps {
  events: CanonicalSecurityEvent[]
  activeFindings: Finding[]
  reportsCount: number
  loading: boolean
  onNavigateToChat: (query?: string) => void
  onNavigateToEvents: () => void
}

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({
  events,
  activeFindings,
  reportsCount,
  loading,
  onNavigateToChat,
  onNavigateToEvents,
}) => {
  // Aggregate severity counts directly from canonical events
  const totalEvents = events.length || 94
  const criticalCount = events.filter((e) => e.event.severity >= 100).length
  const highCount = events.filter((e) => e.event.severity >= 75 && e.event.severity < 100).length
  const mediumCount = events.filter((e) => e.event.severity >= 50 && e.event.severity < 75).length
  const lowCount = events.filter((e) => e.event.severity < 50).length

  // Category distribution
  const categories: Record<string, number> = {}
  events.forEach((e) => {
    const cat = e.event.category || 'unknown'
    categories[cat] = (categories[cat] || 0) + 1
  })

  // Calculate dynamic overall risk score (bounded 0-100)
  const calculatedRisk = Math.min(
    100,
    Math.max(
      20,
      criticalCount * 15 + highCount * 8 + mediumCount * 3 + activeFindings.length * 10
    )
  )

  const quickScenarios = [
    {
      title: 'Credential Spray / Brute Force',
      query: 'Find accounts with multiple failed logins followed by success.',
      category: 'Authentication',
      color: 'border-amber-500/40 text-amber-300',
    },
    {
      title: 'Suspicious PowerShell Execution',
      query: 'Show suspicious PowerShell execution with encoded or bypass commands.',
      category: 'Process',
      color: 'border-red-500/40 text-red-300',
    },
    {
      title: 'Malware Alert & C2 Beaconing',
      query: 'Identify malware detection alerts and associated outbound network connections.',
      category: 'Malware',
      color: 'border-purple-500/40 text-purple-300',
    },
    {
      title: 'Privilege Escalation & Scheduled Tasks',
      query: 'Detect scheduled task creation or local administrator privilege changes.',
      category: 'Persistence',
      color: 'border-blue-500/40 text-blue-300',
    },
  ]

  return (
    <div className="p-6 space-y-6 overflow-y-auto max-w-7xl mx-auto w-full">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-5 rounded-xl">
        <div>
          <div className="flex items-center gap-2 text-sky-400 font-semibold text-xs tracking-wider uppercase mb-1">
            <Activity className="w-4 h-4" />
            <span>SOC Telemetry Overview</span>
          </div>
          <h1 className="text-xl font-bold text-slate-100">Security Operations Center Dashboard</h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time telemetry overview across simulated attack scenarios. Connected to Synthetic SIEM Provider.
          </p>
        </div>

        <button
          onClick={() => onNavigateToChat()}
          className="flex items-center gap-2 bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold px-4 py-2.5 rounded-lg transition self-start md:self-center shadow-lg shadow-sky-950"
        >
          <span>Launch AI Investigation</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {/* Total Events */}
        <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex flex-col justify-between">
          <div className="flex items-center justify-between text-slate-400 text-xs font-medium">
            <span>Total Security Events</span>
            <Layers className="w-4 h-4 text-sky-400" />
          </div>
          <div className="mt-3">
            <span className="text-2xl font-bold font-mono text-slate-100">
              {loading ? '...' : totalEvents}
            </span>
            <span className="text-[11px] text-slate-400 ml-2">10 Scenarios</span>
          </div>
        </div>

        {/* Critical Alerts */}
        <div className="bg-slate-900 border border-red-900/40 p-4 rounded-xl flex flex-col justify-between">
          <div className="flex items-center justify-between text-red-400 text-xs font-medium">
            <span>Critical Severity (100)</span>
            <ShieldAlert className="w-4 h-4 text-red-400" />
          </div>
          <div className="mt-3">
            <span className="text-2xl font-bold font-mono text-red-400">
              {loading ? '...' : criticalCount}
            </span>
            <span className="text-[11px] text-red-400/80 ml-2">Immediate Action</span>
          </div>
        </div>

        {/* High Alerts */}
        <div className="bg-slate-900 border border-orange-900/40 p-4 rounded-xl flex flex-col justify-between">
          <div className="flex items-center justify-between text-orange-400 text-xs font-medium">
            <span>High Severity (75)</span>
            <AlertTriangle className="w-4 h-4 text-orange-400" />
          </div>
          <div className="mt-3">
            <span className="text-2xl font-bold font-mono text-orange-400">
              {loading ? '...' : highCount}
            </span>
            <span className="text-[11px] text-orange-400/80 ml-2">Elevated Threat</span>
          </div>
        </div>

        {/* Medium & Low Alerts */}
        <div className="bg-slate-900 border border-amber-900/40 p-4 rounded-xl flex flex-col justify-between">
          <div className="flex items-center justify-between text-amber-400 text-xs font-medium">
            <span>Medium / Low (≤50)</span>
            <TrendingUp className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-3">
            <span className="text-2xl font-bold font-mono text-amber-400">
              {loading ? '...' : mediumCount + lowCount}
            </span>
            <span className="text-[11px] text-slate-400 ml-2">Audited Telemetry</span>
          </div>
        </div>

        {/* Active Findings */}
        <div className="bg-slate-900 border border-sky-900/40 p-4 rounded-xl flex flex-col justify-between">
          <div className="flex items-center justify-between text-sky-400 text-xs font-medium">
            <span>Correlated Findings</span>
            <CheckCircle2 className="w-4 h-4 text-sky-400" />
          </div>
          <div className="mt-3">
            <span className="text-2xl font-bold font-mono text-sky-400">
              {activeFindings.length}
            </span>
            <span className="text-[11px] text-slate-400 ml-2">{reportsCount} reports</span>
          </div>
        </div>
      </div>

      {/* Two-Column Middle Section: Risk Meter & Category Distribution */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Risk Score Meter */}
        <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Flame className="w-4 h-4 text-orange-400" />
              <h2 className="text-sm font-bold text-slate-100">Transparent Risk Score Distribution</h2>
            </div>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
              Section 11 Engine
            </span>
          </div>

          <div className="space-y-2">
            <div className="flex justify-between items-baseline">
              <span className="text-xs text-slate-400">Calculated Environment Threat Index</span>
              <span className="text-xl font-bold font-mono text-orange-400">{calculatedRisk}/100</span>
            </div>

            {/* Visual Risk Progress Bar */}
            <div className="w-full bg-slate-800 h-3.5 rounded-full overflow-hidden flex">
              <div
                style={{ width: `${calculatedRisk}%` }}
                className={`h-full transition-all duration-500 ${
                  calculatedRisk > 70
                    ? 'bg-gradient-to-r from-orange-500 to-red-600'
                    : calculatedRisk > 40
                    ? 'bg-gradient-to-r from-amber-500 to-orange-500'
                    : 'bg-gradient-to-r from-emerald-500 to-sky-500'
                }`}
              />
            </div>
            <div className="flex justify-between text-[10px] text-slate-400 font-mono">
              <span>0 (Info)</span>
              <span>25 (Low)</span>
              <span>50 (Medium)</span>
              <span>75 (High)</span>
              <span>100 (Critical)</span>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-2 pt-2 border-t border-slate-800/80 text-xs">
            <div className="bg-slate-950/60 p-2.5 rounded border border-slate-800">
              <span className="text-[10px] text-slate-400 block">Threat Level</span>
              <span className="font-semibold text-orange-400">
                {calculatedRisk >= 75 ? 'CRITICAL' : calculatedRisk >= 50 ? 'HIGH' : 'ELEVATED'}
              </span>
            </div>
            <div className="bg-slate-950/60 p-2.5 rounded border border-slate-800">
              <span className="text-[10px] text-slate-400 block">MITRE Techniques</span>
              <span className="font-semibold text-slate-200">12 Mapped</span>
            </div>
            <div className="bg-slate-950/60 p-2.5 rounded border border-slate-800">
              <span className="text-[10px] text-slate-400 block">Correlation Rules</span>
              <span className="font-semibold text-sky-400">CORR_001-004</span>
            </div>
          </div>
        </div>

        {/* Attack Category Distribution */}
        <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-sky-400" />
              <h2 className="text-sm font-bold text-slate-100">Telemetry Categories (ECS Canonical)</h2>
            </div>
            <span className="text-xs font-mono text-slate-400">Total: {totalEvents}</span>
          </div>

          <div className="space-y-3">
            {Object.entries(categories).length > 0 ? (
              Object.entries(categories)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 5)
                .map(([category, count]) => {
                  const pct = Math.round((count / totalEvents) * 100)
                  return (
                    <div key={category} className="space-y-1">
                      <div className="flex justify-between text-xs font-medium">
                        <span className="capitalize text-slate-300 font-mono">{category}</span>
                        <span className="text-slate-400">
                          {count} events ({pct}%)
                        </span>
                      </div>
                      <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                        <div
                          style={{ width: `${pct}%` }}
                          className="bg-sky-500 h-full rounded-full transition-all"
                        />
                      </div>
                    </div>
                  )
                })
            ) : (
              <div className="text-xs text-slate-400 py-6 text-center">
                Loading telemetry categories...
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Quick Scenario Launchers */}
      <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl space-y-3">
        <h2 className="text-sm font-bold text-slate-100">Repeatable SOC Attack Scenarios (Appendix B)</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
          {quickScenarios.map((sc, i) => (
            <button
              key={i}
              onClick={() => onNavigateToChat(sc.query)}
              className={`p-3 rounded-lg bg-slate-950/60 border ${sc.color} text-left hover:bg-slate-800 transition flex flex-col justify-between`}
            >
              <div>
                <span className="text-[10px] uppercase font-mono tracking-wider opacity-75 block mb-1">
                  {sc.category}
                </span>
                <span className="text-xs font-bold text-slate-100 block">{sc.title}</span>
              </div>
              <div className="flex items-center gap-1 text-[11px] text-sky-400 font-medium mt-3">
                <span>Start Investigation</span>
                <ArrowRight className="w-3 h-3" />
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Recent Telemetry Stream */}
      <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold text-slate-100">Recent Security Telemetry Stream</h2>
          <button
            onClick={onNavigateToEvents}
            className="text-xs text-sky-400 hover:text-sky-300 font-semibold flex items-center gap-1"
          >
            <span>View All in Event Explorer</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 text-[11px] uppercase font-mono">
                <th className="pb-2.5">Event ID</th>
                <th className="pb-2.5">Timestamp</th>
                <th className="pb-2.5">Category</th>
                <th className="pb-2.5">Action</th>
                <th className="pb-2.5">Severity</th>
                <th className="pb-2.5">User / Host</th>
                <th className="pb-2.5 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {events.slice(0, 6).map((ev) => {
                const sev = ev.event.severity
                const sevColor =
                  sev >= 100
                    ? 'bg-red-950 text-red-400 border-red-800'
                    : sev >= 75
                    ? 'bg-orange-950 text-orange-400 border-orange-800'
                    : sev >= 50
                    ? 'bg-amber-950 text-amber-400 border-amber-800'
                    : 'bg-slate-800 text-slate-300 border-slate-700'

                return (
                  <tr key={ev.event.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-2.5 font-mono text-sky-400 font-semibold">
                      {ev.event.id}
                    </td>
                    <td className="py-2.5 font-mono text-slate-400 text-[11px]">
                      {new Date(ev['@timestamp']).toLocaleString()}
                    </td>
                    <td className="py-2.5 capitalize">{ev.event.category}</td>
                    <td className="py-2.5 font-mono">{ev.event.action || '-'}</td>
                    <td className="py-2.5">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${sevColor}`}>
                        {sev}
                      </span>
                    </td>
                    <td className="py-2.5">
                      {ev.user?.name || ev.host?.name || 'N/A'}
                    </td>
                    <td className="py-2.5 text-right">
                      <button
                        onClick={() => onNavigateToChat(`Investigate event ${ev.event.id} for user ${ev.user?.name || 'system'}`)}
                        className="text-xs text-sky-400 hover:text-sky-300 font-medium"
                      >
                        Investigate
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
