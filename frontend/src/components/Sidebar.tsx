import React from 'react'
import {
  LayoutDashboard,
  Terminal,
  Search,
  Briefcase,
  Crosshair,
  FileText,
  History,
  ShieldAlert,
} from 'lucide-react'

export type NavTab =
  | 'overview'
  | 'chat'
  | 'events'
  | 'investigation'
  | 'threats'
  | 'reports'
  | 'audit'

interface SidebarProps {
  activeTab: NavTab
  onSelectTab: (tab: NavTab) => void
  activeFindingsCount: number
  reportsCount: number
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  activeFindingsCount,
  reportsCount,
}) => {
  const navItems = [
    {
      id: 'overview' as NavTab,
      label: 'Overview Dashboard',
      icon: LayoutDashboard,
      badge: null,
    },
    {
      id: 'chat' as NavTab,
      label: 'AI Investigation Assistant',
      icon: Terminal,
      badge: null,
    },
    {
      id: 'events' as NavTab,
      label: 'Security Event Explorer',
      icon: Search,
      badge: '94 events',
    },
    {
      id: 'investigation' as NavTab,
      label: 'Investigation Workspace',
      icon: Briefcase,
      badge: activeFindingsCount > 0 ? `${activeFindingsCount} findings` : null,
    },
    {
      id: 'threats' as NavTab,
      label: 'Threat Analysis',
      icon: Crosshair,
      badge: null,
    },
    {
      id: 'reports' as NavTab,
      label: 'Threat Reports',
      icon: FileText,
      badge: reportsCount > 0 ? String(reportsCount) : null,
    },
    {
      id: 'audit' as NavTab,
      label: 'Audit Trail',
      icon: History,
      badge: null,
    },
  ]

  return (
    <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col justify-between select-none">
      <div className="py-4">
        <div className="px-4 pb-3 mb-2 border-b border-slate-800/80">
          <span className="text-[11px] uppercase font-bold tracking-wider text-slate-400">
            SOC Operations
          </span>
        </div>

        <nav className="flex flex-col gap-1 px-2">
          {navItems.map((item) => {
            const Icon = item.icon
            const isActive = activeTab === item.id
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                className={`flex items-center justify-between w-full px-3 py-2.5 rounded-lg text-xs font-semibold transition text-left ${
                  isActive
                    ? 'bg-sky-500/15 text-sky-400 border border-sky-500/30 font-bold'
                    : 'text-slate-300 hover:bg-slate-800/60 hover:text-slate-100 border border-transparent'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-sky-400' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge && (
                  <span
                    className={`text-[10px] font-mono px-1.5 py-0.5 rounded-full ${
                      isActive
                        ? 'bg-sky-500/20 text-sky-300'
                        : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            )
          })}
        </nav>
      </div>

      {/* Bottom Footer Info */}
      <div className="p-4 border-t border-slate-800 bg-slate-950/40 text-[11px] text-slate-400">
        <div className="flex items-center gap-1.5 text-amber-400 font-medium mb-1">
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>Local-First SOC</span>
        </div>
        <p className="text-slate-400 text-[10px] leading-relaxed">
          Evidence-backed read-only investigation with strict deterministic correlation.
        </p>
      </div>
    </aside>
  )
}
