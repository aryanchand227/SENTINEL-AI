import React from 'react'
import {
  Shield,
  AlertTriangle,
  Database,
  CheckCircle,
  Clock,
  User,
  LogOut,
  LogIn,
} from 'lucide-react'
import type { DatabaseHealth, ProviderStatus, UserProfile } from '../types'

interface NavbarProps {
  providerStatus: ProviderStatus | null
  dbHealth: DatabaseHealth | null
  user: UserProfile | null
  onOpenAuth: () => void
  onLogout: () => void
}

export const Navbar: React.FC<NavbarProps> = ({
  providerStatus,
  dbHealth,
  user,
  onOpenAuth,
  onLogout,
}) => {
  return (
    <header className="flex items-center justify-between px-6 py-3 bg-slate-900 border-b border-slate-800 text-slate-100 select-none">
      {/* Brand & Synthetic Badge */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2.5">
          <Shield className="w-6 h-6 text-sky-400" />
          <span className="text-lg font-bold tracking-wider text-slate-100">SENTINEL AI</span>
          <span className="text-xs text-slate-400 uppercase font-mono tracking-widest px-1.5 py-0.5 rounded bg-slate-800">
            SIH25173
          </span>
        </div>

        {/* Mandatory Section 3 & 16 Synthetic Disclosure Badge */}
        <div
          title="Mandatory Disclosure: Synthetic SIEM telemetry is active. All events and alerts are simulated security scenarios."
          className="flex items-center gap-1.5 bg-red-950/80 border border-red-600/80 text-red-300 px-3 py-1 rounded-full text-xs font-bold tracking-wider"
        >
          <AlertTriangle className="w-3.5 h-3.5 text-red-400 animate-pulse" />
          <span>SYNTHETIC DATA MODE</span>
        </div>
      </div>

      {/* Status Indicators & Profile */}
      <div className="flex items-center gap-4 text-xs font-medium">
        {/* Active Provider */}
        <div className="flex items-center gap-1.5 text-slate-400 bg-slate-800/80 px-2.5 py-1 rounded border border-slate-700/60">
          <Database className="w-3.5 h-3.5 text-sky-400" />
          <span>Provider:</span>
          <span className="text-slate-100 font-mono font-semibold">
            {providerStatus?.provider || 'synthetic'}
          </span>
        </div>

        {/* Database Latency */}
        <div className="flex items-center gap-1.5 text-slate-400 bg-slate-800/80 px-2.5 py-1 rounded border border-slate-700/60">
          <Clock className="w-3.5 h-3.5 text-emerald-400" />
          <span>DB:</span>
          <span className="text-slate-100 font-mono">
            {dbHealth ? `${dbHealth.latency_ms}ms` : 'online'}
          </span>
        </div>

        {/* Operational Status */}
        <div className="flex items-center gap-1.5 text-emerald-400 bg-emerald-950/50 px-2.5 py-1 rounded border border-emerald-800/60">
          <CheckCircle className="w-3.5 h-3.5" />
          <span>Operational</span>
        </div>

        {/* User Profile / Auth Toggle */}
        {user ? (
          <div className="flex items-center gap-2 pl-2 border-l border-slate-700">
            <div className="flex items-center gap-1.5 bg-slate-800 px-2.5 py-1 rounded text-slate-200">
              <User className="w-3.5 h-3.5 text-sky-400" />
              <span className="font-medium">{user.display_name}</span>
              <span className="text-[10px] uppercase font-mono px-1 py-0.2 rounded bg-sky-950 text-sky-300 border border-sky-800">
                {user.role}
              </span>
            </div>
            <button
              onClick={onLogout}
              title="Sign out / switch analyst"
              className="text-slate-400 hover:text-red-400 p-1 rounded hover:bg-slate-800 transition"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        ) : (
          <button
            onClick={onOpenAuth}
            className="flex items-center gap-1.5 bg-sky-600 hover:bg-sky-500 text-white px-3 py-1 rounded font-semibold transition"
          >
            <LogIn className="w-3.5 h-3.5" />
            <span>Sign In</span>
          </button>
        )}
      </div>
    </header>
  )
}
