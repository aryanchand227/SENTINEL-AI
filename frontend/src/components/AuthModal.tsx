import React, { useState } from 'react'
import { X, Shield, Lock, Mail, AlertTriangle } from 'lucide-react'
import { login } from '../services/api'
import type { UserProfile } from '../types'

interface AuthModalProps {
  isOpen: boolean
  onClose: () => void
  onSuccess: (user: UserProfile) => void
}

export const AuthModal: React.FC<AuthModalProps> = ({ isOpen, onClose, onSuccess }) => {
  const [email, setEmail] = useState('analyst@sentinel.ai')
  const [password, setPassword] = useState('Sentinel123!')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  if (!isOpen) return null

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)

    try {
      const res = await login(email, password)
      onSuccess({
        id: res.user_id,
        email: res.email,
        display_name: res.display_name,
        role: res.role,
        is_active: true,
      })
      onClose()
    } catch (err: any) {
      setError(err.message || 'Authentication failed')
    } finally {
      setLoading(false)
    }
  }

  const fillDemoCredentials = () => {
    setEmail('analyst@sentinel.ai')
    setPassword('Sentinel123!')
    setError(null)
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950">
          <div className="flex items-center gap-2 text-sky-400">
            <Shield className="w-5 h-5" />
            <h2 className="text-sm font-bold text-slate-100">SOC Analyst Authentication</h2>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-100 p-1 rounded transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <form onSubmit={handleSubmit} className="p-5 space-y-4 text-xs">
          {error && (
            <div className="bg-red-950 border border-red-800 p-3 rounded-lg text-red-300 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div>
            <label className="text-[11px] font-semibold text-slate-300 block mb-1">
              Analyst Email
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500"
              />
            </div>
          </div>

          <div>
            <label className="text-[11px] font-semibold text-slate-300 block mb-1">
              Password
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500"
              />
            </div>
          </div>

          {/* Demo Credentials Chip */}
          <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 flex items-center justify-between">
            <div>
              <span className="text-[10px] text-slate-400 block font-mono">Demo Credentials (Auto-Seeded)</span>
              <span className="text-[11px] text-sky-400 font-mono">analyst@sentinel.ai / Sentinel123!</span>
            </div>
            <button
              type="button"
              onClick={fillDemoCredentials}
              className="text-[11px] bg-slate-800 hover:bg-slate-700 text-slate-200 px-2 py-1 rounded transition"
            >
              Autofill
            </button>
          </div>

          <div className="pt-2 flex justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-2 bg-sky-600 hover:bg-sky-500 text-white font-semibold rounded-lg transition disabled:opacity-50 shadow-md shadow-sky-950"
            >
              {loading ? 'Authenticating...' : 'Sign In'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
