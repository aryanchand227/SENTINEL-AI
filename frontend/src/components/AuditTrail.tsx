import React from 'react'
import { History } from 'lucide-react'
import type { AuditRecord } from '../types'

interface AuditTrailProps {
  auditRecords: AuditRecord[]
}

export const AuditTrail: React.FC<AuditTrailProps> = ({ auditRecords }) => {
  return (
    <div className="p-6 space-y-6 overflow-y-auto max-w-7xl mx-auto w-full">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl">
        <div className="flex items-center gap-2 text-sky-400 font-semibold text-xs tracking-wider uppercase mb-1">
          <History className="w-4 h-4" />
          <span>Compliance & Audit Trail</span>
        </div>
        <h1 className="text-xl font-bold text-slate-100">Analyst Investigation Audit Log</h1>
        <p className="text-xs text-slate-400 mt-1">
          Chronological, tamper-evident audit ledger recording every SQS query execution, validation status, duration, and user interaction.
        </p>
      </div>

      {/* Audit Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold text-slate-100">
            Recorded Execution Events ({auditRecords.length})
          </h2>
          <span className="text-xs font-mono text-emerald-400">Section 14 Audit Compliance</span>
        </div>

        {auditRecords.length === 0 ? (
          <div className="text-center py-16 text-slate-400 text-xs">
            No audit records logged in the current session yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-mono text-[11px] uppercase">
                  <th className="pb-2.5">Audit ID</th>
                  <th className="pb-2.5">Timestamp (UTC)</th>
                  <th className="pb-2.5">Action</th>
                  <th className="pb-2.5">Resource</th>
                  <th className="pb-2.5">Outcome</th>
                  <th className="pb-2.5">Duration</th>
                  <th className="pb-2.5">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300 font-sans">
                {auditRecords.map((rec) => (
                  <tr key={rec.id} className="hover:bg-slate-800/40 transition">
                    <td className="py-2.5 font-mono text-sky-400 font-semibold">{rec.id}</td>
                    <td className="py-2.5 font-mono text-slate-400 text-[11px]">
                      {new Date(rec.timestamp).toISOString()}
                    </td>
                    <td className="py-2.5 font-medium text-slate-200">{rec.action}</td>
                    <td className="py-2.5 font-mono text-slate-300">{rec.resource}</td>
                    <td className="py-2.5">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          rec.status === 'success' || rec.status === 'valid'
                            ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                            : 'bg-red-950 text-red-400 border border-red-800'
                        }`}
                      >
                        {rec.status}
                      </span>
                    </td>
                    <td className="py-2.5 font-mono text-slate-400 text-[11px]">
                      {rec.duration_ms !== undefined ? `${rec.duration_ms}ms` : '-'}
                    </td>
                    <td className="py-2.5 text-slate-400 text-[11px] max-w-xs truncate">
                      {rec.details || '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
