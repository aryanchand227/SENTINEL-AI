import React from 'react'
import {
  Briefcase,
  Shield,
  FileText,
  AlertTriangle,
  CheckCircle2,
  Flame,
  ArrowRight,
} from 'lucide-react'
import type { Finding } from '../types'

interface InvestigationWorkspaceProps {
  investigationId: string | null
  activeFindings: Finding[]
  activeEvidenceIds: string[]
  onGenerateReport: (format: 'pdf' | 'json' | 'csv') => Promise<void>
  reportGenerating: boolean
  onNavigateToChat: (query?: string) => void
  onInspectEvidence?: (evidenceId: string) => void
}

export const InvestigationWorkspace: React.FC<InvestigationWorkspaceProps> = ({
  investigationId,
  activeFindings,
  activeEvidenceIds,
  onGenerateReport,
  reportGenerating,
  onNavigateToChat,
  onInspectEvidence,
}) => {
  // Transparent risk score calculation based on findings
  const criticalFindings = activeFindings.filter((f) => f.severity === 'critical').length
  const highFindings = activeFindings.filter((f) => f.severity === 'high').length
  const mediumFindings = activeFindings.filter((f) => f.severity === 'medium').length

  const score = Math.min(
    100,
    Math.max(
      15,
      criticalFindings * 35 + highFindings * 20 + mediumFindings * 10 + activeEvidenceIds.length * 2
    )
  )

  return (
    <div className="p-6 space-y-6 overflow-y-auto max-w-7xl mx-auto w-full">
      {/* Workspace Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-5 rounded-xl">
        <div className="space-y-1">
          <div className="flex items-center gap-2 text-sky-400 font-semibold text-xs tracking-wider uppercase">
            <Briefcase className="w-4 h-4" />
            <span>Case Workspace</span>
          </div>
          <h1 className="text-xl font-bold text-slate-100">
            Active Security Incident Case
          </h1>
          <p className="text-xs text-slate-400">
            Case ID: <span className="font-mono text-slate-200">{investigationId || 'No active investigation'}</span>
          </p>
        </div>

        {/* Status Pills & Actions */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="flex items-center gap-1.5 bg-emerald-950 text-emerald-400 border border-emerald-800 px-3 py-1 rounded-full text-xs font-semibold">
            <CheckCircle2 className="w-3.5 h-3.5" />
            <span>STATUS: OPEN</span>
          </span>

          <span className="bg-slate-800 text-slate-300 border border-slate-700 px-3 py-1 rounded-full text-xs font-mono">
            Provider: synthetic
          </span>

          {investigationId && (
            <div className="flex gap-2 ml-2">
              <button
                onClick={() => onGenerateReport('pdf')}
                disabled={reportGenerating}
                className="flex items-center gap-1.5 bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold px-3 py-1.5 rounded-lg transition disabled:opacity-50"
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Export Report (PDF)</span>
              </button>
            </div>
          )}
        </div>
      </div>

      {!investigationId ? (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center space-y-4 max-w-md mx-auto">
          <Briefcase className="w-10 h-10 text-slate-600 mx-auto" />
          <h3 className="text-sm font-bold text-slate-200">No Active Investigation Loaded</h3>
          <p className="text-xs text-slate-400">
            Submit an investigation prompt in the AI Assistant or select an attack scenario to initialize an evidence-backed case workspace.
          </p>
          <button
            onClick={() => onNavigateToChat('Find accounts with failed logins in the last 24 hours.')}
            className="inline-flex items-center gap-2 bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold px-4 py-2 rounded-lg transition"
          >
            <span>Start Investigation Query</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      ) : (
        <>
          {/* Top Metrics Row: Risk Score + Evidence Count */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Risk Card */}
            <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-400 font-semibold uppercase">Incident Risk Rating</span>
                <Flame className="w-4 h-4 text-orange-400" />
              </div>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-bold font-mono text-orange-400">{score}</span>
                <span className="text-xs text-slate-400">/ 100 ({score >= 75 ? 'Critical' : score >= 50 ? 'High' : 'Moderate'})</span>
              </div>
              <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                <div
                  style={{ width: `${score}%` }}
                  className={`h-full ${
                    score >= 75 ? 'bg-red-500' : score >= 50 ? 'bg-orange-500' : 'bg-sky-500'
                  }`}
                />
              </div>
            </div>

            {/* Evidence Count */}
            <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-400 font-semibold uppercase">Forensic Evidence</span>
                <Shield className="w-4 h-4 text-sky-400" />
              </div>
              <div className="text-3xl font-bold font-mono text-sky-400">{activeEvidenceIds.length}</div>
              <p className="text-[11px] text-slate-400">
                Cryptographically tracked documents in evidence references table.
              </p>
            </div>

            {/* Findings Count */}
            <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-400 font-semibold uppercase">Correlated Findings</span>
                <AlertTriangle className="w-4 h-4 text-amber-400" />
              </div>
              <div className="text-3xl font-bold font-mono text-amber-400">{activeFindings.length}</div>
              <p className="text-[11px] text-slate-400">
                Deterministic correlation rules verified against evidence.
              </p>
            </div>
          </div>

          {/* Correlated Findings List */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
            <h2 className="text-sm font-bold text-slate-100">
              Investigation Findings ({activeFindings.length})
            </h2>

            {activeFindings.length === 0 ? (
              <div className="text-xs text-slate-400 py-6 text-center">
                No findings generated for this investigation turn yet.
              </div>
            ) : (
              <div className="space-y-3">
                {activeFindings.map((finding, index) => {
                  const isCrit = finding.severity === 'critical'
                  const isHigh = finding.severity === 'high'

                  return (
                    <div
                      key={index}
                      className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-2"
                    >
                      <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                              isCrit
                                ? 'bg-red-950 text-red-400 border border-red-800'
                                : isHigh
                                ? 'bg-orange-950 text-orange-400 border border-orange-800'
                                : 'bg-amber-950 text-amber-400 border border-amber-800'
                            }`}
                          >
                            {finding.severity}
                          </span>
                          <h3 className="text-xs font-bold text-slate-100">{finding.title}</h3>
                        </div>

                        <div className="flex items-center gap-2 text-[10px] font-mono text-slate-400">
                          <span className="bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                            Class: {finding.classification}
                          </span>
                          <span className="bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                            Confidence: {finding.confidence_label}
                          </span>
                        </div>
                      </div>

                      <p className="text-xs text-slate-300 leading-relaxed">{finding.description}</p>

                      {/* Supporting evidence IDs */}
                      <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center gap-1.5 text-[10px]">
                        <span className="text-slate-400">Evidence IDs ({finding.evidence_ids.length}):</span>
                        {finding.evidence_ids.map((eid) => (
                          <button
                            key={eid}
                            onClick={() => onInspectEvidence?.(eid)}
                            className="bg-slate-900 text-sky-400 hover:text-sky-300 font-mono px-1.5 py-0.5 rounded border border-slate-800 hover:border-sky-500 transition"
                          >
                            {eid}
                          </button>
                        ))}
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>

          {/* Evidence Inventory Cloud */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
            <h2 className="text-sm font-bold text-slate-100">
              Supporting Evidence Inventory ({activeEvidenceIds.length} Event IDs)
            </h2>
            <div className="flex flex-wrap gap-2">
              {activeEvidenceIds.map((eid) => (
                <button
                  key={eid}
                  onClick={() => onInspectEvidence?.(eid)}
                  className="bg-slate-950 text-sky-400 hover:text-sky-300 font-mono text-xs px-2.5 py-1 rounded-md border border-slate-800 hover:border-sky-500 transition"
                >
                  {eid}
                </button>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
