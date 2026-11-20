import React from 'react'
import {
  FileText,
  Download,
  AlertTriangle,
  Hash,
} from 'lucide-react'
import type { ReportItem } from '../types'
import { getReportDownloadUrl } from '../services/api'

interface ReportsViewProps {
  reports: ReportItem[]
  activeInvestigationId: string | null
  onGenerateReport: (format: 'pdf' | 'json' | 'csv') => Promise<void>
  reportGenerating: boolean
}

export const ReportsView: React.FC<ReportsViewProps> = ({
  reports,
  activeInvestigationId,
  onGenerateReport,
  reportGenerating,
}) => {
  return (
    <div className="p-6 space-y-6 overflow-y-auto max-w-7xl mx-auto w-full">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-5 rounded-xl">
        <div>
          <div className="flex items-center gap-2 text-sky-400 font-semibold text-xs tracking-wider uppercase mb-1">
            <FileText className="w-4 h-4" />
            <span>Automated Incident Reporting</span>
          </div>
          <h1 className="text-xl font-bold text-slate-100">Immutable Threat Reports & Export</h1>
          <p className="text-xs text-slate-400 mt-1">
            Generate evidence-backed incident reports with SHA-256 cryptographic integrity hashes and formula-injection defenses.
          </p>
        </div>

        {/* Generate Report Buttons */}
        <div className="flex items-center gap-2">
          {(['pdf', 'json', 'csv'] as const).map((fmt) => (
            <button
              key={fmt}
              onClick={() => onGenerateReport(fmt)}
              disabled={!activeInvestigationId || reportGenerating}
              className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-sky-400 border border-slate-700 px-3 py-2 rounded-lg text-xs font-semibold uppercase tracking-wider transition disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export {fmt}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Mandatory Synthetic Data Notice */}
      <div className="bg-red-950/40 border border-red-800/80 p-4 rounded-xl flex items-start gap-3">
        <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
        <div className="text-xs space-y-1">
          <span className="font-bold text-red-300 uppercase tracking-wider">
            Mandatory Report Integrity Notice (Section 16)
          </span>
          <p className="text-red-200/90 leading-relaxed">
            All generated PDF reports feature a mandatory <strong>SYNTHETIC DATA</strong> watermark and header disclosure. CSV exports enforce formula-injection defense by escaping user-controlled string prefixes (<code>=</code>, <code>+</code>, <code>-</code>, <code>@</code>, <code>\t</code>).
          </p>
        </div>
      </div>

      {/* Reports Table / List */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold text-slate-100">
            Generated Report Archive ({reports.length})
          </h2>
          <span className="text-xs font-mono text-slate-400">Read-Only Artifacts</span>
        </div>

        {reports.length === 0 ? (
          <div className="text-center py-16 space-y-3">
            <FileText className="w-10 h-10 text-slate-600 mx-auto" />
            <h3 className="text-sm font-bold text-slate-300">No Reports Generated Yet</h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              Execute an investigation turn in the AI Assistant, then click "Export PDF" or "Export JSON" to produce a cryptographically verifiable report artifact.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {reports.map((rep) => {
              const downloadUrl = getReportDownloadUrl(rep.download_url)

              return (
                <div
                  key={rep.id}
                  className="bg-slate-950 p-4 rounded-lg border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:border-slate-700 transition"
                >
                  <div className="space-y-1.5">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-sm text-sky-400">{rep.id}</span>
                      <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded bg-sky-950 text-sky-300 border border-sky-800">
                        {rep.format}
                      </span>
                      <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded bg-red-950 text-red-300 border border-red-800">
                        SYNTHETIC
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono">
                      <Hash className="w-3.5 h-3.5 text-slate-500" />
                      <span>SHA-256:</span>
                      <span className="text-slate-300 select-all">{rep.sha256}</span>
                    </div>

                    <div className="flex items-center gap-4 text-[11px] text-slate-400">
                      <span>Case: <span className="font-mono text-slate-300">{rep.investigation_id}</span></span>
                      <span>Created: {new Date(rep.created_at).toLocaleString()}</span>
                    </div>
                  </div>

                  <a
                    href={downloadUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center justify-center gap-1.5 bg-sky-600 hover:bg-sky-500 text-white px-4 py-2 rounded-lg text-xs font-semibold transition shrink-0 shadow-md shadow-sky-950"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download Artifact</span>
                  </a>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
