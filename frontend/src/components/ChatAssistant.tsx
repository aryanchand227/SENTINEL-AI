import React, { useState, useRef, useEffect } from 'react'
import {
  Send,
  Terminal,
  Activity,
  Shield,
  AlertTriangle,
  FileText,
  Sparkles,
} from 'lucide-react'
import type { MessageItem, Finding } from '../types'

interface ChatAssistantProps {
  messages: MessageItem[]
  loading: boolean
  errorMsg: string | null
  activeInvestigationId: string | null
  activeFindings: Finding[]
  activeEvidenceIds: string[]
  onSendMessage: (query: string) => Promise<void>
  onGenerateReport: (format: 'pdf' | 'json' | 'csv') => Promise<void>
  reportGenerating: boolean
  onInspectEvidence?: (evidenceId: string) => void
}

export const ChatAssistant: React.FC<ChatAssistantProps> = ({
  messages,
  loading,
  errorMsg,
  activeInvestigationId,
  activeFindings,
  activeEvidenceIds,
  onSendMessage,
  onGenerateReport,
  reportGenerating,
  onInspectEvidence,
}) => {
  const [inputMessage, setInputMessage] = useState('')
  const messagesEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!inputMessage.trim() || loading) return
    const text = inputMessage
    setInputMessage('')
    onSendMessage(text)
  }

  const exampleQueries = [
    'Find accounts with failed logins in the last 24 hours.',
    'Did any of those accounts log in successfully afterwards?',
    'Show suspicious PowerShell execution with encoded commands.',
    'Identify malware detection alerts and outbound connections.',
  ]

  // Helper to split AI narrative assessment from structured markdown findings
  const renderAssistantMessage = (content: string) => {
    // If the message has an Analyst Assessment section, highlight it
    const parts = content.split('\n\n')
    const hasAnalystAssessment = content.includes('**Analyst Assessment:**')

    return (
      <div className="space-y-3">
        {hasAnalystAssessment ? (
          <div className="bg-sky-950/40 border border-sky-800/60 p-3 rounded-lg text-sky-200 text-xs leading-relaxed">
            <div className="flex items-center gap-1.5 text-sky-400 font-bold mb-1">
              <Sparkles className="w-3.5 h-3.5" />
              <span>AI Analyst Executive Assessment (Groq / Cloud LLM)</span>
            </div>
            <p className="whitespace-pre-wrap">{parts[0].replace('**Analyst Assessment:**', '').trim()}</p>
          </div>
        ) : null}

        {/* Remainder of the response (findings, MITRE, SQS plan) */}
        <div className="whitespace-pre-wrap text-slate-200 text-xs leading-relaxed font-sans">
          {hasAnalystAssessment ? parts.slice(1).join('\n\n') : content}
        </div>
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full bg-slate-950">
      {/* Top Investigation Status Bar */}
      <div className="px-6 py-2.5 bg-slate-900 border-b border-slate-800 flex items-center justify-between text-xs">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 text-sky-400 font-medium">
            <Terminal className="w-4 h-4" />
            <span>Investigation Scope:</span>
            <span className="font-mono text-slate-100">
              {activeInvestigationId || 'No active case (query to initialize)'}
            </span>
          </div>

          {activeFindings.length > 0 && (
            <span className="bg-red-950 text-red-300 border border-red-800 px-2 py-0.5 rounded text-[11px] font-semibold">
              {activeFindings.length} Correlated Finding{activeFindings.length > 1 ? 's' : ''}
            </span>
          )}

          {activeEvidenceIds.length > 0 && (
            <span className="bg-sky-950 text-sky-300 border border-sky-800 px-2 py-0.5 rounded text-[11px] font-mono">
              {activeEvidenceIds.length} Verified Evidence Records
            </span>
          )}
        </div>

        {/* Quick Report Trigger */}
        {activeInvestigationId && (
          <div className="flex items-center gap-2">
            <button
              onClick={() => onGenerateReport('pdf')}
              disabled={reportGenerating}
              className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-sky-400 border border-slate-700 px-2.5 py-1 rounded text-xs font-semibold transition disabled:opacity-50"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Export PDF</span>
            </button>
            <button
              onClick={() => onGenerateReport('json')}
              disabled={reportGenerating}
              className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 px-2.5 py-1 rounded text-xs font-semibold transition disabled:opacity-50"
            >
              <span>Export JSON</span>
            </button>
          </div>
        )}
      </div>

      {/* Error Banner */}
      {errorMsg && (
        <div className="bg-red-950 border-b border-red-800 px-6 py-2 text-red-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Messages Stream */}
      <div className="flex-1 overflow-y-auto p-6 space-y-4">
        {messages.length === 0 && (
          <div className="text-center py-16 max-w-xl mx-auto space-y-4">
            <div className="w-12 h-12 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-center mx-auto text-sky-400">
              <Shield className="w-6 h-6" />
            </div>
            <h2 className="text-lg font-bold text-slate-100">
              Conversational SIEM Assistant Ready
            </h2>
            <p className="text-xs text-slate-400 leading-relaxed">
              Ask natural-language SOC inquiries to search simulated security telemetry, evaluate multi-turn attack hypotheses, verify forensic evidence, and generate immutable incident reports.
            </p>

            <div className="pt-2">
              <span className="text-[11px] uppercase font-mono tracking-wider text-slate-400 block mb-2">
                Example Analyst Inquiries
              </span>
              <div className="flex flex-wrap gap-2 justify-center">
                {exampleQueries.map((query, i) => (
                  <button
                    key={i}
                    onClick={() => onSendMessage(query)}
                    className="bg-slate-900 hover:bg-slate-800 border border-slate-800 text-sky-400 text-xs px-3 py-1.5 rounded-full transition text-left"
                  >
                    "{query}"
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {messages.map((m) => {
          const isUser = m.role === 'user'

          return (
            <div
              key={m.id}
              className={`flex flex-col ${isUser ? 'items-end' : 'items-start'} w-full`}
            >
              <div
                className={`max-w-[85%] rounded-xl p-4 text-xs leading-relaxed ${
                  isUser
                    ? 'bg-blue-600/20 border border-blue-500/40 text-blue-100'
                    : 'bg-slate-900 border border-slate-800 text-slate-100 shadow-md'
                }`}
              >
                {/* Header tag */}
                <div className="flex items-center justify-between gap-4 mb-2 pb-1.5 border-b border-slate-800/80 text-[10px] font-mono">
                  <span className={isUser ? 'text-blue-300 font-bold' : 'text-sky-400 font-bold'}>
                    {isUser ? 'SOC Analyst' : 'SENTINEL AI (LangGraph)'}
                  </span>
                  <span className="text-slate-400">
                    {new Date(m.created_at).toLocaleTimeString()}
                  </span>
                </div>

                {/* Content */}
                {isUser ? (
                  <div className="text-sm font-medium text-slate-100 whitespace-pre-wrap">
                    {m.content}
                  </div>
                ) : (
                  renderAssistantMessage(m.content)
                )}

                {/* Cited Evidence Pills */}
                {!isUser && m.metadata?.evidence_ids && m.metadata.evidence_ids.length > 0 && (
                  <div className="mt-3 pt-2.5 border-t border-slate-800/80 flex flex-wrap gap-1.5 items-center">
                    <span className="text-[10px] text-slate-400 font-medium">Cited Evidence:</span>
                    {m.metadata.evidence_ids.map((eid) => (
                      <button
                        key={eid}
                        onClick={() => onInspectEvidence?.(eid)}
                        className="bg-slate-950 text-sky-400 hover:text-sky-300 font-mono text-[10px] px-2 py-0.5 rounded border border-slate-800 hover:border-sky-500 transition"
                      >
                        {eid}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )
        })}

        {loading && (
          <div className="flex items-center gap-3 text-sky-400 text-xs bg-slate-900/60 border border-slate-800/80 p-3 rounded-lg max-w-md">
            <Activity className="w-4 h-4 animate-spin text-sky-400" />
            <div className="flex flex-col">
              <span className="font-semibold text-slate-200">Executing LangGraph Workflow...</span>
              <span className="text-[11px] text-slate-400">
                Planning intent, compiling SQS, executing SIEM search, and mapping ATT&CK
              </span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input Bar & Suggestions */}
      <div className="p-4 bg-slate-900 border-t border-slate-800 space-y-3">
        {/* Quick Follow-up Suggestions */}
        <div className="flex flex-wrap gap-2 text-xs">
          {[
            'Did any of those accounts log in successfully afterwards?',
            'Show top source IP addresses associated with those failures.',
            'Generate a report for this investigation.',
          ].map((sug, i) => (
            <button
              key={i}
              onClick={() => onSendMessage(sug)}
              disabled={loading}
              className="bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700/60 text-slate-300 text-[11px] px-2.5 py-1 rounded-full transition disabled:opacity-50"
            >
              ↳ {sug}
            </button>
          ))}
        </div>

        {/* Text Input Form */}
        <form onSubmit={handleSubmit} className="flex gap-2">
          <input
            type="text"
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            placeholder="Ask an investigation question (e.g. 'Show failed logins for admin', 'Check malware alerts')..."
            disabled={loading}
            className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-4 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-sky-500 transition disabled:opacity-60"
          />
          <button
            type="submit"
            disabled={loading || !inputMessage.trim()}
            className="flex items-center gap-1.5 bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold px-4 py-2.5 rounded-lg transition disabled:opacity-50 disabled:cursor-not-allowed shadow-md shadow-sky-950"
          >
            <Send className="w-3.5 h-3.5" />
            <span>Investigate</span>
          </button>
        </form>
      </div>
    </div>
  )
}
