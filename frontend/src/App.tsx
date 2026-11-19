import { useState, useEffect } from 'react'
import {
  Shield,
  AlertTriangle,
  FileText,
  Terminal,
  Activity,
  Send,
  Download,
  CheckCircle,
  Database,
} from 'lucide-react'
import {
  fetchProviderStatus,
  createConversation,
  getConversationDetail,
  sendChatMessage,
  generateReport,
} from './services/api'
import type {
  Conversation,
  MessageItem,
  ProviderStatus,
  Finding,
  ReportItem,
} from './types'

export default function App() {
  const [activeTab, setActiveTab] = useState<'chat' | 'inspector' | 'evidence' | 'reports' | 'settings'>('chat')
  const [providerStatus, setProviderStatus] = useState<ProviderStatus | null>(null)
  const [conversation, setConversation] = useState<Conversation | null>(null)
  const [messages, setMessages] = useState<MessageItem[]>([])
  const [inputMessage, setInputMessage] = useState('')
  const [loading, setLoading] = useState(false)
  const [activeInvestigationId, setActiveInvestigationId] = useState<string | null>(null)
  const [lastQuerySpec, setLastQuerySpec] = useState<any>(null)
  const [activeFindings, setActiveFindings] = useState<Finding[]>([])
  const [activeEvidenceIds, setActiveEvidenceIds] = useState<string[]>([])
  const [reports, setReports] = useState<ReportItem[]>([])
  const [reportGenerating, setReportGenerating] = useState(false)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)

  // Initialize provider status and default conversation
  useEffect(() => {
    async function init() {
      try {
        const status = await fetchProviderStatus()
        setProviderStatus(status)

        const conv = await createConversation('Initial SOC Investigation')
        setConversation(conv)
      } catch (err: any) {
        console.error('Initialization error:', err)
        setErrorMsg('Could not connect to SENTINEL AI backend. Make sure the server is running on port 8000.')
      }
    }
    init()
  }, [])

  const handleSendMessage = async (textToSend?: string) => {
    const text = textToSend || inputMessage
    if (!text.trim() || !conversation || loading) return

    setInputMessage('')
    setLoading(true)
    setErrorMsg(null)

    // Optimistic user message
    const tempUserMsg: MessageItem = {
      id: `temp-${Date.now()}`,
      role: 'user',
      content: text,
      created_at: new Date().toISOString(),
    }
    setMessages((prev) => [...prev, tempUserMsg])

    try {
      const res = await sendChatMessage(conversation.id, text, activeInvestigationId || undefined)

      setActiveInvestigationId(res.investigation_id)
      setLastQuerySpec(res.query_spec)
      setActiveFindings(res.findings)
      setActiveEvidenceIds(res.evidence_ids)

      // Refresh entire message stream from server for full fidelity
      const detail = await getConversationDetail(conversation.id)
      setMessages(detail.messages)
    } catch (err: any) {
      setErrorMsg(err.message || 'Error executing investigation turn')
    } finally {
      setLoading(false)
    }
  }

  const handleGenerateReport = async (format: 'pdf' | 'json' | 'csv') => {
    if (!activeInvestigationId || reportGenerating) return
    setReportGenerating(true)
    try {
      const rep = await generateReport(activeInvestigationId, format, 'Executive Security Incident Summary')
      setReports((prev) => [rep, ...prev])
      alert(`Report generated: ${rep.id} (SHA256: ${rep.sha256.substring(0, 16)}...)`)
    } catch (err: any) {
      alert(`Report generation failed: ${err.message}`)
    } finally {
      setReportGenerating(false)
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', backgroundColor: '#090d16', color: '#f8fafc', fontFamily: 'system-ui, sans-serif' }}>
      {/* Top Navbar */}
      <header style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 24px', backgroundColor: '#0f172a', borderBottom: '1px solid #1e293b' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Shield size={24} color="#38bdf8" />
            <span style={{ fontSize: '18px', fontWeight: 'bold', letterSpacing: '0.05em' }}>SENTINEL AI</span>
            <span style={{ fontSize: '11px', color: '#64748b', textTransform: 'uppercase' }}>SIH25173</span>
          </div>

          {/* Persistent SYNTHETIC DATA Designation Badge (Mandatory Section 3 & 16) */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            backgroundColor: '#450a0a',
            border: '1px solid #dc2626',
            color: '#fca5a5',
            padding: '3px 10px',
            borderRadius: '12px',
            fontSize: '11px',
            fontWeight: 'bold',
            letterSpacing: '0.08em',
          }}>
            <AlertTriangle size={14} color="#ef4444" />
            SYNTHETIC DATA MODE
          </div>
        </div>

        {/* Status Pills */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', fontSize: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#94a3b8' }}>
            <Database size={15} color="#38bdf8" />
            Provider: <span style={{ color: '#f1f5f9', fontWeight: 600 }}>{providerStatus?.provider || 'synthetic'}</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#4ade80' }}>
            <CheckCircle size={15} />
            <span>Operational</span>
          </div>
        </div>
      </header>

      {/* Main Tab Navigation */}
      <nav style={{ display: 'flex', gap: '8px', padding: '8px 24px', backgroundColor: '#131d31', borderBottom: '1px solid #1e293b' }}>
        {[
          { id: 'chat', label: 'Conversational Workspace', icon: Terminal },
          { id: 'inspector', label: 'Query Inspector (SQS)', icon: Activity },
          { id: 'evidence', label: `Evidence (${activeEvidenceIds.length})`, icon: Shield },
          { id: 'reports', label: `Reports (${reports.length})`, icon: FileText },
          { id: 'settings', label: 'Settings & Status', icon: Database },
        ].map((tab) => {
          const Icon = tab.icon
          const isActive = activeTab === tab.id
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 16px',
                borderRadius: '6px',
                fontSize: '13px',
                fontWeight: 600,
                border: 'none',
                cursor: 'pointer',
                backgroundColor: isActive ? '#1e293b' : 'transparent',
                color: isActive ? '#38bdf8' : '#94a3b8',
                transition: 'all 0.15s ease',
              }}
            >
              <Icon size={16} />
              {tab.label}
            </button>
          )
        })}
      </nav>

      {/* Error alert if any */}
      {errorMsg && (
        <div style={{ backgroundColor: '#7f1d1d', color: '#fecaca', padding: '10px 24px', fontSize: '13px', borderBottom: '1px solid #991b1b' }}>
          {errorMsg}
        </div>
      )}

      {/* Main Content Area */}
      <main style={{ flex: 1, overflow: 'auto', display: 'flex', flexDirection: 'column' }}>
        {/* Tab 1: Chat Workspace */}
        {activeTab === 'chat' && (
          <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
            {/* Messages container */}
            <div style={{ flex: 1, overflowY: 'auto', padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {messages.length === 0 && (
                <div style={{ textAlign: 'center', padding: '60px 20px', color: '#64748b' }}>
                  <Shield size={48} color="#334155" style={{ margin: '0 auto 16px' }} />
                  <h3 style={{ fontSize: '18px', color: '#94a3b8', marginBottom: '8px' }}>
                    Conversational SIEM Assistant Ready
                  </h3>
                  <p style={{ fontSize: '14px', maxWidth: '500px', margin: '0 auto 20px' }}>
                    Ask questions in natural language to search synthetic security telemetry, identify attack patterns, and track investigation evidence.
                  </p>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', justifyContent: 'center', maxWidth: '650px', margin: '0 auto' }}>
                    {[
                      'Find accounts with failed logins in the last 24 hours.',
                      'Show suspicious PowerShell execution.',
                      'Retrieve malware alerts today.',
                    ].map((example, i) => (
                      <button
                        key={i}
                        onClick={() => handleSendMessage(example)}
                        style={{
                          backgroundColor: '#1e293b',
                          color: '#38bdf8',
                          border: '1px solid #334155',
                          borderRadius: '16px',
                          padding: '6px 14px',
                          fontSize: '12px',
                          cursor: 'pointer',
                        }}
                      >
                        "{example}"
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {messages.map((m) => {
                const isUser = m.role === 'user'
                return (
                  <div
                    key={m.id}
                    style={{
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: isUser ? 'flex-end' : 'flex-start',
                      width: '100%',
                    }}
                  >
                    <div
                      style={{
                        maxWidth: '80%',
                        backgroundColor: isUser ? '#1e3a8a' : '#1e293b',
                        borderRadius: '8px',
                        padding: '12px 18px',
                        color: isUser ? '#e0f2fe' : '#f8fafc',
                        fontSize: '14px',
                        lineHeight: '1.5',
                        border: isUser ? '1px solid #2563eb' : '1px solid #334155',
                        whiteSpace: 'pre-wrap',
                      }}
                    >
                      <div style={{ fontSize: '11px', color: isUser ? '#93c5fd' : '#94a3b8', marginBottom: '6px', fontWeight: 'bold' }}>
                        {isUser ? 'SOC Analyst' : 'SENTINEL AI'}
                      </div>
                      <div>{m.content}</div>

                      {/* Evidence Pill inside assistant message */}
                      {!isUser && m.metadata?.evidence_ids && m.metadata.evidence_ids.length > 0 && (
                        <div style={{ marginTop: '10px', paddingTop: '8px', borderTop: '1px solid #334155', display: 'flex', gap: '6px', flexWrap: 'wrap', alignItems: 'center' }}>
                          <span style={{ fontSize: '11px', color: '#64748b' }}>Cited Evidence:</span>
                          {m.metadata.evidence_ids.slice(0, 4).map((eid) => (
                            <span
                              key={eid}
                              style={{
                                backgroundColor: '#0f172a',
                                color: '#38bdf8',
                                fontSize: '10px',
                                fontFamily: 'monospace',
                                padding: '2px 6px',
                                borderRadius: '4px',
                                border: '1px solid #1e293b',
                              }}
                            >
                              {eid}
                            </span>
                          ))}
                          {m.metadata.evidence_ids.length > 4 && (
                            <span style={{ fontSize: '10px', color: '#64748b' }}>+{m.metadata.evidence_ids.length - 4} more</span>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                )
              })}

              {loading && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#38bdf8', fontSize: '13px', padding: '8px 0' }}>
                  <Activity size={18} className="animate-spin" />
                  <span>Planning investigation query and validating security bounds...</span>
                </div>
              )}
            </div>

            {/* Quick Suggestions & Input Bar */}
            <div style={{ padding: '16px 24px', backgroundColor: '#0f172a', borderTop: '1px solid #1e293b' }}>
              {/* Follow-up suggestions */}
              <div style={{ display: 'flex', gap: '8px', marginBottom: '10px', flexWrap: 'wrap' }}>
                {[
                  'Did any of those accounts log in successfully afterwards?',
                  'Show top source IP addresses associated with those failures.',
                  'Generate a report for this investigation.',
                ].map((sug, i) => (
                  <button
                    key={i}
                    onClick={() => handleSendMessage(sug)}
                    style={{
                      backgroundColor: '#1e293b',
                      color: '#cbd5e1',
                      border: '1px solid #334155',
                      borderRadius: '12px',
                      padding: '4px 10px',
                      fontSize: '11px',
                      cursor: 'pointer',
                    }}
                  >
                    ↳ {sug}
                  </button>
                ))}
              </div>

              {/* Chat Input */}
              <form
                onSubmit={(e) => {
                  e.preventDefault()
                  handleSendMessage()
                }}
                style={{ display: 'flex', gap: '10px' }}
              >
                <input
                  type="text"
                  value={inputMessage}
                  onChange={(e) => setInputMessage(e.target.value)}
                  placeholder="Enter analyst query or investigation question..."
                  disabled={loading}
                  style={{
                    flex: 1,
                    backgroundColor: '#1e293b',
                    border: '1px solid #334155',
                    borderRadius: '6px',
                    padding: '10px 16px',
                    color: '#f8fafc',
                    fontSize: '14px',
                    outline: 'none',
                  }}
                />
                <button
                  type="submit"
                  disabled={loading || !inputMessage.trim()}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    backgroundColor: '#2563eb',
                    color: '#fff',
                    border: 'none',
                    borderRadius: '6px',
                    padding: '10px 20px',
                    fontSize: '14px',
                    fontWeight: 600,
                    cursor: loading ? 'not-allowed' : 'pointer',
                    opacity: loading || !inputMessage.trim() ? 0.6 : 1,
                  }}
                >
                  <Send size={16} />
                  Execute
                </button>
              </form>
            </div>
          </div>
        )}

        {/* Tab 2: Query Inspector */}
        {activeTab === 'inspector' && (
          <div style={{ padding: '24px', overflowY: 'auto' }}>
            <h2 style={{ fontSize: '18px', fontWeight: 'bold', marginBottom: '16px', color: '#f1f5f9' }}>
              Query Inspector: Sentinel Query Specification (SQS)
            </h2>
            <p style={{ fontSize: '13px', color: '#94a3b8', marginBottom: '20px' }}>
              Inspect the deterministic query plan generated by the NLP planner, validated by the QueryValidator, and compiled to the SIEM provider.
            </p>

            {lastQuerySpec ? (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                <div style={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', padding: '16px' }}>
                  <h3 style={{ fontSize: '14px', fontWeight: 'bold', color: '#38bdf8', marginBottom: '10px' }}>
                    Typed SQS Plan
                  </h3>
                  <pre style={{ fontSize: '12px', color: '#cbd5e1', overflowX: 'auto', backgroundColor: '#090d16', padding: '12px', borderRadius: '6px' }}>
                    {JSON.stringify(lastQuerySpec, null, 2)}
                  </pre>
                </div>
                <div style={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', padding: '16px' }}>
                  <h3 style={{ fontSize: '14px', fontWeight: 'bold', color: '#4ade80', marginBottom: '10px' }}>
                    Validation & Execution Status
                  </h3>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '13px' }}>
                    <div><b>Status:</b> <span style={{ color: '#4ade80' }}>VALIDATED & APPROVED</span></div>
                    <div><b>Provider:</b> {lastQuerySpec.provider}</div>
                    <div><b>Time Range:</b> {lastQuerySpec.time_range?.start} → {lastQuerySpec.time_range?.end}</div>
                    <div><b>Result Limit:</b> {lastQuerySpec.page_size} events max</div>
                    <div><b>Filters Applied:</b> {lastQuerySpec.filters?.length || 0}</div>
                    <div><b>Aggregations:</b> {lastQuerySpec.aggregations?.length || 0}</div>
                  </div>
                </div>
              </div>
            ) : (
              <div style={{ padding: '40px', textAlign: 'center', color: '#64748b' }}>
                No active query plan yet. Submit an investigation query in the Conversational Workspace to inspect the plan.
              </div>
            )}
          </div>
        )}

        {/* Tab 3: Evidence Panel */}
        {activeTab === 'evidence' && (
          <div style={{ padding: '24px', overflowY: 'auto' }}>
            <h2 style={{ fontSize: '18px', fontWeight: 'bold', marginBottom: '16px', color: '#f1f5f9' }}>
              Forensic Evidence & Findings Log
            </h2>

            {/* Findings cards */}
            {activeFindings.length > 0 && (
              <div style={{ marginBottom: '24px' }}>
                <h3 style={{ fontSize: '14px', fontWeight: 'bold', color: '#38bdf8', marginBottom: '10px' }}>Active Findings</h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {activeFindings.map((f, i) => (
                    <div key={i} style={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '6px', padding: '14px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                        <span style={{ fontWeight: 'bold', fontSize: '14px' }}>{f.title}</span>
                        <div style={{ display: 'flex', gap: '6px' }}>
                          <span style={{ backgroundColor: '#7f1d1d', color: '#fca5a5', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold' }}>
                            {f.severity.toUpperCase()}
                          </span>
                          <span style={{ backgroundColor: '#1e293b', color: '#94a3b8', padding: '2px 8px', borderRadius: '4px', fontSize: '11px' }}>
                            {f.classification.toUpperCase()}
                          </span>
                        </div>
                      </div>
                      <p style={{ fontSize: '13px', color: '#cbd5e1', margin: '4px 0 10px' }}>{f.description}</p>
                      <div style={{ fontSize: '11px', color: '#64748b' }}>
                        Evidence IDs ({f.evidence_ids.length}): {f.evidence_ids.join(', ')}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Evidence ID list */}
            <h3 style={{ fontSize: '14px', fontWeight: 'bold', color: '#38bdf8', marginBottom: '10px' }}>
              Supporting Evidence IDs ({activeEvidenceIds.length})
            </h3>
            {activeEvidenceIds.length > 0 ? (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                {activeEvidenceIds.map((eid) => (
                  <div
                    key={eid}
                    style={{
                      backgroundColor: '#0f172a',
                      border: '1px solid #334155',
                      padding: '8px 14px',
                      borderRadius: '6px',
                      fontFamily: 'monospace',
                      fontSize: '12px',
                      color: '#38bdf8',
                    }}
                  >
                    {eid}
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ padding: '30px', textAlign: 'center', color: '#64748b' }}>
                No active evidence records in current investigation scope.
              </div>
            )}
          </div>
        )}

        {/* Tab 4: Reports Panel */}
        {activeTab === 'reports' && (
          <div style={{ padding: '24px', overflowY: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
              <div>
                <h2 style={{ fontSize: '18px', fontWeight: 'bold', color: '#f1f5f9' }}>Automated Threat Reports</h2>
                <p style={{ fontSize: '13px', color: '#94a3b8', marginTop: '4px' }}>
                  Generate immutable, evidence-backed reports with cryptographic SHA-256 integrity verification and SYNTHETIC DATA watermarks.
                </p>
              </div>

              {/* Generate actions */}
              <div style={{ display: 'flex', gap: '10px' }}>
                {(['pdf', 'json', 'csv'] as const).map((fmt) => (
                  <button
                    key={fmt}
                    onClick={() => handleGenerateReport(fmt)}
                    disabled={!activeInvestigationId || reportGenerating}
                    style={{
                      backgroundColor: '#1e293b',
                      color: '#38bdf8',
                      border: '1px solid #334155',
                      borderRadius: '6px',
                      padding: '8px 14px',
                      fontSize: '12px',
                      fontWeight: 600,
                      cursor: !activeInvestigationId || reportGenerating ? 'not-allowed' : 'pointer',
                      opacity: !activeInvestigationId || reportGenerating ? 0.5 : 1,
                    }}
                  >
                    Export {fmt.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>

            {/* Reports list */}
            {reports.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                {reports.map((rep) => (
                  <div
                    key={rep.id}
                    style={{
                      backgroundColor: '#0f172a',
                      border: '1px solid #1e293b',
                      borderRadius: '6px',
                      padding: '16px',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                    }}
                  >
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <span style={{ fontWeight: 'bold', fontSize: '14px' }}>{rep.id}</span>
                        <span style={{ backgroundColor: '#1e293b', color: '#38bdf8', padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 'bold' }}>
                          {rep.format.toUpperCase()}
                        </span>
                        <span style={{ backgroundColor: '#450a0a', color: '#fca5a5', padding: '2px 8px', borderRadius: '4px', fontSize: '10px', fontWeight: 'bold' }}>
                          SYNTHETIC
                        </span>
                      </div>
                      <div style={{ fontSize: '11px', color: '#64748b', marginTop: '6px' }}>
                        SHA-256 Checksum: <span style={{ fontFamily: 'monospace' }}>{rep.sha256}</span>
                      </div>
                    </div>

                    <a
                      href={rep.download_url.startsWith('http') ? rep.download_url : `${import.meta.env.VITE_API_BASE_URL || ''}${rep.download_url}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px',
                        backgroundColor: '#2563eb',
                        color: '#fff',
                        textDecoration: 'none',
                        padding: '8px 14px',
                        borderRadius: '6px',
                        fontSize: '12px',
                        fontWeight: 600,
                      }}
                    >
                      <Download size={14} />
                      Download
                    </a>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ padding: '60px', textAlign: 'center', color: '#64748b' }}>
                No reports generated yet. Run an investigation query and click "Export PDF" or "Export JSON" to produce a verified report.
              </div>
            )}
          </div>
        )}

        {/* Tab 5: Settings & Status */}
        {activeTab === 'settings' && (
          <div style={{ padding: '24px', overflowY: 'auto' }}>
            <h2 style={{ fontSize: '18px', fontWeight: 'bold', marginBottom: '16px', color: '#f1f5f9' }}>
              System Configuration & Provider Status
            </h2>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
              <div style={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', padding: '16px' }}>
                <h3 style={{ fontSize: '14px', fontWeight: 'bold', color: '#38bdf8', marginBottom: '12px' }}>
                  Active Provider Health
                </h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '13px' }}>
                  <div><b>Provider Name:</b> {providerStatus?.provider}</div>
                  <div><b>Status:</b> <span style={{ color: '#4ade80' }}>{providerStatus?.health.status}</span></div>
                  <div><b>Data Mode:</b> {providerStatus?.data_mode}</div>
                  <div><b>Message:</b> {providerStatus?.health.message}</div>
                </div>
              </div>

              <div style={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', padding: '16px' }}>
                <h3 style={{ fontSize: '14px', fontWeight: 'bold', color: '#38bdf8', marginBottom: '12px' }}>
                  Approved ECS Field Registry ({providerStatus ? Object.keys(providerStatus.field_mappings).length : 0} fields)
                </h3>
                <div style={{ maxHeight: '300px', overflowY: 'auto', fontSize: '12px', fontFamily: 'monospace', color: '#cbd5e1' }}>
                  {providerStatus && Object.entries(providerStatus.field_mappings).map(([field, type]) => (
                    <div key={field} style={{ display: 'flex', justifyContent: 'space-between', padding: '3px 0', borderBottom: '1px solid #1e293b' }}>
                      <span>{field}</span>
                      <span style={{ color: '#94a3b8' }}>{type}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  )
}
