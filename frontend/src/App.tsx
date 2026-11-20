import { useState, useEffect, useCallback } from 'react'
import { Navbar } from './components/Navbar'
import { Sidebar, type NavTab } from './components/Sidebar'
import { OverviewDashboard } from './components/OverviewDashboard'
import { ChatAssistant } from './components/ChatAssistant'
import { EventExplorer } from './components/EventExplorer'
import { InvestigationWorkspace } from './components/InvestigationWorkspace'
import { ThreatAnalysis } from './components/ThreatAnalysis'
import { ReportsView } from './components/ReportsView'
import { AuditTrail } from './components/AuditTrail'
import { AuthModal } from './components/AuthModal'
import {
  fetchProviderStatus,
  fetchDatabaseHealth,
  fetchReadiness,
  fetchCurrentUser,
  login,
  getAuthToken,
  clearAuthToken,
  createConversation,
  getConversationDetail,
  sendChatMessage,
  generateReport,
  executeSqsQuery,
} from './services/api'
import type {
  AuditRecord,
  CanonicalSecurityEvent,
  Conversation,
  DatabaseHealth,
  Finding,
  MessageItem,
  ProviderStatus,
  ReportItem,
  UserProfile,
} from './types'

export default function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('overview')
  const [providerStatus, setProviderStatus] = useState<ProviderStatus | null>(null)
  const [dbHealth, setDbHealth] = useState<DatabaseHealth | null>(null)
  const [user, setUser] = useState<UserProfile | null>(null)
  const [authModalOpen, setAuthModalOpen] = useState(false)

  // Investigation & Chat state
  const [conversation, setConversation] = useState<Conversation | null>(null)
  const [messages, setMessages] = useState<MessageItem[]>([])
  const [activeInvestigationId, setActiveInvestigationId] = useState<string | null>(null)
  const [activeFindings, setActiveFindings] = useState<Finding[]>([])
  const [activeEvidenceIds, setActiveEvidenceIds] = useState<string[]>([])
  const [reports, setReports] = useState<ReportItem[]>([])
  const [events, setEvents] = useState<CanonicalSecurityEvent[]>([])
  const [auditRecords, setAuditRecords] = useState<AuditRecord[]>([])

  // Loading & error flags
  const [loading, setLoading] = useState(false)
  const [reportGenerating, setReportGenerating] = useState(false)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)

  // Append audit record helper
  const addAuditRecord = useCallback((action: string, resource: string, status: string, duration_ms?: number, details?: string) => {
    const record: AuditRecord = {
      id: `aud-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString(),
      action,
      resource,
      status,
      duration_ms,
      details,
    }
    setAuditRecords((prev) => [record, ...prev])
  }, [])

  // Initialization: fetch readiness, health, provider status, user profile, initial events, and conversation
  useEffect(() => {
    async function init() {
      setLoading(true)
      const t0 = performance.now()

      try {
        // 1. Public health & database checks in parallel
        const [_readiness, dbH] = await Promise.allSettled([
          fetchReadiness(),
          fetchDatabaseHealth(),
        ])
        if (dbH.status === 'fulfilled') setDbHealth(dbH.value)

        // 2. Ensure authenticated analyst session
        let profile: UserProfile | null = null
        if (getAuthToken()) {
          try {
            profile = await fetchCurrentUser()
          } catch {
            clearAuthToken()
          }
        }

        if (!profile) {
          try {
            // Auto-authenticate with default demo analyst credentials for seamless SOC demo
            const authRes = await login('analyst@sentinel.ai', 'Sentinel123!')
            profile = {
              id: authRes.user_id,
              email: authRes.email,
              display_name: authRes.display_name,
              role: authRes.role,
              is_active: true,
            }
          } catch (loginErr: any) {
            console.warn('Auto-login notice:', loginErr)
          }
        }
        setUser(profile)

        // 3. Provider status (now authenticated)
        try {
          const provStatus = await fetchProviderStatus()
          setProviderStatus(provStatus)
        } catch (provErr: any) {
          console.warn('Provider status notice:', provErr)
        }

        // 4. Create or load initial investigation conversation
        try {
          const conv = await createConversation('Initial SOC Incident Investigation')
          setConversation(conv)
        } catch (convErr: any) {
          console.warn('Conversation init notice:', convErr)
        }

        // 5. Load initial security telemetry via live backend SQS query
        try {
          const queryRes = await executeSqsQuery({ pageSize: 100, intent: 'Initial SOC telemetry load' })
          setEvents(queryRes.events || [])
          addAuditRecord(
            'QueryExecution',
            'SyntheticProvider',
            'success',
            queryRes.metadata.took_ms,
            `Loaded ${queryRes.metadata.total_hits} canonical events across 10 scenarios`
          )
        } catch (queryErr: any) {
          console.warn('Initial event load notice:', queryErr)
        }

        const elapsed = Math.round(performance.now() - t0)
        addAuditRecord('SystemInit', 'Backend Readiness', 'success', elapsed, 'Initialized SOC dashboard')
      } catch (err: any) {
        console.error('Initialization error:', err)
        setErrorMsg(err.message || 'Could not connect to SENTINEL AI backend. Please verify your connection.')
        addAuditRecord('SystemInit', 'Backend Connection', 'failed', 0, err.message)
      } finally {
        setLoading(false)
      }
    }

    init()
  }, [addAuditRecord])

  // Handle Chat Message Execution
  const handleSendMessage = async (text: string) => {
    if (!text.trim() || loading) return

    setLoading(true)
    setErrorMsg(null)
    const t0 = performance.now()

    let activeConv = conversation
    if (!activeConv) {
      try {
        activeConv = await createConversation('SOC Incident Investigation')
        setConversation(activeConv)
      } catch (convErr: any) {
        setErrorMsg('Failed to initialize conversation: ' + (convErr.message || String(convErr)))
        setLoading(false)
        return
      }
    }

    // Optimistically add user message
    const tempUserMsg: MessageItem = {
      id: `temp-${Date.now()}`,
      role: 'user',
      content: text,
      created_at: new Date().toISOString(),
    }
    setMessages((prev) => [...prev, tempUserMsg])

    try {
      const res = await sendChatMessage(activeConv.id, text, activeInvestigationId || undefined)

      setActiveInvestigationId(res.investigation_id)
      setActiveFindings(res.findings)
      setActiveEvidenceIds(res.evidence_ids)

      // Refresh message history from server for full metadata
      const detail = await getConversationDetail(activeConv.id)
      setMessages(detail.messages)

      const elapsed = Math.round(performance.now() - t0)
      addAuditRecord(
        'ChatTurnExecution',
        res.investigation_id,
        res.validation_status,
        elapsed,
        `Result count: ${res.result_count}, Findings: ${res.findings.length}, Evidence: ${res.evidence_ids.length}`
      )
    } catch (err: any) {
      setErrorMsg(err.message || 'Error executing investigation query')
      addAuditRecord('ChatTurnExecution', activeConv.id, 'failed', Math.round(performance.now() - t0), err.message)
    } finally {
      setLoading(false)
    }
  }

  // Handle Report Generation
  const handleGenerateReport = async (format: 'pdf' | 'json' | 'csv') => {
    if (!activeInvestigationId || reportGenerating) return

    setReportGenerating(true)
    const t0 = performance.now()

    try {
      const rep = await generateReport(
        activeInvestigationId,
        format,
        'Executive Security Incident Summary'
      )
      setReports((prev) => [rep, ...prev])
      const elapsed = Math.round(performance.now() - t0)
      addAuditRecord(
        'ReportGeneration',
        rep.id,
        'completed',
        elapsed,
        `Format: ${format.toUpperCase()}, SHA-256: ${rep.sha256.substring(0, 16)}...`
      )
      setActiveTab('reports')
    } catch (err: any) {
      alert(`Report generation failed: ${err.message}`)
      addAuditRecord('ReportGeneration', activeInvestigationId, 'failed', Math.round(performance.now() - t0), err.message)
    } finally {
      setReportGenerating(false)
    }
  }

  const handleLogout = () => {
    clearAuthToken()
    setUser(null)
    addAuditRecord('AuthSignOut', 'AnalystSession', 'success')
  }

  const handleInspectEvidence = (_evidenceId: string) => {
    setActiveTab('events')
  }

  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-slate-950 text-slate-100 font-sans">
      {/* Top Navigation Bar */}
      <Navbar
        providerStatus={providerStatus}
        dbHealth={dbHealth}
        user={user}
        onOpenAuth={() => setAuthModalOpen(true)}
        onLogout={handleLogout}
      />

      {/* Main Layout: Sidebar + View Container */}
      <div className="flex flex-1 overflow-hidden">
        <Sidebar
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          activeFindingsCount={activeFindings.length}
          reportsCount={reports.length}
        />

        <main className="flex-1 flex flex-col overflow-hidden bg-slate-950">
          {activeTab === 'overview' && (
            <OverviewDashboard
              events={events}
              activeFindings={activeFindings}
              reportsCount={reports.length}
              loading={loading}
              onNavigateToChat={(query) => {
                setActiveTab('chat')
                if (query) handleSendMessage(query)
              }}
              onNavigateToEvents={() => setActiveTab('events')}
            />
          )}

          {activeTab === 'chat' && (
            <ChatAssistant
              messages={messages}
              loading={loading}
              errorMsg={errorMsg}
              activeInvestigationId={activeInvestigationId}
              activeFindings={activeFindings}
              activeEvidenceIds={activeEvidenceIds}
              onSendMessage={handleSendMessage}
              onGenerateReport={handleGenerateReport}
              reportGenerating={reportGenerating}
              onInspectEvidence={handleInspectEvidence}
            />
          )}

          {activeTab === 'events' && (
            <EventExplorer
              events={events}
              loading={loading}
              onInvestigateEvent={(_id, details) => {
                setActiveTab('chat')
                handleSendMessage(details)
              }}
            />
          )}

          {activeTab === 'investigation' && (
            <InvestigationWorkspace
              investigationId={activeInvestigationId}
              activeFindings={activeFindings}
              activeEvidenceIds={activeEvidenceIds}
              onGenerateReport={handleGenerateReport}
              reportGenerating={reportGenerating}
              onNavigateToChat={(query) => {
                setActiveTab('chat')
                if (query) handleSendMessage(query)
              }}
              onInspectEvidence={handleInspectEvidence}
            />
          )}

          {activeTab === 'threats' && (
            <ThreatAnalysis activeFindings={activeFindings} />
          )}

          {activeTab === 'reports' && (
            <ReportsView
              reports={reports}
              activeInvestigationId={activeInvestigationId}
              onGenerateReport={handleGenerateReport}
              reportGenerating={reportGenerating}
            />
          )}

          {activeTab === 'audit' && (
            <AuditTrail auditRecords={auditRecords} />
          )}
        </main>
      </div>

      {/* Auth Modal */}
      <AuthModal
        isOpen={authModalOpen}
        onClose={() => setAuthModalOpen(false)}
        onSuccess={(profile) => {
          setUser(profile)
          addAuditRecord('AuthSignIn', profile.email, 'success')
        }}
      />
    </div>
  )
}
