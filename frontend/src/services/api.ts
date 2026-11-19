import type {
  ChatTurnResponse,
  Conversation,
  MessageItem,
  ProviderStatus,
  ReportItem,
} from '../types'

const API_BASE = `${import.meta.env.VITE_API_BASE_URL || ''}/api/v1`

export async function fetchProviderStatus(): Promise<ProviderStatus> {
  const res = await fetch(`${API_BASE}/providers/status`)
  if (!res.ok) throw new Error(`Failed to fetch provider status: ${res.statusText}`)
  return res.json()
}

export async function createConversation(title = 'New Investigation'): Promise<Conversation> {
  const res = await fetch(`${API_BASE}/conversations`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ title, provider: 'synthetic' }),
  })
  if (!res.ok) throw new Error(`Failed to create conversation: ${res.statusText}`)
  return res.json()
}

export async function listConversations(): Promise<Conversation[]> {
  const res = await fetch(`${API_BASE}/conversations`)
  if (!res.ok) throw new Error(`Failed to list conversations: ${res.statusText}`)
  return res.json()
}

export async function getConversationDetail(
  id: string
): Promise<{ conversation: Conversation; messages: MessageItem[] }> {
  const res = await fetch(`${API_BASE}/conversations/${id}`)
  if (!res.ok) throw new Error(`Failed to get conversation: ${res.statusText}`)
  return res.json()
}

export async function sendChatMessage(
  conversationId: string,
  message: string,
  investigationId?: string
): Promise<ChatTurnResponse> {
  const res = await fetch(`${API_BASE}/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      conversation_id: conversationId,
      message,
      investigation_id: investigationId,
    }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Chat request failed with ${res.status}`)
  }
  return res.json()
}

export async function generateReport(
  investigationId: string,
  format: 'pdf' | 'json' | 'csv',
  title = 'Incident Threat Report'
): Promise<ReportItem> {
  const res = await fetch(`${API_BASE}/investigations/${investigationId}/reports`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ format, title }),
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({}))
    throw new Error(err.detail || `Report generation failed: ${res.statusText}`)
  }
  return res.json()
}
