import type {
  AuthTokenResponse,
  ChatTurnResponse,
  Conversation,
  DatabaseHealth,
  MessageItem,
  ProviderStatus,
  QueryExecuteResponse,
  QueryPreviewResponse,
  ReportItem,
  SystemReadiness,
  UserProfile,
} from '../types'

const API_BASE = `${import.meta.env.VITE_API_BASE_URL || ''}/api/v1`

// --- Token Management ---
const TOKEN_KEY = 'sentinel_auth_token'

export function getAuthToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setAuthToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token)
}

export function clearAuthToken(): void {
  localStorage.removeItem(TOKEN_KEY)
}

// --- Authorized Fetch Helper ---
async function apiFetch<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE}${endpoint}`
  const headers = new Headers(options.headers || {})

  if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json')
  }

  const token = getAuthToken()
  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`)
  }

  const response = await fetch(url, { ...options, headers })

  if (!response.ok) {
    let errorDetail = response.statusText
    try {
      const errorData = await response.json()
      if (errorData.detail) {
        errorDetail = typeof errorData.detail === 'string'
          ? errorData.detail
          : JSON.stringify(errorData.detail)
      }
    } catch {
      // Non-JSON error body
    }
    throw new Error(errorDetail || `HTTP ${response.status}`)
  }

  return response.json()
}

// --- Health Probes ---
export async function fetchReadiness(): Promise<SystemReadiness> {
  return apiFetch<SystemReadiness>('/health/ready')
}

export async function fetchDatabaseHealth(): Promise<DatabaseHealth> {
  return apiFetch<DatabaseHealth>('/health/db')
}

export async function fetchProviderStatus(): Promise<ProviderStatus> {
  return apiFetch<ProviderStatus>('/providers/status')
}

// --- Authentication ---
export async function login(email: string, password: string): Promise<AuthTokenResponse> {
  const res = await apiFetch<AuthTokenResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  })
  if (res.access_token) {
    setAuthToken(res.access_token)
  }
  return res
}

export async function fetchCurrentUser(): Promise<UserProfile> {
  return apiFetch<UserProfile>('/auth/me')
}

// --- Conversations & Chat ---
export async function createConversation(title = 'New Investigation'): Promise<Conversation> {
  return apiFetch<Conversation>('/conversations', {
    method: 'POST',
    body: JSON.stringify({ title, provider: 'synthetic', data_mode: 'synthetic' }),
  })
}

export async function listConversations(): Promise<Conversation[]> {
  return apiFetch<Conversation[]>('/conversations')
}

export async function getConversationDetail(
  id: string
): Promise<{ conversation: Conversation; messages: MessageItem[] }> {
  return apiFetch<{ conversation: Conversation; messages: MessageItem[] }>(`/conversations/${id}`)
}

export async function sendChatMessage(
  conversationId: string,
  message: string,
  investigationId?: string
): Promise<ChatTurnResponse> {
  return apiFetch<ChatTurnResponse>('/chat', {
    method: 'POST',
    body: JSON.stringify({
      conversation_id: conversationId,
      message,
      investigation_id: investigationId,
    }),
  })
}

// --- Query Execution & Event Explorer ---
export interface SqsQueryOptions {
  timeStart?: string
  timeEnd?: string
  filters?: Array<{ field: string; operator: string; value: any }>
  aggregations?: Array<{ type: string; field: string; size?: number; interval?: string }>
  sortField?: string
  sortOrder?: 'asc' | 'desc'
  pageSize?: number
  intent?: string
}

export async function executeSqsQuery(
  options: SqsQueryOptions = {},
  investigationId?: string
): Promise<QueryExecuteResponse> {
  const now = new Date()
  const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)

  const spec = {
    provider: 'synthetic',
    time_range: {
      start: options.timeStart || sevenDaysAgo.toISOString(),
      end: options.timeEnd || now.toISOString(),
    },
    filters: options.filters || [],
    aggregations: options.aggregations || [],
    sort_field: options.sortField || '@timestamp',
    sort_order: options.sortOrder || 'desc',
    page_size: options.pageSize || 100,
    intent: options.intent || 'SOC Security Telemetry Query',
  }

  return apiFetch<QueryExecuteResponse>('/queries/execute', {
    method: 'POST',
    body: JSON.stringify({ spec, investigation_id: investigationId }),
  })
}

export async function previewSqsQuery(spec: any): Promise<QueryPreviewResponse> {
  return apiFetch<QueryPreviewResponse>('/queries/preview', {
    method: 'POST',
    body: JSON.stringify({ spec }),
  })
}

// --- Reports ---
export async function generateReport(
  investigationId: string,
  format: 'pdf' | 'json' | 'csv',
  title = 'Incident Threat Report'
): Promise<ReportItem> {
  return apiFetch<ReportItem>(`/investigations/${investigationId}/reports`, {
    method: 'POST',
    body: JSON.stringify({ format, title }),
  })
}

export async function fetchReportMetadata(reportId: string): Promise<ReportItem> {
  return apiFetch<ReportItem>(`/reports/${reportId}`)
}

export function getReportDownloadUrl(downloadPath: string): string {
  if (downloadPath.startsWith('http')) return downloadPath
  return `${import.meta.env.VITE_API_BASE_URL || ''}${downloadPath}`
}
