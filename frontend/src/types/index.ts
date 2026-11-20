export interface Finding {
  finding_type: string
  title: string
  description: string
  classification: string
  severity: string
  confidence_label: string
  evidence_ids: string[]
}

export interface MessageItem {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  created_at: string
  metadata?: {
    evidence_ids?: string[]
    suspect_accounts?: string[]
    findings?: Finding[]
    result_count?: number
    query_spec?: any
  } | null
}

export interface Conversation {
  id: string
  user_id: string
  title: string
  provider: string
  data_mode: string
  created_at: string
  updated_at: string
}

export interface ChatTurnResponse {
  request_id: string
  conversation_id: string
  investigation_id: string
  assistant_message: string
  query_spec: any
  validation_status: string
  result_count: number
  evidence_ids: string[]
  findings: Finding[]
  data_mode: string
  follow_up_suggestions: string[]
}

export interface ProviderHealth {
  provider: string
  status: string
  version?: string
  message?: string
  checked_at: string
}

export interface ProviderStatus {
  provider: string
  data_mode: string
  is_synthetic: boolean
  health: ProviderHealth
  field_mappings: Record<string, string>
}

export interface ReportItem {
  id: string
  investigation_id: string
  user_id: string
  format: 'pdf' | 'json' | 'csv'
  status: string
  data_mode: string
  artifact_path: string
  sha256: string
  download_url: string
  created_at: string
}

export interface SystemReadiness {
  status: 'ready' | 'degraded'
  provider: string
  data_mode: string
  checks: Record<string, string>
}

export interface DatabaseHealth {
  status: 'healthy' | 'unhealthy'
  database: string
  latency_ms: number
  error: string | null
}

export interface UserProfile {
  id: string
  email: string
  display_name: string
  role: string
  is_active: boolean
}

export interface AuthTokenResponse {
  access_token: string
  token_type: string
  user_id: string
  email: string
  role: string
  display_name: string
}

export interface SecurityEventDetail {
  id: string
  kind: string
  category: string
  type?: string
  action?: string
  outcome?: string
  severity: number
  created?: string
  ingested?: string
}

export interface CanonicalSecurityEvent {
  event: SecurityEventDetail
  '@timestamp': string
  message?: string
  source?: {
    ip?: string
    port?: number
  }
  destination?: {
    ip?: string
    port?: number
  }
  user?: {
    name?: string
    id?: string
  }
  host?: {
    name?: string
    id?: string
    os?: { name?: string }
  }
  process?: {
    name?: string
    command_line?: string
    pid?: number
  }
  file?: {
    path?: string
    hash?: { sha256?: string }
  }
  rule?: {
    id?: string
    name?: string
  }
  sentinel: {
    source: {
      provider: string
      index?: string
      document_id?: string
    }
    data_mode: string
    normalization_version: string
  }
}

export interface QueryExecuteResponse {
  execution_id: string
  provider: string
  data_mode: string
  metadata: {
    total_hits: number
    returned_count: number
    is_exact: boolean
    took_ms: number
    warnings: string[]
  }
  events: CanonicalSecurityEvent[]
  aggregations: Array<{
    name: string
    buckets: Array<{ key: string; doc_count: number }>
  }>
}

export interface QueryPreviewResponse {
  is_valid: boolean
  errors: Array<{ field: string; message: string }>
  warnings: string[]
  compiled_request: Record<string, any> | null
  provider: string
  data_mode: string
}

export interface AuditRecord {
  id: string
  timestamp: string
  action: string
  resource: string
  status: string
  duration_ms?: number
  details?: string
}
