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

export interface ProviderStatus {
  provider: string
  data_mode: string
  is_synthetic: boolean
  health: {
    provider: string
    status: string
    version?: string
    message?: string
    checked_at: string
  }
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
