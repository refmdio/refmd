export type ActiveShareItem = {
  id: string
  token: string
  permission: string
  expires_at?: string
  created_at: string
  document_id: string
  document_title: string
  document_type: 'document' | 'folder'
  url: string
  parent_share_id?: string | null
}
