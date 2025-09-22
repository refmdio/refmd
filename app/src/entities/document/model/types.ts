export type DocumentType = 'document' | 'folder' | 'scrap'

export type DocumentSummary = {
  id: string
  title: string
  type: DocumentType | string
  path?: string | null
  created_at?: string
  updated_at?: string
}

