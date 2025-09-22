export type DocumentNode = {
  id: string
  title: string
  type: 'file' | 'folder'
  children?: DocumentNode[]
  created_at?: string
  updated_at?: string
}

