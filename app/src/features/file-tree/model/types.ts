export type DocumentNode = {
  id: string
  sourceId?: string
  title: string
  type: 'file' | 'folder'
  // Follows source structure for mounted shares
  children?: DocumentNode[]
  created_at?: string
  updated_at?: string
  archived?: boolean
  shareToken?: string
  isShareMount?: boolean
  shareMountId?: string
}
