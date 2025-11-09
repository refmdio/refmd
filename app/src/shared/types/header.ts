import type { DocumentHeaderAction } from '@/shared/types/document'

export type HeaderRealtimeState = {
  connected: boolean
  showEditorFeatures: boolean
  documentTitle?: string
  documentId?: string
  documentPath?: string
  documentStatus?: string
  documentBadge?: string
  documentActions?: DocumentHeaderAction[]
  onlineUsers: Array<{ id: string; name: string; color?: string; clientId?: number }>
}
