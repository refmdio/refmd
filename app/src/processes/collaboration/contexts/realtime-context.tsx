import React, { createContext, useContext, useMemo, useState } from 'react'

export type DocumentHeaderAction = {
  id?: string
  label: string
  onSelect?: () => void
  disabled?: boolean
  variant?: 'default' | 'primary' | 'outline'
}

type RealtimeState = {
  connected: boolean
  userCount: number
  onlineUsers: Array<{ id: string; name: string; color?: string; clientId?: number }>
  documentTitle?: string
  documentPath?: string
  documentId?: string
  showEditorFeatures: boolean
  documentStatus?: string
  documentBadge?: string
  documentActions: DocumentHeaderAction[]
  setConnected: (v: boolean) => void
  setUserCount: (n: number) => void
  setOnlineUsers: (list: Array<{ id: string; name: string; color?: string; clientId?: number }>) => void
  setDocumentTitle: (t?: string | null) => void
  setDocumentPath: (p?: string | null) => void
  setDocumentId: (id?: string | null) => void
  setShowEditorFeatures: (v: boolean) => void
  setDocumentStatus: (status?: string | null) => void
  setDocumentBadge: (badge?: string | null) => void
  setDocumentActions: (actions: DocumentHeaderAction[]) => void
}

const Ctx = createContext<RealtimeState | null>(null)

export function RealtimeProvider({ children }: { children: React.ReactNode }) {
  const [connected, setConnected] = useState(false)
  const [userCount, setUserCount] = useState(0)
  const [onlineUsers, setOnlineUsers] = useState<Array<{ id: string; name: string; color?: string; clientId?: number }>>([])
  const [documentTitle, setDocumentTitleState] = useState<string | undefined>(undefined)
  const [documentPath, setDocumentPathState] = useState<string | undefined>(undefined)
  const [documentId, setDocumentIdState] = useState<string | undefined>(undefined)
  const [showEditorFeatures, setShowEditorFeaturesState] = useState(false)
  const [documentStatus, setDocumentStatusState] = useState<string | undefined>(undefined)
  const [documentBadge, setDocumentBadgeState] = useState<string | undefined>(undefined)
  const [documentActions, setDocumentActionsState] = useState<DocumentHeaderAction[]>([])
  const value = useMemo(() => ({
    connected,
    userCount,
    onlineUsers,
    documentTitle,
    documentPath,
    documentId,
    showEditorFeatures,
    documentStatus,
    documentBadge,
    documentActions,
    setConnected,
    setUserCount,
    setOnlineUsers,
    setDocumentTitle: (title?: string | null) => setDocumentTitleState(title ?? undefined),
    setDocumentPath: (pathValue?: string | null) => setDocumentPathState(pathValue ?? undefined),
    setDocumentId: (identifier?: string | null) => setDocumentIdState(identifier ?? undefined),
    setShowEditorFeatures: (value: boolean) => setShowEditorFeaturesState(value),
    setDocumentStatus: (status?: string | null) => setDocumentStatusState(status ?? undefined),
    setDocumentBadge: (badge?: string | null) => setDocumentBadgeState(badge ?? undefined),
    setDocumentActions: (actions: DocumentHeaderAction[]) => setDocumentActionsState(actions),
  }), [
    connected,
    userCount,
    onlineUsers,
    documentTitle,
    documentPath,
    documentId,
    showEditorFeatures,
    documentStatus,
    documentBadge,
    documentActions,
  ])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useRealtime() {
  const v = useContext(Ctx)
  if (!v) throw new Error('useRealtime must be used within RealtimeProvider')
  return v
}
