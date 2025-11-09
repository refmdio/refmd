import React, { createContext, useContext, useMemo, useState, useCallback } from 'react'

import type { DocumentHeaderAction } from '@/shared/types/document'

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
  const setDocumentTitle = useCallback((title?: string | null) => setDocumentTitleState(title ?? undefined), [])
  const setDocumentPath = useCallback((pathValue?: string | null) => setDocumentPathState(pathValue ?? undefined), [])
  const setDocumentId = useCallback((identifier?: string | null) => setDocumentIdState(identifier ?? undefined), [])
  const setShowEditorFeatures = useCallback((value: boolean) => setShowEditorFeaturesState(value), [])
  const setDocumentStatus = useCallback((status?: string | null) => setDocumentStatusState(status ?? undefined), [])
  const setDocumentBadge = useCallback((badge?: string | null) => setDocumentBadgeState(badge ?? undefined), [])
  const setDocumentActions = useCallback((actions: DocumentHeaderAction[]) => setDocumentActionsState(actions), [])

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
    setDocumentTitle,
    setDocumentPath,
    setDocumentId,
    setShowEditorFeatures,
    setDocumentStatus,
    setDocumentBadge,
    setDocumentActions,
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
    setConnected,
    setUserCount,
    setOnlineUsers,
    setDocumentTitle,
    setDocumentPath,
    setDocumentId,
    setShowEditorFeatures,
    setDocumentStatus,
    setDocumentBadge,
    setDocumentActions,
  ])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useRealtime() {
  const v = useContext(Ctx)
  if (!v) throw new Error('useRealtime must be used within RealtimeProvider')
  return v
}
