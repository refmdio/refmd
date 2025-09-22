import React, { createContext, useContext, useMemo, useState } from 'react'

type RealtimeState = {
  connected: boolean
  userCount: number
  onlineUsers: Array<{ id: string; name: string; color?: string; clientId?: number }>
  documentTitle?: string
  documentPath?: string
  documentId?: string
  showEditorFeatures: boolean
  setConnected: (v: boolean) => void
  setUserCount: (n: number) => void
  setOnlineUsers: (list: Array<{ id: string; name: string; color?: string; clientId?: number }>) => void
  setDocumentTitle: (t?: string) => void
  setDocumentPath: (p?: string) => void
  setDocumentId: (id?: string) => void
  setShowEditorFeatures: (v: boolean) => void
}

const Ctx = createContext<RealtimeState | null>(null)

export function RealtimeProvider({ children }: { children: React.ReactNode }) {
  const [connected, setConnected] = useState(false)
  const [userCount, setUserCount] = useState(0)
  const [onlineUsers, setOnlineUsers] = useState<Array<{ id: string; name: string; color?: string; clientId?: number }>>([])
  const [documentTitle, setDocumentTitle] = useState<string | undefined>(undefined)
  const [documentPath, setDocumentPath] = useState<string | undefined>(undefined)
  const [documentId, setDocumentId] = useState<string | undefined>(undefined)
  const [showEditorFeatures, setShowEditorFeatures] = useState(false)
  const value = useMemo(() => ({ connected, userCount, onlineUsers, documentTitle, documentPath, documentId, showEditorFeatures, setConnected, setUserCount, setOnlineUsers, setDocumentTitle, setDocumentPath, setDocumentId, setShowEditorFeatures }), [connected, userCount, onlineUsers, documentTitle, documentPath, documentId, showEditorFeatures])
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useRealtime() {
  const v = useContext(Ctx)
  if (!v) throw new Error('useRealtime must be used within RealtimeProvider')
  return v
}
