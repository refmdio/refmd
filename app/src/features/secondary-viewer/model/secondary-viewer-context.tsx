"use client"

import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'

type SecondaryType = 'document' | 'scrap' | 'plugin'

type StoredState = {
  documentId: string | null
  documentType: SecondaryType
  isOpen: boolean
}

type CtxType = {
  secondaryDocumentId: string | null
  secondaryDocumentType: SecondaryType
  showSecondaryViewer: boolean
  setSecondaryDocumentId: (id: string | null) => void
  setSecondaryDocumentType: (t: SecondaryType) => void
  setShowSecondaryViewer: (v: boolean) => void
  openSecondaryViewer: (id: string, type?: SecondaryType) => void
  closeSecondaryViewer: () => void
}

const STORAGE_KEY = 'refmd-secondary-viewer'
const Ctx = createContext<CtxType | null>(null)

export function SecondaryViewerProvider({ children }: { children: React.ReactNode }) {
  const [secondaryDocumentId, setSecondaryDocumentIdState] = useState<string | null>(null)
  const [secondaryDocumentType, setSecondaryDocumentTypeState] = useState<SecondaryType>('document')
  const [showSecondaryViewer, setShowSecondaryViewerState] = useState(false)
  const [initialized, setInitialized] = useState(false)

  useEffect(() => {
    try {
      const raw = typeof window !== 'undefined' ? localStorage.getItem(STORAGE_KEY) : null
      if (raw) {
        const parsed = JSON.parse(raw) as StoredState
        setSecondaryDocumentIdState(parsed.documentId)
        setSecondaryDocumentTypeState(parsed.documentType || 'document')
        setShowSecondaryViewerState(!!parsed.isOpen)
      }
    } catch {}
    setInitialized(true)
  }, [])

  useEffect(() => {
    if (!initialized) return
    try {
      const state: StoredState = {
        documentId: secondaryDocumentId,
        documentType: secondaryDocumentType,
        isOpen: showSecondaryViewer,
      }
      localStorage.setItem(STORAGE_KEY, JSON.stringify(state))
    } catch {}
  }, [initialized, secondaryDocumentId, secondaryDocumentType, showSecondaryViewer])

  const setSecondaryDocumentId = useCallback((id: string | null) => setSecondaryDocumentIdState(id), [])
  const setSecondaryDocumentType = useCallback((t: SecondaryType) => setSecondaryDocumentTypeState(t), [])
  const setShowSecondaryViewer = useCallback((v: boolean) => setShowSecondaryViewerState(v), [])
  const openSecondaryViewer = useCallback((id: string, type: SecondaryType = 'document') => {
    setSecondaryDocumentIdState(id)
    setSecondaryDocumentTypeState(type)
    setShowSecondaryViewerState(true)
  }, [])
  const closeSecondaryViewer = useCallback(() => setShowSecondaryViewerState(false), [])

  const value = useMemo<CtxType>(() => ({
    secondaryDocumentId,
    secondaryDocumentType,
    showSecondaryViewer,
    setSecondaryDocumentId,
    setSecondaryDocumentType,
    setShowSecondaryViewer,
    openSecondaryViewer,
    closeSecondaryViewer,
  }), [secondaryDocumentId, secondaryDocumentType, showSecondaryViewer, setSecondaryDocumentId, setSecondaryDocumentType, setShowSecondaryViewer, openSecondaryViewer, closeSecondaryViewer])

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useSecondaryViewer() {
  const v = useContext(Ctx)
  if (!v) throw new Error('useSecondaryViewer must be used within SecondaryViewerProvider')
  return v
}

