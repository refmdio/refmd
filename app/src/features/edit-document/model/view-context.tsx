import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'

import type { ViewMode } from '@/shared/types/view-mode'

type Ctx = {
  viewMode: ViewMode
  setViewMode: (m: ViewMode) => void
  showBacklinks: boolean
  setShowBacklinks: (v: boolean) => void
  toggleBacklinks: () => void
  // Search request trigger for Header's SearchDialog
  searchPresetTag: string | null
  searchNonce: number
  openSearch: (presetTag?: string | null) => void
}

const ViewCtx = createContext<Ctx | null>(null)

export function ViewProvider({ children }: { children: React.ReactNode }) {
  const [viewMode, setViewMode] = useState<ViewMode>('split')
  const [showBacklinks, setShowBacklinks] = useState(false)
  const [searchPresetTag, setSearchPresetTag] = useState<string | null>(null)
  const [searchNonce, setSearchNonce] = useState(0)

  const toggleBacklinks = useCallback(() => setShowBacklinks((v) => !v), [])
  const openSearch = useCallback((presetTag?: string | null) => {
    setSearchPresetTag(presetTag ?? null)
    setSearchNonce((n) => n + 1)
  }, [])

  useEffect(() => {
    if (typeof window === 'undefined') return
    const handler = (event: Event) => {
      const detail = (event as CustomEvent<{ tag?: string | null }>).detail
      const tag = typeof detail?.tag === 'string' ? detail.tag : null
      openSearch(tag)
    }
    window.addEventListener('refmd:open-search', handler as EventListener)
    return () => { window.removeEventListener('refmd:open-search', handler as EventListener) }
  }, [openSearch])

  const value = useMemo<Ctx>(() => ({
    viewMode,
    setViewMode,
    showBacklinks,
    setShowBacklinks,
    toggleBacklinks,
    searchPresetTag,
    searchNonce,
    openSearch,
  }), [viewMode, showBacklinks, toggleBacklinks, searchPresetTag, searchNonce, openSearch])

  return <ViewCtx.Provider value={value}>{children}</ViewCtx.Provider>
}

export function useViewContext() {
  const v = useContext(ViewCtx)
  if (!v) throw new Error('useViewContext must be used within ViewProvider')
  return v
}
