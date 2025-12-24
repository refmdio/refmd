import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'

import type { ViewMode } from '@/shared/types/view-mode'

const VIEW_MODE_STORAGE_KEY = 'refmd-view-mode'

type ViewModeSetter = ViewMode | ((prev: ViewMode) => ViewMode)

type Ctx = {
  viewMode: ViewMode
  setViewMode: (mode: ViewModeSetter) => void
  viewModeHydrated: boolean
  hasPersistentViewMode: boolean
  // Search request trigger for Header's SearchDialog
  searchPresetTag: string | null
  searchNonce: number
  openSearch: (presetTag?: string | null) => void
}

const ViewCtx = createContext<Ctx | null>(null)

export function ViewProvider({ children }: { children: React.ReactNode }) {
  const [viewMode, setViewModeState] = useState<ViewMode>('editor')
  const [viewModeHydrated, setViewModeHydrated] = useState(() => typeof window === 'undefined')
  const [hasPersistentViewMode, setHasPersistentViewMode] = useState(false)
  const [searchPresetTag, setSearchPresetTag] = useState<string | null>(null)
  const [searchNonce, setSearchNonce] = useState(0)

  useEffect(() => {
    if (typeof window === 'undefined') {
      return
    }
    try {
      const saved = localStorage.getItem(VIEW_MODE_STORAGE_KEY)
      if (saved === 'editor' || saved === 'preview') {
        setViewModeState(saved)
        setHasPersistentViewMode(true)
      } else if (saved === 'split') {
        setViewModeState('editor')
        try { localStorage.setItem(VIEW_MODE_STORAGE_KEY, 'editor') } catch {}
        setHasPersistentViewMode(true)
      }
    } catch {
      /* noop */
    } finally {
      setViewModeHydrated(true)
    }
  }, [])

  const setViewMode = useCallback((mode: ViewModeSetter) => {
    setViewModeState((prev) => {
      const next = typeof mode === 'function' ? (mode as (value: ViewMode) => ViewMode)(prev) : mode
      if (next === prev) return prev
      try {
        if (typeof window !== 'undefined') {
          localStorage.setItem(VIEW_MODE_STORAGE_KEY, next)
        }
      } catch {
        /* noop */
      }
      setHasPersistentViewMode(true)
      return next
    })
  }, [])

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
    viewModeHydrated,
    hasPersistentViewMode,
    setViewMode,
    searchPresetTag,
    searchNonce,
    openSearch,
  }), [viewMode, viewModeHydrated, hasPersistentViewMode, searchPresetTag, searchNonce, openSearch, setViewMode])

  return <ViewCtx.Provider value={value}>{children}</ViewCtx.Provider>
}

export function useViewContext() {
  const v = useContext(ViewCtx)
  if (!v) throw new Error('useViewContext must be used within ViewProvider')
  return v
}
