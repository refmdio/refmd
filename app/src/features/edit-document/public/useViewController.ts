import { useMemo } from 'react'

import type { ViewMode } from '@/shared/types/view-mode'

import { useViewContext } from '@/features/edit-document/model/view-context'

export function useViewController() {
  const ctx = useViewContext()
  return useMemo(() => ({
    viewMode: ctx.viewMode as ViewMode,
    setViewMode: (mode: ViewMode) => ctx.setViewMode(mode),
    showBacklinks: ctx.showBacklinks,
    setShowBacklinks: ctx.setShowBacklinks,
    toggleBacklinks: ctx.toggleBacklinks,
    openSearch: (presetTag?: string) => ctx.openSearch(presetTag),
    searchPresetTag: ctx.searchPresetTag,
    searchNonce: ctx.searchNonce,
  }), [ctx])
}
