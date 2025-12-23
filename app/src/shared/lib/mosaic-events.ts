export const OPEN_PREVIEW_TILE_EVENT = 'refmd:mosaic:open-preview-tile'
export const OPEN_EDITOR_TILE_EVENT = 'refmd:mosaic:open-editor-tile'
export const OPEN_BACKLINKS_TILE_EVENT = 'refmd:mosaic:open-backlinks-tile'
export const MOSAIC_SCROLL_SYNC_EVENT = 'refmd:mosaic:scroll-sync'
export const MOSAIC_SET_VIEW_MODE_EVENT = 'refmd:mosaic:set-view-mode'

export type OpenPreviewTileDetail = {
  documentId: string
  splitMode?: 'auto' | 'row' | 'column'
}

export function dispatchOpenPreviewTile(documentId: string, splitMode?: OpenPreviewTileDetail['splitMode']) {
  if (typeof window === 'undefined') return
  const normalizedMode = splitMode === 'auto' || splitMode === 'row' || splitMode === 'column' ? splitMode : undefined
  window.dispatchEvent(
    new CustomEvent<OpenPreviewTileDetail>(OPEN_PREVIEW_TILE_EVENT, {
      detail: normalizedMode ? { documentId, splitMode: normalizedMode } : { documentId },
    }),
  )
}

export type OpenEditorTileDetail = {
  documentId: string
}

export function dispatchOpenEditorTile(documentId: string) {
  if (typeof window === 'undefined') return
  window.dispatchEvent(
    new CustomEvent<OpenEditorTileDetail>(OPEN_EDITOR_TILE_EVENT, {
      detail: { documentId },
    }),
  )
}

export type OpenBacklinksTileDetail = {
  documentId: string
}

export function dispatchOpenBacklinksTile(documentId: string) {
  if (typeof window === 'undefined') return
  window.dispatchEvent(
    new CustomEvent<OpenBacklinksTileDetail>(OPEN_BACKLINKS_TILE_EVENT, {
      detail: { documentId },
    }),
  )
}

export type MosaicScrollSyncDetail = {
  groupId: string
  source: 'editor' | 'preview'
  line?: number
}

export function dispatchMosaicScrollSync(detail: MosaicScrollSyncDetail) {
  if (typeof window === 'undefined') return
  window.dispatchEvent(
    new CustomEvent<MosaicScrollSyncDetail>(MOSAIC_SCROLL_SYNC_EVENT, {
      detail,
    }),
  )
}

export type MosaicSetViewModeDetail = {
  documentId: string
  mode: 'editor' | 'split' | 'preview'
}

export function dispatchMosaicSetViewMode(documentId: string, mode: MosaicSetViewModeDetail['mode']) {
  if (typeof window === 'undefined') return
  const id = (documentId || '').trim()
  if (!id) return
  window.dispatchEvent(
    new CustomEvent<MosaicSetViewModeDetail>(MOSAIC_SET_VIEW_MODE_EVENT, {
      detail: { documentId: id, mode },
    }),
  )
}
