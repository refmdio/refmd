/**
 * Document Workspace Context
 *
 * Manages multiple open documents in a mosaic tile layout.
 * Each document has separate Editor and Preview panels.
 */

import React, { createContext, useCallback, useContext, useEffect, useState } from 'react'
import type { MosaicNode } from 'react-mosaic-component'
import {
  encodePanelId,
  decodePanelId,
  findFirstDocumentId,
  removeFromMosaic,
  replacePanelInMosaic,
  replacePanelIdInMosaic,
  hasDocumentPanels,
  type PanelType,
} from './mosaic-utils'

export type { PanelType, PanelId } from './mosaic-utils'
export { encodePanelId, decodePanelId } from './mosaic-utils'

export interface OpenDocument {
  id: string
  title?: string
  workspaceId?: string
}

interface DocumentWorkspaceContextValue {
  openDocuments: Map<string, OpenDocument>
  mosaicState: MosaicNode<string> | null
  focusedDocumentId: string | null
  openDocument: (doc: OpenDocument) => void
  upsertDocumentMetadata: (doc: OpenDocument) => void
  closePanel: (panelId: string) => void
  splitPanel: (panelId: string, direction: 'row' | 'column') => void
  switchPanelType: (panelId: string) => void
  setMosaicState: (state: MosaicNode<string> | null) => void
  setFocusedDocumentId: (id: string | null) => void
}

const DocumentWorkspaceContext = createContext<DocumentWorkspaceContextValue | null>(null)

export function DocumentWorkspaceProvider({ children }: { children: React.ReactNode }) {
  const [openDocuments, setOpenDocuments] = useState<Map<string, OpenDocument>>(new Map())
  const [mosaicState, setMosaicState] = useState<MosaicNode<string> | null>(null)
  const [focusedDocumentId, setFocusedDocumentId] = useState<string | null>(null)

  const upsertDocumentMetadata = useCallback((doc: OpenDocument) => {
    setOpenDocuments((prev) => {
      const next = new Map(prev)
      const existing = next.get(doc.id)
      next.set(doc.id, { ...existing, ...doc })
      return next
    })
  }, [])

  const openDocument = useCallback(
    (doc: OpenDocument) => {
      upsertDocumentMetadata(doc)

      const editorId = encodePanelId(doc.id, 'editor')
      const previewId = encodePanelId(doc.id, 'preview')

      const newDocPanels: MosaicNode<string> = {
        direction: 'row',
        first: editorId,
        second: previewId,
        splitPercentage: 50,
      }

      setMosaicState((prev) => {
        if (!prev) return newDocPanels
        return {
          direction: 'column',
          first: prev,
          second: newDocPanels,
          splitPercentage: 50,
        }
      })

      setFocusedDocumentId(doc.id)
    },
    [upsertDocumentMetadata]
  )

  const closePanel = useCallback(
    (panelId: string) => {
      setMosaicState((prev) => {
        if (!prev) return null
        return removeFromMosaic(prev, panelId)
      })
    },
    []
  )

  // Sync openDocuments and focusedDocumentId when mosaic panels change.
  useEffect(() => {
    setOpenDocuments((docs) => {
      if (!mosaicState) {
        return docs.size > 0 ? new Map() : docs
      }
      let changed = false
      const next = new Map(docs)
      for (const docId of next.keys()) {
        if (!hasDocumentPanels(mosaicState, docId)) {
          next.delete(docId)
          changed = true
        }
      }
      return changed ? next : docs
    })

    setFocusedDocumentId((current) => {
      if (!current) return current
      if (!mosaicState) return null
      if (!hasDocumentPanels(mosaicState, current)) {
        return findFirstDocumentId(mosaicState)
      }
      return current
    })
  }, [mosaicState])

  const splitPanel = useCallback((panelId: string, direction: 'row' | 'column') => {
    const panel = decodePanelId(panelId)
    if (!panel) return

    const newType: PanelType = panel.type === 'editor' ? 'preview' : 'editor'
    const newPanelId = encodePanelId(panel.documentId, newType)

    setMosaicState((prev) => {
      if (!prev) return null
      return replacePanelInMosaic(prev, panelId, {
        direction,
        first: panelId,
        second: newPanelId,
        splitPercentage: 50,
      })
    })
  }, [])

  const switchPanelType = useCallback((panelId: string) => {
    const panel = decodePanelId(panelId)
    if (!panel) return

    const newType: PanelType = panel.type === 'editor' ? 'preview' : 'editor'
    const newPanelId = encodePanelId(panel.documentId, newType, panel.instanceId)

    setMosaicState((prev) => {
      if (!prev) return null
      return replacePanelIdInMosaic(prev, panelId, newPanelId)
    })
  }, [])

  return (
    <DocumentWorkspaceContext.Provider
      value={{
        openDocuments,
        mosaicState,
        focusedDocumentId,
        openDocument,
        upsertDocumentMetadata,
        closePanel,
        splitPanel,
        switchPanelType,
        setMosaicState,
        setFocusedDocumentId,
      }}
    >
      {children}
    </DocumentWorkspaceContext.Provider>
  )
}

export function useDocumentWorkspace() {
  const context = useContext(DocumentWorkspaceContext)
  if (!context) {
    throw new Error('useDocumentWorkspace must be used within DocumentWorkspaceProvider')
  }
  return context
}
