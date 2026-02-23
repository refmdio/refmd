/**
 * Document Workspace Context
 *
 * Manages multiple open documents in a mosaic tile layout.
 * Each document has separate Editor and Preview panels.
 */

import React, { createContext, useCallback, useContext, useEffect, useLayoutEffect, useRef, useState } from 'react'
import type { MosaicNode } from 'react-mosaic-component'
import { useWorkspaceSelection } from '@/entities/workspace'
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
  closeAll: () => void
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

  // Reset all document state SYNCHRONOUSLY (before paint) when workspace changes.
  // useLayoutEffect ensures the stale tiles are never visible to the user.
  const { currentWorkspaceId } = useWorkspaceSelection()
  const prevWorkspaceRef = useRef(currentWorkspaceId)

  useLayoutEffect(() => {
    if (prevWorkspaceRef.current !== currentWorkspaceId) {
      setOpenDocuments(new Map())
      setMosaicState(null)
      setFocusedDocumentId(null)
      prevWorkspaceRef.current = currentWorkspaceId
    }
  }, [currentWorkspaceId])

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

  const closeAll = useCallback(() => {
    setOpenDocuments(new Map())
    setMosaicState(null)
    setFocusedDocumentId(null)
  }, [])

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
        closeAll,
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
