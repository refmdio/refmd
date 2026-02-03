/**
 * Document Workspace Context
 *
 * Manages multiple open documents in a mosaic tile layout.
 * Each document has separate Editor and Preview panels.
 */

import React, { createContext, useCallback, useContext, useState } from 'react'
import type { MosaicNode } from 'react-mosaic-component'

export interface OpenDocument {
  id: string
  title?: string
  workspaceId?: string
}

export type PanelType = 'editor' | 'preview'

export interface PanelId {
  documentId: string
  type: PanelType
  instanceId: string
}

let instanceCounter = 0
function generateInstanceId(): string {
  return `${Date.now()}-${++instanceCounter}`
}

export function encodePanelId(documentId: string, type: PanelType, instanceId?: string): string {
  const id = instanceId ?? generateInstanceId()
  return `${documentId}:${type}:${id}`
}

export function decodePanelId(panelId: string): PanelId | null {
  const parts = panelId.split(':')
  if (parts.length < 3) return null

  const [documentId, type, ...rest] = parts
  const instanceId = rest.join(':')

  if (!documentId || (type !== 'editor' && type !== 'preview') || !instanceId) {
    return null
  }

  return { documentId, type: type as PanelType, instanceId }
}

interface DocumentWorkspaceContextValue {
  openDocuments: Map<string, OpenDocument>
  mosaicState: MosaicNode<string> | null
  focusedDocumentId: string | null
  openDocument: (doc: OpenDocument) => void
  upsertDocumentMetadata: (doc: OpenDocument) => void
  closeDocument: (documentId: string) => void
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

  const closeDocument = useCallback((documentId: string) => {
    setOpenDocuments((prev) => {
      const next = new Map(prev)
      next.delete(documentId)
      return next
    })

    setMosaicState((prev) => {
      if (!prev) {
        setFocusedDocumentId((current) => (current === documentId ? null : current))
        return null
      }

      const nextState = removeDocumentFromMosaic(prev, documentId)

      setFocusedDocumentId((current) => {
        if (current !== documentId) return current
        return findFirstDocumentId(nextState)
      })

      return nextState
    })
  }, [])

  const closePanel = useCallback(
    (panelId: string) => {
      const panel = decodePanelId(panelId)
      if (!panel) return

      setMosaicState((prev) => {
        if (!prev) return null

        const nextState = removeFromMosaic(prev, panelId)

        const documentStillOpen =
          nextState != null && hasDocumentPanels(nextState, panel.documentId)

        if (!documentStillOpen) {
          setOpenDocuments((docs) => {
            const next = new Map(docs)
            next.delete(panel.documentId)
            return next
          })

          setFocusedDocumentId((current) => {
            if (current !== panel.documentId) return current
            return findFirstDocumentId(nextState)
          })
        }

        return nextState
      })
    },
    []
  )

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
        closeDocument,
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

function findFirstDocumentId(node: MosaicNode<string> | null): string | null {
  if (!node) return null
  if (typeof node === 'string') {
    return decodePanelId(node)?.documentId ?? null
  }
  return findFirstDocumentId(node.first) ?? findFirstDocumentId(node.second)
}

function removeFromMosaic(node: MosaicNode<string>, idToRemove: string): MosaicNode<string> | null {
  if (typeof node === 'string') {
    return node === idToRemove ? null : node
  }

  const first = removeFromMosaic(node.first, idToRemove)
  const second = removeFromMosaic(node.second, idToRemove)

  if (!first && !second) return null
  if (!first) return second
  if (!second) return first

  return { ...node, first, second }
}

function replacePanelInMosaic(
  node: MosaicNode<string>,
  panelId: string,
  newNode: MosaicNode<string>
): MosaicNode<string> {
  if (typeof node === 'string') {
    return node === panelId ? newNode : node
  }

  return {
    ...node,
    first: replacePanelInMosaic(node.first, panelId, newNode),
    second: replacePanelInMosaic(node.second, panelId, newNode),
  }
}

function replacePanelIdInMosaic(
  node: MosaicNode<string>,
  oldId: string,
  newId: string
): MosaicNode<string> {
  if (typeof node === 'string') {
    return node === oldId ? newId : node
  }

  return {
    ...node,
    first: replacePanelIdInMosaic(node.first, oldId, newId),
    second: replacePanelIdInMosaic(node.second, oldId, newId),
  }
}

function removeDocumentFromMosaic(
  node: MosaicNode<string>,
  documentId: string
): MosaicNode<string> | null {
  if (typeof node === 'string') {
    const panel = decodePanelId(node)
    return panel?.documentId === documentId ? null : node
  }

  const first = removeDocumentFromMosaic(node.first, documentId)
  const second = removeDocumentFromMosaic(node.second, documentId)

  if (!first && !second) return null
  if (!first) return second
  if (!second) return first

  return { ...node, first, second }
}

function hasDocumentPanels(node: MosaicNode<string>, documentId: string): boolean {
  if (typeof node === 'string') {
    const panel = decodePanelId(node)
    return panel?.documentId === documentId
  }

  return hasDocumentPanels(node.first, documentId) || hasDocumentPanels(node.second, documentId)
}

