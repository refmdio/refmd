/**
 * Document Workspace Context
 *
 * Manages multiple open documents in a mosaic tile layout.
 * Each document has separate Editor and Preview panels.
 */

import React, { createContext, useContext, useCallback, useState } from 'react'
import type { MosaicNode } from 'react-mosaic-component'

export interface OpenDocument {
  id: string
  title: string
  workspaceId: string
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
  const instanceId = rest.join(':') // Handle case where instanceId might contain colons
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

  const openDocument = useCallback((doc: OpenDocument) => {
    // Always track document metadata
    if (!openDocuments.has(doc.id)) {
      setOpenDocuments((prev) => {
        const next = new Map(prev)
        next.set(doc.id, doc)
        return next
      })
    }

    // Always create new panels (allows multiple instances of same document)
    const editorId = encodePanelId(doc.id, 'editor')
    const previewId = encodePanelId(doc.id, 'preview')

    // Create editor + preview side by side
    const newDocPanels: MosaicNode<string> = {
      direction: 'row',
      first: editorId,
      second: previewId,
      splitPercentage: 50,
    }

    // Update mosaic state to include new document panels
    setMosaicState((prev) => {
      if (!prev) {
        return newDocPanels
      }
      // Add below existing
      return {
        direction: 'column',
        first: prev,
        second: newDocPanels,
        splitPercentage: 50,
      }
    })

    setFocusedDocumentId(doc.id)
  }, [openDocuments])

  const closePanel = useCallback((panelId: string) => {
    const panel = decodePanelId(panelId)
    if (!panel) return

    // Remove panel from mosaic state and check if document should be removed
    setMosaicState((prev) => {
      if (!prev) return null
      const newState = removeFromMosaic(prev, panelId)

      // Check if any panels for this document remain
      if (!newState || !hasDocumentPanels(newState, panel.documentId)) {
        setOpenDocuments((docs) => {
          const next = new Map(docs)
          next.delete(panel.documentId)
          return next
        })
      }

      return newState
    })
  }, [])

  const closeDocument = useCallback((documentId: string) => {
    setOpenDocuments((prev) => {
      const next = new Map(prev)
      next.delete(documentId)
      return next
    })

    // Remove all panels for this document from mosaic state
    setMosaicState((prev) => {
      if (!prev) return null
      return removeDocumentFromMosaic(prev, documentId)
    })

    // Update focus if closing focused document
    setFocusedDocumentId((prev) => {
      if (prev === documentId) {
        const remaining = Array.from(openDocuments.keys()).filter((id) => id !== documentId)
        return remaining[0] ?? null
      }
      return prev
    })
  }, [openDocuments])

  const splitPanel = useCallback((panelId: string, direction: 'row' | 'column') => {
    const panel = decodePanelId(panelId)
    if (!panel) return

    // Create the other panel type with new instance ID
    const newType: PanelType = panel.type === 'editor' ? 'preview' : 'editor'
    const newPanelId = encodePanelId(panel.documentId, newType) // generates new instanceId

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
    // Keep same instance ID when switching type
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

// Helper to remove a node from mosaic
function removeFromMosaic(
  node: MosaicNode<string>,
  idToRemove: string
): MosaicNode<string> | null {
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

// Helper to replace a panel with a new node structure
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

// Helper to replace a panel ID with another
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

// Helper to remove all panels for a document
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

// Helper to check if any panels for a document exist
function hasDocumentPanels(node: MosaicNode<string>, documentId: string): boolean {
  if (typeof node === 'string') {
    const panel = decodePanelId(node)
    return panel?.documentId === documentId
  }

  return hasDocumentPanels(node.first, documentId) || hasDocumentPanels(node.second, documentId)
}
