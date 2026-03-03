/**
 * Mosaic tree utility functions
 *
 * Pure functions for manipulating react-mosaic-component tree structures.
 */

import type { MosaicNode } from 'react-mosaic-component'

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

export function findFirstDocumentId(node: MosaicNode<string> | null): string | null {
  if (!node) return null
  if (typeof node === 'string') {
    return decodePanelId(node)?.documentId ?? null
  }
  return findFirstDocumentId(node.first) ?? findFirstDocumentId(node.second)
}

export function removeFromMosaic(node: MosaicNode<string>, idToRemove: string): MosaicNode<string> | null {
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

export function replacePanelInMosaic(
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

export function replacePanelIdInMosaic(
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

export function hasDocumentPanels(node: MosaicNode<string>, documentId: string): boolean {
  if (typeof node === 'string') {
    const panel = decodePanelId(node)
    return panel?.documentId === documentId
  }

  return hasDocumentPanels(node.first, documentId) || hasDocumentPanels(node.second, documentId)
}

export function hasDocumentPanelOfType(node: MosaicNode<string>, documentId: string, type: PanelType): boolean {
  if (typeof node === 'string') {
    const panel = decodePanelId(node)
    return panel?.documentId === documentId && panel.type === type
  }

  return hasDocumentPanelOfType(node.first, documentId, type) || hasDocumentPanelOfType(node.second, documentId, type)
}

export function findFirstPanelType(node: MosaicNode<string>, documentId: string): PanelType | null {
  if (typeof node === 'string') {
    const panel = decodePanelId(node)
    return panel?.documentId === documentId ? panel.type : null
  }

  return findFirstPanelType(node.first, documentId) ?? findFirstPanelType(node.second, documentId)
}
