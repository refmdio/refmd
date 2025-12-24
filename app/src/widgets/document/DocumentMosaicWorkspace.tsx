"use client"

import { useQuery } from '@tanstack/react-query'
import { useNavigate } from '@tanstack/react-router'
import { Columns2, Eye, FileCode, Loader2 } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState, type Dispatch, type SetStateAction } from 'react'
import {
  Mosaic,
  MosaicWindow,
  RemoveButton,
  Separator,
  createExpandUpdate,
  getLeaves,
  isParent,
  updateTree,
  type MosaicNode,
  type MosaicParent,
  type MosaicPath,
} from 'react-mosaic-component'
import { toast } from 'sonner'

import { useShortcut } from '@/shared/hooks/use-shortcut'
import {
  MOSAIC_SCROLL_SYNC_EVENT,
  OPEN_BACKLINKS_TILE_EVENT,
  OPEN_EDITOR_TILE_EVENT,
  OPEN_PREVIEW_TILE_EVENT,
  MOSAIC_SET_VIEW_MODE_EVENT,
  dispatchMosaicScrollSync,
  dispatchMosaicSetViewMode,
  dispatchMosaicCurrentViewMode,
  type MosaicScrollSyncDetail,
} from '@/shared/lib/mosaic-events'

import { fetchDocumentContent, fetchDocumentMeta } from '@/entities/document'
import { browseShare } from '@/entities/share'

import { useAuthContext } from '@/features/auth'
import { BacklinksPanel } from '@/features/document-backlinks'
import { EditorOverlay, MarkdownEditor, PreviewPane, useCollaborativeDocument } from '@/features/edit-document'
import { mountResolvedPlugin, resolvePluginForDocument, resolvePluginForDocumentById, type DocumentPluginMatch } from '@/features/plugins'
import { mountSplitEditorPreviewStage } from '@/features/plugins/ui/SplitEditorHost'

import DocumentPage, { type DocumentLoaderData, type DocumentPageProps, type DocumentPageRenderContext } from './DocumentPage'

type TileKey = `tile:${string}`
type TileMode = 'editor' | 'preview' | 'backlinks'
type TileSpec = {
  mode: TileMode
  documentId: string
  syncGroupId?: string
}

type MosaicState = {
  layout: MosaicNode<TileKey> | null
  tiles: Record<TileKey, TileSpec>
}

type ShareScope = 'document' | 'folder'

const STORAGE_KEY_PREFIX = 'refmd-document-mosaic-state-v3'
const FORCE_FLOATING_TOC_MAX_WIDTH_PX = 1024
const EXPAND_PERCENTAGE = 80
const UNEXPAND_PERCENTAGE = 50
const PLUGIN_USES_SPLIT_EDITOR_EVENT = 'refmd:plugin:uses-split-editor'

const splitCapablePluginDocIds = new Set<string>()
const splitCapablePluginDocSubscribers = new Set<() => void>()
let splitCapablePluginDocListening = false

function emitSplitCapablePluginDocUpdate() {
  for (const listener of splitCapablePluginDocSubscribers) {
    try {
      listener()
    } catch {
      /* noop */
    }
  }
}

function markSplitCapablePluginDoc(docId: string) {
  const id = docId.trim()
  if (!id) return
  if (splitCapablePluginDocIds.has(id)) return
  splitCapablePluginDocIds.add(id)
  emitSplitCapablePluginDocUpdate()
}

function ensureSplitCapablePluginDocListener() {
  if (splitCapablePluginDocListening) return
  if (typeof window === 'undefined') return
  splitCapablePluginDocListening = true
  window.addEventListener(
    PLUGIN_USES_SPLIT_EDITOR_EVENT,
    ((event: Event) => {
      const detail = (event as CustomEvent<{ docId?: string }>).detail
      const docId = typeof detail?.docId === 'string' ? detail.docId.trim() : ''
      if (!docId) return
      markSplitCapablePluginDoc(docId)
    }) as EventListener,
  )
}

function buildMosaicStorageKey(args: { userId: string | null | undefined; workspaceId: string | null | undefined }) {
  const userId = typeof args.userId === 'string' ? args.userId.trim() : ''
  const workspaceId = typeof args.workspaceId === 'string' ? args.workspaceId.trim() : ''
  if (!workspaceId) return null
  return `${STORAGE_KEY_PREFIX}:${userId || 'anon'}:${workspaceId}`
}

function updateParentSplitPercentage(
  layout: MosaicNode<TileKey> | null,
  path: MosaicPath,
  splitPercentage: number,
): MosaicNode<TileKey> | null {
  if (!layout) return null
  if (path.length === 0) {
    if (!isParent(layout)) return layout
    const parent = layout as MosaicParent<TileKey>
    const current = normalizeSplitPercentage((parent as any).splitPercentage)
    const next = normalizeSplitPercentage(splitPercentage)
    if (current === next) return layout
    return { ...parent, splitPercentage: next }
  }
  if (!isParent(layout)) return layout
  const parent = layout as MosaicParent<TileKey>
  const [head, ...rest] = path
  if (head === 'first') {
    const updated = updateParentSplitPercentage(parent.first, rest as MosaicPath, splitPercentage)
    if (updated === parent.first) return layout
    return { ...parent, first: updated as any }
  }
  const updated = updateParentSplitPercentage(parent.second, rest as MosaicPath, splitPercentage)
  if (updated === parent.second) return layout
  return { ...parent, second: updated as any }
}

function tileControlsToggle(key = 'more') {
  return (
    <button
      key={key}
      type="button"
      className="mosaic-default-control mosaic-controls-toggle"
      aria-label="Tile actions"
      title="Tile actions"
    >
      ⋯
    </button>
  )
}

function makeTileKey(): TileKey {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return `tile:${crypto.randomUUID()}` as TileKey
  }
  return `tile:${Math.random().toString(36).slice(2)}` as TileKey
}

function makeSyncGroupId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return `split:${crypto.randomUUID()}`
  }
  return `split:${Math.random().toString(36).slice(2)}`
}

function replaceNodeAtPath(
  layout: MosaicNode<TileKey> | null,
  path: MosaicPath,
  replacement: MosaicNode<TileKey>,
): MosaicNode<TileKey> {
  if (!layout) return replacement
  if (path.length === 0) return replacement
  if (!isParent(layout)) return layout
  const parent = layout as MosaicParent<TileKey>
  const [head, ...rest] = path
  if (head === 'first') return { ...parent, first: replaceNodeAtPath(parent.first, rest as MosaicPath, replacement) }
  return { ...parent, second: replaceNodeAtPath(parent.second, rest as MosaicPath, replacement) }
}

function findPathToTile(layout: MosaicNode<TileKey> | null, target: TileKey): MosaicPath | null {
  if (!layout) return null
  if (!isParent(layout)) return (layout as TileKey) === target ? ([] as MosaicPath) : null
  const parent = layout as MosaicParent<TileKey>
  const inFirst = findPathToTile(parent.first, target)
  if (inFirst) return ['first', ...inFirst]
  const inSecond = findPathToTile(parent.second, target)
  if (inSecond) return ['second', ...inSecond]
  return null
}

function removeLeaf(layout: MosaicNode<TileKey> | null, target: TileKey): MosaicNode<TileKey> | null {
  if (!layout) return null
  if (!isParent(layout)) return (layout as TileKey) === target ? null : layout
  const parent = layout as MosaicParent<TileKey>
  const first = removeLeaf(parent.first, target)
  const second = removeLeaf(parent.second, target)
  if (!first && !second) return null
  if (!first) return second
  if (!second) return first
  if (first === parent.first && second === parent.second) return parent
  return { ...parent, first, second }
}

function getLeavesSafe(layout: MosaicNode<TileKey> | null): TileKey[] {
  if (!layout) return []
  try {
    return getLeaves(layout)
  } catch {
    return []
  }
}

function normalizeSplitPercentage(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 50
  return Math.min(100, Math.max(0, value))
}

function insertLeafAtRight(layout: MosaicNode<TileKey> | null, leaf: TileKey): MosaicNode<TileKey> {
  if (!layout) return leaf
  return { direction: 'row', first: layout, second: leaf, splitPercentage: 50 }
}

type InsertSplitMode = 'auto' | 'row' | 'column'

function insertLeafWithMode(
  layout: MosaicNode<TileKey> | null,
  leaf: TileKey,
  preferredLeaf: TileKey | undefined,
  mode: InsertSplitMode,
): MosaicNode<TileKey> {
  if (mode === 'row') return insertLeafAtRight(layout, leaf)
  return insertLeafBsp(layout, leaf, preferredLeaf, mode)
}

type BspRect = { x: number; y: number; w: number; h: number }
type BspLeafPane = { leaf: TileKey; path: MosaicPath; rect: BspRect }

function getRootRect(): BspRect {
  if (typeof window === 'undefined') return { x: 0, y: 0, w: 1, h: 1 }
  const w = window.innerWidth
  const h = window.innerHeight
  if (!w || !h) return { x: 0, y: 0, w: 1, h: 1 }
  const aspect = w / h
  if (aspect >= 1) return { x: 0, y: 0, w: aspect, h: 1 }
  return { x: 0, y: 0, w: 1, h: 1 / aspect }
}

function collectLeafPanes(
  node: MosaicNode<TileKey>,
  rect: BspRect,
  path: MosaicPath,
  out: BspLeafPane[],
) {
  if (!isParent(node)) {
    out.push({ leaf: node as TileKey, path, rect })
    return
  }

  const parent = node as MosaicParent<TileKey>
  const split = normalizeSplitPercentage((parent as any).splitPercentage) / 100
  if (parent.direction === 'row') {
    const firstRect: BspRect = { x: rect.x, y: rect.y, w: rect.w * split, h: rect.h }
    const secondRect: BspRect = { x: rect.x + firstRect.w, y: rect.y, w: rect.w * (1 - split), h: rect.h }
    collectLeafPanes(parent.first, firstRect, [...path, 'first'], out)
    collectLeafPanes(parent.second, secondRect, [...path, 'second'], out)
    return
  }

  const firstRect: BspRect = { x: rect.x, y: rect.y, w: rect.w, h: rect.h * split }
  const secondRect: BspRect = { x: rect.x, y: rect.y + firstRect.h, w: rect.w, h: rect.h * (1 - split) }
  collectLeafPanes(parent.first, firstRect, [...path, 'first'], out)
  collectLeafPanes(parent.second, secondRect, [...path, 'second'], out)
}

function pickBspTarget(layout: MosaicNode<TileKey>, preferredLeaf?: TileKey): BspLeafPane {
  const panes: BspLeafPane[] = []
  collectLeafPanes(layout, getRootRect(), [] as MosaicPath, panes)

  if (preferredLeaf) {
    const preferred = panes.find((pane) => pane.leaf === preferredLeaf)
    if (preferred) {
      const preferredArea = preferred.rect.w * preferred.rect.h
      let maxArea = preferredArea
      for (const pane of panes) {
        const area = pane.rect.w * pane.rect.h
        if (area > maxArea) maxArea = area
      }
      // If preferred is tied for "largest" (within epsilon), split it for more intuitive placement.
      const epsilon = 1e-6
      if (preferredArea + epsilon >= maxArea) return preferred
    }
  }

  // BSPwm-style: split the largest visible pane by area.
  let best = panes[0]
  let bestArea = (best?.rect.w ?? 0) * (best?.rect.h ?? 0)
  for (const pane of panes) {
    const area = pane.rect.w * pane.rect.h
    if (area > bestArea) {
      best = pane
      bestArea = area
    }
  }
  return best
}

function computeBspSplitDirection(rect: BspRect): 'row' | 'column' {
  // BSPwm-style: split along the longer axis (vertical split when pane is wider).
  return rect.w >= rect.h ? 'row' : 'column'
}

function resolveInsertSplitDirection(mode: InsertSplitMode, rect: BspRect): 'row' | 'column' {
  if (mode === 'row') return 'row'
  if (mode === 'column') return 'column'
  return computeBspSplitDirection(rect)
}

function insertLeafBsp(
  layout: MosaicNode<TileKey> | null,
  leaf: TileKey,
  preferredLeaf?: TileKey,
  mode: InsertSplitMode = 'auto',
): MosaicNode<TileKey> {
  if (!layout) return leaf
  if (!isParent(layout)) {
    const rootRect = getRootRect()
    return {
      direction: resolveInsertSplitDirection(mode, rootRect),
      first: layout,
      second: leaf,
      splitPercentage: 50,
    }
  }
  const target = pickBspTarget(layout, preferredLeaf)
  const direction = resolveInsertSplitDirection(mode, target.rect)
  const replacement: MosaicNode<TileKey> = {
    direction,
    first: target.leaf,
    second: leaf,
    splitPercentage: 50,
  }
  return replaceNodeAtPath(layout, target.path, replacement)
}

type SwapDirection = 'left' | 'right' | 'up' | 'down'

function overlaps(a0: number, a1: number, b0: number, b1: number) {
  return Math.min(a1, b1) - Math.max(a0, b0) > 0
}

function pickNeighborLeaf(panes: BspLeafPane[], fromLeaf: TileKey, direction: SwapDirection): TileKey | null {
  const from = panes.find((pane) => pane.leaf === fromLeaf)
  if (!from) return null

  const fromCx = from.rect.x + from.rect.w / 2
  const fromCy = from.rect.y + from.rect.h / 2

  const isOverlapMatch = (pane: BspLeafPane) => {
    if (direction === 'left' || direction === 'right') {
      return overlaps(from.rect.y, from.rect.y + from.rect.h, pane.rect.y, pane.rect.y + pane.rect.h)
    }
    return overlaps(from.rect.x, from.rect.x + from.rect.w, pane.rect.x, pane.rect.x + pane.rect.w)
  }

  const candidates = panes.filter((pane) => pane.leaf !== fromLeaf)

  const score = (pane: BspLeafPane) => {
    const cx = pane.rect.x + pane.rect.w / 2
    const cy = pane.rect.y + pane.rect.h / 2
    if (direction === 'left') return cx < fromCx ? cx : -Infinity
    if (direction === 'right') return cx > fromCx ? -cx : -Infinity
    if (direction === 'up') return cy < fromCy ? cy : -Infinity
    return cy > fromCy ? -cy : -Infinity
  }

  const pick = (list: BspLeafPane[]) => {
    let best: BspLeafPane | null = null
    let bestScore = -Infinity
    for (const pane of list) {
      const s = score(pane)
      if (s > bestScore) {
        best = pane
        bestScore = s
      }
    }
    return best?.leaf ?? null
  }

  const overlapCandidates = candidates.filter((pane) => isOverlapMatch(pane))
  return pick(overlapCandidates) ?? pick(candidates)
}

function ensureLeafInLayout(
  layout: MosaicNode<TileKey> | null,
  leaf: TileKey,
  preferredLeaf?: TileKey,
  mode: InsertSplitMode = 'auto',
): MosaicNode<TileKey> {
  const leaves = getLeavesSafe(layout)
  if (leaves.includes(leaf)) return layout ?? leaf
  return insertLeafWithMode(layout, leaf, preferredLeaf, mode)
}

function maybeBuildTwoDocSplitGrid(
  layout: MosaicNode<TileKey> | null,
  tiles: Record<TileKey, TileSpec>,
): MosaicNode<TileKey> | null {
  if (!layout) return null
  const leaves = getLeavesSafe(layout)
  if (leaves.length !== 4) return null

  const docOrder: string[] = []
  const groups = new Map<string, { editor?: TileKey; preview?: TileKey }>()
  for (const leaf of leaves) {
    const spec = tiles[leaf]
    if (!spec) return null
    if (spec.mode !== 'editor' && spec.mode !== 'preview') return null
    const docId = spec.documentId
    if (!groups.has(docId)) {
      groups.set(docId, {})
      docOrder.push(docId)
    }
    const group = groups.get(docId)!
    if (spec.mode === 'editor') group.editor = leaf
    else group.preview = leaf
  }

  if (groups.size !== 2) return null
  for (const group of groups.values()) {
    if (!group.editor || !group.preview) return null
  }

  const makeRow = (docId: string): MosaicNode<TileKey> => {
    const group = groups.get(docId)!
    return {
      direction: 'row',
      first: group.editor!,
      second: group.preview!,
      splitPercentage: 50,
    }
  }

  const [firstDoc, secondDoc] = docOrder
  if (!firstDoc || !secondDoc) return null
  return {
    direction: 'column',
    first: makeRow(firstDoc),
    second: makeRow(secondDoc),
    splitPercentage: 50,
  }
}

function pruneLayout(
  layout: MosaicNode<TileKey> | null,
  isValidLeaf: (leaf: TileKey) => boolean,
): MosaicNode<TileKey> | null {
  if (!layout) return null
  if (!isParent(layout)) {
    const leaf = layout as TileKey
    return isValidLeaf(leaf) ? leaf : null
  }
  const parent = layout as MosaicParent<TileKey>
  const first = pruneLayout(parent.first, isValidLeaf)
  const second = pruneLayout(parent.second, isValidLeaf)
  if (!first && !second) return null
  if (!first) return second
  if (!second) return first
  if (first === parent.first && second === parent.second) return parent
  return { ...parent, first, second }
}

function balanceLayoutSplits(layout: MosaicNode<TileKey>): MosaicNode<TileKey> {
  const equalize = (node: MosaicNode<TileKey>): { node: MosaicNode<TileKey>; leafCount: number } => {
    if (!isParent(node)) return { node, leafCount: 1 }
    const parent = node as MosaicParent<TileKey>
    const first = equalize(parent.first)
    const second = equalize(parent.second)
    const total = first.leafCount + second.leafCount
    const nextSplit = total > 0 ? (first.leafCount / total) * 100 : 50
    const currentSplit = normalizeSplitPercentage((parent as any).splitPercentage)
    const normalizedNext = normalizeSplitPercentage(nextSplit)
    const epsilon = 1e-6
    const sameSplit = Math.abs(currentSplit - normalizedNext) < epsilon
    const nextNode =
      first.node === parent.first && second.node === parent.second && sameSplit
        ? node
        : { ...parent, first: first.node, second: second.node, splitPercentage: normalizedNext }
    return { node: nextNode, leafCount: total }
  }

  return equalize(layout).node
}

function defaultState(activeDocumentId: string): MosaicState {
  const editorKey = makeTileKey()
  const previewKey = makeTileKey()
  const groupId = makeSyncGroupId()
  return {
    layout: { direction: 'row', first: editorKey, second: previewKey, splitPercentage: 50 },
    tiles: {
      [editorKey]: { mode: 'editor', documentId: activeDocumentId, syncGroupId: groupId },
      [previewKey]: { mode: 'preview', documentId: activeDocumentId, syncGroupId: groupId },
    },
  }
}

function deriveDocumentViewMode(documentId: string, tiles: Record<TileKey, TileSpec>): 'editor' | 'split' | 'preview' {
  const id = documentId.trim()
  if (!id) return 'editor'
  let hasEditor = false
  let hasPreview = false
  for (const spec of Object.values(tiles)) {
    if (spec.documentId !== id) continue
    if (spec.mode === 'editor') hasEditor = true
    else if (spec.mode === 'preview') hasPreview = true
    if (hasEditor && hasPreview) return 'split'
  }
  if (hasEditor) return 'editor'
  if (hasPreview) return 'preview'
  return 'editor'
}

function sanitizeState(state: MosaicState, activeDocumentId: string): MosaicState {
  const prunedLayout = pruneLayout(state.layout, (leaf) => Boolean(state.tiles[leaf]))
  const leaves = getLeavesSafe(prunedLayout)
  const nextTiles: Record<TileKey, TileSpec> = {}
  for (const leaf of leaves) {
    const spec = state.tiles[leaf]
    if (spec && typeof spec.documentId === 'string' && spec.documentId.trim()) {
      const trimmedId = spec.documentId.trim()
      const rawGroupId = (spec as any).syncGroupId
      const trimmedGroupId = typeof rawGroupId === 'string' ? rawGroupId.trim() : ''

      const needsDocUpdate = trimmedId !== spec.documentId
      const needsGroupUpdate =
        typeof rawGroupId === 'string'
          ? (trimmedGroupId ? trimmedGroupId !== rawGroupId : rawGroupId.length > 0)
          : false

      if (!needsDocUpdate && !needsGroupUpdate) {
        nextTiles[leaf] = spec
        continue
      }

      const nextSpec: TileSpec = { ...spec, documentId: trimmedId }
      if (trimmedGroupId) nextSpec.syncGroupId = trimmedGroupId
      else delete (nextSpec as any).syncGroupId
      nextTiles[leaf] = nextSpec
    }
  }

  // Ensure editor/preview tiles for the same document share a sync group.
  let needsSyncUpdate = false
  const byDoc = new Map<string, { editors: TileKey[]; previews: TileKey[] }>()
  for (const leaf of leaves) {
    const spec = nextTiles[leaf]
    if (!spec) continue
    if (spec.mode !== 'editor' && spec.mode !== 'preview') continue
    const docId = spec.documentId
    let bucket = byDoc.get(docId)
    if (!bucket) {
      bucket = { editors: [], previews: [] }
      byDoc.set(docId, bucket)
    }
    if (spec.mode === 'editor') bucket.editors.push(leaf)
    else bucket.previews.push(leaf)
  }

  for (const [, bucket] of byDoc) {
    if (bucket.editors.length === 0 || bucket.previews.length === 0) continue

    const editorGroups = new Set(bucket.editors.map((key) => nextTiles[key]?.syncGroupId).filter(Boolean) as string[])
    const previewGroups = new Set(bucket.previews.map((key) => nextTiles[key]?.syncGroupId).filter(Boolean) as string[])

    let groupId: string | null = null
    for (const candidate of editorGroups) {
      if (previewGroups.has(candidate)) {
        groupId = candidate
        break
      }
    }
    if (!groupId) {
      groupId = editorGroups.values().next().value ?? previewGroups.values().next().value ?? null
    }
    if (!groupId) groupId = makeSyncGroupId()

    for (const key of [...bucket.editors, ...bucket.previews]) {
      const spec = nextTiles[key]
      if (!spec) continue
      if (spec.syncGroupId !== groupId) {
        nextTiles[key] = { ...spec, syncGroupId: groupId }
        needsSyncUpdate = true
      }
    }
  }
  if (leaves.length === 0) {
    return defaultState(activeDocumentId)
  }
  if (state.layout === prunedLayout) {
    const stateKeys = Object.keys(state.tiles) as TileKey[]
    if (stateKeys.length === leaves.length) {
      let same = true
      for (const key of stateKeys) {
        if (!nextTiles[key] || state.tiles[key] !== nextTiles[key]) {
          same = false
          break
        }
      }
      if (same && !needsSyncUpdate) return state
    }
  }
  return { layout: prunedLayout, tiles: nextTiles }
}

function loadState(activeDocumentId: string, storageKey: string): MosaicState {
  if (typeof window === 'undefined') return defaultState(activeDocumentId)
  try {
    const raw = localStorage.getItem(storageKey)
    if (!raw) return defaultState(activeDocumentId)
    const parsed = JSON.parse(raw) as unknown
    if (!parsed || typeof parsed !== 'object') return defaultState(activeDocumentId)
    const candidate = parsed as Partial<MosaicState>
    if (!candidate.tiles || typeof candidate.tiles !== 'object') return defaultState(activeDocumentId)
    const layout = (candidate.layout ?? null) as MosaicNode<TileKey> | null
    const tiles = candidate.tiles as Record<TileKey, TileSpec>
    return sanitizeState({ layout, tiles }, activeDocumentId)
  } catch {
    return defaultState(activeDocumentId)
  }
}

function saveState(state: MosaicState, storageKey: string) {
  try {
    localStorage.setItem(storageKey, JSON.stringify(state))
  } catch {
    /* noop */
  }
}

type Props = Pick<DocumentPageProps, 'id' | 'loaderData' | 'shareToken' | 'conflictMode'> & {
  shareScope?: ShareScope
  isShareMount?: boolean
}

export default function DocumentMosaicWorkspace(props: Props) {
  const { id, loaderData, shareToken, shareScope: shareScopeProp, isShareMount = false, conflictMode } = props
  const navigate = useNavigate()
  const { user, activeWorkspaceId } = useAuthContext()
  const shareLinkToken = shareToken && !isShareMount ? shareToken : undefined
  const mosaicStorageKey = useMemo(() => {
    if (shareLinkToken) return null
    return buildMosaicStorageKey({ userId: user?.id ?? null, workspaceId: activeWorkspaceId })
  }, [activeWorkspaceId, shareLinkToken, user?.id])
  const mosaicStorageKeyRef = useRef<string | null>(mosaicStorageKey)
  const [mosaicState, setMosaicState] = useState<MosaicState>(() => {
    return mosaicStorageKey ? loadState(id, mosaicStorageKey) : defaultState(id)
  })
  const [activeDocumentId, setActiveDocumentId] = useState(id)
  const activeDocumentIdRef = useRef(activeDocumentId)
  const activeTileRef = useRef<{ tileKey: TileKey; documentId: string; mode: TileMode } | null>(null)
  const previousTileKeyRef = useRef<TileKey | null>(null)
  const expandedTileKeyRef = useRef<TileKey | null>(null)
  const [insertSplitMode, setInsertSplitMode] = useState<InsertSplitMode>(() => {
    if (typeof window === 'undefined') return 'row'
    try {
      const raw = localStorage.getItem('refmd:mosaic:insert-split-mode')
      if (raw === 'row' || raw === 'column' || raw === 'auto') return raw
      return 'row'
    } catch {
      return 'row'
    }
  })
  const insertSplitModeRef = useRef(insertSplitMode)
  const focusRequestIdRef = useRef(0)
  const saveTimerRef = useRef<number | null>(null)
  const latestStateRef = useRef(mosaicState)
  const shareLinkTokenRef = useRef(shareLinkToken)
  const clearSavedLayoutRef = useRef(false)
  const lastReportedViewModeRef = useRef<{ docId: string; mode: 'editor' | 'split' | 'preview' } | null>(null)
  const lastRouteDocIdRef = useRef<string>(id)
  const lastSeenRouteDocIdRef = useRef<string>(id)

  useEffect(() => {
    insertSplitModeRef.current = insertSplitMode
  }, [insertSplitMode])

  useEffect(() => {
    if (typeof window === 'undefined') return
    try {
      localStorage.setItem('refmd:mosaic:insert-split-mode', insertSplitMode)
    } catch {
      // ignore
    }
  }, [insertSplitMode])

  useEffect(() => {
    latestStateRef.current = mosaicState
  }, [mosaicState])

  useEffect(() => {
    if (!mosaicStorageKey) return
    if (mosaicStorageKeyRef.current === mosaicStorageKey) return
    mosaicStorageKeyRef.current = mosaicStorageKey
    activeTileRef.current = null
    previousTileKeyRef.current = null
    expandedTileKeyRef.current = null
    setMosaicState(loadState(id, mosaicStorageKey))
  }, [id, mosaicStorageKey, setMosaicState])

  useEffect(() => {
    const previous = lastRouteDocIdRef.current
    lastRouteDocIdRef.current = id
    if (!previous || previous === id) return

    setMosaicState((prev) => {
      const safe = sanitizeState(prev, id)
      const alreadyOpen = Object.values(safe.tiles).some((spec) => spec.documentId === id)
      if (alreadyOpen) return safe

      let changed = false
      const nextTiles: Record<TileKey, TileSpec> = { ...safe.tiles }
      for (const [tileKey, spec] of Object.entries(safe.tiles) as Array<[TileKey, TileSpec]>) {
        if (spec.documentId !== previous) continue
        nextTiles[tileKey] = { ...spec, documentId: id }
        changed = true
      }
      if (!changed) return safe

      // If the previous focused document was in split view, reset that pair's divider to 50/50
      // so the newly opened document starts balanced.
      let nextLayout = safe.layout
      const entries = Object.entries(nextTiles) as Array<[TileKey, TileSpec]>
      const editorKey = entries.find(([, spec]) => spec.documentId === id && spec.mode === 'editor')?.[0] ?? null
      const previewKey = entries.find(([, spec]) => spec.documentId === id && spec.mode === 'preview')?.[0] ?? null
      if (editorKey && previewKey && nextLayout) {
        const editorPath = findPathToTile(nextLayout, editorKey)
        const previewPath = findPathToTile(nextLayout, previewKey)
        if (editorPath && previewPath) {
          const minLength = Math.min(editorPath.length, previewPath.length)
          let idx = 0
          while (idx < minLength && editorPath[idx] === previewPath[idx]) idx += 1
          const lcaPath = editorPath.slice(0, idx) as MosaicPath
          const lcaNode = ((): MosaicNode<TileKey> | null => {
            let node: MosaicNode<TileKey> | null = nextLayout
            for (const step of lcaPath) {
              if (!node || !isParent(node)) return null
              node = step === 'first' ? (node as MosaicParent<TileKey>).first : (node as MosaicParent<TileKey>).second
            }
            return node
          })()
          if (
            lcaNode &&
            isParent(lcaNode) &&
            ((lcaNode as MosaicParent<TileKey>).first === editorKey || (lcaNode as MosaicParent<TileKey>).second === editorKey) &&
            ((lcaNode as MosaicParent<TileKey>).first === previewKey || (lcaNode as MosaicParent<TileKey>).second === previewKey)
          ) {
            nextLayout = updateParentSplitPercentage(nextLayout, lcaPath, 50)
          }
        }
      }

      return sanitizeState({ layout: nextLayout, tiles: nextTiles }, id)
    })
  }, [id, setMosaicState])

  const focusTileElement = useCallback((tileKey: TileKey) => {
    if (typeof document === 'undefined') return
    if (typeof window === 'undefined') return
    const requestId = ++focusRequestIdRef.current
    const selectorKey =
      typeof CSS !== 'undefined' && typeof CSS.escape === 'function' ? CSS.escape(tileKey) : tileKey
    const el = document.querySelector<HTMLElement>(`[data-refmd-tile-key="${selectorKey}"]`)
    if (!el) return
    try {
      el.scrollIntoView({ block: 'nearest', inline: 'nearest' })
    } catch {}

    const focusInside = () => {
      if (focusRequestIdRef.current !== requestId) return true
      if (!el.isConnected) return false
      const safe = sanitizeState(latestStateRef.current, id)
      const leaves = getLeavesSafe(safe.layout)
      if (!leaves.includes(tileKey)) return false

      const monacoInput =
        el.querySelector<HTMLElement>('.monaco-editor textarea.inputarea') ??
        el.querySelector<HTMLElement>('.monaco-editor textarea') ??
        el.querySelector<HTMLElement>('textarea.inputarea')
      if (monacoInput) {
        try {
          monacoInput.focus({ preventScroll: true } as any)
        } catch {
          try {
            monacoInput.focus()
          } catch {}
        }
        return true
      }

      const firstInput =
        el.querySelector<HTMLElement>('textarea, input, [contenteditable="true"], [tabindex="0"]') ?? null
      if (firstInput) {
        try {
          firstInput.focus({ preventScroll: true } as any)
        } catch {
          try {
            firstInput.focus()
          } catch {}
        }
        return true
      }
      return false
    }

    if (focusInside()) return
    // Monaco might mount a tick later; try a few times.
    let tries = 0
    const retry = () => {
      if (focusRequestIdRef.current !== requestId) return
      tries += 1
      if (focusInside()) return
      if (tries >= 8) {
        try {
          el.focus({ preventScroll: true } as any)
        } catch {
          try {
            el.focus()
          } catch {}
        }
        return
      }
      window.requestAnimationFrame(retry)
    }
    window.requestAnimationFrame(retry)
  }, [id])

  useEffect(() => {
    activeDocumentIdRef.current = activeDocumentId
  }, [activeDocumentId])

  useEffect(() => {
    setActiveDocumentId(id)
    activeDocumentIdRef.current = id

    const safe = sanitizeState(latestStateRef.current, id)
    const existingTileKey = activeTileRef.current?.tileKey ?? null
    const existingSpec = existingTileKey ? safe.tiles[existingTileKey] : undefined
    if (existingTileKey && existingSpec?.documentId === id) {
      activeTileRef.current = { tileKey: existingTileKey, documentId: id, mode: existingSpec.mode }
      return
    }

    const leaves = getLeavesSafe(safe.layout)
    const candidates: Array<{ key: TileKey; spec: TileSpec }> = []
    for (const key of leaves) {
      const spec = safe.tiles[key]
      if (!spec) continue
      if (spec.documentId !== id) continue
      candidates.push({ key, spec })
    }
    if (candidates.length === 0) return

    const modeRank: Record<TileMode, number> = { editor: 0, preview: 1, backlinks: 2 }
    candidates.sort((a, b) => (modeRank[a.spec.mode] ?? 9) - (modeRank[b.spec.mode] ?? 9))
    const picked = candidates[0]
    if (!picked) return
    activeTileRef.current = { tileKey: picked.key, documentId: id, mode: picked.spec.mode }
  }, [id])

  useEffect(() => {
    shareLinkTokenRef.current = shareLinkToken
  }, [shareLinkToken])

  const shareBrowseQuery = useQuery({
    queryKey: ['share-browse', shareToken],
    queryFn: async () => browseShare(shareToken!),
    staleTime: 5 * 60 * 1000,
    enabled: Boolean(shareToken && (isShareMount || shareScopeProp === 'folder' || shareScopeProp == null)),
  })

  const inferredShareScope = useMemo<ShareScope | undefined>(() => {
    const tree = (shareBrowseQuery.data as any)?.tree
    if (!Array.isArray(tree) || tree.length === 0) return undefined
    const root = tree.find((n: any) => !n.parent_id) ?? tree[0]
    return root?.type === 'folder' ? 'folder' : 'document'
  }, [shareBrowseQuery.data])

  const effectiveShareScope = shareScopeProp ?? inferredShareScope
  const isSingleDocShare = Boolean(shareLinkToken && effectiveShareScope === 'document')
  const focusedPluginLookup = useCreatedByPluginId(id, shareToken ?? null)
  const splitCapablePluginDocs = useSplitCapablePluginDocs()
  const focusedIsNonSplitPluginDoc = useMemo(() => {
    const pluginId = focusedPluginLookup.pluginId
    if (!pluginId) return false
    return !splitCapablePluginDocs.has(id)
  }, [focusedPluginLookup.pluginId, id, splitCapablePluginDocs])

  const allowedSharedDocIds = useMemo<Set<string> | null>(() => {
    if (!shareToken) return null
    if (effectiveShareScope === 'document') return new Set([id])
    if (effectiveShareScope !== 'folder') return null
    const tree = (shareBrowseQuery.data as any)?.tree
    if (!Array.isArray(tree) || tree.length === 0) return null
    return new Set<string>(tree.filter((n: any) => n?.type === 'document').map((n: any) => String(n.id)))
  }, [effectiveShareScope, id, shareBrowseQuery.data, shareToken])

  const canAccessSharedDocument = useCallback(
    (documentId: string) => {
      const target = documentId.trim()
      if (!target) return false
      if (!shareToken) return true
      if (effectiveShareScope === 'document') return target === id
      if (effectiveShareScope === 'folder') {
        if (!allowedSharedDocIds) return target === id
        return allowedSharedDocIds.has(target)
      }
      // Unknown share scope: default to least privilege until scope is resolved.
      return target === id
    },
    [allowedSharedDocIds, effectiveShareScope, id, shareToken],
  )

  const markActiveDocument = useCallback(
    (documentId: string, tileKey?: TileKey, mode?: TileMode) => {
      const trimmed = documentId.trim()
      if (!trimmed) return
      setActiveDocumentId(trimmed)
      activeDocumentIdRef.current = trimmed
      if (tileKey && mode) {
        const prev = activeTileRef.current?.tileKey ?? null
        if (prev && prev !== tileKey) {
          previousTileKeyRef.current = prev
        }
        activeTileRef.current = { tileKey, documentId: trimmed, mode }
      }
      // Keep the URL in sync with the currently focused document so share/copy works and
      // "focused document" logic (ctx.id) updates across tiles.
      if (trimmed === id) return
      if (isSingleDocShare) return
      try {
        navigate({
          to: '/document/$id',
          params: { id: trimmed },
          replace: true,
          search: (prev: Record<string, unknown>) => {
            const next: Record<string, unknown> = { ...(prev || {}) }
            if (shareToken) next.token = shareToken
            if (shareScopeProp) next.shareScope = shareScopeProp
            if (isShareMount) next.shareMount = '1'
            return next
          },
        })
      } catch {
        // ignore
      }
    },
    [id, isShareMount, isSingleDocShare, navigate, setActiveDocumentId, shareScopeProp, shareToken],
  )

  const swapTiles = useCallback(
    (firstKey: TileKey, secondKey: TileKey) => {
      if (firstKey === secondKey) return
      setMosaicState((prev) => {
        const safe = sanitizeState(prev, id)
        const firstSpec = safe.tiles[firstKey]
        const secondSpec = safe.tiles[secondKey]
        if (!firstSpec || !secondSpec) return safe
        const nextTiles: Record<TileKey, TileSpec> = { ...safe.tiles }
        nextTiles[firstKey] = secondSpec
        nextTiles[secondKey] = firstSpec
        return sanitizeState({ ...safe, tiles: nextTiles }, id)
      })
    },
    [id],
  )

  const swapActiveTileWithLast = useCallback(() => {
    const active = activeTileRef.current?.tileKey ?? null
    const previous = previousTileKeyRef.current
    if (!active || !previous) return
    swapTiles(active, previous)
  }, [swapTiles])

  const swapActiveTileByDirection = useCallback(
    (direction: SwapDirection) => {
      setMosaicState((prev) => {
        const safe = sanitizeState(prev, id)
        const active = activeTileRef.current?.tileKey ?? null
        if (!active) return safe
        if (!safe.layout) return safe
        const panes: BspLeafPane[] = []
        collectLeafPanes(safe.layout, getRootRect(), [] as MosaicPath, panes)
        const neighbor = pickNeighborLeaf(panes, active, direction)
        if (!neighbor) return safe
        const a = safe.tiles[active]
        const b = safe.tiles[neighbor]
        if (!a || !b) return safe
        const nextTiles: Record<TileKey, TileSpec> = { ...safe.tiles, [active]: b, [neighbor]: a }
        return sanitizeState({ ...safe, tiles: nextTiles }, id)
      })
    },
    [id],
  )

  useEffect(() => {
    const currentActive = activeDocumentIdRef.current
    if (currentActive === id) return
    const stillExists = Object.values(mosaicState.tiles).some((tile) => tile.documentId === currentActive)
    if (!stillExists) {
      setActiveDocumentId(id)
      activeDocumentIdRef.current = id
      activeTileRef.current = null
    }
  }, [id, mosaicState.tiles])

  const applyViewModeForDocument = useCallback(
    (documentId: string, mode: 'editor' | 'split' | 'preview') => {
      const target = documentId.trim()
      if (!target) return
      if (isSingleDocShare && target !== id) return

      if (!canAccessSharedDocument(target)) {
        toast.info('This document is not included in the shared scope.')
        return
      }

      setMosaicState((prev) => {
        const safe = sanitizeState(prev, id)
        let nextLayout = safe.layout
        let nextTiles: Record<TileKey, TileSpec> = { ...safe.tiles }
        let didMutateLayout = false

        const entries = Object.entries(safe.tiles) as Array<[TileKey, TileSpec]>
        const editorKeys = entries
          .filter(([, spec]) => spec.documentId === target && spec.mode === 'editor')
          .map(([k]) => k)
        const previewKeys = entries
          .filter(([, spec]) => spec.documentId === target && spec.mode === 'preview')
          .map(([k]) => k)

        const removeTile = (key: TileKey) => {
          delete nextTiles[key]
        }

        const clearSync = (key: TileKey) => {
          const spec = nextTiles[key]
          if (!spec) return
          if (!spec.syncGroupId) return
          nextTiles[key] = { ...spec, syncGroupId: undefined }
        }

        const setSpec = (key: TileKey, spec: TileSpec) => {
          nextTiles[key] = spec
        }

        const addLeaf = (key: TileKey) => {
          nextLayout = insertLeafWithMode(nextLayout, key, activeTileRef.current?.tileKey, insertSplitMode)
          didMutateLayout = true
        }

        if (mode === 'editor') {
          const existingEditorKey = editorKeys[0]
          const reusedFromPreviewKey = !existingEditorKey ? previewKeys[0] : undefined
          const editorKey = existingEditorKey ?? reusedFromPreviewKey ?? makeTileKey()

          if (!existingEditorKey && !reusedFromPreviewKey) {
            setSpec(editorKey, { mode: 'editor', documentId: target })
            addLeaf(editorKey)
          } else {
            setSpec(editorKey, { ...nextTiles[editorKey], mode: 'editor', documentId: target, syncGroupId: undefined })
          }

          for (const key of editorKeys) {
            if (key !== editorKey) removeTile(key)
          }
          for (const key of previewKeys) {
            if (key !== editorKey) removeTile(key)
          }
          clearSync(editorKey)
        } else if (mode === 'preview') {
          const existingPreviewKey = previewKeys[0]
          const reusedFromEditorKey = !existingPreviewKey ? editorKeys[0] : undefined
          const previewKey = existingPreviewKey ?? reusedFromEditorKey ?? makeTileKey()

          if (!existingPreviewKey && !reusedFromEditorKey) {
            setSpec(previewKey, { mode: 'preview', documentId: target })
            addLeaf(previewKey)
          } else {
            setSpec(previewKey, { ...nextTiles[previewKey], mode: 'preview', documentId: target, syncGroupId: undefined })
          }

          for (const key of previewKeys) {
            if (key !== previewKey) removeTile(key)
          }
          for (const key of editorKeys) {
            if (key !== previewKey) removeTile(key)
          }
          clearSync(previewKey)
        } else {
          const groupId = makeSyncGroupId()
          const active = activeTileRef.current

          const pickBaseKey = () => {
            if (active && active.documentId === target) {
              const spec = safe.tiles[active.tileKey]
              if (spec && spec.documentId === target && (spec.mode === 'editor' || spec.mode === 'preview')) {
                return active.tileKey
              }
            }
            const first = entries.find(([, spec]) => spec.documentId === target && (spec.mode === 'editor' || spec.mode === 'preview'))
            return first?.[0]
          }

          const baseKey = pickBaseKey()
          if (!baseKey) {
            const editorKey = makeTileKey()
            const previewKey = makeTileKey()
            setSpec(editorKey, { mode: 'editor', documentId: target, syncGroupId: groupId })
            setSpec(previewKey, { mode: 'preview', documentId: target, syncGroupId: groupId })
            nextLayout = insertLeafWithMode(nextLayout, editorKey, activeTileRef.current?.tileKey, insertSplitMode)
            nextLayout = insertLeafWithMode(nextLayout, previewKey, editorKey, insertSplitMode)
            didMutateLayout = true
          } else {
            const baseSpec = safe.tiles[baseKey]
            const baseMode: TileMode = baseSpec?.mode === 'preview' ? 'preview' : 'editor'
            const oppositeMode: TileMode = baseMode === 'editor' ? 'preview' : 'editor'
            const existingOppositeKey = entries.find(
              ([key, spec]) => key !== baseKey && spec.documentId === target && spec.mode === oppositeMode,
            )?.[0]
            const oppositeKey = existingOppositeKey ?? makeTileKey()

            setSpec(baseKey, { ...nextTiles[baseKey], mode: baseMode, documentId: target, syncGroupId: groupId })
            setSpec(oppositeKey, { ...nextTiles[oppositeKey], mode: oppositeMode, documentId: target, syncGroupId: groupId })

            if (existingOppositeKey) {
              const oppositePath = findPathToTile(nextLayout, existingOppositeKey)
              if (oppositePath) {
                nextLayout = removeLeaf(nextLayout, existingOppositeKey)
              }
            }

            const basePath = findPathToTile(nextLayout, baseKey)
            if (!basePath) {
              nextLayout = ensureLeafInLayout(nextLayout, baseKey, undefined, insertSplitMode)
            }

            const finalBasePath = findPathToTile(nextLayout, baseKey)
            if (!finalBasePath) {
              // Shouldn't happen, but keep existing layout and append instead of replacing the whole tree.
              nextLayout = ensureLeafInLayout(nextLayout, baseKey, undefined, insertSplitMode)
              nextLayout = ensureLeafInLayout(nextLayout, oppositeKey, baseKey, insertSplitMode)
            }
          const finalPath = findPathToTile(nextLayout, baseKey) ?? ([] as MosaicPath)
          const editorKey = baseMode === 'editor' ? baseKey : oppositeKey
          const previewKey = baseMode === 'preview' ? baseKey : oppositeKey
            const replacement: MosaicNode<TileKey> = {
              direction: 'row',
              first: editorKey,
              second: previewKey,
              splitPercentage: 50,
            }
            nextLayout = replaceNodeAtPath(nextLayout, finalPath, replacement)
            didMutateLayout = true
          }

          if (insertSplitMode === 'auto') {
            const grid = maybeBuildTwoDocSplitGrid(nextLayout, nextTiles)
            if (grid) nextLayout = grid
          }
        }

        if (insertSplitMode === 'row' && didMutateLayout && nextLayout) {
          nextLayout = balanceLayoutSplits(nextLayout)
          expandedTileKeyRef.current = null
        }

        return sanitizeState({ layout: nextLayout, tiles: nextTiles }, id)
      })
    },
    [canAccessSharedDocument, id, insertSplitMode, isSingleDocShare],
  )

  useEffect(() => {
    if (isSingleDocShare) return
    if (!focusedIsNonSplitPluginDoc) return
    const current = deriveDocumentViewMode(id, mosaicState.tiles)
    if (current === 'preview') return
    applyViewModeForDocument(id, 'preview')
  }, [applyViewModeForDocument, focusedIsNonSplitPluginDoc, id, isSingleDocShare, mosaicState.tiles])

  useEffect(() => {
    if (!mosaicStorageKeyRef.current) return
    if (typeof window === 'undefined') return
    if (saveTimerRef.current != null) {
      window.clearTimeout(saveTimerRef.current)
      saveTimerRef.current = null
    }
    saveTimerRef.current = window.setTimeout(() => {
      saveTimerRef.current = null
      const key = mosaicStorageKeyRef.current
      if (!key) return
      saveState(mosaicState, key)
    }, 250)
    return () => {
      if (saveTimerRef.current != null) {
        window.clearTimeout(saveTimerRef.current)
        saveTimerRef.current = null
      }
    }
  }, [mosaicState, shareLinkToken])

  useEffect(() => {
    return () => {
      if (shareLinkTokenRef.current) return
      const key = mosaicStorageKeyRef.current
      if (clearSavedLayoutRef.current) {
        if (key) {
          try {
            localStorage.removeItem(key)
          } catch {}
        }
        return
      }
      if (saveTimerRef.current != null) {
        try {
          window.clearTimeout(saveTimerRef.current)
        } catch {}
        saveTimerRef.current = null
      }
      if (key) saveState(latestStateRef.current, key)
    }
  }, [])

  const closeAllTilesToDashboard = useCallback(() => {
    if (typeof window === 'undefined') return
    clearSavedLayoutRef.current = true
    if (saveTimerRef.current != null) {
      try {
        window.clearTimeout(saveTimerRef.current)
      } catch {}
      saveTimerRef.current = null
    }
    const key = mosaicStorageKeyRef.current
    if (key) {
      try {
        localStorage.removeItem(key)
      } catch {}
    }
    navigate({ to: '/dashboard', replace: true })
  }, [navigate])

  const toggleExpandTile = useCallback(
    (tileKey: TileKey) => {
      if (typeof window === 'undefined') return
      setMosaicState((prev) => {
        const safe = sanitizeState(prev, id)
        const layout = safe.layout
        if (!layout) return safe
        const path = findPathToTile(layout, tileKey)
        if (!path) return safe

        const isExpanded = expandedTileKeyRef.current === tileKey
        const percentage = isExpanded ? UNEXPAND_PERCENTAGE : EXPAND_PERCENTAGE
        expandedTileKeyRef.current = isExpanded ? null : tileKey

        const nextLayout = updateTree(layout, [createExpandUpdate<TileKey>(path, percentage)])
        return sanitizeState({ ...safe, layout: nextLayout }, id)
      })
    },
    [id],
  )

  const focusActiveTileByDirection = useCallback(
    (direction: SwapDirection) => {
      const safe = sanitizeState(latestStateRef.current, id)
      const active = activeTileRef.current?.tileKey ?? null
      const layout = safe.layout
      if (!active || !layout) return
      const panes: BspLeafPane[] = []
      collectLeafPanes(layout, getRootRect(), [] as MosaicPath, panes)
      const neighbor = pickNeighborLeaf(panes, active, direction)
      if (!neighbor) return
      const spec = safe.tiles[neighbor]
      if (!spec) return
      markActiveDocument(spec.documentId, neighbor, spec.mode)
      focusTileElement(neighbor)
    },
    [focusTileElement, id, markActiveDocument],
  )

  const balanceTileSizes = useCallback(() => {
    setMosaicState((prev) => {
      const safe = sanitizeState(prev, id)
      if (!safe.layout) return safe
      const nextLayout = balanceLayoutSplits(safe.layout)
      if (nextLayout === safe.layout) return safe
      expandedTileKeyRef.current = null
      return sanitizeState({ ...safe, layout: nextLayout }, id)
    })
  }, [id])

  const closeActiveTile = useCallback(() => {
    const active = activeTileRef.current?.tileKey ?? null
    if (!active) return
    if (isSingleDocShare) return

    const safeNow = sanitizeState(latestStateRef.current, id)
    const leaves = getLeavesSafe(safeNow.layout)
    if (leaves.length <= 1) {
      closeAllTilesToDashboard()
      return
    }

    setMosaicState((prev) => {
      const safe = sanitizeState(prev, id)
      if (!safe.layout) return safe
      if (!safe.tiles[active]) return safe
      const nextLayout = removeLeaf(safe.layout, active)
      const nextTiles: Record<TileKey, TileSpec> = { ...safe.tiles }
      delete nextTiles[active]
      expandedTileKeyRef.current = null
      return sanitizeState({ layout: nextLayout, tiles: nextTiles }, id)
    })
  }, [closeAllTilesToDashboard, id, isSingleDocShare])

  const closeOtherTiles = useCallback(() => {
    const active = activeTileRef.current?.tileKey ?? null
    if (!active) return
    if (isSingleDocShare) return

    setMosaicState((prev) => {
      const safe = sanitizeState(prev, id)
      const spec = safe.tiles[active]
      if (!spec) return safe
      expandedTileKeyRef.current = null
      return sanitizeState({ layout: active, tiles: { [active]: spec } as Record<TileKey, TileSpec> }, id)
    })
  }, [id, isSingleDocShare])

  useEffect(() => {
    if (!isSingleDocShare) return
    setMosaicState(defaultState(id))
  }, [id, isSingleDocShare])

  useEffect(() => {
    if (typeof window === 'undefined') return
    const mode = deriveDocumentViewMode(id, mosaicState.tiles)
    const prev = lastReportedViewModeRef.current
    if (prev && prev.docId === id && prev.mode === mode) return
    lastReportedViewModeRef.current = { docId: id, mode }
    dispatchMosaicCurrentViewMode(id, mode)
  }, [id, mosaicState.tiles])

  useShortcut('tiles.split.direction.auto', () => setInsertSplitMode('auto'))
  useShortcut('tiles.split.direction.row', () => setInsertSplitMode('row'))
  useShortcut('tiles.split.direction.column', () => setInsertSplitMode('column'))
  useShortcut('tiles.swap.left', () => swapActiveTileByDirection('left'), { preventDefault: true })
  useShortcut('tiles.swap.right', () => swapActiveTileByDirection('right'), { preventDefault: true })
  useShortcut('tiles.swap.up', () => swapActiveTileByDirection('up'), { preventDefault: true })
  useShortcut('tiles.swap.down', () => swapActiveTileByDirection('down'), { preventDefault: true })
  useShortcut('tiles.swap.last', () => swapActiveTileWithLast(), { preventDefault: true })
  useShortcut('tiles.focus.left', () => focusActiveTileByDirection('left'), { preventDefault: true })
  useShortcut('tiles.focus.right', () => focusActiveTileByDirection('right'), { preventDefault: true })
  useShortcut('tiles.focus.up', () => focusActiveTileByDirection('up'), { preventDefault: true })
  useShortcut('tiles.focus.down', () => focusActiveTileByDirection('down'), { preventDefault: true })
  useShortcut(
    'tiles.toggle.expand',
    () => {
      const active = activeTileRef.current?.tileKey ?? null
      if (!active) return
      toggleExpandTile(active)
    },
    { preventDefault: true },
  )
  useShortcut('tiles.balance', () => balanceTileSizes(), { preventDefault: true })
  useShortcut('tiles.close.active', () => closeActiveTile(), { preventDefault: true })
  useShortcut('tiles.close.others', () => closeOtherTiles(), { preventDefault: true })
  useShortcut(
    'tiles.open.editor',
    () => {
      const target = activeDocumentIdRef.current || id
      addEditorTile(target)
    },
    { preventDefault: true },
  )
  useShortcut(
    'tiles.open.preview',
    () => {
      const target = activeDocumentIdRef.current || id
      addPreviewTile(target)
    },
    { preventDefault: true },
  )

  useEffect(() => {
    if (isSingleDocShare) return
    // If the currently focused document (URL) is no longer present in any tile (e.g. the user closed that tile),
    // do not rewrite existing tiles to show it. Instead, move focus/URL to a remaining document.
    const tilesNow = Object.values(mosaicState.tiles)
    const hasFocused = tilesNow.some((t) => t.documentId === id)
    if (!hasFocused && tilesNow.length > 0 && lastSeenRouteDocIdRef.current === id) {
      const fallback = tilesNow[0]?.documentId?.trim()
      if (fallback && fallback !== id) {
        markActiveDocument(fallback)
        return
      }
    }
    lastSeenRouteDocIdRef.current = id
    setMosaicState((prev) => {
      const safe = sanitizeState(prev, id)
      const tiles = Object.entries(safe.tiles) as Array<[TileKey, TileSpec]>
      const hasAny = tiles.some(([, t]) => t.documentId === id)
      if (hasAny) return safe

      const editorCandidate = tiles.find(([, t]) => t.mode === 'editor')
      if (editorCandidate) {
        const [editorKey, editorSpec] = editorCandidate
        const prevDocId = editorSpec.documentId
        const previewCandidate = tiles.find(([, t]) => t.mode === 'preview' && t.documentId === prevDocId)
        const nextTiles: Record<TileKey, TileSpec> = {}
        for (const [key, spec] of tiles) {
          if (key === editorKey) nextTiles[key] = { ...spec, documentId: id }
          else if (previewCandidate && key === previewCandidate[0]) nextTiles[key] = { ...spec, documentId: id }
          else nextTiles[key] = spec
        }
        return sanitizeState({ ...safe, tiles: nextTiles }, id)
      }

      const editorKey = makeTileKey()
      const nextTiles: Record<TileKey, TileSpec> = {
        ...safe.tiles,
        [editorKey]: { mode: 'editor', documentId: id },
      }
      const nextLayoutBase: MosaicNode<TileKey> = insertLeafWithMode(
        safe.layout,
        editorKey,
        activeTileRef.current?.tileKey,
        insertSplitMode,
      )
      const nextLayout =
        insertSplitMode === 'row' && nextLayoutBase ? balanceLayoutSplits(nextLayoutBase) : nextLayoutBase
      return sanitizeState({ layout: nextLayout, tiles: nextTiles }, id)
    })
  }, [id, insertSplitMode, isSingleDocShare, markActiveDocument, mosaicState.tiles])

  const addEditorTile = useCallback(
    (docId: string) => {
      const target = docId.trim()
      if (!target) return
      if (isSingleDocShare) return
      if (!canAccessSharedDocument(target)) {
        toast.info('This document is not included in the shared scope.')
        return
      }
      setMosaicState((prev) => {
        const safe = sanitizeState(prev, id)
        const exists = Object.values(safe.tiles).some((t) => t.documentId === target && t.mode === 'editor')
        if (exists) return safe
        const editorKey = makeTileKey()
        const nextLayoutBase = insertLeafWithMode(safe.layout, editorKey, activeTileRef.current?.tileKey, insertSplitMode)
        const nextLayout =
          insertSplitMode === 'row' && nextLayoutBase ? balanceLayoutSplits(nextLayoutBase) : nextLayoutBase
        if (insertSplitMode === 'row') expandedTileKeyRef.current = null
        const nextTiles: Record<TileKey, TileSpec> = {
          ...safe.tiles,
          [editorKey]: { mode: 'editor', documentId: target },
        }
        return sanitizeState({ layout: nextLayout, tiles: nextTiles }, id)
      })
    },
    [canAccessSharedDocument, id, insertSplitMode, isSingleDocShare],
  )

  const addPreviewTile = useCallback(
    (docId: string, splitMode?: InsertSplitMode) => {
      const target = docId.trim()
      if (!target) return
      if (isSingleDocShare) return
      if (!canAccessSharedDocument(target)) {
        toast.info('This document is not included in the shared scope.')
        return
      }
      setMosaicState((prev) => {
        const safe = sanitizeState(prev, id)
        const exists = Object.values(safe.tiles).some((t) => t.documentId === target && t.mode === 'preview')
        if (exists) return safe
        const previewKey = makeTileKey()
        const mode = splitMode ?? insertSplitMode
        const nextLayoutBase = insertLeafWithMode(safe.layout, previewKey, activeTileRef.current?.tileKey, mode)
        const nextLayout = mode === 'row' && nextLayoutBase ? balanceLayoutSplits(nextLayoutBase) : nextLayoutBase
        if (mode === 'row') expandedTileKeyRef.current = null
        const nextTiles: Record<TileKey, TileSpec> = {
          ...safe.tiles,
          [previewKey]: { mode: 'preview', documentId: target },
        }
        return sanitizeState({ layout: nextLayout, tiles: nextTiles }, id)
      })
    },
    [canAccessSharedDocument, id, insertSplitMode, isSingleDocShare],
  )

  const addBacklinksTile = useCallback(
    (docId: string) => {
      const target = docId.trim()
      if (!target) return
      if (isSingleDocShare) return
      if (!canAccessSharedDocument(target)) {
        toast.info('This document is not included in the shared scope.')
        return
      }
      setMosaicState((prev) => {
        const safe = sanitizeState(prev, id)
        const exists = Object.values(safe.tiles).some((t) => t.documentId === target && t.mode === 'backlinks')
        if (exists) return safe
        const tileKey = makeTileKey()
        const nextLayoutBase = insertLeafWithMode(safe.layout, tileKey, activeTileRef.current?.tileKey, insertSplitMode)
        const nextLayout =
          insertSplitMode === 'row' && nextLayoutBase ? balanceLayoutSplits(nextLayoutBase) : nextLayoutBase
        if (insertSplitMode === 'row') expandedTileKeyRef.current = null
        const nextTiles: Record<TileKey, TileSpec> = {
          ...safe.tiles,
          [tileKey]: { mode: 'backlinks', documentId: target },
        }
        return sanitizeState({ layout: nextLayout, tiles: nextTiles }, id)
      })
    },
    [canAccessSharedDocument, id, insertSplitMode, isSingleDocShare],
  )

  useEffect(() => {
    if (isSingleDocShare) return
    const handler = (event: Event) => {
      const detail = (event as CustomEvent<{ documentId?: string; splitMode?: InsertSplitMode }>).detail
      const documentId = typeof detail?.documentId === 'string' ? detail.documentId.trim() : ''
      if (!documentId) return
      addPreviewTile(documentId, detail?.splitMode)
    }
    window.addEventListener(OPEN_PREVIEW_TILE_EVENT, handler as EventListener)
    return () => window.removeEventListener(OPEN_PREVIEW_TILE_EVENT, handler as EventListener)
  }, [addPreviewTile, isSingleDocShare])

  useEffect(() => {
    if (isSingleDocShare) return
    const handler = (event: Event) => {
      const detail = (event as CustomEvent<{ documentId?: string }>).detail
      const documentId = typeof detail?.documentId === 'string' ? detail.documentId.trim() : ''
      if (!documentId) return
      addEditorTile(documentId)
    }
    window.addEventListener(OPEN_EDITOR_TILE_EVENT, handler as EventListener)
    return () => window.removeEventListener(OPEN_EDITOR_TILE_EVENT, handler as EventListener)
  }, [addEditorTile, isSingleDocShare])

  useEffect(() => {
    if (isSingleDocShare) return
    const handler = (event: Event) => {
      const detail = (event as CustomEvent<{ documentId?: string }>).detail
      const documentId = typeof detail?.documentId === 'string' ? detail.documentId.trim() : ''
      if (!documentId) return
      addBacklinksTile(documentId)
    }
    window.addEventListener(OPEN_BACKLINKS_TILE_EVENT, handler as EventListener)
    return () => window.removeEventListener(OPEN_BACKLINKS_TILE_EVENT, handler as EventListener)
  }, [addBacklinksTile, isSingleDocShare])

  useEffect(() => {
    if (typeof window === 'undefined') return
    const handler = (event: Event) => {
      const detail = (event as CustomEvent<{ documentId?: string; mode?: string }>).detail
      const documentId = typeof detail?.documentId === 'string' ? detail.documentId.trim() : ''
      const mode = detail?.mode
      if (!documentId) return
      if (mode !== 'editor' && mode !== 'split' && mode !== 'preview') return
      applyViewModeForDocument(documentId, mode)
    }
    window.addEventListener(MOSAIC_SET_VIEW_MODE_EVENT, handler as EventListener)
    return () => window.removeEventListener(MOSAIC_SET_VIEW_MODE_EVENT, handler as EventListener)
  }, [applyViewModeForDocument])

  return (
    <DocumentPage
      id={id}
      loaderData={loaderData as DocumentLoaderData | undefined}
      shareToken={shareToken}
      conflictMode={conflictMode}
      render={(ctx) => (
        <DocumentMosaicBody
          ctx={ctx}
          mosaicState={mosaicState}
          setMosaicState={setMosaicState}
          addPreviewTile={addPreviewTile}
          insertSplitMode={insertSplitMode}
          isSingleDocShare={isSingleDocShare}
          onCloseAllTiles={closeAllTilesToDashboard}
          onActivateDocument={markActiveDocument}
          onToggleExpandTile={toggleExpandTile}
          expandedTileKeyRef={expandedTileKeyRef}
        />
      )}
    />
  )
}

function getDocText(doc: NonNullable<DocumentPageRenderContext['doc']>) {
  try {
    return doc.getText('content').toString()
  } catch {
    return ''
  }
}

function toggleTaskInDoc(doc: NonNullable<DocumentPageRenderContext['doc']>, lineNumber: number, checked: boolean) {
  if (!Number.isInteger(lineNumber) || lineNumber < 1) return
  const ytext = doc.getText('content')
  const text = ytext.toString()
  let offset = 0
  let currentLine = 1
  while (currentLine < lineNumber) {
    const nextNewline = text.indexOf('\n', offset)
    if (nextNewline === -1) return
    offset = nextNewline + 1
    currentLine += 1
  }
  const nextNewline = text.indexOf('\n', offset)
  const lineEnd = nextNewline === -1 ? text.length : nextNewline
  const lineText = text.slice(offset, lineEnd)
  const taskMatch = lineText.match(/^(\s*(?:>\s*)*(?:[-*+]|\d+[.)])\s*\[)([ xX])(\]\s*)(.*)$/)
  if (!taskMatch) return
  const [, prefix, currentChar, closing, rest] = taskMatch
  const nextChar = checked ? 'x' : ' '
  if (currentChar === nextChar) return
  const newLine = `${prefix}${nextChar}${closing}${rest}`
  doc.transact(() => {
    const y = doc.getText('content')
    y.delete(offset, lineText.length)
    y.insert(offset, newLine)
  })
}

function useDocText(doc: DocumentPageRenderContext['doc'], override?: string) {
  const [text, setText] = useState(() => (override != null ? override : doc ? getDocText(doc) : ''))
  const rafRef = useRef<number | null>(null)

  useEffect(() => {
    if (override != null) {
      setText(override)
      return
    }
    if (!doc) {
      setText('')
      return
    }
    setText(getDocText(doc))
    const ytext = doc.getText('content')
    const onUpdate = () => {
      if (rafRef.current != null) return
      rafRef.current = window.requestAnimationFrame(() => {
        rafRef.current = null
        setText(ytext.toString())
      })
    }
    ytext.observe(onUpdate)
    return () => {
      try {
        ytext.unobserve(onUpdate)
      } catch {}
      if (rafRef.current != null) {
        window.cancelAnimationFrame(rafRef.current)
        rafRef.current = null
      }
    }
  }, [doc, override])

  return text
}

function useElementWidth<T extends HTMLElement>() {
  const ref = useRef<T | null>(null)
  const [width, setWidth] = useState(0)

  useEffect(() => {
    const el = ref.current
    if (!el) return

    const measure = () => {
      try {
        setWidth(el.getBoundingClientRect().width)
      } catch {}
    }

    measure()

    if (typeof window === 'undefined') return

    let ro: ResizeObserver | null = null
    if ('ResizeObserver' in window) {
      ro = new ResizeObserver(() => measure())
      try {
        ro.observe(el)
      } catch {}
    }

    window.addEventListener('resize', measure)
    return () => {
      try {
        ro?.disconnect()
      } catch {}
      window.removeEventListener('resize', measure)
    }
  }, [])

  return [ref, width] as const
}

function useCreatedByPluginId(documentId: string, token?: string | null) {
  const docId = documentId.trim()
  const query = useQuery({
    queryKey: ['document-meta', docId, token ?? null],
    queryFn: async () => fetchDocumentMeta(docId, token ?? undefined),
    staleTime: 60_000,
    enabled: Boolean(docId),
  })

  const pluginId = useMemo(() => {
    const raw = (query.data as any)?.created_by_plugin
    return typeof raw === 'string' && raw.trim() ? raw.trim() : ''
  }, [query.data])

  const docType = useMemo(() => {
    const raw = (query.data as any)?.type
    return typeof raw === 'string' && raw.trim() ? raw.trim() : ''
  }, [query.data])

  return { pluginId, docType, loading: query.isPending, error: query.isError }
}

function useSplitCapablePluginDocs() {
  const [, forceUpdate] = useState(0)
  useEffect(() => {
    ensureSplitCapablePluginDocListener()
    const listener = () => forceUpdate((n) => n + 1)
    splitCapablePluginDocSubscribers.add(listener)
    return () => {
      splitCapablePluginDocSubscribers.delete(listener)
    }
  }, [])
  return splitCapablePluginDocIds
}

function PluginDocumentTileMount({
  match,
  mode,
  variant = 'full',
  className,
}: {
  match: DocumentPluginMatch
  mode: 'primary' | 'secondary'
  variant?: 'full' | 'preview'
  className?: string
}) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const mountNodeKey = useMemo(() => {
    const pluginId = match?.manifest?.id ? String(match.manifest.id) : 'none'
    return `${pluginId}:${match.docId}:${match.route}:${match.token ?? ''}:${mode}:${variant}`
  }, [match, mode, variant])

  useEffect(() => {
    const container = containerRef.current
    if (!container) return
    let dispose: (() => void) | null = null

    ;(async () => {
      try {
        dispose = (await mountResolvedPlugin(
          match,
          container,
          mode,
          variant === 'preview'
            ? {
                tweakHost: (host) => {
                  if (!host || typeof host !== 'object') return
                  if (!host.ui || typeof host.ui !== 'object') host.ui = {}
                  ;(host.ui as any).mountSplitEditor = (target: Element, options?: any) => {
                    if (typeof window === 'undefined') return undefined
                    if (!target) return undefined
                    const el = target as HTMLElement
                    const previewDelegate = options?.preview?.delegate
                    const onDocumentReady = options?.document?.onReady
                    const nextDocId = options?.docId ?? host?.context?.docId ?? null
                    const nextToken = options?.token ?? host?.context?.token ?? null
                    if (typeof nextDocId === 'string' && nextDocId.trim()) {
                      try {
                        window.dispatchEvent(
                          new CustomEvent<{ docId: string }>(PLUGIN_USES_SPLIT_EDITOR_EVENT, {
                            detail: { docId: nextDocId.trim() },
                          }),
                        )
                      } catch {
                        /* noop */
                      }
                    }
                    return mountSplitEditorPreviewStage(el, {
                      docId: nextDocId,
                      token: nextToken,
                      host,
                      previewDelegate,
                      onDocumentReady,
                    })
                  }
                },
              }
            : {},
        )) as any
      } catch (err) {
        console.error('[plugins] failed to mount plugin in tile', err)
      }
    })()
    return () => {
      try {
        dispose?.()
      } catch {}
    }
  }, [match, mode, mountNodeKey])

  return (
    <div className={className ?? 'h-full w-full overflow-auto'}>
      <div key={mountNodeKey} ref={containerRef} className="h-full w-full" />
    </div>
  )
}

function DocumentMosaicBody({
  ctx,
  mosaicState,
  setMosaicState,
  addPreviewTile,
  insertSplitMode,
  isSingleDocShare,
  onCloseAllTiles,
  onActivateDocument,
  onToggleExpandTile,
  expandedTileKeyRef,
}: {
  ctx: DocumentPageRenderContext
  mosaicState: MosaicState
  setMosaicState: Dispatch<SetStateAction<MosaicState>>
  addPreviewTile: (documentId: string) => void
  insertSplitMode: InsertSplitMode
  isSingleDocShare: boolean
  onCloseAllTiles: () => void
  onActivateDocument: (documentId: string, tileKey?: TileKey, mode?: TileMode) => void
  onToggleExpandTile: (tileKey: TileKey) => void
  expandedTileKeyRef: { current: TileKey | null }
}) {
  const setTileMode = useCallback(
    (tileKey: TileKey, mode: TileMode) => {
      setMosaicState((prev) => {
        const safe = sanitizeState(prev, ctx.id)
        const spec = safe.tiles[tileKey]
        if (!spec) return safe
        const nextTiles: Record<TileKey, TileSpec> = {}
        for (const [key, value] of Object.entries(safe.tiles) as Array<[TileKey, TileSpec]>) {
          if (key === tileKey) nextTiles[key] = { ...value, mode, syncGroupId: undefined }
          else nextTiles[key] = value
        }
        return { ...safe, tiles: nextTiles }
      })
    },
    [ctx.id, setMosaicState],
  )

  const splitFromTile = useCallback(
    (tileKey: TileKey, path: MosaicPath) => {
      if (isSingleDocShare) return
      const splitPath = [...path] as MosaicPath
      setMosaicState((prev) => {
        const safe = sanitizeState(prev, ctx.id)
        const spec = safe.tiles[tileKey]
        if (!spec) return safe
        if (spec.mode !== 'editor' && spec.mode !== 'preview') return safe

        const opposite: TileMode = spec.mode === 'editor' ? 'preview' : 'editor'
        const groupId = makeSyncGroupId()
        const newKey = makeTileKey()

        const nextTiles: Record<TileKey, TileSpec> = {
          ...safe.tiles,
          [tileKey]: { ...spec, syncGroupId: groupId },
          [newKey]: { mode: opposite, documentId: spec.documentId, syncGroupId: groupId },
        }

        const wantsEditorLeft = spec.mode === 'preview'
        const replacement: MosaicNode<TileKey> = {
          direction: 'row',
          first: wantsEditorLeft ? newKey : tileKey,
          second: wantsEditorLeft ? tileKey : newKey,
          splitPercentage: 50,
        }
        let nextLayout = replaceNodeAtPath(safe.layout, splitPath, replacement)
        const nextState = sanitizeState({ layout: nextLayout, tiles: nextTiles }, ctx.id)
        if (insertSplitMode === 'auto') {
          const grid = maybeBuildTwoDocSplitGrid(nextState.layout, nextState.tiles)
          if (!grid) return nextState
          return sanitizeState({ ...nextState, layout: grid }, ctx.id)
        }
        if (insertSplitMode === 'row' && nextState.layout) {
          expandedTileKeyRef.current = null
          return sanitizeState({ ...nextState, layout: balanceLayoutSplits(nextState.layout) }, ctx.id)
        }
        return nextState
      })
    },
    [ctx.id, expandedTileKeyRef, insertSplitMode, isSingleDocShare, setMosaicState],
  )

  return (
    <div className="h-full w-full min-h-0 min-w-0">
      <Mosaic<TileKey>
        className="refmd-mosaic-theme"
        value={mosaicState.layout}
        onChange={(next) => {
          expandedTileKeyRef.current = null
          if (!isSingleDocShare && getLeavesSafe(next).length === 0) {
            onCloseAllTiles()
            return
          }
          setMosaicState((prev) => {
            const prevSafe = sanitizeState(prev, ctx.id)
            return sanitizeState({ ...prevSafe, layout: next }, ctx.id)
          })
        }}
        renderTile={(tileId, path) => {
          const spec = mosaicState.tiles[tileId]
          if (!spec) {
            return (
              <MosaicWindow<TileKey> path={path} title="" toolbarControls={[<RemoveButton key="close" />]}>
                <div className="p-4 text-sm text-muted-foreground">Missing tile state.</div>
              </MosaicWindow>
            )
          }

          const docId = spec.documentId
          const isFocusedDoc = docId === ctx.id
          const hasPreviewTileForDoc = Object.entries(mosaicState.tiles).some(
            ([key, tile]) => key !== tileId && tile.documentId === docId && tile.mode === 'preview',
          )
          const hasEditorTileForDoc = Object.entries(mosaicState.tiles).some(
            ([key, tile]) => key !== tileId && tile.documentId === docId && tile.mode === 'editor',
          )

          if (spec.mode === 'editor') {
            return (
              <EditorTile
                tileKey={tileId}
                path={path}
                documentId={docId}
                scrollSyncGroupId={hasPreviewTileForDoc ? (spec.syncGroupId ?? null) : null}
                isFocusedDocument={isFocusedDoc}
                ctx={ctx}
                onSplit={() => splitFromTile(tileId, path)}
                onToggleExpand={() => onToggleExpandTile(tileId)}
                onSwitchToPreview={() => setTileMode(tileId, 'preview')}
                isSingleDocShare={isSingleDocShare}
                onActivate={() => onActivateDocument(docId, tileId, 'editor')}
              />
            )
          }

          if (spec.mode === 'backlinks') {
            return (
              <BacklinksTile
                path={path}
                tileKey={tileId}
                documentId={docId}
                onToggleExpand={() => onToggleExpandTile(tileId)}
                onActivate={() => onActivateDocument(docId, tileId, 'backlinks')}
              />
            )
          }

          return (
            <MosaicPreviewTile
              key={tileId}
              tileKey={tileId}
              path={path}
              documentId={docId}
              syncGroupId={hasEditorTileForDoc ? (spec.syncGroupId ?? null) : null}
              isFocusedDocument={isFocusedDoc}
              activeCtx={ctx}
              addPreviewTile={addPreviewTile}
              onSplit={() => splitFromTile(tileId, path)}
              onToggleExpand={() => onToggleExpandTile(tileId)}
              onSwitchToEditor={() => setTileMode(tileId, 'editor')}
              isSingleDocShare={isSingleDocShare}
              onActivate={() => onActivateDocument(docId, tileId, 'preview')}
            />
          )
        }}
      />
    </div>
  )
}

function MosaicPreviewTile({
  tileKey,
  path,
  documentId,
  syncGroupId,
  isFocusedDocument,
  activeCtx,
  addPreviewTile,
  onSplit,
  onToggleExpand,
  onSwitchToEditor,
  isSingleDocShare,
  onActivate,
}: {
  tileKey: TileKey
  path: MosaicPath
  documentId: string
  syncGroupId?: string | null
  isFocusedDocument: boolean
  activeCtx: DocumentPageRenderContext
  addPreviewTile: (documentId: string) => void
  onSplit: () => void
  onToggleExpand: () => void
  onSwitchToEditor: () => void
  isSingleDocShare: boolean
  onActivate?: () => void
}) {
  const { activeWorkspaceId } = useAuthContext()
  const splitCapablePluginDocs = useSplitCapablePluginDocs()
  const [containerRef, containerWidth] = useElementWidth<HTMLDivElement>()
  const forceFloatingToc = containerWidth > 0 && containerWidth < FORCE_FLOATING_TOC_MAX_WIDTH_PX
  const [externalScrollToLine, setExternalScrollToLine] = useState<number | undefined>(undefined)

  useEffect(() => {
    if (!syncGroupId) {
      setExternalScrollToLine(undefined)
      return
    }
    const handler = (event: Event) => {
      const detail = (event as CustomEvent<MosaicScrollSyncDetail>).detail
      if (!detail || detail.source !== 'editor') return
      if (detail.groupId !== syncGroupId) return
      const line = detail.line
      if (!Number.isFinite(line) || (line as number) < 1) return
      setExternalScrollToLine(line)
    }
    window.addEventListener(MOSAIC_SCROLL_SYNC_EVENT, handler as EventListener)
    return () => window.removeEventListener(MOSAIC_SCROLL_SYNC_EVENT, handler as EventListener)
  }, [syncGroupId])

  const pluginHint = isFocusedDocument ? activeCtx.loaderData?.createdByPlugin ?? null : null
  const pluginLookup = useCreatedByPluginId(documentId, activeCtx.shareToken ?? null)
  const pluginId =
    (typeof pluginHint === 'string' && pluginHint.trim() ? pluginHint.trim() : pluginLookup.pluginId) || ''
  const docType = pluginLookup.docType || ''
  const pluginTileMode = isFocusedDocument ? ('primary' as const) : ('secondary' as const)

  const pluginQuery = useQuery({
    queryKey: [
      'plugin-doc-match',
      documentId,
      activeCtx.shareToken ?? null,
      pluginId || null,
      docType || null,
      pluginTileMode,
      activeWorkspaceId ?? null,
    ],
    queryFn: async () => {
      const token = activeCtx.shareToken ?? null
      const document = docType ? { type: docType } : undefined
      if (pluginId) {
        return resolvePluginForDocumentById(documentId, pluginId, token, { source: pluginTileMode, document, workspaceId: activeWorkspaceId ?? null })
      }
      return resolvePluginForDocument(documentId, token, { source: pluginTileMode, document, workspaceId: activeWorkspaceId ?? null })
    },
    staleTime: 60_000,
    enabled: Boolean(documentId),
  })

  const pluginMatch = (pluginQuery.data ?? null) as DocumentPluginMatch | null
  const shouldMountPlugin = Boolean(pluginMatch)
  const isPluginDocument = Boolean(pluginId || pluginMatch)
  const pluginSupportsSplit = Boolean(isPluginDocument && splitCapablePluginDocs.has(documentId))

  const allowSplitControls = !isSingleDocShare && (!isPluginDocument || pluginSupportsSplit)
  const isMarkdownPreview = !shouldMountPlugin && !isPluginDocument

  const useLiveContent = Boolean(
    isMarkdownPreview &&
      isFocusedDocument &&
      !activeCtx.showOverlay &&
      activeCtx.doc &&
      activeCtx.awareness &&
      !activeCtx.realtimeError,
  )
  const liveContent = useDocText(useLiveContent ? activeCtx.doc : null, useLiveContent ? activeCtx.previewOverride : undefined)
  const canToggleTasks = Boolean(useLiveContent && activeCtx.doc && !activeCtx.isReadOnly && !activeCtx.previewOverride)
  const shareToken = activeCtx.shareToken

  const previewSession = useCollaborativeDocument(documentId, shareToken, {
    enabled: isMarkdownPreview && !useLiveContent,
    contributeToRealtimeContext: false,
    useUrlShareTokenFallback: false,
    validateShareToken: false,
    loadMeta: false,
    trackAwareness: false,
    disablePersistence: true,
  })
  const realtimeContent = useDocText(!useLiveContent ? previewSession.doc : null, undefined)

  const contentQuery = useQuery({
    queryKey: ['document-content', documentId],
    queryFn: async () => fetchDocumentContent(documentId),
    staleTime: 30 * 1000,
    enabled: isMarkdownPreview && !useLiveContent && !shareToken,
  })

  const fetchedContent = useMemo(() => {
    const data = contentQuery.data as any
    if (data && typeof data === 'object' && 'content' in data) {
      const raw = (data as any).content
      return typeof raw === 'string' ? raw : ''
    }
    return ''
  }, [contentQuery.data])

  const resolvedContent = useMemo(() => {
    if (useLiveContent) return liveContent
    if (realtimeContent.length > 0) return realtimeContent
    if (fetchedContent.length > 0) return fetchedContent
    // Both sources are currently empty. Prefer REST for non-share (it represents persisted content),
    // otherwise fall back to realtime content.
    return shareToken ? realtimeContent : fetchedContent
  }, [
    fetchedContent,
    liveContent,
    realtimeContent,
    shareToken,
    useLiveContent,
  ])

  const showError = useMemo(() => {
    if (useLiveContent) return false
    if (previewSession.error && !fetchedContent) return true
    if (!shareToken && contentQuery.isError && !previewSession.doc) return true
    return false
  }, [contentQuery.isError, fetchedContent, previewSession.doc, previewSession.error, shareToken, useLiveContent])

  const showLoading = useMemo(() => {
    if (useLiveContent) return false
    if (showError) return false
    if (shareToken) return previewSession.status === 'connecting' && !previewSession.error
    return contentQuery.isLoading && !previewSession.error
  }, [
    contentQuery.isLoading,
    contentQuery.isError,
    previewSession.status,
    previewSession.error,
    shareToken,
    showError,
    useLiveContent,
  ])

  const toolbarControls = useMemo(() => {
    if (isSingleDocShare) return []
    return [
      ...(allowSplitControls
        ? [
            <button
              key="split"
              type="button"
              className="mosaic-default-control"
              onClick={onSplit}
              aria-label="Split: add editor tile"
            >
              <Columns2 className="h-4 w-4" aria-hidden="true" />
            </button>,
          ]
        : []),
      ...(allowSplitControls
        ? [
            <button
              key="mode"
              type="button"
              className="mosaic-default-control"
              onClick={onSwitchToEditor}
              aria-label="Open editor tile"
            >
              <FileCode className="h-4 w-4" aria-hidden="true" />
            </button>,
          ]
        : []),
      <Separator key="sep" />,
      <button
        key="expand"
        type="button"
        className="mosaic-default-control expand-button"
        onClick={onToggleExpand}
        aria-label="Expand tile"
      />,
      <RemoveButton key="close" />,
      tileControlsToggle(),
    ]
  }, [allowSplitControls, isSingleDocShare, onSplit, onSwitchToEditor, onToggleExpand])

  return (
    <MosaicWindow<TileKey>
      path={path}
      title=""
      toolbarControls={toolbarControls}
    >
      <div
        ref={containerRef}
        className="h-full min-h-0"
        tabIndex={-1}
        data-refmd-tile-key={tileKey}
        onPointerDownCapture={onActivate}
        onFocusCapture={onActivate}
      >
        {shouldMountPlugin && pluginMatch ? (
          <PluginDocumentTileMount
            match={pluginMatch}
            mode={pluginTileMode}
            variant={isPluginDocument && !pluginSupportsSplit ? 'full' : 'preview'}
            className="h-full w-full overflow-auto"
          />
        ) : isPluginDocument ? (
          <div className="p-4 text-sm text-muted-foreground">
            Plugin is not available for this document.
          </div>
        ) : (
          <div className="refmd-mosaic-panel">
            {showError ? (
              <div className="p-4 text-sm text-destructive">Failed to load preview.</div>
            ) : showLoading ? (
              <div className="flex h-full items-center justify-center text-muted-foreground">
                <Loader2 className="h-5 w-5 animate-spin mr-2" />
                Loading preview…
              </div>
            ) : (
              <div className="h-full min-h-0 px-4 pb-6 pt-6 sm:px-6 sm:pb-8 sm:pt-8">
                <PreviewPane
                  content={resolvedContent}
                  viewMode="preview"
                  documentIdOverride={documentId}
                  forceFloatingToc={forceFloatingToc}
                  scrollToLine={syncGroupId ? externalScrollToLine : undefined}
                  onScrollAnchorLine={
                    syncGroupId
                      ? (line) => dispatchMosaicScrollSync({ groupId: syncGroupId, source: 'preview', line })
                      : undefined
                  }
                  onScroll={
                    syncGroupId
                      ? (_top, pct) => {
                          if (pct >= 0.999) {
                            dispatchMosaicScrollSync({ groupId: syncGroupId, source: 'preview', line: Number.MAX_SAFE_INTEGER })
                          }
                        }
                      : undefined
                  }
                  onNavigate={(targetId) => {
                    const target = (targetId || '').trim()
                    if (!target) return
                    addPreviewTile(target)
                  }}
                  onToggleTask={
                    canToggleTasks
                      ? (lineNumber, checked) => {
                          if (!activeCtx.doc) return
                          toggleTaskInDoc(activeCtx.doc, lineNumber, checked)
                        }
                      : undefined
                  }
                  taskToggleDisabled={!canToggleTasks}
                />
              </div>
            )}
          </div>
        )}
      </div>
    </MosaicWindow>
  )
}

function BacklinksTile({
  path,
  tileKey,
  documentId,
  onToggleExpand,
  onActivate,
}: {
  path: MosaicPath
  tileKey: TileKey
  documentId: string
  onToggleExpand: () => void
  onActivate?: () => void
}) {
  return (
    <MosaicWindow<TileKey>
      path={path}
      title=""
      toolbarControls={[
        <Separator key="sep" />,
        <button
          key="expand"
          type="button"
          className="mosaic-default-control expand-button"
          onClick={onToggleExpand}
          aria-label="Expand tile"
        />,
        <RemoveButton key="close" />,
        tileControlsToggle(),
      ]}
    >
      <div
        className="h-full min-h-0"
        tabIndex={-1}
        data-refmd-tile-key={tileKey}
        onPointerDownCapture={onActivate}
        onFocusCapture={onActivate}
      >
        <div className="refmd-mosaic-panel">
          <BacklinksPanel documentId={documentId} className="h-full" />
        </div>
      </div>
    </MosaicWindow>
  )
}

function useEditorIdentity() {
  const { user } = useAuthContext()
  const anonIdentity = useMemo(() => {
    if (user) return null
    try {
      const keyName = 'refmd_anon_identity'
      const saved = localStorage.getItem(keyName)
      if (saved) return JSON.parse(saved) as { id: string; name: string }
      const rnd = Math.random().toString(36).slice(-4)
      const ident = { id: `guest:${rnd}`, name: `Guest-${rnd}` }
      localStorage.setItem(keyName, JSON.stringify(ident))
      return ident
    } catch {
      const rnd = Math.random().toString(36).slice(-4)
      return { id: `guest:${rnd}`, name: `Guest-${rnd}` }
    }
  }, [user])
  return {
    userId: (user as any)?.id || anonIdentity?.id,
    userName: (user as any)?.name || anonIdentity?.name,
  }
}

function EditorTile({
  tileKey,
  path,
  documentId,
  scrollSyncGroupId,
  isFocusedDocument,
  ctx,
  onSplit,
  onToggleExpand,
  onSwitchToPreview,
  isSingleDocShare,
  onActivate,
}: {
  tileKey: TileKey
  path: MosaicPath
  documentId: string
  scrollSyncGroupId?: string | null
  isFocusedDocument: boolean
  ctx: DocumentPageRenderContext
  onSplit: () => void
  onToggleExpand: () => void
  onSwitchToPreview: () => void
  isSingleDocShare: boolean
  onActivate?: () => void
}) {
  const pluginLookup = useCreatedByPluginId(documentId, ctx.shareToken ?? null)
  const splitCapablePluginDocs = useSplitCapablePluginDocs()
  const isPluginDocument = Boolean(pluginLookup.pluginId)
  const isNonSplitPluginDoc = Boolean(isPluginDocument && !splitCapablePluginDocs.has(documentId))

  useEffect(() => {
    if (!isNonSplitPluginDoc) return
    dispatchMosaicSetViewMode(documentId, 'preview')
  }, [documentId, isNonSplitPluginDoc])

  return (
    <MosaicWindow<TileKey>
      path={path}
      title=""
      toolbarControls={
        isSingleDocShare
          ? []
          : isNonSplitPluginDoc
            ? [
                <Separator key="sep" />,
                <button
                  key="expand"
                  type="button"
                  className="mosaic-default-control expand-button"
                  onClick={onToggleExpand}
                  aria-label="Expand tile"
                />,
                <RemoveButton key="close" />,
                tileControlsToggle(),
              ]
            : [
              <button
                key="split"
                type="button"
                className="mosaic-default-control"
                onClick={onSplit}
                aria-label="Split: add preview tile"
              >
                <Columns2 className="h-4 w-4" aria-hidden="true" />
              </button>,
              <button
                key="mode"
                type="button"
                className="mosaic-default-control"
                onClick={onSwitchToPreview}
                aria-label="Open preview tile"
              >
                <Eye className="h-4 w-4" aria-hidden="true" />
              </button>,
              <Separator key="sep" />,
              <button
                key="expand"
                type="button"
                className="mosaic-default-control expand-button"
                onClick={onToggleExpand}
                aria-label="Expand tile"
              />,
              <RemoveButton key="close" />,
              tileControlsToggle(),
            ]
      }
      >
      <div
        className="h-full w-full min-h-0 min-w-0"
        tabIndex={-1}
        data-refmd-tile-key={tileKey}
        onPointerDownCapture={onActivate}
        onFocusCapture={onActivate}
      >
        <div className="refmd-mosaic-panel">
          <MarkdownEditorTileBody
            tileKey={tileKey}
            documentId={documentId}
            scrollSyncGroupId={scrollSyncGroupId}
            isFocusedDocument={isFocusedDocument}
            ctx={ctx}
          />
        </div>
      </div>
    </MosaicWindow>
  )
}

function MarkdownEditorTileBody({
  tileKey,
  documentId,
  scrollSyncGroupId,
  isFocusedDocument,
  ctx,
}: {
  tileKey: TileKey
  documentId: string
  scrollSyncGroupId?: string | null
  isFocusedDocument: boolean
  ctx: DocumentPageRenderContext
}) {
  const identity = useEditorIdentity()
  const localSession = useCollaborativeDocument(documentId, ctx.shareToken, {
    contributeToRealtimeContext: false,
    useUrlShareTokenFallback: false,
  })
  const canUseFocusedProps = isFocusedDocument && Boolean(ctx.markdownEditorProps)

  if (ctx.showOverlay && canUseFocusedProps) {
    return (
      <div className="relative flex h-full flex-1 min-h-0 flex-col">
        <EditorOverlay label={ctx.overlayLabel} />
      </div>
    )
  }

  if (canUseFocusedProps) {
    return (
      <MarkdownEditor
        key={`${ctx.id}:${tileKey}`}
        {...ctx.markdownEditorProps!}
        forcedView="editor"
        embedded
        scrollSyncGroupId={scrollSyncGroupId ?? null}
      />
    )
  }

  if (localSession.doc && localSession.awareness) {
    return (
      <MarkdownEditor
        key={`${documentId}:${tileKey}`}
        doc={localSession.doc}
        awareness={localSession.awareness}
        connected={localSession.status === 'connected'}
        initialView="editor"
        forcedView="editor"
        embedded
        scrollSyncGroupId={scrollSyncGroupId ?? null}
        userId={identity.userId}
        userName={identity.userName}
        documentId={documentId}
        readOnly={localSession.isReadOnly}
      />
    )
  }

  return (
    <div className="flex h-full items-center justify-center text-muted-foreground">
      <Loader2 className="h-5 w-5 animate-spin mr-2" />
      Loading editor…
    </div>
  )
}
