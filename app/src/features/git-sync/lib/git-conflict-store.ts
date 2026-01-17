/**
 * Git Conflict Store for E2EE Git Sync
 *
 * Client-side store for tracking git merge conflicts.
 * No server-side sessions - everything is client-side.
 */

import { getClientWorkspaceId } from '@/shared/api/client.config'

import type { ConflictItem } from './pull'

export type { ConflictItem }

export const GIT_CONFLICT_EVENT = 'refmd:git-conflicts-updated'

let currentConflicts: ConflictItem[] = []
let currentWorkspaceId: string | null = null

const STORAGE_CONFLICTS_KEY = 'refmd:git-conflicts'

type StoredArray<T> = { items: T[]; found: boolean }

const normalizeWorkspaceId = (value: string | null | undefined) => {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : null
}

const scopedKey = (base: string, workspaceId: string | null) => (workspaceId ? `${base}:${workspaceId}` : base)

const refreshWorkspaceState = () => {
  const workspaceId = normalizeWorkspaceId(getClientWorkspaceId())
  currentWorkspaceId = workspaceId
  currentConflicts = loadScopedArray<ConflictItem>(STORAGE_CONFLICTS_KEY, currentWorkspaceId).items
}

const loadFromStorage = <T>(key: string): StoredArray<T> => {
  if (typeof window === 'undefined') return { items: [], found: false }
  try {
    const raw = window.localStorage.getItem(key)
    if (raw === null) return { items: [], found: false }
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? { items: parsed as T[], found: true } : { items: [], found: true }
  } catch {
    return { items: [], found: false }
  }
}

const persistStorage = (key: string, value: unknown) => {
  if (typeof window === 'undefined') return
  try {
    window.localStorage.setItem(key, JSON.stringify(value))
  } catch {
    /* ignore */
  }
}

const loadScopedArray = <T>(baseKey: string, workspaceId: string | null): StoredArray<T> => {
  const scoped = scopedKey(baseKey, workspaceId)
  const scopedValue = loadFromStorage<T>(scoped)
  if (scopedValue.found) return scopedValue

  // Do not leak legacy (unscoped) values into another workspace
  if (workspaceId) return { items: [], found: false }

  return loadFromStorage<T>(baseKey)
}

// Hydrate initial state from storage when on client
if (typeof window !== 'undefined') {
  refreshWorkspaceState()
}

export const readConflicts = (): ConflictItem[] => {
  refreshWorkspaceState()
  return currentConflicts.slice()
}

export const setConflicts = (conflicts: ConflictItem[] | null | undefined) => {
  refreshWorkspaceState()
  currentConflicts = Array.isArray(conflicts) ? conflicts.slice() : []
  persistStorage(scopedKey(STORAGE_CONFLICTS_KEY, currentWorkspaceId), currentConflicts)
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(GIT_CONFLICT_EVENT, { detail: currentConflicts }))
  }
}

export const clearAllConflicts = () => {
  setConflicts([])
}

export const subscribeConflicts = (handler: (items: ConflictItem[]) => void) => {
  if (typeof window === 'undefined') return () => {}
  refreshWorkspaceState()
  const listener = (event: Event) => {
    const detail = (event as CustomEvent<ConflictItem[]>).detail || currentConflicts
    handler(detail)
  }
  const storageListener = () => {
    refreshWorkspaceState()
    handler(readConflicts())
  }
  window.addEventListener(GIT_CONFLICT_EVENT, listener)
  window.addEventListener('storage', storageListener)
  return () => {
    window.removeEventListener(GIT_CONFLICT_EVENT, listener)
    window.removeEventListener('storage', storageListener)
  }
}
