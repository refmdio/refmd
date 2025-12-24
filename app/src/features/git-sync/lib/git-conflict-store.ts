import type { GitPullConflictItem, GitPullResolution } from '@/shared/api'
import { getClientWorkspaceId } from '@/shared/api/client.config'

export const GIT_CONFLICT_EVENT = 'refmd:git-conflicts-updated'
export const GIT_SESSION_EVENT = 'refmd:git-session-updated'

let currentConflicts: GitPullConflictItem[] = []
let currentResolutions: GitPullResolution[] = []
let currentSessionId: string | null = null
let currentWorkspaceId: string | null = null

const STORAGE_CONFLICTS_KEY = 'refmd:git-conflicts'
const STORAGE_RESOLUTIONS_KEY = 'refmd:git-conflict-resolutions'
const STORAGE_SESSION_KEY = 'refmd:git-conflict-session'

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
  currentConflicts = loadScopedArray<GitPullConflictItem>(STORAGE_CONFLICTS_KEY, currentWorkspaceId).items
  currentResolutions = loadScopedArray<GitPullResolution>(STORAGE_RESOLUTIONS_KEY, currentWorkspaceId).items
  const sid = loadScopedArray<string>(STORAGE_SESSION_KEY, currentWorkspaceId)
  currentSessionId = sid.items.length ? sid.items[0] : null
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

  // Do not leak legacy (unscoped) values into another workspace; only use legacy when no workspace is selected.
  if (workspaceId) return { items: [], found: false }

  return loadFromStorage<T>(baseKey)
}

// Hydrate initial state from storage when on client
if (typeof window !== 'undefined') {
  refreshWorkspaceState()
}

export const readConflicts = (): GitPullConflictItem[] => {
  refreshWorkspaceState()
  return currentConflicts.slice()
}
export const readResolutions = (): GitPullResolution[] => {
  refreshWorkspaceState()
  return currentResolutions.slice()
}
export const readSessionId = (): string | null => {
  refreshWorkspaceState()
  return currentSessionId
}

export const setConflicts = (conflicts: GitPullConflictItem[] | null | undefined) => {
  refreshWorkspaceState()
  currentConflicts = Array.isArray(conflicts) ? conflicts.slice() : []
  persistStorage(scopedKey(STORAGE_CONFLICTS_KEY, currentWorkspaceId), currentConflicts)
  // Clear resolutions if conflicts are cleared
  if (!currentConflicts.length) {
    setResolutions([])
  }
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(GIT_CONFLICT_EVENT, { detail: currentConflicts }))
  }
}

export const setResolutions = (resolutions: GitPullResolution[] | null | undefined) => {
  refreshWorkspaceState()
  currentResolutions = Array.isArray(resolutions) ? resolutions.slice() : []
  persistStorage(scopedKey(STORAGE_RESOLUTIONS_KEY, currentWorkspaceId), currentResolutions)
}

export const clearResolutions = () => setResolutions([])

export const setSessionId = (sessionId: string | null) => {
  refreshWorkspaceState()
  currentSessionId = sessionId || null
  persistStorage(scopedKey(STORAGE_SESSION_KEY, currentWorkspaceId), sessionId ? [sessionId] : [])
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(GIT_SESSION_EVENT, { detail: currentSessionId }))
  }
}

export const clearSession = () => {
  clearAllConflicts()
}

export const clearAllConflicts = () => {
  setConflicts([])
  setSessionId(null)
}

export const subscribeConflicts = (handler: (items: GitPullConflictItem[]) => void) => {
  if (typeof window === 'undefined') return () => {}
  refreshWorkspaceState()
  const listener = (event: Event) => {
    const detail = (event as CustomEvent<GitPullConflictItem[]>).detail || currentConflicts
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

export const subscribeSessionId = (handler: (sessionId: string | null) => void) => {
  if (typeof window === 'undefined') return () => {}
  refreshWorkspaceState()
  const storageListener = (event: StorageEvent) => {
    refreshWorkspaceState()
    if (event.key && event.key !== scopedKey(STORAGE_SESSION_KEY, currentWorkspaceId)) return
    handler(readSessionId())
  }
  const eventListener = (event: Event) => {
    const detail = (event as CustomEvent<string | null>).detail
    handler(detail ?? readSessionId())
  }
  window.addEventListener('storage', storageListener)
  window.addEventListener(GIT_SESSION_EVENT, eventListener)
  return () => {
    window.removeEventListener('storage', storageListener)
    window.removeEventListener(GIT_SESSION_EVENT, eventListener)
  }
}
