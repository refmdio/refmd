import type { GitPullConflictItem, GitPullResolution } from '@/shared/api'

export const GIT_CONFLICT_EVENT = 'refmd:git-conflicts-updated'

let currentConflicts: GitPullConflictItem[] = []
let currentResolutions: GitPullResolution[] = []
let currentSessionId: string | null = null

const STORAGE_CONFLICTS_KEY = 'refmd:git-conflicts'
const STORAGE_RESOLUTIONS_KEY = 'refmd:git-conflict-resolutions'
const STORAGE_SESSION_KEY = 'refmd:git-conflict-session'

const loadFromStorage = <T>(key: string): T[] => {
  if (typeof window === 'undefined') return []
  try {
    const raw = window.localStorage.getItem(key)
    if (!raw) return []
    const parsed = JSON.parse(raw)
    return Array.isArray(parsed) ? (parsed as T[]) : []
  } catch {
    return []
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

// Hydrate initial state from storage when on client
if (typeof window !== 'undefined') {
  currentConflicts = loadFromStorage<GitPullConflictItem>(STORAGE_CONFLICTS_KEY)
  currentResolutions = loadFromStorage<GitPullResolution>(STORAGE_RESOLUTIONS_KEY)
  const sid = loadFromStorage<string>(STORAGE_SESSION_KEY)
  currentSessionId = sid && sid.length ? sid[0] : null
}

export const readConflicts = (): GitPullConflictItem[] => currentConflicts.slice()
export const readResolutions = (): GitPullResolution[] => currentResolutions.slice()
export const readSessionId = (): string | null => currentSessionId

export const setConflicts = (conflicts: GitPullConflictItem[] | null | undefined) => {
  currentConflicts = Array.isArray(conflicts) ? conflicts.slice() : []
  persistStorage(STORAGE_CONFLICTS_KEY, currentConflicts)
  // Clear resolutions if conflicts are cleared
  if (!currentConflicts.length) {
    setResolutions([])
  }
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(GIT_CONFLICT_EVENT, { detail: currentConflicts }))
  }
}

export const setResolutions = (resolutions: GitPullResolution[] | null | undefined) => {
  currentResolutions = Array.isArray(resolutions) ? resolutions.slice() : []
  persistStorage(STORAGE_RESOLUTIONS_KEY, currentResolutions)
}

export const clearResolutions = () => setResolutions([])

export const setSessionId = (sessionId: string | null) => {
  currentSessionId = sessionId || null
  persistStorage(STORAGE_SESSION_KEY, sessionId ? [sessionId] : [])
}

export const clearSession = () => {
  setSessionId(null)
  clearAllConflicts()
}

export const clearAllConflicts = () => {
  setConflicts([])
  setResolutions([])
  setSessionId(null)
}

export const subscribeConflicts = (handler: (items: GitPullConflictItem[]) => void) => {
  if (typeof window === 'undefined') return () => {}
  const listener = (event: Event) => {
    const detail = (event as CustomEvent<GitPullConflictItem[]>).detail || currentConflicts
    handler(detail)
  }
  window.addEventListener(GIT_CONFLICT_EVENT, listener)
  return () => window.removeEventListener(GIT_CONFLICT_EVENT, listener)
}
