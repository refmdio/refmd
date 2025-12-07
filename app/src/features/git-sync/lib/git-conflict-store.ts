import type { GitPullConflictItem } from '@/shared/api'

export const GIT_CONFLICT_EVENT = 'refmd:git-conflicts-updated'

let currentConflicts: GitPullConflictItem[] = []

export const readConflicts = (): GitPullConflictItem[] => currentConflicts.slice()

export const setConflicts = (conflicts: GitPullConflictItem[] | null | undefined) => {
  currentConflicts = Array.isArray(conflicts) ? conflicts.slice() : []
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(GIT_CONFLICT_EVENT, { detail: currentConflicts }))
  }
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
