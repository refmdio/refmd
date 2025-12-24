import { ApiError, type GitPullConflictItem, type GitPullResolution, type GitPullSessionResponse } from '@/shared/api'

import { finalizePullSession, resolvePullSession, startPullSession } from '@/entities/git'

import { clearAllConflicts, clearSession, clearResolutions, readConflicts, readResolutions, readSessionId, setConflicts, setSessionId } from './git-conflict-store'

export type PullSessionResult = {
  status: 'merged' | 'conflicts' | 'stale' | 'error'
  conflicts: GitPullConflictItem[]
  sessionId?: string | null
  message?: string | null
  emptyConflictWarning?: boolean
}

const extractConflicts = (value: unknown): GitPullConflictItem[] => {
  const toArr = (v: unknown): GitPullConflictItem[] => (Array.isArray(v) ? (v as GitPullConflictItem[]) : [])
  if (!value) return []
  if (Array.isArray(value)) return toArr(value)
  if (typeof value === 'object') {
    const maybe = (value as any)?.conflicts
    if (Array.isArray(maybe)) return toArr(maybe)
  }
  return []
}

export const performPullSession = async (
  resolutions?: GitPullResolution[],
  options?: { sessionId?: string | null; autoFinalize?: boolean },
): Promise<PullSessionResult> => {
  const sessionIdFromStore = readSessionId()
  const sessionId: string | undefined = (options?.sessionId ?? sessionIdFromStore) || undefined
  let requestResolutions = resolutions ?? readResolutions()

  if (!sessionId) {
    requestResolutions = resolutions ?? []
    clearResolutions()
  }
  try {
    const res: GitPullSessionResponse = sessionId
      ? await resolvePullSession({ id: sessionId, requestBody: { resolutions: requestResolutions } })
      : await startPullSession()

    if ((res as any)?.status === 'stale') {
      clearAllConflicts()
      return {
        status: 'stale',
        conflicts: [],
        sessionId: undefined,
        message: res.message,
      }
    }

    const conflicts = res.conflicts ?? []
    const sid: string | undefined = res.session_id || sessionId || undefined
    const sessionChanged = Boolean(sid && sid !== sessionIdFromStore)
    if (conflicts.length > 0) {
      setSessionId(sid ?? null)
      if (sessionChanged) {
        clearResolutions()
      }
      setConflicts(conflicts)
      return {
        status: 'conflicts',
        conflicts,
        sessionId: sid,
        message: res.message,
      }
    }

    const finalizeIfNeeded = async (): Promise<PullSessionResult> => {
      if (options?.autoFinalize === false) {
        // Caller will explicitly finalize; keep session available to them.
        return {
          status: 'merged',
          conflicts: [],
          sessionId: sid,
          message: res.message,
        }
      }
      if (!sid) {
        clearSession()
        return {
          status: 'merged',
          conflicts: [],
          sessionId: undefined,
          message: res.message,
        }
      }

      try {
        const finalizeRes = await finalizePullSession({ id: sid })
        const msg = finalizeRes.message || res.message || 'Finalize failed'
        if (typeof msg === 'string' && msg.toLowerCase().includes('stale')) {
          clearAllConflicts()
          return { status: 'stale', conflicts: [], sessionId: undefined, message: msg }
        }

        if (finalizeRes.success) {
          clearSession()
          return {
            status: 'merged',
            conflicts: [],
            sessionId: undefined,
            message: msg,
          }
        }

        const remaining = finalizeRes.conflicts ?? []
        if (remaining.length > 0) {
          setSessionId(sid ?? null)
          setConflicts(remaining)
          return {
            status: 'conflicts',
            conflicts: remaining,
            sessionId: sid,
            message: finalizeRes.message || res.message,
          }
        }

        return {
          status: 'error',
          conflicts: readConflicts(),
          sessionId: sid,
          message: msg,
        }
      } catch (err: any) {
        // Surface finalize errors so caller can prompt a retry.
        const detail = err?.body?.message || err?.message || 'Finalize failed'
        return {
          status: 'error',
          conflicts: readConflicts(),
          sessionId: sid,
          message: detail,
        }
      }
    }

    return await finalizeIfNeeded()
  } catch (e: any) {
    const bodyConflicts = extractConflicts(e?.body)
    const statusField = (e as any)?.body?.status
    const msg = (e as any)?.body?.message || e?.message || `${e}`

    if (statusField === 'stale' || (typeof msg === 'string' && msg.toLowerCase().includes('stale'))) {
      clearAllConflicts()
      return { status: 'stale', conflicts: [], sessionId: undefined, message: msg }
    }

    if (e instanceof ApiError && e.status === 409) {
      if (bodyConflicts.length > 0) {
        const sid = (e as any)?.body?.session_id || sessionId || readSessionId() || undefined
        setSessionId(sid ?? null)
        if (!sessionId || sid !== sessionIdFromStore) {
          clearResolutions()
        }
        setConflicts(bodyConflicts)
        return { status: 'conflicts', conflicts: bodyConflicts, sessionId: sid, message: msg }
      }
      clearResolutions()
      const fallback = readConflicts()
      setConflicts(fallback)
      return {
        status: 'conflicts',
        conflicts: fallback,
        sessionId: readSessionId() || undefined,
        message: msg || 'Conflicts reported but none returned.',
        emptyConflictWarning: true,
      }
    }

    return {
      status: 'error',
      conflicts: readConflicts(),
      sessionId: readSessionId() || undefined,
      message: msg,
    }
  }
}
