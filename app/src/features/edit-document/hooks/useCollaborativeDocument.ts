import { useQueryClient } from '@tanstack/react-query'
import * as React from 'react'
import { toast } from 'sonner'

import { useRealtime } from '@/shared/contexts/realtime-context'
import { createYjsConnection, destroyYjsConnection } from '@/shared/lib/yjsConnection'
import type { YjsConnection } from '@/shared/lib/yjsConnection'

import { fetchDocumentMeta, updateDocumentContent } from '@/entities/document'
import { validateShareToken } from '@/entities/share'

import { useAuthContext } from '@/features/auth'


export type RealtimeStatus = 'connecting' | 'connected' | 'disconnected'

export type UseCollaborativeDocumentOptions = {
  enabled?: boolean
  contributeToRealtimeContext?: boolean
  useUrlShareTokenFallback?: boolean
  validateShareToken?: boolean
  loadMeta?: boolean
  trackAwareness?: boolean
  disablePersistence?: boolean
}

type ConnectionCacheEntry = {
  refs: number
  connection: YjsConnection | null
  promise: Promise<YjsConnection> | null
}

type PendingContentEntry = {
  content: string
  revision: number
}

type DocumentContentFlushRegistration = {
  token: string | null
}

const connectionCache = new Map<string, ConnectionCacheEntry>()
const invalidShareTokenToastShown = new Set<string>()
const pendingContentByDocumentId = new Map<string, PendingContentEntry>()
const pendingContentFlushByDocumentId = new Map<string, Promise<void>>()
const pendingContentFlushTimersByDocumentId = new Map<string, number>()
const documentContentFlushRegistrations = new Map<string, DocumentContentFlushRegistration>()
let pendingContentRevision = 0
const SHARE_TOKEN_VALIDATION_STALE_MS = 5 * 60 * 1000
const DOCUMENT_META_STALE_MS = 60 * 1000
const DOCUMENT_CONTENT_FLUSH_DELAY_MS = 1200

export function markDocumentContentDirty(documentId: string, content: string) {
  if (!documentId) return
  if (!documentContentFlushRegistrations.has(documentId)) return
  pendingContentByDocumentId.set(documentId, {
    content,
    revision: ++pendingContentRevision,
  })
  schedulePendingDocumentContentFlush(documentId)
}

function registerDocumentContentFlush(documentId: string, token: string | null) {
  documentContentFlushRegistrations.set(documentId, { token })
  return () => {
    const current = documentContentFlushRegistrations.get(documentId)
    if (current?.token === token) {
      documentContentFlushRegistrations.delete(documentId)
    }
    if (!pendingContentByDocumentId.has(documentId)) {
      clearPendingDocumentContentFlushTimer(documentId)
    }
  }
}

function clearPendingDocumentContentFlushTimer(documentId: string) {
  const timer = pendingContentFlushTimersByDocumentId.get(documentId)
  if (timer != null && typeof window !== 'undefined') {
    window.clearTimeout(timer)
  }
  pendingContentFlushTimersByDocumentId.delete(documentId)
}

function schedulePendingDocumentContentFlush(documentId: string) {
  if (typeof window === 'undefined') return
  if (!documentContentFlushRegistrations.has(documentId)) return
  clearPendingDocumentContentFlushTimer(documentId)
  const timer = window.setTimeout(() => {
    pendingContentFlushTimersByDocumentId.delete(documentId)
    void flushPendingDocumentContent(documentId)
  }, DOCUMENT_CONTENT_FLUSH_DELAY_MS)
  pendingContentFlushTimersByDocumentId.set(documentId, timer)
}

function flushPendingDocumentContent(documentId: string, tokenOverride?: string | null): Promise<void> {
  const existing = pendingContentFlushByDocumentId.get(documentId)
  if (existing) return existing

  clearPendingDocumentContentFlushTimer(documentId)

  let flushPromise: Promise<void>
  flushPromise = (async () => {
    for (;;) {
      const entry = pendingContentByDocumentId.get(documentId)
      if (!entry) return

      const token = tokenOverride ?? documentContentFlushRegistrations.get(documentId)?.token ?? null
      try {
        await updateDocumentContent({ id: documentId, content: entry.content, token })
      } catch (error) {
        console.warn('[collaboration] failed to persist pending document content', documentId, error)
        schedulePendingDocumentContentFlush(documentId)
        return
      }

      const current = pendingContentByDocumentId.get(documentId)
      if (!current || current.revision === entry.revision) {
        pendingContentByDocumentId.delete(documentId)
        return
      }
    }
  })().finally(() => {
    if (pendingContentFlushByDocumentId.get(documentId) === flushPromise) {
      pendingContentFlushByDocumentId.delete(documentId)
    }
  })

  pendingContentFlushByDocumentId.set(documentId, flushPromise)
  return flushPromise
}

function buildCollaborativeDocumentConnectionCacheKey(args: {
  documentId: string
  token: string | undefined
  disablePersistence: boolean
  workspaceId: string | null | undefined
}) {
  const workspaceScope = typeof args.workspaceId === 'string' ? args.workspaceId.trim() : ''
  return `${args.documentId}::${args.token ?? ''}::ws:${workspaceScope}::p:${args.disablePersistence ? '0' : '1'}`
}

function buildCacheKey(
  documentId: string,
  token: string | undefined,
  disablePersistence: boolean,
  workspaceId: string | null | undefined,
) {
  return buildCollaborativeDocumentConnectionCacheKey({ documentId, token, disablePersistence, workspaceId })
}

async function acquireConnection(
  documentId: string,
  token: string | undefined,
  disablePersistence: boolean,
  workspaceId: string | null | undefined,
) {
  if (!disablePersistence) {
    await flushPendingDocumentContent(documentId, token ?? null)
  }

  const cacheKey = buildCacheKey(documentId, token, disablePersistence, workspaceId)
  const existing = connectionCache.get(cacheKey)
  if (existing) {
    existing.refs += 1
    if (existing.connection) return { cacheKey, connection: existing.connection }
    if (existing.promise) return { cacheKey, connection: await existing.promise }
  }

  const entry: ConnectionCacheEntry = { refs: 1, connection: null, promise: null }
  entry.promise = createYjsConnection(documentId, {
    token: token ?? null,
    connect: false,
    disablePersistence,
  })
  connectionCache.set(cacheKey, entry)
  try {
    const connection = await entry.promise
    entry.connection = connection
    entry.promise = null
    return { cacheKey, connection }
  } catch (error) {
    connectionCache.delete(cacheKey)
    throw error
  }
}

function releaseConnection(cacheKey: string) {
  const entry = connectionCache.get(cacheKey)
  if (!entry) return
  entry.refs -= 1
  if (entry.refs > 0) return
  connectionCache.delete(cacheKey)
  destroyYjsConnection(entry.connection)
}

export function useCollaborativeDocument(
  id: string,
  shareToken?: string,
  options: UseCollaborativeDocumentOptions = {},
) {
  const queryClient = useQueryClient()
  const { permissions, loading: authLoading, activeWorkspaceId } = useAuthContext()
  const enabled = options.enabled ?? true
  const contributeToRealtimeContext = options.contributeToRealtimeContext ?? true
  const useUrlShareTokenFallback = options.useUrlShareTokenFallback ?? true
  const shouldValidateShareToken = options.validateShareToken ?? true
  const shouldLoadMeta = options.loadMeta ?? true
  const trackAwareness = options.trackAwareness ?? true
  const disablePersistence = options.disablePersistence ?? !contributeToRealtimeContext
  const {
    setDocumentId: setRealtimeDocumentId,
    setDocumentTitle,
    setDocumentStatus,
    setDocumentBadge,
    setDocumentActions,
    setDocumentPath,
    setDocumentPluginId,
    setShowEditorFeatures,
    setConnected,
    setUserCount,
    setOnlineUsers,
    userCount,
  } = useRealtime()
  const [status, setStatus] = React.useState<RealtimeStatus>('connecting')
  const [isReadOnly, setIsReadOnly] = React.useState(false)
  const [archived, setArchived] = React.useState(false)
  const [shareReadOnly, setShareReadOnly] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)
  const connectionRef = React.useRef<YjsConnection | null>(null)
  const cacheKeyRef = React.useRef<string | null>(null)

  // Validate share token and set readonly. Also set documentId early for attachments.
  React.useEffect(() => {
    if (!enabled) return
    if (contributeToRealtimeContext) {
      setRealtimeDocumentId(id)
    }
    const token = resolveShareToken(shareToken, useUrlShareTokenFallback)
    if (!token) {
      setShareReadOnly(false)
      return
    }
    if (!shouldValidateShareToken) {
      setShareReadOnly(false)
      return
    }

    let cancelled = false
    ;(async () => {
      try {
        const info = await queryClient.fetchQuery({
          queryKey: ['share-token', token],
          queryFn: () => validateShareToken(token),
          staleTime: SHARE_TOKEN_VALIDATION_STALE_MS,
        })
        if (cancelled) return
        setShareReadOnly(info?.permission !== 'edit')
      } catch {
        if (cancelled) return
        if (!invalidShareTokenToastShown.has(token)) {
          invalidShareTokenToastShown.add(token)
          toast.error('Invalid or expired share link')
        }
        setShareReadOnly(true)
      }
    })()

    return () => {
      cancelled = true
    }
  }, [
    contributeToRealtimeContext,
    enabled,
    id,
    queryClient,
    shareToken,
    shouldValidateShareToken,
    useUrlShareTokenFallback,
  ])

  React.useEffect(() => {
    if (!enabled) return
    const token = resolveShareToken(shareToken, useUrlShareTokenFallback)
    if (token) {
      setIsReadOnly(shareReadOnly || archived)
      return
    }

    if (authLoading) return
    const hasEditPermission = permissions.includes('doc:edit')
    setIsReadOnly(archived || !hasEditPermission)
  }, [archived, authLoading, enabled, permissions, shareReadOnly, shareToken, useUrlShareTokenFallback])

  const loadMeta = React.useCallback(async () => {
    if (!shouldLoadMeta) return
    try {
      const token = resolveShareToken(shareToken, useUrlShareTokenFallback)
      const meta = await queryClient.fetchQuery({
        queryKey: ['document-meta', id, token ?? null],
        queryFn: () => fetchDocumentMeta(id, token ?? undefined),
        staleTime: DOCUMENT_META_STALE_MS,
      })
      if (meta) {
        const isDocArchived = Boolean(meta.archived_at)
        setArchived(isDocArchived)
        if (contributeToRealtimeContext) {
          const pluginId = typeof (meta as any).created_by_plugin === 'string' ? String((meta as any).created_by_plugin).trim() : ''
          setDocumentTitle(meta.title)
          setDocumentStatus(isDocArchived ? 'Archived document' : undefined)
          setDocumentBadge(isDocArchived ? 'Archived' : undefined)
          setDocumentActions([])
          setDocumentPath(undefined)
          setRealtimeDocumentId(id)
          setDocumentPluginId(pluginId || undefined)
          setShowEditorFeatures(true)
        }
      }
    } catch {
      /* ignore meta load failures */
    }
  }, [
    id,
    queryClient,
    shareToken,
    setDocumentTitle,
    setDocumentStatus,
    setDocumentBadge,
    setDocumentActions,
    setDocumentPath,
    setDocumentPluginId,
    setRealtimeDocumentId,
    setShowEditorFeatures,
    contributeToRealtimeContext,
    useUrlShareTokenFallback,
    shouldLoadMeta,
  ])

  React.useEffect(() => {
    if (!enabled) {
      setStatus('disconnected')
      setError(null)
      if (cacheKeyRef.current) {
        releaseConnection(cacheKeyRef.current)
        cacheKeyRef.current = null
      }
      connectionRef.current = null
      return () => {}
    }

    setStatus('connecting')
    setError(null)
    connectionRef.current = null
    cacheKeyRef.current = null

    let cancelled = false
    let cleanupProvider: any | null = null
    let cleanupCacheKey: string | null = null
    let unregisterContentFlush: (() => void) | null = null
    let onStatus: ((ev: { status: string }) => void) | null = null
    let onAwareness: (() => void) | null = null
    let onOnline: (() => void) | null = null
    let onOffline: (() => void) | null = null
    let lastStatus: RealtimeStatus = 'connecting'

    ;(async () => {
      try {
        const urlShareToken = resolveShareToken(shareToken, useUrlShareTokenFallback)
        if (!disablePersistence) {
          unregisterContentFlush = registerDocumentContentFlush(id, urlShareToken ?? null)
        }

        const acquired = await acquireConnection(id, urlShareToken ?? undefined, disablePersistence, activeWorkspaceId)
        if (cancelled) {
          releaseConnection(acquired.cacheKey)
          return
        }
        const { cacheKey, connection } = acquired
        cacheKeyRef.current = cacheKey
        connectionRef.current = connection
        cleanupCacheKey = cacheKey

        const { provider } = connection
        cleanupProvider = provider

        const updateStatus = (next: RealtimeStatus) => {
          if (cancelled) return
          setStatus(next)
          if (contributeToRealtimeContext) {
            setConnected(next === 'connected')
          }
          lastStatus = next
        }

        onStatus = (ev: { status: string }) => {
          if (ev.status === 'connected') {
            updateStatus('connected')
          } else if (ev.status === 'disconnected') {
            updateStatus('disconnected')
            if (contributeToRealtimeContext) {
              const shouldNotify = typeof navigator === 'undefined' ? true : navigator.onLine
              if (shouldNotify && lastStatus !== 'disconnected') toast.error('Disconnected from realtime server')
            }
          } else {
            updateStatus('connecting')
          }
        }
        provider.on('status', onStatus)

        const isOnline = typeof navigator === 'undefined' ? true : navigator.onLine
        provider.shouldConnect = isOnline
        const isProviderConnected = (() => {
          const anyProvider = provider as any
          if (typeof anyProvider?.wsconnected === 'boolean') return anyProvider.wsconnected
          const ws = anyProvider?.ws
          return Boolean(ws && typeof ws.readyState === 'number' && ws.readyState === 1)
        })()

        if (!isOnline) {
          updateStatus('disconnected')
        } else if (isProviderConnected) {
          updateStatus('connected')
        } else {
          updateStatus('connecting')
          provider.connect()
        }

        onOnline = () => {
          provider.shouldConnect = true
          try {
            provider.connect()
            updateStatus('connecting')
          } catch {}
        }

        onOffline = () => {
          provider.shouldConnect = false
          try {
            provider.disconnect()
          } catch {}
          updateStatus('disconnected')
        }

        window.addEventListener('online', onOnline)
        window.addEventListener('offline', onOffline)

        if (trackAwareness || contributeToRealtimeContext) {
          const prevCountRef = { current: userCount }
          const lastIdsRef = { current: new Set<string>() }
          onAwareness = () => {
            const states = provider.awareness.getStates() as Map<number, any>
            const seen = new Map<string, { id: string; name: string; color?: string; clientId?: number }>()
            states.forEach((st: any, clientId: number) => {
              const u = st?.user
              if (!u) return
              const hasId = typeof u.id === 'string' && u.id.trim().length > 0
              const hasName = typeof u.name === 'string' && u.name.trim().length > 0
              if (!hasId && !hasName) return
              const uid = hasId ? String(u.id) : `name:${String(u.name)}`
              const name = hasName ? String(u.name) : String(u.id)
              const color = typeof u.color === 'string' ? (u.color as string) : undefined
              if (!seen.has(uid)) seen.set(uid, { id: uid, name, color, clientId })
            })
            const list = Array.from(seen.values())
            const uniqueCount = list.length
            if (contributeToRealtimeContext && uniqueCount !== prevCountRef.current) {
              prevCountRef.current = uniqueCount
              setUserCount(uniqueCount)
            }
            const ids = new Set(list.map((u) => u.id))
            let changed = ids.size !== lastIdsRef.current.size
            if (!changed) {
              for (const id of ids) {
                if (!lastIdsRef.current.has(id)) {
                  changed = true
                  break
                }
              }
            }
            if (changed) {
              lastIdsRef.current = ids
              if (contributeToRealtimeContext) {
                setOnlineUsers(list)
              }
            }
          }
          provider.awareness.on('update', onAwareness)
        }

        await loadMeta()
      } catch (err) {
        console.error('[collaboration] failed to initialise realtime session', id, err)
        if (!cancelled) {
          setStatus('disconnected')
          setError('Failed to establish realtime connection. Please reload.')
          if (contributeToRealtimeContext) {
            setConnected(false)
          }
        }
        if (cleanupCacheKey) {
          releaseConnection(cleanupCacheKey)
          cleanupCacheKey = null
        } else if (cacheKeyRef.current) {
          releaseConnection(cacheKeyRef.current)
          cacheKeyRef.current = null
        }
        cleanupProvider = null
        connectionRef.current = null
      }
    })()

    return () => {
      cancelled = true
      const provider = cleanupProvider ?? connectionRef.current?.provider
      if (!disablePersistence) {
        const token = resolveShareToken(shareToken, useUrlShareTokenFallback)
        void flushPendingDocumentContent(id, token ?? null)
      }
      if (provider) {
        try {
          if (onStatus) provider.off('status', onStatus)
        } catch {}
        try {
          if (onAwareness) provider.awareness.off('update', onAwareness)
        } catch {}
      }
      if (onOnline) {
        try { window.removeEventListener('online', onOnline) } catch {}
      }
      if (onOffline) {
        try { window.removeEventListener('offline', onOffline) } catch {}
      }
      if (cleanupCacheKey) {
        releaseConnection(cleanupCacheKey)
        cleanupCacheKey = null
      } else if (cacheKeyRef.current) {
        releaseConnection(cacheKeyRef.current)
        cacheKeyRef.current = null
      }
      cleanupProvider = null
      connectionRef.current = null
      if (unregisterContentFlush) {
        unregisterContentFlush()
        unregisterContentFlush = null
      }
      if (contributeToRealtimeContext) {
        setShowEditorFeatures(false)
        setUserCount(0)
        setOnlineUsers([])
        setConnected(false)
        setDocumentTitle(undefined)
        setDocumentStatus(undefined)
        setDocumentBadge(undefined)
        setDocumentActions([])
        setDocumentPath(undefined)
        setDocumentPluginId(undefined)
      }
      setArchived(false)
      setShareReadOnly(false)
      setIsReadOnly(false)
      setError(null)
    }
  }, [
    id,
    shareToken,
    loadMeta,
    contributeToRealtimeContext,
    disablePersistence,
    enabled,
    useUrlShareTokenFallback,
    trackAwareness,
    activeWorkspaceId,
  ])

  React.useEffect(() => {
    if (typeof window === 'undefined') return
    if (!enabled) return
    const handler = (event: Event) => {
      const detail = (event as CustomEvent<{ id?: string }>).detail
      if (detail?.id === id) {
        void loadMeta()
      }
    }
    window.addEventListener('refmd:document-archive-change', handler as EventListener)
    return () => {
      window.removeEventListener('refmd:document-archive-change', handler as EventListener)
    }
  }, [enabled, id, loadMeta])

  return {
    status,
    isReadOnly,
    setIsReadOnly,
    doc: connectionRef.current?.doc ?? null,
    awareness: connectionRef.current?.provider.awareness ?? null,
    error,
    archived,
  }
}

function normalizeShareToken(token?: string | null) {
  if (typeof token !== 'string') return undefined
  const trimmed = token.trim()
  return trimmed.length > 0 ? trimmed : undefined
}

function resolveShareToken(explicitToken: string | undefined, useUrlFallback: boolean) {
  const normalized = normalizeShareToken(explicitToken)
  if (normalized) return normalized

  if (typeof window === 'undefined') return undefined
  if (!useUrlFallback) return undefined

  try {
    const candidate = new URLSearchParams(window.location.search).get('token')
    return normalizeShareToken(candidate)
  } catch {
    return undefined
  }
}
