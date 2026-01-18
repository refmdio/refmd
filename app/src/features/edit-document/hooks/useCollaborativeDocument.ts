import { useQueryClient } from '@tanstack/react-query'
import * as React from 'react'
import { toast } from 'sonner'
import type { Awareness } from 'y-protocols/awareness'
import type * as Y from 'yjs'

import { useRealtime } from '@/shared/contexts/realtime-context'
import { createYjsConnection, destroyYjsConnection } from '@/shared/lib/yjsConnection'
import type { YjsConnection, YjsConnectionOptions } from '@/shared/lib/yjsConnection'

import { fetchDocumentMeta } from '@/entities/document'
import { validateShareToken } from '@/entities/share'

import { useAuthContext } from '@/features/auth'
import {
  extractShareKeyFromFragment,
  decryptDekWithShareKey,
} from '@/features/security'
import { useShareContextOptional, type ShareContextValue } from '@/features/sharing'

import { useKeyVaultStatus } from './useKeyVaultStatus'


export type RealtimeStatus = 'connecting' | 'connected' | 'disconnected'

export type UseCollaborativeDocumentOptions = {
  enabled?: boolean
  contributeToRealtimeContext?: boolean
  useUrlShareTokenFallback?: boolean
  validateShareToken?: boolean
  loadMeta?: boolean
  trackAwareness?: boolean
}

type ConnectionCacheEntry = {
  refs: number
  connection: YjsConnection | null
  promise: Promise<YjsConnection> | null
}

const connectionCache = new Map<string, ConnectionCacheEntry>()
const invalidShareTokenToastShown = new Set<string>()
const SHARE_TOKEN_VALIDATION_STALE_MS = 5 * 60 * 1000
const DOCUMENT_META_STALE_MS = 60 * 1000

function buildCollaborativeDocumentConnectionCacheKey(args: {
  documentId: string
  token: string | undefined
  workspaceId: string | null | undefined
}) {
  const workspaceScope = typeof args.workspaceId === 'string' ? args.workspaceId.trim() : ''
  return `${args.documentId}::${args.token ?? ''}::ws:${workspaceScope}`
}

function buildCacheKey(
  documentId: string,
  token: string | undefined,
  workspaceId: string | null | undefined,
) {
  return buildCollaborativeDocumentConnectionCacheKey({ documentId, token, workspaceId })
}

/** Resolve share mode options by extracting share key from URL and decrypting DEK */
async function resolveShareMode(
  token: string,
  queryClient: ReturnType<typeof useQueryClient>,
  documentId?: string,
  shareCtx?: ShareContextValue | null,
): Promise<YjsConnectionOptions['shareMode'] | null> {
  // Try ShareContext first (available when navigating from folder share page)
  let shareKey: Uint8Array | null = shareCtx?.shareKey ?? null
  let encryptedDekBase64: string | null = null

  // Try to get encrypted DEK from ShareContext (folder share navigation)
  if (shareCtx?.encryptedDeks && documentId) {
    encryptedDekBase64 = shareCtx.encryptedDeks.get(documentId) ?? null
  }

  // Fallback: extract share key from URL fragment (direct document share links)
  if (!shareKey) {
    const fragment = typeof window !== 'undefined' ? window.location.hash : ''
    if (!fragment) {
      return null
    }
    shareKey = await extractShareKeyFromFragment(fragment)
  }

  if (!shareKey) {
    return null
  }

  // Fallback: fetch encrypted DEK from API if not in context
  if (!encryptedDekBase64) {
    const shareInfo = await queryClient.fetchQuery({
      queryKey: ['share-token', token],
      queryFn: () => validateShareToken(token),
      staleTime: SHARE_TOKEN_VALIDATION_STALE_MS,
    })
    encryptedDekBase64 = shareInfo?.encryptedDek ?? null
  }

  if (!encryptedDekBase64) {
    // Document might not be encrypted or share key not stored
    return null
  }

  // For password-protected shares, salt/kdfParams would be present
  // For URL fragment mode, we just have encryptedDek
  // The nonce is stored together with the encrypted DEK (first 24 bytes)
  // Try to decrypt - assume nonce is prepended to ciphertext (common pattern)
  try {
    const { getSodium } = await import('@/features/security')
    const sodium = await getSodium()
    const combined = sodium.from_base64(encryptedDekBase64, sodium.base64_variants.ORIGINAL)

    // XChaCha20-Poly1305 nonce is 24 bytes
    const NONCE_LENGTH = 24
    if (combined.length <= NONCE_LENGTH) {
      console.warn('[share] Encrypted DEK too short')
      return null
    }

    const nonce = combined.slice(0, NONCE_LENGTH)
    const ciphertext = combined.slice(NONCE_LENGTH)

    const nonceBase64 = sodium.to_base64(nonce, sodium.base64_variants.ORIGINAL)
    const ciphertextBase64 = sodium.to_base64(ciphertext, sodium.base64_variants.ORIGINAL)

    const dek = await decryptDekWithShareKey(ciphertextBase64, nonceBase64, shareKey)

    return { dek }
  } catch (err) {
    console.warn('[share] Failed to decrypt DEK with share key:', err)
    return null
  }
}

async function acquireConnection(
  documentId: string,
  token: string | undefined,
  workspaceId: string | null | undefined,
  queryClient?: ReturnType<typeof useQueryClient>,
  shareCtx?: ShareContextValue | null,
) {
  const cacheKey = buildCacheKey(documentId, token, workspaceId)
  const existing = connectionCache.get(cacheKey)
  if (existing) {
    existing.refs += 1
    if (existing.connection) return { cacheKey, connection: existing.connection }
    if (existing.promise) return { cacheKey, connection: await existing.promise }
  }

  // For share token access, try to resolve share mode
  let shareMode: YjsConnectionOptions['shareMode'] = undefined
  if (token && queryClient) {
    try {
      shareMode = await resolveShareMode(token, queryClient, documentId, shareCtx) ?? undefined
    } catch (err) {
      console.warn('[share] Failed to resolve share mode:', err)
    }
  }

  const entry: ConnectionCacheEntry = { refs: 1, connection: null, promise: null }
  entry.promise = createYjsConnection(documentId, {
    token: token ?? null,
    connect: false,
    workspaceId: workspaceId ?? undefined,
    shareMode,
  })
  connectionCache.set(cacheKey, entry)
  try {
    const connection = await entry.promise
    entry.connection = connection
    entry.promise = null
    return { cacheKey, connection }
  } catch {
    connectionCache.delete(cacheKey)
    throw new Error('Failed to create Yjs connection')
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
  const shareCtx = useShareContextOptional()
  const enabled = options.enabled ?? true
  const contributeToRealtimeContext = options.contributeToRealtimeContext ?? true
  const useUrlShareTokenFallback = options.useUrlShareTokenFallback ?? true
  const shouldValidateShareToken = options.validateShareToken ?? true
  const shouldLoadMeta = options.loadMeta ?? true
  const trackAwareness = options.trackAwareness ?? true
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
  // KeyVault status check
  const { keyVaultUnlocked, needsKeyVaultUnlock, retryKeyVaultCheck } = useKeyVaultStatus({
    enabled,
    shareToken,
    useUrlShareTokenFallback,
  })

  // Track if KeyVault is ready - once true, stays true (one-way transition)
  // This prevents effect re-runs when keyVaultUnlocked changes from null to true
  const [keyVaultReady, setKeyVaultReady] = React.useState(false)
  React.useEffect(() => {
    if (keyVaultUnlocked === true && !keyVaultReady) {
      setKeyVaultReady(true)
    }
  }, [keyVaultUnlocked, keyVaultReady])

  // Handle KeyVault lock state separately (show error if locked)
  React.useEffect(() => {
    if (needsKeyVaultUnlock) {
      setError('Session locked. Please unlock to continue.')
    }
  }, [needsKeyVaultUnlock])

  const [status, setStatus] = React.useState<RealtimeStatus>('connecting')
  const [isReadOnly, setIsReadOnly] = React.useState(false)
  const [archived, setArchived] = React.useState(false)
  const [shareReadOnly, setShareReadOnly] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)
  const [doc, setDoc] = React.useState<Y.Doc | null>(null)
  const [awareness, setAwareness] = React.useState<Awareness | null>(null)
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
      return () => {}
    }

    // Wait for KeyVault to be ready (keyVaultReady transitions from false to true only once)
    if (!keyVaultReady) {
      setStatus('connecting')
      return () => {}
    }

    // For authenticated access (no share token), require activeWorkspaceId
    const urlShareToken = resolveShareToken(shareToken, useUrlShareTokenFallback)
    if (!urlShareToken && !activeWorkspaceId) {
      setStatus('connecting')
      return () => {}
    }

    setStatus('connecting')
    setError(null)
    connectionRef.current = null
    cacheKeyRef.current = null

    let cancelled = false
    let cleanupProvider: any | null = null
    let cleanupCacheKey: string | null = null
    let onStatus: ((ev: { status: string }) => void) | null = null
    let onAwareness: (() => void) | null = null
    let onOnline: (() => void) | null = null
    let onOffline: (() => void) | null = null
    let lastStatus: RealtimeStatus = 'connecting'

    ;(async () => {
      try {
        const acquired = await acquireConnection(id, urlShareToken ?? undefined, activeWorkspaceId, queryClient, shareCtx)
        if (cancelled) {
          releaseConnection(acquired.cacheKey)
          return
        }
        const { cacheKey, connection } = acquired
        cacheKeyRef.current = cacheKey
        connectionRef.current = connection
        cleanupCacheKey = cacheKey

        // Set doc and awareness state to trigger re-render
        setDoc(connection.doc)
        setAwareness(connection.provider.awareness)

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

        if (!isOnline) {
          updateStatus('disconnected')
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
      } catch {
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
      setDoc(null)
      setAwareness(null)
    }
  }, [
    id,
    shareToken,
    loadMeta,
    contributeToRealtimeContext,
    enabled,
    useUrlShareTokenFallback,
    trackAwareness,
    activeWorkspaceId,
    keyVaultReady,
    shareCtx,
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
    doc,
    awareness,
    error,
    archived,
    needsKeyVaultUnlock,
    retryKeyVaultCheck,
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
