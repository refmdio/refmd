import * as React from 'react'
import { toast } from 'sonner'

import { useRealtime } from '@/shared/contexts/realtime-context'
import { createYjsConnection, destroyYjsConnection } from '@/shared/lib/yjsConnection'
import type { YjsConnection } from '@/shared/lib/yjsConnection'

import { fetchDocumentMeta } from '@/entities/document'
import { validateShareToken } from '@/entities/share'


export type RealtimeStatus = 'connecting' | 'connected' | 'disconnected'

export function useCollaborativeDocument(id: string, shareToken?: string) {
  const {
    setDocumentId: setRealtimeDocumentId,
    setDocumentTitle,
    setDocumentStatus,
    setDocumentBadge,
    setDocumentActions,
    setDocumentPath,
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

  // Validate share token and set readonly. Also set documentId early for attachments.
  React.useEffect(() => {
    setRealtimeDocumentId(id)
    const token = resolveShareToken(shareToken)
    if (!token) {
      setShareReadOnly(false)
      return
    }

    ;(async () => {
      try {
        const info = await validateShareToken(token)
        setShareReadOnly(info?.permission !== 'edit')
      } catch {
        toast.error('Invalid or expired share link')
        setShareReadOnly(true)
      }
    })()
  }, [id, shareToken])

  React.useEffect(() => {
    setIsReadOnly(shareReadOnly || archived)
  }, [shareReadOnly, archived])

  const loadMeta = React.useCallback(async () => {
    try {
      const token = resolveShareToken(shareToken)
      const meta = await fetchDocumentMeta(id, token ?? undefined)
      if (meta) {
        const isDocArchived = Boolean(meta.archived_at)
        setArchived(isDocArchived)
        setDocumentTitle(meta.title)
        setDocumentStatus(isDocArchived ? 'Archived document' : undefined)
        setDocumentBadge(isDocArchived ? 'Archived' : undefined)
        setDocumentActions([])
        setDocumentPath(undefined)
        setRealtimeDocumentId(id)
        setShowEditorFeatures(true)
      }
    } catch {
      /* ignore meta load failures */
    }
  }, [
    id,
    shareToken,
    setDocumentTitle,
    setDocumentStatus,
    setDocumentBadge,
    setDocumentActions,
    setDocumentPath,
    setRealtimeDocumentId,
    setShowEditorFeatures,
  ])

  React.useEffect(() => {
    setStatus('connecting')
    setError(null)
    connectionRef.current = null

    let onStatus: ((ev: { status: string }) => void) | null = null
    let onAwareness: (() => void) | null = null
    let onOnline: (() => void) | null = null
    let onOffline: (() => void) | null = null
    let lastStatus: RealtimeStatus = 'connecting'

    ;(async () => {
      try {
        const urlShareToken = resolveShareToken(shareToken)

        const connection = await createYjsConnection(id, {
          token: urlShareToken,
          connect: false,
        })
        connectionRef.current = connection

        const { provider } = connection

        const isOnline = typeof navigator === 'undefined' ? true : navigator.onLine
        provider.shouldConnect = isOnline
        if (isOnline) {
          provider.connect()
        } else {
          setStatus('disconnected')
          setConnected(false)
          lastStatus = 'disconnected'
        }

        onStatus = (ev: { status: string }) => {
          if (ev.status === 'connected') {
            setStatus('connected')
            setConnected(true)
            lastStatus = 'connected'
          } else if (ev.status === 'disconnected') {
            setStatus('disconnected')
            setConnected(false)
            const shouldNotify = typeof navigator === 'undefined' ? true : navigator.onLine
            if (shouldNotify && lastStatus !== 'disconnected') toast.error('Disconnected from realtime server')
            lastStatus = 'disconnected'
          } else {
            setStatus('connecting')
            lastStatus = 'connecting'
          }
        }
        provider.on('status', onStatus)

        onOnline = () => {
          provider.shouldConnect = true
          try {
            provider.connect()
            setStatus('connecting')
            lastStatus = 'connecting'
          } catch {}
        }

        onOffline = () => {
          provider.shouldConnect = false
          try {
            provider.disconnect()
          } catch {}
          setStatus('disconnected')
          setConnected(false)
          lastStatus = 'disconnected'
        }

        window.addEventListener('online', onOnline)
        window.addEventListener('offline', onOffline)

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
          if (uniqueCount !== prevCountRef.current) {
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
            setOnlineUsers(list)
          }
        }
        provider.awareness.on('update', onAwareness)

        await loadMeta()
      } catch (err) {
        console.error('[collaboration] failed to initialise realtime session', id, err)
        setStatus('disconnected')
        setError('Failed to establish realtime connection. Please reload.')
        setConnected(false)
        destroyYjsConnection(connectionRef.current)
        connectionRef.current = null
      }
    })()

    return () => {
      const connection = connectionRef.current
      const provider = connection?.provider
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
      destroyYjsConnection(connectionRef.current)
      connectionRef.current = null
      setShowEditorFeatures(false)
      setUserCount(0)
      setOnlineUsers([])
      setConnected(false)
      setDocumentTitle(undefined)
      setDocumentStatus(undefined)
      setDocumentBadge(undefined)
      setDocumentActions([])
      setDocumentPath(undefined)
      setArchived(false)
      setShareReadOnly(false)
      setIsReadOnly(false)
      setError(null)
    }
  }, [id, shareToken, loadMeta])

  React.useEffect(() => {
    if (typeof window === 'undefined') return
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
  }, [id, loadMeta])

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

function resolveShareToken(explicitToken?: string) {
  const normalized = normalizeShareToken(explicitToken)
  if (normalized) return normalized

  if (typeof window === 'undefined') return undefined

  try {
    const candidate = new URLSearchParams(window.location.search).get('token')
    return normalizeShareToken(candidate)
  } catch {
    return undefined
  }
}
