import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { Awareness } from 'y-protocols/awareness'
import type { IndexeddbPersistence } from 'y-indexeddb'
import type * as Y from 'yjs'

export const TEMPORARY_DOCUMENT_PERSISTENCE_KEY = 'refmd:temporary-document'
export const TEMPORARY_DOCUMENT_META_KEY = `${TEMPORARY_DOCUMENT_PERSISTENCE_KEY}:meta`
const STALE_TTL_MS = 24 * 60 * 60 * 1000

type TempMeta = { updatedAt: number; preview?: string; length?: number }

type UserIdentity = { id?: string | null; name?: string | null }

type UseTemporaryDocumentOptions = {
  user?: UserIdentity | null
  persistenceKey?: string
  metaKey?: string
  ttlMs?: number
}

export type TemporaryDocumentState = {
  status: 'idle' | 'loading' | 'ready' | 'error'
  error: string | null
  doc: Y.Doc | null
  awareness: Awareness | null
  hasContent: boolean
  contentLength: number
  lastUpdatedAt: number | null
  clear: () => Promise<void>
  getContentSnapshot: () => string
}

const hasIndexedDb = () => {
  if (typeof window === 'undefined') return false
  try {
    return typeof window.indexedDB !== 'undefined' && window.indexedDB !== null
  } catch {
    return false
  }
}

const readMeta = (key: string): TempMeta | null => {
  if (typeof window === 'undefined') return null
  try {
    const raw = window.localStorage.getItem(key)
    if (!raw) return null
    const parsed = JSON.parse(raw) as TempMeta
    if (typeof parsed?.updatedAt === 'number') return parsed
    return null
  } catch {
    return null
  }
}

const writeMeta = (key: string, meta: TempMeta) => {
  if (typeof window === 'undefined') return
  try {
    window.localStorage.setItem(key, JSON.stringify(meta))
  } catch {
    /* noop */
  }
}

const clearMeta = (key: string) => {
  if (typeof window === 'undefined') return
  try {
    window.localStorage.removeItem(key)
  } catch {
    /* noop */
  }
}

export function useTemporaryDocument(options?: UseTemporaryDocumentOptions): TemporaryDocumentState {
  const persistenceKey = options?.persistenceKey ?? TEMPORARY_DOCUMENT_PERSISTENCE_KEY
  const metaKey = options?.metaKey ?? TEMPORARY_DOCUMENT_META_KEY
  const ttlMs = options?.ttlMs ?? STALE_TTL_MS
  const [status, setStatus] = useState<'idle' | 'loading' | 'ready' | 'error'>(() => (typeof window === 'undefined' ? 'idle' : 'loading'))
  const [error, setError] = useState<string | null>(null)
  const [doc, setDoc] = useState<Y.Doc | null>(null)
  const [awareness, setAwareness] = useState<Awareness | null>(null)
  const [contentLength, setContentLength] = useState(0)
  const [lastUpdatedAt, setLastUpdatedAt] = useState<number | null>(() => readMeta(metaKey)?.updatedAt ?? null)
  const persistenceRef = useRef<IndexeddbPersistence | null>(null)
  const docRef = useRef<Y.Doc | null>(null)
  const awarenessRef = useRef<Awareness | null>(null)
  const suppressMetaRef = useRef(false)
  const userId = options?.user?.id ?? null
  const userName = options?.user?.name ?? null

  useEffect(() => {
    if (typeof window === 'undefined') return
    let cancelled = false
    setStatus('loading')
    setError(null)

    ;(async () => {
      try {
        const [{ Doc }, { Awareness }] = await Promise.all([import('yjs'), import('y-protocols/awareness')])
        const instance = new Doc() as Y.Doc
        docRef.current = instance

        let persistence: IndexeddbPersistence | null = null
        if (hasIndexedDb()) {
          try {
            const { IndexeddbPersistence } = await import('y-indexeddb')
            persistence = new IndexeddbPersistence(persistenceKey, instance)
            persistenceRef.current = persistence
            await persistence.whenSynced.catch(() => undefined)
          } catch (err) {
            console.warn('[temporary-document] Failed to initialise IndexedDB persistence', err)
            persistence = null
            persistenceRef.current = null
          }
        }

        if (cancelled) {
          try { persistence?.destroy?.() } catch {}
          try { (instance as any)?.destroy?.() } catch {}
          persistenceRef.current = null
          docRef.current = null
          return
        }

        const awarenessInstance = new Awareness(instance)
        awarenessRef.current = awarenessInstance
        setDoc(instance)
        setAwareness(awarenessInstance)
        setStatus('ready')
      } catch (err) {
        if (cancelled) return
        console.error('[temporary-document] failed to prepare document', err)
        setError(err instanceof Error ? err.message : 'Failed to prepare temporary document')
        setStatus('error')
      }
    })()

    return () => {
      cancelled = true
      const persistence = persistenceRef.current
      const currentDoc = docRef.current
      const currentAwareness = awarenessRef.current
      persistenceRef.current = null
      docRef.current = null
      awarenessRef.current = null
      setDoc(null)
      setAwareness(null)
      if (currentAwareness) {
        try { currentAwareness.destroy?.() } catch {}
      }
      if (persistence) {
        try { persistence.destroy() } catch {}
      }
      if (currentDoc) {
        try { (currentDoc as any)?.destroy?.() } catch {}
      }
    }
  }, [persistenceKey])

  useEffect(() => {
    if (!doc) return
    const meta = readMeta(metaKey)
    if (meta?.updatedAt) {
      const age = Date.now() - meta.updatedAt
      if (age > ttlMs) {
        try {
          suppressMetaRef.current = true
          doc.transact(() => {
            const text = doc.getText('content')
            text.delete(0, text.length)
          })
          void persistenceRef.current?.clearData?.()
        } catch (err) {
          console.warn('[temporary-document] failed to purge stale state', err)
        }
        clearMeta(metaKey)
        setLastUpdatedAt(null)
      }
    }
  }, [doc, metaKey, ttlMs])

  useEffect(() => {
    if (!doc) return
    const text = doc.getText('content')
    setContentLength(text.length)

    const handleChange = () => {
      setContentLength(text.length)
      if (suppressMetaRef.current) {
        suppressMetaRef.current = false
        return
      }
      const now = Date.now()
      let snapshot = ''
      try {
        snapshot = text.toString()
      } catch {
        snapshot = ''
      }
      setLastUpdatedAt(now)
      writeMeta(metaKey, {
        updatedAt: now,
        preview: summarizePreview(snapshot),
        length: snapshot.length,
      })
    }

    text.observe(handleChange)
    return () => {
      text.unobserve(handleChange)
    }
  }, [doc, metaKey])

  useEffect(() => {
    if (!awareness) return
    const id = userId ?? 'temp-local'
    const resolvedName = userName && userName.trim().length > 0 ? userName : 'Temporary note'
    awareness.setLocalStateField('user', {
      id,
      name: resolvedName,
      color: '#8b5cf6',
    })
  }, [awareness, userId, userName])

  const getContentSnapshot = useCallback(() => {
    const instance = docRef.current
    if (!instance) return ''
    try {
      return instance.getText('content').toString()
    } catch {
      return ''
    }
  }, [])

  const clear = useCallback(async () => {
    const instance = docRef.current
    if (!instance) return
    suppressMetaRef.current = true
    instance.transact(() => {
      const text = instance.getText('content')
      text.delete(0, text.length)
    })
    try {
      await persistenceRef.current?.clearData?.()
    } catch {
      /* noop */
    }
    clearMeta(metaKey)
    setLastUpdatedAt(null)
  }, [metaKey])

  const hasContent = useMemo(() => contentLength > 0, [contentLength])

  return {
    status,
    error,
    doc,
    awareness,
    hasContent,
    contentLength,
    lastUpdatedAt,
    clear,
    getContentSnapshot,
  }
}

function summarizePreview(content: string) {
  if (!content) return ''
  const first = content.split(/\r?\n/).find((line) => line.trim().length > 0)
  if (!first) return ''
  return first.replace(/^#+\s*/, '').slice(0, 140)
}
