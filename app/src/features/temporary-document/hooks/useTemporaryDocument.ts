import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { IndexeddbPersistence } from 'y-indexeddb'
import type { Awareness } from 'y-protocols/awareness'
import type * as Y from 'yjs'

import {
  deleteTemporaryDocumentEntry,
  getTemporaryDocumentEntry,
  TEMPORARY_DOCUMENT_PERSISTENCE_PREFIX,
  touchTemporaryDocumentEntry,
  updateTemporaryDocumentEntry,
} from '@/features/temporary-document/lib/storage'

type UserIdentity = { id?: string | null; name?: string | null }

type UseTemporaryDocumentOptions = {
  id: string
  user?: UserIdentity | null
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
  removeEntry: () => Promise<void>
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

export function useTemporaryDocument(options: UseTemporaryDocumentOptions): TemporaryDocumentState {
  const { id } = options
  const persistenceKey = `${TEMPORARY_DOCUMENT_PERSISTENCE_PREFIX}:${id}`
  const [status, setStatus] = useState<'idle' | 'loading' | 'ready' | 'error'>(() => (typeof window === 'undefined' ? 'idle' : 'loading'))
  const [error, setError] = useState<string | null>(null)
  const [doc, setDoc] = useState<Y.Doc | null>(null)
  const [awareness, setAwareness] = useState<Awareness | null>(null)
  const [contentLength, setContentLength] = useState(0)
  const [lastUpdatedAt, setLastUpdatedAt] = useState<number | null>(() => {
    if (typeof window === 'undefined') return null
    return getTemporaryDocumentEntry(id)?.updatedAt ?? null
  })
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
    if (!doc || typeof window === 'undefined') return
    const meta = getTemporaryDocumentEntry(id)
    if (meta) {
      setLastUpdatedAt(meta.updatedAt)
      return
    }
    const timestamp = Date.now()
    updateTemporaryDocumentEntry(id, { createdAt: timestamp, updatedAt: timestamp })
    setLastUpdatedAt(timestamp)
  }, [doc, id])

  useEffect(() => {
    if (!doc) return
    const text = doc.getText('content')
    setContentLength(text.length)

    const handleChange = () => {
      setContentLength(text.length)
      if (suppressMetaRef.current) {
        suppressMetaRef.current = false
        const ts = Date.now()
        updateTemporaryDocumentEntry(id, { updatedAt: ts, preview: '', length: text.length })
        setLastUpdatedAt(ts)
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
      touchTemporaryDocumentEntry(id, summarizePreview(snapshot), snapshot.length)
    }

    text.observe(handleChange)
    return () => {
      text.unobserve(handleChange)
    }
  }, [doc, id])

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
    const ts = Date.now()
    updateTemporaryDocumentEntry(id, { updatedAt: ts, preview: '', length: 0 })
    setLastUpdatedAt(ts)
  }, [id])

  const removeEntry = useCallback(async () => {
    try {
      await persistenceRef.current?.clearData?.()
    } catch {}
    deleteTemporaryDocumentEntry(id)
    setLastUpdatedAt(null)
  }, [id])

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
    removeEntry,
    getContentSnapshot,
  }
}

function summarizePreview(content: string) {
  if (!content) return ''
  const first = content.split(/\r?\n/).find((line) => line.trim().length > 0)
  if (!first) return ''
  return first.replace(/^#+\s*/, '').slice(0, 140)
}
