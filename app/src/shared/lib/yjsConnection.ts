import type { IndexeddbPersistence } from 'y-indexeddb'
import type { WebsocketProvider } from 'y-websocket'
import type * as Y from 'yjs'

import { YJS_SERVER_URL } from '@/shared/lib/config'

export type YjsConnectionOptions = {
  token?: string | null
  connect?: boolean
  params?: Record<string, string>
  disablePersistence?: boolean
  persistenceKey?: string
}

export type YjsConnection = {
  doc: Y.Doc
  provider: WebsocketProvider
  persistence: IndexeddbPersistence | null
}

export async function createYjsConnection(documentId: string, options: YjsConnectionOptions = {}): Promise<YjsConnection> {
  const { Doc } = await import('yjs')
  const { WebsocketProvider } = await import('y-websocket')

  const doc = new Doc() as unknown as Y.Doc
  const persistenceKey = options.persistenceKey ?? `refmd:${documentId}`
  const hasIndexedDb = (() => {
    try {
      return typeof indexedDB !== 'undefined' && indexedDB !== null
    } catch {
      return false
    }
  })()
  let persistence: IndexeddbPersistence | null = null
  let persistenceReady: Promise<unknown> | null = null

  if (!options.disablePersistence && hasIndexedDb) {
    try {
      const { IndexeddbPersistence } = await import('y-indexeddb')
      persistence = new IndexeddbPersistence(persistenceKey, doc)
      persistenceReady = persistence.whenSynced.catch((err) => {
        console.warn('[yjs] IndexedDB sync failed', documentId, err)
      })
    } catch (err) {
      console.warn('[yjs] Failed to initialise IndexedDB persistence', documentId, err)
      persistence = null
    }
  }
  const params: Record<string, string> = { ...(options.params ?? {}) }
  const token = options.token ?? null
  if (token) params.token = token

  const provider = new WebsocketProvider(
    YJS_SERVER_URL,
    documentId,
    doc as any,
    {
      connect: options.connect ?? true,
      params,
    },
  ) as WebsocketProvider

  if (persistenceReady) {
    try {
      await persistenceReady
    } catch {
      /* noop */
    }
  }

  return { doc, provider, persistence }
}

export function destroyYjsConnection(connection: YjsConnection | null | undefined) {
  if (!connection) return
  const { provider, doc, persistence } = connection
  try { provider.disconnect() } catch {}
  try { provider.destroy() } catch {}
  try { (doc as any)?.destroy?.() } catch {}
  if (persistence) {
    try {
      void persistence.destroy()
    } catch {}
  }
}
