import type { Awareness } from 'y-protocols/awareness'
import type { IndexeddbPersistence } from 'y-indexeddb'
import type * as Y from 'yjs'

import { YJS_SERVER_URL } from '@/shared/lib/config'
import { createConnection, type StatusEventHandler, type ShareModeOptions } from './realtime'

export type YjsConnectionOptions = {
  token?: string | null
  connect?: boolean
  params?: Record<string, string>
  disablePersistence?: boolean
  persistenceKey?: string
  workspaceId?: string
  /** For share-based access - pre-decrypted DEK */
  shareMode?: ShareModeOptions
}

/** Status event handler type (compatible with y-websocket) */
type ProviderStatusHandler = (event: { status: string }) => void

/**
 * Provider-like interface for compatibility with existing code.
 * Wraps Connection to provide WebsocketProvider-compatible API.
 */
export interface ProviderLike {
  awareness: Awareness
  shouldConnect: boolean
  connect(): void
  disconnect(): void
  on(event: 'status', handler: ProviderStatusHandler): void
  off(event: 'status', handler: ProviderStatusHandler): void
}

export type YjsConnection = {
  doc: Y.Doc
  provider: ProviderLike
  persistence: IndexeddbPersistence | null
}

export async function createYjsConnection(
  documentId: string,
  options: YjsConnectionOptions = {}
): Promise<YjsConnection> {
  const { Doc } = await import('yjs')

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

  // Wait for IndexedDB to sync before creating connection
  if (persistenceReady) {
    try {
      await persistenceReady
    } catch {
      /* noop */
    }
  }

  // Create encrypted connection
  const workspaceId = options.workspaceId ?? ''
  const isShareMode = !!options.shareMode

  if (!workspaceId && !isShareMode) {
    console.warn('[yjs] No workspaceId provided - encryption will not work correctly')
  }

  const connection = await createConnection(YJS_SERVER_URL, doc, documentId, {
    token: options.token,
    connect: options.connect ?? true,
    workspaceId,
    shareMode: options.shareMode,
  })

  // Create provider-like wrapper for compatibility
  const provider: ProviderLike = {
    awareness: connection.awareness,
    get shouldConnect() {
      return connection.shouldConnect
    },
    set shouldConnect(value: boolean) {
      connection.shouldConnect = value
    },
    connect: () => connection.connect(),
    disconnect: () => connection.disconnect(),
    on: (event: 'status', handler: ProviderStatusHandler) => {
      // Cast handler to StatusEventHandler - our status events are compatible
      connection.on(event, handler as StatusEventHandler)
    },
    off: (event: 'status', handler: ProviderStatusHandler) => {
      connection.off(event, handler as StatusEventHandler)
    },
  }

  return { doc, provider, persistence }
}

export function destroyYjsConnection(connection: YjsConnection | null | undefined) {
  if (!connection) return
  const { provider, doc, persistence } = connection
  try {
    provider.disconnect()
  } catch {}
  try {
    (doc as any)?.destroy?.()
  } catch {}
  if (persistence) {
    try {
      void persistence.destroy()
    } catch {}
  }
}
