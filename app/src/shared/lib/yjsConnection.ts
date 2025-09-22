import type { WebsocketProvider } from 'y-websocket'
import type * as Y from 'yjs'

import { YJS_SERVER_URL } from '@/shared/lib/config'

export type YjsConnectionOptions = {
  token?: string | null
  connect?: boolean
  params?: Record<string, string>
}

export type YjsConnection = {
  doc: Y.Doc
  provider: WebsocketProvider
}

export async function createYjsConnection(documentId: string, options: YjsConnectionOptions = {}): Promise<YjsConnection> {
  const { Doc } = await import('yjs')
  const { WebsocketProvider } = await import('y-websocket')

  const doc = new Doc() as unknown as Y.Doc
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

  return { doc, provider }
}

export function destroyYjsConnection(connection: YjsConnection | null | undefined) {
  if (!connection) return
  const { provider, doc } = connection
  try { provider.disconnect() } catch {}
  try { provider.destroy() } catch {}
  try { (doc as any)?.destroy?.() } catch {}
}
