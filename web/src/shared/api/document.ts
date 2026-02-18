/**
 * Document API
 */

import { api, unwrap } from './core'
import type { components } from './schema'

export const documentApi = {
  async list(
    workspaceId: string,
    params?: { parentId?: string; rootOnly?: boolean; includeArchived?: boolean }
  ) {
    return unwrap(await api.GET(
      '/api/workspaces/{workspace_id}/documents',
      {
        params: {
          path: { workspace_id: workspaceId },
          query: {
            parent_id: params?.parentId,
            root_only: params?.rootOnly ?? true,
            include_archived: params?.includeArchived ?? false,
          },
        },
      }
    ))
  },

  async get(documentId: string) {
    return unwrap(await api.GET('/api/documents/{document_id}', {
      params: { path: { document_id: documentId } },
    }))
  },

  async create(workspaceId: string, body: components['schemas']['CreateDocumentRequest']) {
    return unwrap(await api.POST(
      '/api/workspaces/{workspace_id}/documents',
      {
        params: { path: { workspace_id: workspaceId } },
        body,
      }
    ))
  },

  async listUpdates(documentId: string, afterSeq?: number) {
    return unwrap(await api.GET('/api/documents/{document_id}/updates', {
      params: {
        path: { document_id: documentId },
        query: afterSeq !== undefined ? { after_seq: afterSeq } : undefined,
      },
    }))
  },

  async createUpdate(
    documentId: string,
    body: {
      update_data: string
      nonce: string
      key_version: number
      update_hash: string
      prev_update_hash: string | null
      signature: string
      author_device_id: string
      timestamp: number
    }
  ) {
    return unwrap(await api.POST('/api/documents/{document_id}/updates', {
      params: { path: { document_id: documentId } },
      body,
    }))
  },
}
