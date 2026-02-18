/**
 * Encryption API
 */

import { api, unwrap } from './core'

export const encryptionApi = {
  async getWorkspaceKey(workspaceId: string, deviceId: string) {
    return unwrap(await api.GET('/api/encryption/workspaces/{workspace_id}/keys', {
      params: {
        path: { workspace_id: workspaceId },
        query: { device_id: deviceId },
      },
    }))
  },

  async saveWorkspaceKey(
    workspaceId: string,
    body: {
      device_id: string
      sender_device_id: string
      key_version?: number
      encrypted_kek: string
      nonce: string
      is_active: boolean
    }
  ) {
    return unwrap(await api.POST('/api/encryption/workspaces/{workspace_id}/keys', {
      params: { path: { workspace_id: workspaceId } },
      body,
    }))
  },

  async getDocumentKey(documentId: string) {
    return unwrap(await api.GET('/api/encryption/documents/{document_id}/keys', {
      params: { path: { document_id: documentId } },
    }))
  },

  async saveDocumentKey(
    documentId: string,
    body: {
      key_version?: number
      encrypted_dek: string
      nonce: string
      is_active: boolean
    }
  ) {
    return unwrap(await api.POST('/api/encryption/documents/{document_id}/keys', {
      params: { path: { document_id: documentId } },
      body,
    }))
  },

  async getWorkspaceKekBackup(workspaceId: string) {
    return unwrap(await api.GET('/api/encryption/workspaces/{workspace_id}/kek-backup', {
      params: { path: { workspace_id: workspaceId } },
    }))
  },

  async saveWorkspaceKekBackup(
    workspaceId: string,
    body: {
      key_version: number
      encrypted_kek: string
      nonce: string
    }
  ) {
    return unwrap(await api.POST('/api/encryption/workspaces/{workspace_id}/kek-backup', {
      params: { path: { workspace_id: workspaceId } },
      body,
    }))
  },

  async completeKekRotation(workspaceId: string, newMinKekVersion: number) {
    return unwrap(await api.POST(
      '/api/encryption/workspaces/{workspace_id}/kek-rotation/complete',
      {
        params: { path: { workspace_id: workspaceId } },
        body: { new_min_kek_version: newMinKekVersion },
      }
    ))
  },
}
