/**
 * API Client for RefMD backend
 *
 * Uses openapi-fetch for type-safe API calls with OpenAPI schema
 */

import createClient from 'openapi-fetch'
import type { paths, components } from './schema'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:3001'

/**
 * Type-safe API client generated from OpenAPI schema
 */
export const api = createClient<paths>({
  baseUrl: API_BASE,
  credentials: 'include', // Include HttpOnly cookies
})

/**
 * Custom error class for API errors
 */
export class ApiRequestError extends Error {
  constructor(
    public status: number,
    public body: components['schemas']['AuthErrorResponse']
  ) {
    super(body.error)
    this.name = 'ApiRequestError'
  }
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public body: { error: string }
  ) {
    super(body.error)
    this.name = 'ApiError'
  }
}

/**
 * Auth API wrapper with error handling
 */
export const authApi = {
  /**
   * Get salt and KDF parameters for a user
   * Returns dummy salt for non-existent users (security feature)
   */
  async getSalt(email: string) {
    const { data, error, response } = await api.GET('/api/auth/salt', {
      params: { query: { email } },
    })

    if (error) {
      throw new ApiRequestError(response.status, error)
    }

    return data
  },

  /**
   * Register a new user with E2EE keys
   */
  async register(body: components['schemas']['RegisterRequest']) {
    const { data, error, response } = await api.POST('/api/auth/register', {
      body,
    })

    if (error) {
      throw new ApiRequestError(response.status, error)
    }

    return data
  },

  /**
   * Login with email and authKey
   * Sets HttpOnly session cookie on success
   */
  async login(body: components['schemas']['LoginRequest']) {
    const { data, error, response } = await api.POST('/api/auth/login', {
      body,
    })

    if (error) {
      throw new ApiRequestError(response.status, error)
    }

    return data
  },

  /**
   * Get current user info (session restoration)
   * Requires valid session cookie
   */
  async me() {
    const { data, error, response } = await api.GET('/api/auth/me')

    if (error) {
      throw new ApiRequestError(response.status, error)
    }

    return data
  },

  /**
   * Logout and clear session cookie
   */
  async logout() {
    const { data } = await api.POST('/api/auth/logout')
    return data
  },
}

export const workspaceApi = {
  async list() {
    const { data, error, response } = await api.GET('/api/workspaces')

    if (error) {
      throw new ApiError(response.status, error)
    }

    return data
  },

  async get(id: string) {
    const { data, error, response } = await api.GET('/api/workspaces/{id}', {
      params: { path: { id } },
    })

    if (error) {
      throw new ApiError(response.status, error)
    }

    return data
  },
}

export const documentApi = {
  async list(
    workspaceId: string,
    params?: { parentId?: string; rootOnly?: boolean; includeArchived?: boolean }
  ) {
    const { data, error, response } = await api.GET(
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
    )

    if (error) {
      throw new ApiError(response.status, error)
    }

    return data
  },

  async get(documentId: string) {
    const { data, error, response } = await api.GET('/api/documents/{document_id}', {
      params: {
        path: { document_id: documentId },
      },
    })

    if (error) {
      throw new ApiError(response.status, error)
    }

    return data
  },

  async create(workspaceId: string, body: components['schemas']['CreateDocumentRequest']) {
    const { data, error, response } = await api.POST(
      '/api/workspaces/{workspace_id}/documents',
      {
        params: { path: { workspace_id: workspaceId } },
        body,
      }
    )

    if (error) {
      throw new ApiError(response.status, error)
    }

    return data
  },

  async update(documentId: string, body: components['schemas']['UpdateDocumentRequest']) {
    const { data, error, response } = await api.PATCH('/api/documents/{document_id}', {
      params: { path: { document_id: documentId } },
      body,
    })

    if (error) {
      throw new ApiError(response.status, error)
    }

    return data
  },

  async delete(documentId: string) {
    const { error, response } = await api.DELETE('/api/documents/{document_id}', {
      params: { path: { document_id: documentId } },
    })

    if (error) {
      throw new ApiError(response.status, error)
    }
  },

  async archive(documentId: string) {
    const { data, error, response } = await api.POST('/api/documents/{document_id}/archive', {
      params: { path: { document_id: documentId } },
    })

    if (error) {
      throw new ApiError(response.status, error)
    }

    return data
  },

  async unarchive(documentId: string) {
    const { data, error, response } = await api.POST('/api/documents/{document_id}/unarchive', {
      params: { path: { document_id: documentId } },
    })

    if (error) {
      throw new ApiError(response.status, error)
    }

    return data
  },

  /**
   * List document updates (CRDT update log)
   */
  async listUpdates(documentId: string, afterSeq?: number) {
    const { data, error, response } = await api.GET('/api/documents/{document_id}/updates', {
      params: {
        path: { document_id: documentId },
        query: afterSeq !== undefined ? { after_seq: afterSeq } : undefined,
      },
    })

    if (error) {
      throw new ApiError(response.status, error)
    }

    return data
  },

  /**
   * Create a document update (CRDT update)
   */
  async createUpdate(
    documentId: string,
    body: {
      update_data: string
      nonce: string
      key_version: number
      timestamp: number
    }
  ) {
    const { data, error, response } = await api.POST('/api/documents/{document_id}/updates', {
      params: { path: { document_id: documentId } },
      body,
    })

    if (error) {
      throw new ApiError(response.status, error)
    }

    return data
  },
}

export const encryptionApi = {
  /**
   * Get workspace key (KEK)
   * @param deviceId - Device ID (optional, for multi-device support)
   */
  async getWorkspaceKey(workspaceId: string, deviceId?: string) {
    const { data, error, response } = await api.GET('/api/encryption/workspaces/{workspace_id}/keys', {
      params: {
        path: { workspace_id: workspaceId },
        query: { device_id: deviceId },
      },
    })

    if (error) {
      throw new ApiError(response.status, error)
    }

    return data
  },

  /**
   * Save workspace key (KEK)
   */
  async saveWorkspaceKey(
    workspaceId: string,
    body: {
      device_id?: string
      sender_device_id?: string
      key_version?: number
      encrypted_kek: string
      nonce: string
      is_active: boolean
    }
  ) {
    const { data, error, response } = await api.POST('/api/encryption/workspaces/{workspace_id}/keys', {
      params: { path: { workspace_id: workspaceId } },
      body,
    })

    if (error) {
      throw new ApiError(response.status, error)
    }

    return data
  },

  /**
   * Get document key (DEK)
   */
  async getDocumentKey(documentId: string) {
    const { data, error, response } = await api.GET('/api/encryption/documents/{document_id}/keys', {
      params: { path: { document_id: documentId } },
    })

    if (error) {
      throw new ApiError(response.status, error)
    }

    return data
  },

  /**
   * Save document key (DEK)
   */
  async saveDocumentKey(
    documentId: string,
    body: {
      key_version?: number
      encrypted_dek: string
      nonce: string
      is_active: boolean
    }
  ) {
    const { data, error, response } = await api.POST('/api/encryption/documents/{document_id}/keys', {
      params: { path: { document_id: documentId } },
      body,
    })

    if (error) {
      throw new ApiError(response.status, error)
    }

    return data
  },
}
