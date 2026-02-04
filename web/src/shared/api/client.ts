/**
 * API Client for RefMD backend
 *
 * Uses openapi-fetch for type-safe API calls with OpenAPI schema
 */

import createClient, { type Middleware } from 'openapi-fetch'
import type { paths, components } from './schema'
import { getPopCredentials } from '@/shared/lib/pop-store'
import { generatePopHeaders } from '@/shared/lib/crypto/pop'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:3001'

/**
 * Paths that don't require PoP headers (auth endpoints)
 */
const POP_EXEMPT_PATHS = [
  '/api/auth/salt',
  '/api/auth/register',
  '/api/auth/login',
  '/api/auth/logout',
  '/api/auth/me',
  '/api/devices/pending', // Pending device creation doesn't require PoP
]

/**
 * Check if a path is exempt from PoP requirements
 *
 * Most device endpoints require PoP. Only specific patterns for new device
 * setup are exempt:
 * - /api/devices/pending/* (creating/viewing pending devices)
 * - GET /api/devices/{uuid}/keys/umk (new device fetching their UMK)
 *
 * Endpoints that require PoP:
 * - POST /api/devices/{uuid}/keys/umk (distributing UMK - requires sender PoP)
 * - DELETE /api/devices/{uuid} (revoking devices)
 * - GET /api/devices (listing devices)
 */
function isPopExempt(path: string, method?: string): boolean {
  // Check prefix matches (auth endpoints and pending device endpoints)
  if (POP_EXEMPT_PATHS.some(exempt => path.startsWith(exempt))) {
    return true
  }
  // Exempt GET device UMK retrieval (new devices don't have PoP yet)
  // POST to same endpoint (distribute) requires PoP
  // Use case-insensitive regex to handle both uppercase and lowercase UUIDs
  if (
    /^\/api\/devices\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/keys\/umk$/i.test(
      path
    ) && method === 'GET'
  ) {
    return true
  }
  return false
}

/**
 * Middleware that adds PoP headers to protected requests
 */
const popMiddleware: Middleware = {
  async onRequest({ request }) {
    const url = new URL(request.url)
    const path = url.pathname
    const method = request.method

    // Skip PoP for exempt paths
    if (isPopExempt(path, method)) {
      return request
    }

    // Add PoP headers if credentials are available
    const credentials = getPopCredentials()
    if (credentials) {
      const popHeaders = generatePopHeaders(
        credentials.deviceId,
        credentials.signingPrivateKey
      )

      // Add PoP headers to the request
      for (const [key, value] of Object.entries(popHeaders)) {
        request.headers.set(key, value)
      }
    }

    return request
  },
}

/**
 * Type-safe API client generated from OpenAPI schema
 */
export const api = createClient<paths>({
  baseUrl: API_BASE,
  credentials: 'include', // Include HttpOnly cookies
})

// Add PoP middleware
api.use(popMiddleware)

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

/**
 * Device API wrapper for multi-device support
 */
export const deviceApi = {
  /**
   * Create a new pending device
   * Returns pending device ID and expiration time
   */
  async createPendingDevice(body: components['schemas']['CreatePendingDeviceRequest']) {
    const { data, error, response } = await api.POST('/api/devices/pending', {
      body,
    })

    if (error) {
      throw new ApiError(response.status, error)
    }

    return data
  },

  /**
   * List pending devices awaiting approval
   */
  async listPendingDevices() {
    const { data, error, response } = await api.GET('/api/devices/pending')

    if (error) {
      throw new ApiError(response.status, error)
    }

    return data
  },

  /**
   * Get SAS data for pending device verification
   */
  async getSas(pendingDeviceId: string) {
    const { data, error, response } = await api.GET('/api/devices/pending/{id}/sas', {
      params: { path: { id: pendingDeviceId } },
    })

    if (error) {
      throw new ApiError(response.status, error)
    }

    return data
  },

  /**
   * Approve a pending device after SAS verification
   */
  async approveDevice(
    pendingDeviceId: string,
    body: components['schemas']['ApproveDeviceRequest']
  ) {
    const { data, error, response } = await api.POST('/api/devices/pending/{id}/approve', {
      params: { path: { id: pendingDeviceId } },
      body,
    })

    if (error) {
      throw new ApiError(response.status, error)
    }

    return data
  },

  /**
   * Reject a pending device
   */
  async rejectPendingDevice(pendingDeviceId: string) {
    const { error, response } = await api.DELETE('/api/devices/pending/{id}', {
      params: { path: { id: pendingDeviceId } },
    })

    if (error) {
      throw new ApiError(response.status, error)
    }
  },

  /**
   * List all devices for the current user
   */
  async listDevices() {
    const { data, error, response } = await api.GET('/api/devices')

    if (error) {
      throw new ApiError(response.status, error)
    }

    return data
  },

  /**
   * Revoke a device
   */
  async revokeDevice(deviceId: string) {
    const { error, response } = await api.DELETE('/api/devices/{id}', {
      params: { path: { id: deviceId } },
    })

    if (error) {
      throw new ApiError(response.status, error)
    }
  },

  /**
   * Distribute UMK to an approved device
   */
  async distributeUmk(deviceId: string, body: components['schemas']['DistributeUmkRequest']) {
    const { data, error, response } = await api.POST('/api/devices/{id}/keys/umk', {
      params: { path: { id: deviceId } },
      body,
    })

    if (error) {
      throw new ApiError(response.status, error)
    }

    return data
  },

  /**
   * Get encrypted UMK for a device
   * Used by new devices after approval to retrieve their UMK
   */
  async getDeviceUmk(deviceId: string) {
    const { data, error, response } = await api.GET('/api/devices/{id}/keys/umk', {
      params: { path: { id: deviceId } },
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
