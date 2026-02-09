/**
 * API Client for RefMD backend
 *
 * Uses openapi-fetch for type-safe API calls with OpenAPI schema
 */

import createClient, { type Middleware } from 'openapi-fetch'
import type { paths, components } from './schema'
import { getPopCredentials } from '@/shared/lib/pop-store'
import { getPopHeaders } from '@/shared/lib/crypto/pop'

export const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

/**
 * Paths that don't require PoP headers (auth endpoints)
 */
const POP_EXEMPT_PATHS = [
  '/api/auth/salt',
  '/api/auth/register',
  '/api/auth/login',
  '/api/auth/logout',
  '/api/auth/me',
  '/api/auth/recovery', // Recovery data fetch doesn't require PoP
  '/api/auth/pop-challenge', // Challenge request itself doesn't require PoP
  '/api/auth/recovery/challenge', // Recovery challenge doesn't require PoP
  '/api/auth/recovery/session', // Recovery session creation doesn't require PoP
  '/api/devices/pending', // Pending device creation doesn't require PoP
  '/api/trust-transfer/nonce', // Nonce request from new device
  // Note: /api/trust-transfer/state is NOT exempt for POST (existing device submits with PoP)
  // but IS exempt for GET (new device retrieves without PoP yet)
]

/**
 * Check if a path is exempt from PoP requirements
 *
 * Most device endpoints require PoP. Only specific patterns for new device
 * setup are exempt:
 * - /api/devices/pending (POST: create, GET: list)
 * - /api/devices/pending/{id}/sas (GET: SAS data)
 * - /api/devices/pending/{id}/events (GET: SSE)
 * - /api/devices/pending/{id} (DELETE: reject)
 * - GET /api/trust-transfer/state (new device retrieving trust state)
 *
 * Endpoints that require PoP:
 * - POST /api/devices/pending/{id}/approve (approving device - ADR-009)
 * - GET /api/devices/{uuid}/keys/umk (new device sets PoP credentials before fetching)
 * - POST /api/devices/{uuid}/keys/umk (distributing UMK - requires sender PoP)
 * - POST /api/trust-transfer/state (existing device submits trust state)
 * - DELETE /api/devices/{uuid} (revoking devices)
 * - GET /api/devices (listing devices)
 */
function isPopExempt(path: string, method?: string): boolean {
  // Check exact/prefix matches for auth endpoints
  if (POP_EXEMPT_PATHS.some(exempt => path.startsWith(exempt))) {
    // Exception: /api/devices/pending/{id}/approve requires PoP
    if (path.endsWith('/approve')) {
      return false
    }
    return true
  }
  // GET /api/devices/{id}/keys/umk requires PoP (new device sets PoP credentials before fetching)
  // POST to same endpoint (distribute) also requires PoP
  // Trust transfer state: GET is exempt (new device retrieves), POST requires PoP (existing device submits)
  if (path === '/api/trust-transfer/state' && method === 'GET') {
    return true
  }
  return false
}

/**
 * Middleware that adds PoP headers to protected requests
 *
 * For each PoP-protected request:
 * 1. Fetches a server-issued challenge from /api/auth/pop-challenge
 * 2. Signs the challenge with the device signing key
 * 3. Attaches the challenge and signature as headers
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
      // Fetch server-issued challenge and sign it
      const popHeaders = await getPopHeaders(
        API_BASE,
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

  /**
   * Get recovery data for account recovery
   * Returns encrypted UMK and identity keys needed to restore access
   */
  async getRecoveryData(email: string) {
    const { data, error, response } = await api.GET('/api/auth/recovery', {
      params: { query: { email } },
    })

    if (error) {
      throw new ApiRequestError(response.status, error)
    }

    return data
  },

  /**
   * Get a recovery challenge for account recovery
   * Returns a server-issued challenge to be signed with identity key
   */
  async getRecoveryChallenge(email: string) {
    const { data, error, response } = await api.POST('/api/auth/recovery/challenge', {
      body: { email },
    })

    if (error) {
      throw new ApiRequestError(response.status, error)
    }

    return data
  },

  /**
   * Create a recovery session using identity signature
   * No password required - authenticates via identity key
   */
  async createRecoverySession(body: {
    email: string
    challenge: string
    identity_signature: string
    timestamp: number
  }) {
    const { data, error, response } = await api.POST('/api/auth/recovery/session', {
      body,
    })

    if (error) {
      throw new ApiRequestError(response.status, error)
    }

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
      update_hash: string
      prev_update_hash: string | null
      signature: string
      author_device_id: string
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
   * @param deviceId - Device ID to revoke
   * @param body - Revocation request containing identity signature
   * Returns list of workspace IDs that need KEK rotation
   */
  async revokeDevice(deviceId: string, body: components['schemas']['RevokeDeviceRequest']) {
    const { data, error, response } = await api.DELETE('/api/devices/{id}', {
      params: { path: { id: deviceId } },
      body,
    })

    if (error) {
      throw new ApiError(response.status, error)
    }

    return data
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

/**
 * SSE (Server-Sent Events) URL builders
 *
 * EventSource doesn't work with openapi-fetch, so we provide type-safe URL builders
 * that match the OpenAPI schema paths.
 */
export const sseUrls = {
  /**
   * SSE endpoint for existing devices to receive pending device notifications
   * @see /api/devices/events in OpenAPI schema
   */
  deviceEvents(): string {
    return `${API_BASE}/api/devices/events`
  },

  /**
   * SSE endpoint for a new device waiting for approval
   * @see /api/devices/pending/{id}/events in OpenAPI schema
   */
  pendingDeviceEvents(pendingDeviceId: string): string {
    return `${API_BASE}/api/devices/pending/${pendingDeviceId}/events`
  },
}

export const encryptionApi = {
  /**
   * Get workspace key (KEK)
   * @param deviceId - Device ID (required for multi-device support)
   */
  async getWorkspaceKey(workspaceId: string, deviceId: string) {
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
      device_id: string
      sender_device_id: string
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

  /**
   * Get workspace KEK backup (UMK-wrapped)
   */
  async getWorkspaceKekBackup(workspaceId: string) {
    const { data, error, response } = await api.GET('/api/encryption/workspaces/{workspace_id}/kek-backup', {
      params: { path: { workspace_id: workspaceId } },
    })

    if (error) {
      throw new ApiError(response.status, error)
    }

    return data
  },

  /**
   * Save workspace KEK backup (UMK-wrapped)
   */
  async saveWorkspaceKekBackup(
    workspaceId: string,
    body: {
      key_version: number
      encrypted_kek: string
      nonce: string
    }
  ) {
    const { data, error, response } = await api.POST('/api/encryption/workspaces/{workspace_id}/kek-backup', {
      params: { path: { workspace_id: workspaceId } },
      body,
    })

    if (error) {
      throw new ApiError(response.status, error)
    }

    return data
  },

  /**
   * Complete KEK rotation after distributing new KEKs to all devices
   */
  async completeKekRotation(workspaceId: string, newMinKekVersion: number) {
    const { data, error, response } = await api.POST(
      '/api/encryption/workspaces/{workspace_id}/kek-rotation/complete',
      {
        params: { path: { workspace_id: workspaceId } },
        body: { new_min_kek_version: newMinKekVersion },
      }
    )

    if (error) {
      throw new ApiError(response.status, error)
    }

    return data
  },
}

/**
 * Trust Transfer API wrapper for secure trust state transfer between devices
 */
export const trustTransferApi = {
  /**
   * Request a transfer nonce (new device)
   * Returns a nonce for replay protection
   */
  async requestNonce(deviceId: string) {
    const { data, error, response } = await api.POST('/api/trust-transfer/nonce', {
      body: { device_id: deviceId },
    })

    if (error) {
      throw new ApiError(response.status, error as { error: string })
    }

    return data
  },

  /**
   * Submit encrypted trust state (existing device)
   */
  async submitState(body: {
    target_device_id: string
    transfer_nonce: string
    ciphertext: string
    nonce: string
    signature: string
  }) {
    const { error, response } = await api.POST('/api/trust-transfer/state', {
      body,
    })

    if (error) {
      throw new ApiError(response.status, error as { error: string })
    }
  },

  /**
   * Retrieve encrypted trust state (new device)
   * @param deviceId - The device ID requesting the trust state
   */
  async retrieveState(deviceId: string) {
    const { data, error, response } = await api.GET('/api/trust-transfer/state', {
      params: { query: { device_id: deviceId } },
    })

    if (error) {
      throw new ApiError(response.status, error as { error: string })
    }

    return data
  },
}
