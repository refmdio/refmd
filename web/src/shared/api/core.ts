/**
 * API Client Core
 *
 * Client instance, middleware, and error classes.
 */

import createClient, { type Middleware } from 'openapi-fetch'
import type { paths } from './schema'
import { getPopCredentials } from '@/shared/lib/pop-store'
import { getPopHeaders } from '@/shared/lib/crypto'

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
 * - GET /api/devices/{uuid}/keys/umk (new device sets PoP credentials before fetching)
 * - POST /api/devices/{uuid}/keys/umk (distributing UMK - requires sender PoP)
 * - POST /api/trust-transfer/state (existing device submits trust state)
 * - DELETE /api/devices/{uuid} (revoking devices)
 * - GET /api/devices (listing devices)
 *
 * PoP-optional (sent if available, skipped for recovery sessions):
 * - POST /api/devices/pending/{id}/approve (PoP or Recovery)
 */
function isPopExempt(path: string, method?: string): boolean {
  // Check exact/prefix matches for auth endpoints
  if (POP_EXEMPT_PATHS.some(exempt => path.startsWith(exempt))) {
    // Exception: /api/devices/pending/{id}/approve is PoP-optional (not exempt)
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
 * Check if a path has optional PoP (send if credentials available, skip otherwise).
 * Used for endpoints that accept both PoP-verified and recovery sessions.
 */
function isPopOptional(path: string): boolean {
  return path.endsWith('/approve') && path.includes('/api/devices/pending/')
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

    // Fail-close: reject requests to protected paths when PoP credentials are missing
    const credentials = getPopCredentials()
    if (!credentials) {
      // PoP-optional paths (e.g. approve_device): proceed without PoP for recovery sessions
      if (isPopOptional(path)) {
        return request
      }
      throw new Error(`[PoP] Missing credentials for protected path: ${method} ${path}. Ensure device is registered and PoP is established before calling protected endpoints.`)
    }

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
 * Extract a user-friendly error message from an API error or unknown error.
 */
export function getApiErrorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message
  return 'An unexpected error occurred'
}

/**
 * Unwrap an openapi-fetch response, throwing ApiError on failure.
 */
export function unwrap<D>(
  result: { data?: D; error?: { error: string }; response: Response }
): NonNullable<D> {
  if (result.error) {
    throw new ApiError(result.response.status, result.error)
  }
  return result.data as NonNullable<D>
}
