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
    const { data, error, response } = await api.POST('/api/auth/logout')

    if (error) {
      throw new ApiRequestError(response.status, error)
    }

    return data
  },
}
