/**
 * Auth API
 */

import type { components } from './schema'
import { api, unwrap } from './core'

export const authApi = {
  async getSalt(email: string) {
    return unwrap(await api.GET('/api/auth/salt', {
      params: { query: { email } },
    }))
  },

  async register(body: components['schemas']['RegisterRequest']) {
    return unwrap(await api.POST('/api/auth/register', { body }))
  },

  async login(body: components['schemas']['LoginRequest']) {
    return unwrap(await api.POST('/api/auth/login', { body }))
  },

  async me() {
    return unwrap(await api.GET('/api/auth/me'))
  },

  async logout() {
    const { data } = await api.POST('/api/auth/logout')
    return data
  },

  async getRecoveryData(email: string) {
    return unwrap(await api.GET('/api/auth/recovery', {
      params: { query: { email } },
    }))
  },

  async getRecoveryChallenge(email: string) {
    return unwrap(await api.POST('/api/auth/recovery/challenge', {
      body: { email },
    }))
  },

  async createRecoverySession(body: {
    email: string
    challenge: string
    identity_signature: string
    timestamp: number
  }) {
    return unwrap(await api.POST('/api/auth/recovery/session', { body }))
  },
}
