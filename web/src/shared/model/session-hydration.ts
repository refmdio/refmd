/**
 * Session hydration helpers
 *
 * Builds AuthState / DeviceState objects for setFullSession() calls.
 * Centralises the object-construction pattern that was repeated in 5 places.
 */

import type { AuthState, DeviceState } from './auth-types'
import type { IdentityKeyPair, DeviceKeyPair } from '@/shared/lib/crypto'

export function buildAuthState(params: {
  userId: string
  email: string
  expiresAt: Date | string
  umk: Uint8Array
  identityKeys: IdentityKeyPair
}): AuthState {
  return {
    userId: params.userId,
    email: params.email,
    expiresAt:
      params.expiresAt instanceof Date
        ? params.expiresAt
        : new Date(params.expiresAt),
    umk: params.umk,
    identityKeys: params.identityKeys,
  }
}

export function buildDeviceState(params: {
  deviceId: string
  deviceKeys: DeviceKeyPair
}): DeviceState {
  return {
    deviceId: params.deviceId,
    deviceKeys: params.deviceKeys,
  }
}
