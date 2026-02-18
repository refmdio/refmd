/**
 * Auth & Device state types (UI-independent)
 *
 * These interfaces describe the authenticated session and device state.
 * Extracted from AuthContext so that pure service functions can depend on
 * them without coupling to React Context.
 */

import type { IdentityKeyPair, DeviceKeyPair } from '@/shared/lib/crypto'

export interface AuthState {
  userId: string
  email: string
  expiresAt: Date
  /** UMK - may be null for device_required state (new device pending approval) */
  umk: Uint8Array | null
  /** Identity keys - may be null for device_required state (new device pending approval) */
  identityKeys: IdentityKeyPair | null
}

export interface DeviceState {
  deviceId: string
  deviceKeys: DeviceKeyPair
}
