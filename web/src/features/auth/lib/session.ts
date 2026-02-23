/**
 * Session Restoration
 *
 * Handles restoring user sessions from cached credentials (DSK, PDK, sessionStorage).
 */

import { authApi, ApiError } from '@/shared/api'
import type { components } from '@/shared/api'
import {
  deriveAuthKeys,
  unwrapUmk,
  decryptIdentityKeysFromResponse,
  base64UrlDecode,
  loadDsk,
  loadAndUnwrapUmk,
  clearDskData,
  hasCachedSession,
  storeDeviceId,
  loadDeviceId,
  loadSessionUmk,
  clearSessionUmk,
  unwrapPdkDeviceKeys,
  unwrapPdkUmk,
  hasPdkWrappedDeviceKeys,
  type IdentityKeyPair,
  type DeviceKeyPair,
} from '@/shared/lib/crypto'
import { persistDeviceKeysToDsk, loadDeviceKeysFromDsk, updatePdkWraps, buildDeviceKeyPairFromPdk } from './key-persistence'


type MeResponse = components['schemas']['MeResponse']

/** Call authApi.me(), returning null on 401 instead of throwing. */
async function fetchMeOrNull(): Promise<MeResponse | null> {
  try {
    return await authApi.me()
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) return null
    throw error
  }
}

export interface SessionRestoreResult {
  userId: string
  email: string
  umk: Uint8Array
  identityKeys: IdentityKeyPair
  expiresAt: Date
  deviceData?: {
    deviceId: string
    deviceKeys: DeviceKeyPair
  }
}

export interface PdkSessionRestoreResult extends SessionRestoreResult {
  deviceId: string
  deviceKeys: DeviceKeyPair
}

export interface PdkFallbackRequired {
  type: 'pdk_fallback_required'
  email: string
}

/** Try to load cached UMK from sessionStorage or IndexedDB. */
async function loadCachedUmk(): Promise<{ umk: Uint8Array; userId: string } | null> {
  // 1. sessionStorage (tab-scoped, for rememberMe=false)
  const sessionData = loadSessionUmk()
  if (sessionData) return sessionData

  // 2. IndexedDB DSK-wrapped UMK (persistent, for rememberMe=true)
  try {
    if (await hasCachedSession()) {
      const dsk = await loadDsk()
      if (dsk) {
        const unwrapped = await loadAndUnwrapUmk(dsk)
        if (unwrapped) return unwrapped
        console.warn('[session] DSK found but UMK unwrap failed (corrupted or tampered)')
      } else {
        console.warn('[session] hasCachedSession=true but loadDsk returned null')
      }
    }
  } catch (e) {
    console.warn('[session] IndexedDB error during UMK load:', e)
  }

  return null
}

/** Try to load device keys from DSK store. */
async function loadDeviceData(userId: string): Promise<SessionRestoreResult['deviceData']> {
  try {
    const deviceId = await loadDeviceId()
    if (!deviceId) {
      console.warn('[session] No device ID in IndexedDB')
      return undefined
    }

    const deviceKeys = await loadDeviceKeysFromDsk(userId)
    if (!deviceKeys) {
      console.warn('[session] Device ID found but device keys unavailable')
      return undefined
    }

    return { deviceId, deviceKeys }
  } catch (e) {
    console.warn('[session] Error loading device data from IndexedDB:', e)
    return undefined
  }
}

/**
 * Restore session from cache
 *
 * Checks for UMK in order of preference:
 * 1. sessionStorage (for rememberMe=false, persists until tab close)
 * 2. IndexedDB wrapped with DSK (for rememberMe=true, persists across restarts)
 * 3. If DSK fails but PDK-wrapped keys exist, signals that password re-entry is needed
 */
export async function restoreSession(): Promise<SessionRestoreResult | PdkFallbackRequired | null> {
  const cached = await loadCachedUmk()

  if (!cached) {
    // No cached UMK — check if we can prompt for password to recover
    if (hasPdkWrappedDeviceKeys()) {
      const meResponse = await fetchMeOrNull()
      if (meResponse?.auth_type === 'password' && meResponse.device_verified && meResponse.device_id) {
        console.warn('[session] No cached UMK but session cookie valid — requesting PDK fallback')
        return { type: 'pdk_fallback_required', email: meResponse.email }
      }
    }
    console.warn('[session] No cached UMK and no PDK fallback available')
    return null
  }

  const { umk, userId: cachedUserId } = cached

  // Validate session with server
  const meResponse = await fetchMeOrNull()
  if (!meResponse) {
    console.warn('[session] Session cookie invalid or expired (401 from /me)')
    clearSessionUmk()
    return null
  }

  if (cachedUserId !== meResponse.user_id) {
    console.warn('[session] Cached user ID mismatch — clearing local state')
    clearSessionUmk()
    await clearDskData()
    return null
  }

  if (!meResponse.device_verified || !meResponse.keys) {
    console.warn('[session] Device not verified or keys missing in /me response')
    clearSessionUmk()
    return null
  }

  const deviceData = await loadDeviceData(meResponse.user_id)

  if (!deviceData) {
    // Device keys lost from IndexedDB but we still have UMK + valid session.
    // Try PDK fallback to re-derive device keys without requiring password re-entry.
    if (hasPdkWrappedDeviceKeys() && meResponse.auth_type === 'password') {
      console.warn('[session] Device keys lost from IndexedDB — requesting PDK fallback')
      return { type: 'pdk_fallback_required', email: meResponse.email }
    }
    console.warn('[session] Device keys unavailable and no PDK fallback — session unrecoverable')
    clearSessionUmk()
    return null
  }

  const identityKeys = decryptIdentityKeysFromResponse(meResponse.keys, umk, meResponse.user_id)

  return {
    userId: meResponse.user_id,
    email: meResponse.email,
    umk,
    identityKeys,
    expiresAt: new Date(meResponse.expires_at),
    deviceData,
  }
}

/**
 * Restore session using PDK fallback (password re-entry)
 *
 * Called when restoreSession() returns PdkFallbackRequired.
 */
export async function restoreSessionWithPdk(
  email: string,
  password: string
): Promise<PdkSessionRestoreResult | null> {
  const saltResponse = await authApi.getSalt(email)
  const derivedKeys = await deriveAuthKeys(password, saltResponse.salt, saltResponse.kdf_params)

  const pdkKeys = unwrapPdkDeviceKeys(derivedKeys.pdk)
  if (!pdkKeys) {
    return null
  }

  const meResponse = await fetchMeOrNull()
  if (!meResponse) return null

  if (pdkKeys.userId !== meResponse.user_id) return null
  if (!meResponse.device_verified || !meResponse.device_id || !meResponse.keys) return null
  if (pdkKeys.deviceId !== meResponse.device_id) return null

  // Decrypt UMK: try server-returned PUK-wrapped UMK first, fall back to PDK-wrapped UMK in localStorage
  const keys = meResponse.keys
  let umk: Uint8Array
  if (keys.encrypted_umk && keys.umk_nonce) {
    const encryptedUmk = base64UrlDecode(keys.encrypted_umk)
    const umkNonce = base64UrlDecode(keys.umk_nonce)
    umk = unwrapUmk(encryptedUmk, umkNonce, derivedKeys.puk, meResponse.user_id)
  } else {
    // Fallback: recover UMK from PDK-wrapped localStorage
    const pdkUmk = unwrapPdkUmk(derivedKeys.pdk)
    if (!pdkUmk || pdkUmk.userId !== meResponse.user_id) return null
    umk = pdkUmk.umk
  }

  // Decrypt identity keys
  const identityKeys = decryptIdentityKeysFromResponse(keys, umk, meResponse.user_id)

  const deviceKeys = buildDeviceKeyPairFromPdk(pdkKeys)

  // Persist device ID
  await storeDeviceId(meResponse.device_id)

  // Re-establish DSK and persist device keys + UMK
  await persistDeviceKeysToDsk(deviceKeys, meResponse.user_id, umk)

  // Update PDK wraps
  updatePdkWraps(deviceKeys, derivedKeys.pdk, umk, meResponse.user_id, meResponse.device_id)

  return {
    userId: meResponse.user_id,
    email: meResponse.email,
    umk,
    identityKeys,
    expiresAt: new Date(meResponse.expires_at),
    deviceId: meResponse.device_id,
    deviceKeys,
  }
}

