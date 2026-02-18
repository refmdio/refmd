/**
 * Initialize Device State
 *
 * Common device initialization pattern shared between device-register and recovery flows.
 * Sets PoP credentials, persists device ID, and wraps device keys with DSK when available.
 * When DSK persistence is unavailable, returns null so callers can fall back to
 * PDK-wrapped keys in localStorage (registration) or session-only keys (recovery).
 */

import { setPopCredentials } from '@/shared/lib/pop-store'
import {
  ensureDsk,
  wrapAndStoreDeviceKeys,
  storeDeviceId,
  type DeviceKeyPair,
} from '@/shared/lib/crypto'

export async function initializeDeviceState(params: {
  deviceId: string
  deviceKeyPair: DeviceKeyPair
  userId: string
}): Promise<CryptoKey | null> {
  const { deviceId, deviceKeyPair, userId } = params
  setPopCredentials(deviceId, deviceKeyPair.signingPrivateKey)
  await storeDeviceId(deviceId)

  const dsk = await ensureDsk()
  if (!dsk) return null

  await wrapAndStoreDeviceKeys(deviceKeyPair, dsk, userId)
  return dsk
}
