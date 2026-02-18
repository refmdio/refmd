/**
 * Trust Transfer Fetch
 *
 * Network operations for retrieving trust transfer data.
 */

import { base64UrlDecode } from '@/shared/lib/crypto'
import { trustTransferApi, deviceApi } from '@/shared/api'
import { verifyAllDevicesTofu } from './trust-transfer-verify'
import type { TrustStateResponse, FetchedTrustData } from './trust-transfer-types'

/**
 * Phases 1-3: Request nonce, retrieve trust state, verify devices TOFU.
 * Returns null if transfer should be skipped.
 */
export async function fetchTrustData(
  params: { deviceId: string; userId: string }
): Promise<FetchedTrustData | null> {
  const nonceResponse = await trustTransferApi.requestNonce(params.deviceId)
  if (!nonceResponse) return null
  const transferNonce = base64UrlDecode(nonceResponse.nonce)

  const stateResponse = await retryRetrieveState(params.deviceId)
  if (!stateResponse) return null

  const devicesResponse = await deviceApi.listDevices()
  const devicesWithKeyChange = await verifyAllDevicesTofu(devicesResponse.devices, params.userId)

  const deviceKeyInfos = devicesResponse.devices.map(d => ({
    id: d.id, name: d.name,
    signing_public_key: d.signing_public_key,
    ecdh_public_key: d.ecdh_public_key,
  }))

  return { transferNonce, stateResponse, devicesWithKeyChange, deviceKeyInfos }
}

// --- Retry retrieve state ---

export async function retryRetrieveState(
  deviceId: string,
  maxAttempts: number = 10,
  delayMs: number = 500
): Promise<TrustStateResponse | null> {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      const stateResponse = await trustTransferApi.retrieveState(deviceId)
      if (stateResponse) return stateResponse
      await new Promise(r => setTimeout(r, delayMs))
    } catch (err) {
      if (err && typeof err === 'object' && 'status' in err && err.status === 404) {
        await new Promise(r => setTimeout(r, delayMs))
        continue
      }
      return null
    }
  }
  return null
}
