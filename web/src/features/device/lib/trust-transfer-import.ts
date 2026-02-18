/**
 * Trust Transfer Import
 *
 * Decrypt and import trust state from an existing device.
 */

import { decryptTrustState } from '@/shared/lib/crypto'
import { importTofuEntries } from '@/shared/lib/trust-store'
import { logger } from '@/shared/lib/logger'
import type { ImportParams } from './trust-transfer-types'

// --- Decrypt and import ---

interface TrustTransferImportParams {
  encryptedState: { encryptedState: Uint8Array; nonce: Uint8Array; signature: Uint8Array }
  ecdhPrivateKey: Uint8Array
  senderEcdhPk: Uint8Array
  senderSigningPk: Uint8Array
  transferNonce: Uint8Array
  userId: string
  senderDeviceId: string
  targetDeviceId: string
}

async function decryptAndImportTrustState(params: TrustTransferImportParams): Promise<void> {
  const snapshot = decryptTrustState(
    params.encryptedState,
    params.ecdhPrivateKey,
    params.senderEcdhPk,
    params.senderSigningPk,
    params.transferNonce,
    {
      userId: params.userId,
      senderDeviceId: params.senderDeviceId,
      targetDeviceId: params.targetDeviceId,
    }
  )
  await importTofuEntries(snapshot.tofuEntries)
}

/**
 * Import trust state with error handling.
 * Returns null on success, error message string on failure (non-blocking).
 */
export async function safeImportTrustState(params: ImportParams, senderDeviceId: string): Promise<string | null> {
  try {
    await decryptAndImportTrustState({
      encryptedState: params.encryptedState,
      ecdhPrivateKey: params.ecdhPrivateKey,
      senderEcdhPk: params.senderEcdhPk,
      senderSigningPk: params.senderSigningPk,
      transferNonce: params.transferNonce,
      userId: params.userId,
      senderDeviceId,
      targetDeviceId: params.deviceId,
    })
    return null
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Trust state import failed'
    logger.warn('trust-transfer', `Trust state import failed (non-blocking): ${message}`)
    return message
  }
}
