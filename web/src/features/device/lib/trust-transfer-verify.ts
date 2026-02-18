/**
 * Trust Transfer Verification
 *
 * TOFU verification for sender devices and device lists.
 */

import {
  base64UrlDecode,
  evaluateDeviceTofu,
  verifyDeviceListTofu,
  toKeyChangeItem,
} from '@/shared/lib/crypto'
import { logger } from '@/shared/lib/logger'
import type { TrustDeviceInfo, TrustStateResponse, ImportParams, SenderAction } from './trust-transfer-types'
import { TrustTransferAbortError } from './trust-transfer-types'

// --- Sender verification ---

type SenderVerificationResult =
  | { status: 'sender_not_found' }
  | { status: 'abort' }
  | {
      status: 'key_changed'
      decision: import('@/shared/lib/crypto').TofuDecision & { action: 'key_changed' }
      senderDeviceId: string
      senderDeviceName: string
      senderEcdhPk: Uint8Array
      senderSigningPk: Uint8Array
    }
  | { status: 'verified'; senderEcdhPk: Uint8Array; senderSigningPk: Uint8Array }

async function verifySenderForTrustTransfer(params: {
  devices: TrustDeviceInfo[]
  senderDeviceId: string
  userId: string
}): Promise<SenderVerificationResult> {
  const senderDevice = params.devices.find(d => d.id === params.senderDeviceId)
  if (!senderDevice) return { status: 'sender_not_found' }

  const senderEcdhPk = base64UrlDecode(senderDevice.ecdh_public_key)
  const senderSigningPk = base64UrlDecode(senderDevice.signing_public_key)

  const decision = await evaluateDeviceTofu(
    params.userId, params.senderDeviceId, senderDevice.signing_public_key, senderDevice.ecdh_public_key
  )

  if (decision.action === 'abort') return { status: 'abort' }
  if (decision.action === 'key_changed') {
    return {
      status: 'key_changed',
      decision,
      senderDeviceId: params.senderDeviceId,
      senderDeviceName: senderDevice.name,
      senderEcdhPk,
      senderSigningPk,
    }
  }

  return { status: 'verified', senderEcdhPk, senderSigningPk }
}

// --- Device TOFU verification ---

export async function verifyAllDevicesTofu(
  devices: TrustDeviceInfo[],
  userId: string
): Promise<Array<ReturnType<typeof toKeyChangeItem>>> {
  const result = await verifyDeviceListTofu(devices, userId)

  if (result.abortedDevice) {
    throw new TrustTransferAbortError(
      `Trust transfer aborted: Device "${result.abortedDevice.name}" has a key mismatch. This may indicate a security issue.`
    )
  }

  if (result.failedDevices.length > 0) {
    const names = result.failedDevices.map(d => d.name).join(', ')
    logger.warn('trust-transfer', `${result.failedDevices.length} device(s) failed TOFU verification: ${names}`)
  }

  return result.keyChangeItems
}

// --- Helpers ---

function extractSenderKeys(result: SenderVerificationResult): { ecdhPk: Uint8Array; signingPk: Uint8Array } {
  if ('senderEcdhPk' in result) {
    return { ecdhPk: result.senderEcdhPk, signingPk: result.senderSigningPk }
  }
  return { ecdhPk: new Uint8Array(0), signingPk: new Uint8Array(0) }
}

function decodeEncryptedState(stateResponse: TrustStateResponse) {
  return {
    encryptedState: base64UrlDecode(stateResponse.ciphertext),
    nonce: base64UrlDecode(stateResponse.nonce),
    signature: base64UrlDecode(stateResponse.signature),
  }
}

function buildImportParams(
  stateResponse: TrustStateResponse,
  senderResult: SenderVerificationResult,
  transferNonce: Uint8Array,
  userId: string,
  deviceId: string,
  ecdhPrivateKey: Uint8Array,
): ImportParams {
  const senderKeys = extractSenderKeys(senderResult)
  return {
    encryptedState: decodeEncryptedState(stateResponse),
    senderEcdhPk: senderKeys.ecdhPk,
    senderSigningPk: senderKeys.signingPk,
    transferNonce, userId, deviceId, ecdhPrivateKey,
  }
}

function resolveSenderAction(
  senderResult: SenderVerificationResult,
  importParams: ImportParams,
  senderDeviceId: string,
): SenderAction {
  if (senderResult.status === 'sender_not_found') {
    return { action: 'skip', reason: 'Sender device not found' }
  }
  if (senderResult.status === 'abort') {
    return { action: 'abort', message: 'Trust transfer aborted: Sender device key mismatch detected.' }
  }
  if (senderResult.status === 'key_changed') {
    return {
      action: 'show_key_change',
      senderDeviceId,
      importParams,
      keyChangeItem: toKeyChangeItem(senderResult.decision, senderResult.senderDeviceName),
    }
  }
  return { action: 'import', senderDeviceId, importParams }
}

// --- Orchestration ---

export async function verifySenderAndResolve(
  devices: TrustDeviceInfo[],
  stateResponse: TrustStateResponse,
  transferNonce: Uint8Array,
  userId: string,
  deviceId: string,
  ecdhPrivateKey: Uint8Array,
): Promise<SenderAction> {
  const senderResult = await verifySenderForTrustTransfer({
    devices,
    senderDeviceId: stateResponse.sender_device_id,
    userId,
  })
  const importParams = buildImportParams(stateResponse, senderResult, transferNonce, userId, deviceId, ecdhPrivateKey)
  return resolveSenderAction(senderResult, importParams, stateResponse.sender_device_id)
}

export function buildDirectImportAction(
  devices: TrustDeviceInfo[],
  stateResponse: TrustStateResponse,
  transferNonce: Uint8Array,
  userId: string,
  deviceId: string,
  ecdhPrivateKey: Uint8Array,
): SenderAction {
  const senderDevice = devices.find(d => d.id === stateResponse.sender_device_id)
  if (!senderDevice) {
    return { action: 'skip', reason: 'Sender device not found' }
  }

  const senderEcdhPk = base64UrlDecode(senderDevice.ecdh_public_key)
  const senderSigningPk = base64UrlDecode(senderDevice.signing_public_key)
  const importParams: ImportParams = {
    encryptedState: decodeEncryptedState(stateResponse),
    senderEcdhPk,
    senderSigningPk,
    transferNonce, userId, deviceId, ecdhPrivateKey,
  }
  return { action: 'import', senderDeviceId: stateResponse.sender_device_id, importParams }
}
