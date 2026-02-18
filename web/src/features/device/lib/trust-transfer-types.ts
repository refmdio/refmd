/**
 * Trust Transfer Types
 *
 * Shared types and error classes for trust state transfer.
 */

import type { toKeyChangeItem } from '@/shared/lib/crypto'
import type { components } from '@/shared/api'

// --- Shared types ---

export type TrustDeviceInfo = Pick<components['schemas']['DeviceResponse'], 'id' | 'name' | 'signing_public_key' | 'ecdh_public_key'>

export interface TrustStateResponse {
  sender_device_id: string; ciphertext: string; nonce: string; signature: string
}

// --- Error type for blocking abort ---

export class TrustTransferAbortError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'TrustTransferAbortError'
  }
}

// --- Import params ---

export interface ImportParams {
  encryptedState: { encryptedState: Uint8Array; nonce: Uint8Array; signature: Uint8Array }
  senderEcdhPk: Uint8Array
  senderSigningPk: Uint8Array
  transferNonce: Uint8Array
  userId: string
  deviceId: string
  ecdhPrivateKey: Uint8Array
}

// --- Sender action ---

export type SenderAction =
  | { action: 'skip'; reason: string }
  | { action: 'abort'; message: string }
  | { action: 'show_key_change'; senderDeviceId: string; importParams: ImportParams; keyChangeItem: ReturnType<typeof toKeyChangeItem> }
  | { action: 'import'; senderDeviceId: string; importParams: ImportParams }

// --- Fetched data ---

export interface FetchedTrustData {
  transferNonce: Uint8Array
  stateResponse: TrustStateResponse
  devicesWithKeyChange: ReturnType<typeof toKeyChangeItem>[]
  deviceKeyInfos: TrustDeviceInfo[]
}
