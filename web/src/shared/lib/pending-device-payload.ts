/**
 * Pending Device Payload Builder
 *
 * Shared logic for building createPendingDevice API payloads.
 * Used by both new device registration and account recovery flows.
 */

import {
  generateClientNonce,
  base64UrlEncode,
  type DeviceKeyPair,
} from '@/shared/lib/crypto'
import type { DeviceType } from '@/shared/lib/device'

export interface PendingDevicePayload {
  device_name: string
  device_type: DeviceType
  ecdh_public_key: string
  signing_public_key: string
  client_nonce: string
}

export interface PendingDevicePayloadResult {
  payload: PendingDevicePayload
  clientNonce: Uint8Array
}

export function buildPendingDevicePayload(
  deviceKeyPair: DeviceKeyPair,
  deviceName: string,
  deviceType: DeviceType,
): PendingDevicePayloadResult {
  const clientNonce = generateClientNonce()
  return {
    payload: {
      device_name: deviceName,
      device_type: deviceType,
      ecdh_public_key: base64UrlEncode(deviceKeyPair.ecdhPublicKey),
      signing_public_key: base64UrlEncode(deviceKeyPair.signingPublicKey),
      client_nonce: base64UrlEncode(clientNonce),
    },
    clientNonce,
  }
}
