/**
 * Ephemeral Message Send Helper
 *
 * Encrypts an ephemeral payload with the document DEK and signs
 * the WS envelope with the device signing key, then sends via WS.
 */

import { ed25519 } from '@noble/curves/ed25519.js'
import {
  base64UrlEncode,
  encryptContent,
  buildWsEnvelopeMessage,
  WS_SIGNATURE_PREFIX,
} from '@/shared/lib/crypto'
import type { DeviceState } from '@/shared/model/auth-types'
import type { DocumentWebSocket } from './ws'
import type { DocumentState } from './types'

/**
 * Encrypt, sign, and send an ephemeral message through the WebSocket.
 *
 * @param payload   Raw ephemeral payload (already encoded via encodeEphemeralPayload)
 * @param state     Current document state (provides DEK, keyVersion)
 * @param ws        WebSocket connection
 * @param device    Current device state (signing keys)
 * @param documentId Document ID for AAD binding
 */
export function sendEphemeralEnvelope(
  payload: Uint8Array,
  state: DocumentState,
  ws: DocumentWebSocket,
  device: DeviceState,
  documentId: string,
): void {
  // Encrypt with document DEK (same AAD as document content)
  const { encrypted, nonce } = encryptContent(payload, state.dek, documentId, state.keyVersion)
  const ciphertextB64 = base64UrlEncode(encrypted)
  const nonceB64 = base64UrlEncode(nonce)

  const publicData: Record<string, unknown> = {
    docId: documentId,
    deviceId: device.deviceId,
    signingPubKey: base64UrlEncode(device.deviceKeys.signingPublicKey),
  }

  // Sign envelope
  const envelopeMessage = buildWsEnvelopeMessage(
    WS_SIGNATURE_PREFIX.EPHEMERAL,
    ciphertextB64,
    nonceB64,
    publicData,
    base64UrlEncode,
  )
  const signature = ed25519.sign(envelopeMessage, device.deviceKeys.signingPrivateKey)

  ws.send({
    envelope: {
      ciphertext: ciphertextB64,
      nonce: nonceB64,
      signature: base64UrlEncode(signature),
      publicData,
    },
    type: 'ephemeral',
  })
}
