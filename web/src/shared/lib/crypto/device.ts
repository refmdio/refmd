/**
 * Device Key Generation & Approval Signatures
 *
 * Generates X25519 ECDH and Ed25519 signing key pairs for new devices.
 * Used during multi-device registration.
 */

import { x25519, ed25519 } from '@noble/curves/ed25519.js'
import { randomBytes } from '@noble/ciphers/utils.js'
import { buildSignatureMessage, SIGNATURE_ACTION } from './signature'

/**
 * Device key pair for E2EE
 */
export interface DeviceKeyPair {
  /** X25519 ECDH private key (32 bytes) */
  ecdhPrivateKey: Uint8Array
  /** X25519 ECDH public key (32 bytes) */
  ecdhPublicKey: Uint8Array
  /** Ed25519 signing private key seed (32 bytes) */
  signingPrivateKey: Uint8Array
  /** Ed25519 signing public key (32 bytes) */
  signingPublicKey: Uint8Array
}

/**
 * Generate a new device key pair
 *
 * Creates:
 * - X25519 ECDH key pair for key exchange
 * - Ed25519 signing key pair for authentication
 *
 * @returns Device key pair
 */
export function generateDeviceKeyPair(): DeviceKeyPair {
  // Generate X25519 ECDH key pair
  const ecdhPrivateKey = x25519.utils.randomSecretKey()
  const ecdhPublicKey = x25519.getPublicKey(ecdhPrivateKey)

  // Generate Ed25519 signing key pair
  const signingPrivateKey = ed25519.utils.randomSecretKey()
  const signingPublicKey = ed25519.getPublicKey(signingPrivateKey)

  return {
    ecdhPrivateKey,
    ecdhPublicKey,
    signingPrivateKey,
    signingPublicKey,
  }
}

/**
 * Generate a client nonce for SAS
 *
 * @returns 16-byte random nonce
 */
export function generateClientNonce(): Uint8Array {
  return randomBytes(16)
}

/**
 * Device approval signature payload (base64url-encoded strings).
 * Shared between interactive approval (useDeviceApprovalFlow)
 * and self-approval (selfApproveDevice) to prevent field-set drift.
 */
export interface DeviceApprovalPayload {
  device_signing_public_key: string
  device_ecdh_public_key: string
  client_nonce: string
}

/**
 * Sign a DEVICE_APPROVAL message with the given signing private key.
 *
 * Builds a canonical signature message (JCS) for the approval payload
 * and signs it with Ed25519.
 *
 * @param payload Device approval payload with base64url-encoded keys
 * @param signingPrivateKey Ed25519 private key seed (32 bytes)
 * @returns Ed25519 signature (64 bytes)
 */
export function signDeviceApproval(
  payload: DeviceApprovalPayload,
  signingPrivateKey: Uint8Array,
): Uint8Array {
  const message = buildSignatureMessage(SIGNATURE_ACTION.DEVICE_APPROVAL, {
    device_signing_public_key: payload.device_signing_public_key,
    device_ecdh_public_key: payload.device_ecdh_public_key,
    client_nonce: payload.client_nonce,
  })
  return ed25519.sign(message, signingPrivateKey)
}

