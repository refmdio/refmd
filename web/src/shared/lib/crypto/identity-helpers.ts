/**
 * Identity Key Helpers
 *
 * Convenience functions for decrypting identity keys from API responses.
 */

import { decryptIdentityPrivateKeys, type IdentityKeyPair } from './identity'
import { base64UrlDecode } from './encoding'

export interface EncryptedIdentityKeysResponse {
  encrypted_ecdh_private: string
  encrypted_ecdh_private_nonce: string
  encrypted_signing_private: string
  encrypted_signing_private_nonce: string
}

export function decryptIdentityKeysFromResponse(
  keys: EncryptedIdentityKeysResponse,
  umk: Uint8Array,
  userId: string
): IdentityKeyPair {
  return decryptIdentityPrivateKeys(
    {
      encryptedEcdhPrivate: base64UrlDecode(keys.encrypted_ecdh_private),
      ecdhPrivateNonce: base64UrlDecode(keys.encrypted_ecdh_private_nonce),
      encryptedSigningPrivate: base64UrlDecode(keys.encrypted_signing_private),
      signingPrivateNonce: base64UrlDecode(keys.encrypted_signing_private_nonce),
    },
    umk,
    userId
  )
}
