/**
 * DSK Device Keys — Device key wrap/unwrap and device ID storage
 *
 * Handles wrapping/unwrapping device key pairs (ECDH + signing)
 * with the DSK for local persistence in IndexedDB.
 */

import { buildAad, AAD_PURPOSE } from './aad'
import { SIGNATURE_PROTOCOL } from './signature'
import { dbGet, dbSet, DEVICE_KEYS_KEY, DEVICE_ID_KEY } from './dsk-store'

/**
 * Wrapped device keys structure stored in IndexedDB
 */
interface WrappedDeviceKeysData {
  /** Encrypted ECDH private key */
  encryptedEcdhPrivate: ArrayBuffer
  ecdhNonce: Uint8Array
  /** Encrypted signing private key */
  encryptedSigningPrivate: ArrayBuffer
  signingNonce: Uint8Array
  /** Public keys (not encrypted) */
  ecdhPublicKey: Uint8Array
  signingPublicKey: Uint8Array
  /** User ID for AAD binding */
  userId: string
}

/**
 * Build AAD for device ECDH private key encryption
 */
function buildDskDeviceEcdhAad(userId: string): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.DSK_DEVICE_ECDH_PRIVATE,
    user_id: userId,
  })
}

/**
 * Build AAD for device signing private key encryption
 */
function buildDskDeviceSigningAad(userId: string): Uint8Array {
  return buildAad({
    ...SIGNATURE_PROTOCOL,
    purpose: AAD_PURPOSE.DSK_DEVICE_SIGNING_PRIVATE,
    user_id: userId,
  })
}

/**
 * Store device ID in IndexedDB
 */
export async function storeDeviceId(deviceId: string): Promise<void> {
  await dbSet(DEVICE_ID_KEY, deviceId)
}

/**
 * Load device ID from IndexedDB
 */
export async function loadDeviceId(): Promise<string | null> {
  const deviceId = await dbGet<string>(DEVICE_ID_KEY)
  return deviceId ?? null
}

/**
 * Wrap device keys with DSK and store in IndexedDB
 *
 * @param deviceKeys Device key pair (ECDH + signing)
 * @param dsk Device Storage Key
 * @param userId User ID for AAD binding
 */
export async function wrapAndStoreDeviceKeys(
  deviceKeys: {
    ecdhPrivateKey: Uint8Array
    ecdhPublicKey: Uint8Array
    signingPrivateKey: Uint8Array
    signingPublicKey: Uint8Array
  },
  dsk: CryptoKey,
  userId: string
): Promise<void> {
  // Encrypt ECDH private key
  const ecdhNonce = crypto.getRandomValues(new Uint8Array(12))
  const ecdhAad = buildDskDeviceEcdhAad(userId)
  const encryptedEcdhPrivate = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: ecdhNonce as Uint8Array<ArrayBuffer>,
      additionalData: ecdhAad as Uint8Array<ArrayBuffer>,
    },
    dsk,
    deviceKeys.ecdhPrivateKey as Uint8Array<ArrayBuffer>
  )

  // Encrypt signing private key
  const signingNonce = crypto.getRandomValues(new Uint8Array(12))
  const signingAad = buildDskDeviceSigningAad(userId)
  const encryptedSigningPrivate = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: signingNonce as Uint8Array<ArrayBuffer>,
      additionalData: signingAad as Uint8Array<ArrayBuffer>,
    },
    dsk,
    deviceKeys.signingPrivateKey as Uint8Array<ArrayBuffer>
  )

  const wrappedData: WrappedDeviceKeysData = {
    encryptedEcdhPrivate,
    ecdhNonce,
    encryptedSigningPrivate,
    signingNonce,
    ecdhPublicKey: deviceKeys.ecdhPublicKey,
    signingPublicKey: deviceKeys.signingPublicKey,
    userId,
  }

  await dbSet(DEVICE_KEYS_KEY, wrappedData)
}

/**
 * Load and unwrap device keys from IndexedDB
 *
 * @param dsk Device Storage Key
 * @returns Unwrapped device keys, or null if not found
 */
export async function loadAndUnwrapDeviceKeys(
  dsk: CryptoKey
): Promise<{
  ecdhPrivateKey: Uint8Array
  ecdhPublicKey: Uint8Array
  signingPrivateKey: Uint8Array
  signingPublicKey: Uint8Array
  userId: string
} | null> {
  const wrappedData = await dbGet<WrappedDeviceKeysData>(DEVICE_KEYS_KEY)
  if (!wrappedData) {
    return null
  }

  try {
    // Decrypt ECDH private key
    const ecdhAad = buildDskDeviceEcdhAad(wrappedData.userId)
    const ecdhPrivateBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: wrappedData.ecdhNonce as Uint8Array<ArrayBuffer>,
        additionalData: ecdhAad as Uint8Array<ArrayBuffer>,
      },
      dsk,
      wrappedData.encryptedEcdhPrivate
    )

    // Decrypt signing private key
    const signingAad = buildDskDeviceSigningAad(wrappedData.userId)
    const signingPrivateBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: wrappedData.signingNonce as Uint8Array<ArrayBuffer>,
        additionalData: signingAad as Uint8Array<ArrayBuffer>,
      },
      dsk,
      wrappedData.encryptedSigningPrivate
    )

    return {
      ecdhPrivateKey: new Uint8Array(ecdhPrivateBuffer),
      ecdhPublicKey: wrappedData.ecdhPublicKey,
      signingPrivateKey: new Uint8Array(signingPrivateBuffer),
      signingPublicKey: wrappedData.signingPublicKey,
      userId: wrappedData.userId,
    }
  } catch {
    // Decryption failed
    return null
  }
}
