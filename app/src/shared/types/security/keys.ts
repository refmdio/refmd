/**
 * E2EE Key Types
 *
 * Type definitions for the key hierarchy:
 * UMK -> User Key Pair -> Workspace KEK -> Document DEK
 */

/** User Master Key - the root of the key hierarchy */
export interface UserMasterKey {
  /** 32-byte master key (stored encrypted with passphrase) */
  key: Uint8Array
  /** Salt used for passphrase derivation */
  salt: Uint8Array
  /** KDF used (argon2id or pbkdf2) */
  kdf: 'argon2id' | 'pbkdf2'
  /** KDF parameters */
  kdfParams: Argon2Params | Pbkdf2Params
}

export interface Argon2Params {
  type: 'argon2id'
  memory: number
  iterations: number
  parallelism: number
}

export interface Pbkdf2Params {
  type: 'pbkdf2'
  iterations: number
}

/** ECDH Key Pair for key exchange */
export interface EcdhKeyPair {
  /** 32-byte private key */
  privateKey: Uint8Array
  /** 65-byte uncompressed public key */
  publicKey: Uint8Array
}

/** Ed25519 Key Pair for signing */
export interface SigningKeyPair {
  /** 64-byte private key (libsodium format) */
  privateKey: Uint8Array
  /** 32-byte public key */
  publicKey: Uint8Array
}

/** User's complete key set */
export interface UserKeys {
  /** User Master Key */
  umk: Uint8Array
  /** ECDH key pair for key exchange */
  ecdhKeyPair: EcdhKeyPair
  /** Ed25519 key pair for signing */
  signingKeyPair: SigningKeyPair
}

/** Workspace Key Encryption Key */
export interface WorkspaceKek {
  /** Workspace ID */
  workspaceId: string
  /** 32-byte KEK */
  key: Uint8Array
  /** Key version for rotation */
  version: number
}

/** Encrypted KEK as stored on server */
export interface EncryptedWorkspaceKek {
  /** Workspace ID */
  workspaceId: string
  /** User ID this is encrypted for */
  userId: string
  /** Encrypted KEK */
  encryptedKey: Uint8Array
  /** Nonce used for encryption */
  nonce: Uint8Array
  /** Ephemeral public key (for ECDH) */
  ephemeralPublicKey: Uint8Array
  /** Key version */
  version: number
}

/** Document Data Encryption Key */
export interface DocumentDek {
  /** Document ID */
  documentId: string
  /** 32-byte DEK */
  key: Uint8Array
  /** Key version for rotation */
  version: number
}

/** Encrypted DEK as stored on server */
export interface EncryptedDocumentDek {
  /** Document ID */
  documentId: string
  /** Workspace ID */
  workspaceId: string
  /** Encrypted DEK */
  encryptedKey: Uint8Array
  /** Nonce used for encryption */
  nonce: Uint8Array
  /** Key version */
  version: number
  /** KEK version used to encrypt this DEK */
  kekVersion: number
}

/** Share Key for shared links */
export interface ShareKey {
  /** Share token */
  token: string
  /** 32-byte share key */
  key: Uint8Array
  /** Whether this is password-derived */
  isPasswordProtected: boolean
}

/** Encrypted share key as stored on server */
export interface EncryptedShareKey {
  /** Share token */
  token: string
  /** Document ID */
  documentId: string
  /** Encrypted DEK (encrypted with share key) */
  encryptedDek: Uint8Array
  /** Nonce used for encryption */
  nonce: Uint8Array
  /** Salt for password-protected shares (if applicable) */
  salt?: Uint8Array
}

/** Key cache entry with expiration */
export interface CachedKey<T> {
  /** The cached key */
  key: T
  /** Timestamp when cached */
  cachedAt: number
  /** Time-to-live in milliseconds */
  ttl: number
}

/** Public key as stored on server */
export interface UserPublicKeys {
  /** User ID */
  userId: string
  /** ECDH public key (Base64) */
  ecdhPublicKey: string
  /** Ed25519 signing public key (Base64) */
  signingPublicKey: string
  /** When the keys were registered */
  createdAt: string
}
