// Shared types between Crypto Worker and main thread CryptoWorkerClient.
// This file must NOT import crypto libraries (imported by both contexts).
// ── Request types ─────────────────────────────────────────
type CryptoRequestType =
  // Lifecycle
  | "init"
  | "init-from-password"
  | "lock"
  | "get-public-keys"
  | "get-device-id"
  | "is-ready"
  | "set-user-context"
  | "set-dsk"
  | "set-initialized"
  | "clear-transient-keys"
  // Key import (for keys received from server)
  | "import-identity-keys"
  | "import-device-keys"
  | "import-umk"
  // Key generation
  | "generate-identity-keys"
  | "generate-device-keys"
  | "generate-umk"
  | "generate-kek"
  | "generate-dek"
  | "generate-client-nonce"
  | "generate-recovery-key"
  // Password derivation
  | "derive-auth-keys"
  | "derive-ruk"
  | "validate-mnemonic"
  // UMK wrapping
  | "wrap-umk-for-server"
  | "wrap-umk-with-ruk"
  | "unwrap-umk-with-ruk"
  // Identity key wrapping (for server storage)
  | "wrap-identity-keys-for-server"
  // DEK operations
  | "wrap-dek"
  | "unwrap-dek"
  | "encrypt-title"
  | "decrypt-title"
  | "decrypt-title-batch"
  | "encrypt-content"
  | "decrypt-content"
  | "encrypt-snapshot"
  | "decrypt-snapshot"
  | "has-dek"
  | "cache-dek"
  | "evict-dek"
  // KEK operations
  | "set-active-kek-version"
  | "resolve-kek"
  | "encrypt-kek-for-device"
  | "decrypt-kek-from-device-envelope"
  | "encrypt-kek-for-member"
  | "decrypt-kek-from-member-envelope"
  | "wrap-kek-with-umk"
  | "unwrap-kek-from-backup"
  | "encrypt-kek-for-invitation"
  | "decrypt-kek-from-invitation"
  | "cache-kek"
  // Signing
  | "sign-pop"
  | "sign-ws-envelope"
  | "sign-message"
  | "sign-device-approval"
  | "sign-device-registration"
  | "sign-recovery-challenge"
  | "sign-session-proof"
  // Verification
  | "verify-session-proof"
  | "verify-ws-signature"
  | "verify-ed25519"
  | "verify-device-identity-signature"
  // Hashing
  | "compute-update-hash"
  | "compute-snapshot-proof"
  | "blake3-hash"
  | "compute-sas"
  | "calculate-fingerprint"
  // ECDH
  | "ecdh-encrypt"
  | "ecdh-decrypt"
  | "ecdh-encrypt-umk"
  | "ecdh-decrypt-umk"
  // Trust transfer
  | "encrypt-trust-state"
  | "decrypt-trust-state"
  // TOFU
  | "tofu-verify"
  | "tofu-verify-all-devices"
  | "tofu-trust-device"
  | "tofu-update-last-seen"
  | "tofu-handle-result"
  // DSK wrapping (for offline cache / persistence)
  | "wrap-with-dsk"
  | "unwrap-with-dsk"
  | "wrap-umk-with-dsk"
  | "unwrap-umk-from-dsk"
  | "wrap-device-keys-with-dsk"
  | "unwrap-device-keys-from-dsk"
  // Offline cache operations
  | "encrypt-offline-cache"
  | "decrypt-offline-cache"
  | "encrypt-offline-pending"
  | "decrypt-offline-pending"
  | "wrap-dek-for-offline"
  | "unwrap-dek-from-offline"
  | "wrap-kek-for-offline"
  | "unwrap-kek-from-offline"
  // PDK wrapping
  | "wrap-with-pdk"
  | "unwrap-with-pdk"
  // Invitation token
  | "generate-invitation-token"
  // SHA-256
  | "sha256-hash"
  // DSK generation
  | "generate-dsk"
  // TOFU store management
  | "tofu-get-all-entries"
  | "tofu-import-entries";
export interface CryptoRequest {
  id: string;
  type: CryptoRequestType;
  payload: Record<string, unknown>;
}
export interface CryptoResponse {
  id: string;
  type: "success" | "error";
  payload: unknown;
}
// ── Init payloads ─────────────────────────────────────────
export interface PdkWrappedBlobs {
  ciphertext: string;
  nonce: string;
}
export interface InitPdkResult {
  wrappedUmk?: PdkWrappedBlobs;
  wrappedDeviceKeys?: {
    ecdh: PdkWrappedBlobs;
    signing: PdkWrappedBlobs;
  };
}
export interface InitPayload {
  dsk: CryptoKey | null;
  wrappedUmk?: {
    ciphertext: ArrayBuffer;
    iv: ArrayBuffer;
  };
  wrappedDeviceEcdh?: {
    ciphertext: ArrayBuffer;
    iv: ArrayBuffer;
  };
  wrappedDeviceSigning?: {
    ciphertext: ArrayBuffer;
    iv: ArrayBuffer;
  };
  userId: string;
  deviceId: string;
  encryptedIdentityEcdh?: Uint8Array;
  identityEcdhNonce?: Uint8Array;
  encryptedIdentitySigning?: Uint8Array;
  identitySigningNonce?: Uint8Array;
  serverEncryptedUmk?: Uint8Array;
  serverUmkNonce?: Uint8Array;
  // PDK fallback: localStorage blobs for DSK-unavailable environments
  pdkWrappedUmk?: PdkWrappedBlobs;
  pdkWrappedDeviceEcdh?: PdkWrappedBlobs;
  pdkWrappedDeviceSigning?: PdkWrappedBlobs;
  // Request PDK re-wrap of restored keys (for KDF migration / DSK-unavailable persistence)
  returnPdkWrapped?: boolean;
  // Password params for PDK derivation within this single request
  passwordParams?: {
    password: string;
    salt: Uint8Array;
    kdfParams: {
      memory: number;
      iterations: number;
      parallelism: number;
    };
  };
}
export interface InitFromPasswordPayload {
  password: string;
  salt: Uint8Array;
  kdfParams: {
    memory: number;
    iterations: number;
    parallelism: number;
  };
  dsk: CryptoKey | null;
  wrappedDeviceEcdh?: {
    ciphertext: ArrayBuffer;
    iv: ArrayBuffer;
  };
  wrappedDeviceSigning?: {
    ciphertext: ArrayBuffer;
    iv: ArrayBuffer;
  };
  serverEncryptedUmk?: Uint8Array;
  serverUmkNonce?: Uint8Array;
  userId: string;
  deviceId: string;
  encryptedIdentityEcdh?: Uint8Array;
  identityEcdhNonce?: Uint8Array;
  encryptedIdentitySigning?: Uint8Array;
  identitySigningNonce?: Uint8Array;
  pdkWrappedUmk?: PdkWrappedBlobs;
  pdkWrappedDeviceEcdh?: PdkWrappedBlobs;
  pdkWrappedDeviceSigning?: PdkWrappedBlobs;
  returnPdkWrapped?: boolean;
}
// ── Public keys (safe to expose) ──────────────────────────
export interface PublicKeys {
  deviceSigningPublic: Uint8Array;
  deviceEcdhPublic: Uint8Array;
  identitySigningPublic: Uint8Array | null;
  identityEcdhPublic: Uint8Array | null;
}
// ── Title batch ───────────────────────────────────────────
export interface TitleDecryptItem {
  documentId: string;
  keyVersion: number;
  encrypted: Uint8Array;
  nonce: Uint8Array;
}
export interface TitleDecryptResult {
  documentId: string;
  title: string | null;
}
// ── KEK distribution params ───────────────────────────────
export interface KekForDeviceParams {
  workspaceId: string;
  userId: string;
  senderDeviceId: string;
  targetDeviceId: string;
  targetDeviceEcdhPublic: Uint8Array;
  keyVersion: number;
}
export interface KekFromDeviceEnvelopeParams {
  workspaceId: string;
  userId: string;
  senderDeviceId: string;
  targetDeviceId: string;
  senderEcdhPublic: Uint8Array;
  encryptedKek: Uint8Array;
  nonce: Uint8Array;
  keyVersion: number;
}
export interface KekForMemberParams {
  workspaceId: string;
  targetUserId: string;
  targetIdentityEcdhPublic: Uint8Array;
  senderDeviceId: string;
  keyVersion: number;
}
export interface KekFromMemberEnvelopeParams {
  workspaceId: string;
  targetUserId: string;
  senderDeviceId: string;
  senderIdentityEcdhPublic: Uint8Array;
  encryptedKek: Uint8Array;
  nonce: Uint8Array;
  keyVersion: number;
}
export interface KekBackupParams {
  workspaceId: string;
  userId: string;
  keyVersion: number;
}
export interface KekFromBackupParams {
  workspaceId: string;
  userId: string;
  encryptedKek: Uint8Array;
  nonce: Uint8Array;
  keyVersion: number;
}
export interface KekForInvitationParams {
  workspaceId: string;
  invitationId: string;
  token: Uint8Array;
  keyVersion: number;
}
export interface KekFromInvitationParams {
  workspaceId: string;
  invitationId: string;
  token: Uint8Array;
  encryptedKek: Uint8Array;
  nonce: Uint8Array;
  keyVersion: number;
}
// ── SAS result ────────────────────────────────────────────
export interface SasResultData {
  emojis: {
    emoji: string;
    name: string;
  }[];
  hash: Uint8Array;
}
// ── Error codes ───────────────────────────────────────────
export type CryptoErrorCode =
  | "not_initialized"
  | "already_initialized"
  | "rate_limited"
  | "decryption_failed"
  | "signature_failed"
  | "invalid_key"
  | "key_not_found"
  | "tofu_hard_fail"
  | "internal_error";
export interface CryptoError {
  code: CryptoErrorCode;
  message: string;
}
