import { x25519 } from "@noble/curves/ed25519.js";
import type { CryptoErrorCode } from "../types";
import type { HybridSigningState, WorkerKeyState } from "../state";
import {
  computeSigningKeyId,
  publicKeyMaterialFromPrivate,
  type HybridSigningPrivateKeyMaterial,
} from "../../signature";
import {
  publicHybridEncryptionMaterialFromPrivate,
  type HybridEncryptionPrivateKeyMaterial,
} from "../../hybrid-encryption";
import { base64UrlEncode } from "../../encoding";
import { CryptoOperationError } from "../operation-error";
import { getCachedDek, getCachedKek } from "../state";
export type HandlerPayload = Record<string, unknown>;

const DSK_DERIVATION_SALT = new TextEncoder().encode("refmd-v2-dsk-hkdf-salt");
const DSK_AES_GCM_INFO = new TextEncoder().encode("refmd-v2-dsk-aes-gcm");
const DSK_XCHACHA20_POLY1305_INFO = new TextEncoder().encode("refmd-v2-dsk-xchacha20poly1305");

function wrapCryptoOperationError(code: CryptoErrorCode, error: unknown): CryptoOperationError {
  if (error instanceof CryptoOperationError) return error;
  const message = error instanceof Error ? error.message : "Unknown error";
  return new CryptoOperationError(code, message);
}
export async function withCryptoOperationError<T>(
  code: CryptoErrorCode,
  operation: () => T | Promise<T>,
): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    throw wrapCryptoOperationError(code, error);
  }
}
export function requireUmk(state: WorkerKeyState): Uint8Array {
  if (!state.umk) throw new CryptoOperationError("not_initialized", "UMK not available");
  return state.umk;
}
export function requireDeviceEcdhPrivate(state: WorkerKeyState): Uint8Array {
  if (!state.deviceEcdhPrivate) {
    throw new CryptoOperationError("not_initialized", "Device ECDH private key not available");
  }
  return state.deviceEcdhPrivate;
}
export function requireDeviceHybridSigningPrivateKeyMaterial(
  state: WorkerKeyState,
): HybridSigningPrivateKeyMaterial {
  const signingState = currentDeviceHybridSigningState(state);
  if (!signingState) {
    throw new CryptoOperationError(
      "not_initialized",
      "Device hybrid signing private key material not available",
    );
  }
  return signingState.privateKeyMaterial;
}
export function requireShareParticipantHybridSigningPrivateKeyMaterial(
  state: WorkerKeyState,
): HybridSigningPrivateKeyMaterial {
  const signingState = state.shareParticipantHybridSigningState;
  if (!signingState) {
    throw new CryptoOperationError(
      "not_initialized",
      "Share participant hybrid signing private key material not available",
    );
  }
  return signingState.privateKeyMaterial;
}
export function currentDeviceHybridSigningState(state: WorkerKeyState): HybridSigningState | null {
  return state.deviceHybridSigningState;
}
export function requireDeviceHybridSigningPublicKeyMaterial(
  state: WorkerKeyState,
): HybridSigningState["publicKeyMaterial"] {
  const signingState = currentDeviceHybridSigningState(state);
  if (!signingState) {
    throw new CryptoOperationError(
      "not_initialized",
      "Device hybrid signing public key material not available",
    );
  }
  return signingState.publicKeyMaterial;
}
export function requireDeviceHybridEncryptionPrivateKeyMaterial(
  state: WorkerKeyState,
): HybridEncryptionPrivateKeyMaterial {
  if (!state.deviceHybridEncryptionPrivateKeyMaterial) {
    throw new CryptoOperationError(
      "not_initialized",
      "Device hybrid encryption private key material not available",
    );
  }
  return state.deviceHybridEncryptionPrivateKeyMaterial;
}
export function requireIdentityHybridSigningPrivateKeyMaterial(
  state: WorkerKeyState,
  options: { allowOverdue?: boolean } = {},
): HybridSigningPrivateKeyMaterial {
  assertIdentityPrivateKeyUsable(state);
  if (!state.identityHybridSigningState) {
    throw new CryptoOperationError(
      "not_initialized",
      "Identity hybrid signing private key material not available",
    );
  }
  if (
    !options.allowOverdue &&
    state.identityRotationDueAtMs !== null &&
    state.identityRotationDueAtMs <= Date.now()
  ) {
    throw new CryptoOperationError("key_expired", "Identity signing key rotation is overdue");
  }
  return state.identityHybridSigningState.privateKeyMaterial;
}
export function requireIdentityHybridEncryptionPrivateKeyMaterial(
  state: WorkerKeyState,
): HybridEncryptionPrivateKeyMaterial {
  assertIdentityPrivateKeyUsable(state);
  if (!state.identityHybridEncryptionPrivateKeyMaterial) {
    throw new CryptoOperationError(
      "not_initialized",
      "Identity hybrid encryption private key material not available",
    );
  }
  return state.identityHybridEncryptionPrivateKeyMaterial;
}
export function requireIdentityEcdhPrivate(state: WorkerKeyState): Uint8Array {
  assertIdentityPrivateKeyUsable(state);
  if (!state.identityEcdhPrivate) {
    throw new CryptoOperationError("not_initialized", "Identity ECDH private key not available");
  }
  return state.identityEcdhPrivate;
}

function assertIdentityPrivateKeyUsable(state: WorkerKeyState): void {
  if (state.identityRotationFinalization) {
    throw new CryptoOperationError(
      "key_expired",
      "Identity private key is blocked during rotation finalization",
    );
  }
}
export function requireDsk(state: WorkerKeyState): CryptoKey {
  if (!state.dsk) throw new CryptoOperationError("not_initialized", "DSK not available");
  return state.dsk;
}
export function requireUserId(state: WorkerKeyState): string {
  if (!state.userId) throw new CryptoOperationError("not_initialized", "userId not available");
  return state.userId;
}
export function requireDeviceId(state: WorkerKeyState): string {
  if (!state.deviceId) throw new CryptoOperationError("not_initialized", "deviceId not available");
  return state.deviceId;
}
export function requireKekForWorkspace(
  state: WorkerKeyState,
  workspaceId: string,
  keyVersion?: number,
): {
  kek: Uint8Array;
  keyVersion: number;
} {
  const cached = getCachedKek(state, workspaceId, keyVersion);
  if (!cached) {
    throw new CryptoOperationError(
      "key_not_found",
      `KEK not cached for workspace ${workspaceId}${keyVersion !== undefined ? ` version ${keyVersion}` : ""}`,
    );
  }
  return cached;
}
export function requireDekForDocument(
  state: WorkerKeyState,
  documentId: string,
  keyVersion?: number,
  cacheKey = documentId,
): {
  dek: Uint8Array;
  keyVersion: number;
} {
  const cached = getCachedDek(state, cacheKey, keyVersion);
  if (!cached) {
    throw new CryptoOperationError(
      "key_not_found",
      `DEK not cached for document ${documentId}${keyVersion !== undefined ? ` version ${keyVersion}` : ""}`,
    );
  }
  return cached;
}
export async function dskEncrypt(
  dsk: CryptoKey,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<{
  ciphertext: ArrayBuffer;
  iv: ArrayBuffer;
}> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await deriveDskAesGcmKey(dsk);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: new Uint8Array(aad).buffer },
    aesKey,
    new Uint8Array(plaintext),
  );
  return { ciphertext, iv: iv.buffer };
}
export async function dskDecrypt(
  dsk: CryptoKey,
  ciphertext: ArrayBuffer,
  iv: ArrayBuffer,
  aad: Uint8Array,
): Promise<Uint8Array> {
  const aesKey = await deriveDskAesGcmKey(dsk);
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: new Uint8Array(aad).buffer },
    aesKey,
    ciphertext,
  );
  return new Uint8Array(plaintext);
}

async function deriveDskAesGcmKey(dsk: CryptoKey): Promise<CryptoKey> {
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: DSK_DERIVATION_SALT,
      info: DSK_AES_GCM_INFO,
    },
    dsk,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function deriveDskXChaCha20Poly1305KeyBytes(dsk: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: DSK_DERIVATION_SALT,
        info: DSK_XCHACHA20_POLY1305_INFO,
      },
      dsk,
      256,
    ),
  );
}

export function setIdentityFromDecrypted(
  state: WorkerKeyState,
  identity: {
    ecdhPrivate: Uint8Array;
    ecdhPublic: Uint8Array;
    hybridEncryptionPrivateKeyMaterial: WorkerKeyState["identityHybridEncryptionPrivateKeyMaterial"];
    hybridEncryptionPublicKeyMaterial: WorkerKeyState["identityHybridEncryptionPublicKeyMaterial"];
    hybridSigningPrivateKeyMaterial: HybridSigningPrivateKeyMaterial;
  },
): void {
  const publicKeyMaterial = publicKeyMaterialFromPrivate(identity.hybridSigningPrivateKeyMaterial);
  const signingKeyId = computeSigningKeyId(publicKeyMaterial);

  state.identityEcdhPrivate = identity.ecdhPrivate;
  state.identityEcdhPublic = identity.ecdhPublic;
  state.identityHybridEncryptionPrivateKeyMaterial = identity.hybridEncryptionPrivateKeyMaterial;
  state.identityHybridEncryptionPublicKeyMaterial = identity.hybridEncryptionPublicKeyMaterial;
  state.identityHybridSigningState = {
    privateKeyMaterial: identity.hybridSigningPrivateKeyMaterial,
    publicKeyMaterial,
    signingKeyId,
  };
}
export function setDeviceFromPrivateKeys(
  state: WorkerKeyState,
  ecdhPrivate: Uint8Array,
  hybridEncryptionPrivateKeyMaterial: HybridEncryptionPrivateKeyMaterial,
  hybridSigningPrivateKeyMaterial: HybridSigningPrivateKeyMaterial,
  expectedOwnerKind: "device" | "share_participant_device",
  expectedOwnerId: string,
): void {
  if (
    hybridEncryptionPrivateKeyMaterial.owner_kind !== expectedOwnerKind ||
    hybridEncryptionPrivateKeyMaterial.owner_id !== expectedOwnerId ||
    hybridSigningPrivateKeyMaterial.owner_kind !== expectedOwnerKind ||
    hybridSigningPrivateKeyMaterial.owner_id !== expectedOwnerId
  ) {
    throw new Error("device_key_owner_mismatch");
  }
  const ecdhPublic = x25519.getPublicKey(ecdhPrivate);
  if (base64UrlEncode(ecdhPublic) !== hybridEncryptionPrivateKeyMaterial.x25519_public) {
    throw new Error("device_ecdh_public_mismatch");
  }
  const hybridEncryptionPublicKeyMaterial = publicHybridEncryptionMaterialFromPrivate(
    hybridEncryptionPrivateKeyMaterial,
  );
  const publicKeyMaterial = publicKeyMaterialFromPrivate(hybridSigningPrivateKeyMaterial);
  const signingState = {
    privateKeyMaterial: hybridSigningPrivateKeyMaterial,
    publicKeyMaterial,
    signingKeyId: computeSigningKeyId(publicKeyMaterial),
  };

  state.deviceEcdhPrivate = ecdhPrivate;
  state.deviceEcdhPublic = ecdhPublic;
  state.deviceHybridEncryptionPrivateKeyMaterial = hybridEncryptionPrivateKeyMaterial;
  state.deviceHybridEncryptionPublicKeyMaterial = hybridEncryptionPublicKeyMaterial;
  if (publicKeyMaterial.owner_kind === "share_participant_device") {
    state.shareParticipantHybridSigningState = signingState;
    state.deviceHybridSigningState = null;
  } else {
    state.deviceHybridSigningState = signingState;
    state.shareParticipantHybridSigningState = null;
  }
}
