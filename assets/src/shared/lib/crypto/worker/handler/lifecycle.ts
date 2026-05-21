import type { WorkerKeyState } from "../state";
import { clearState } from "../state";
import { base64UrlDecode, base64UrlEncode } from "../../encoding";
import {
  buildDskDeviceEcdhAad,
  buildDskDeviceMlkem768Aad,
  buildDskDeviceSigningAad,
  buildDskAuthBootstrapAad,
  buildDskUmkCacheAad,
} from "../../aad";
import { deriveAuthKeys } from "../../kdf";
import { decryptIdentityPrivateKeys } from "../../identity";
import { unwrapUmk } from "../../umk";
import {
  assertHybridSigningPrivateKeyMaterial,
  computeSigningKeyId,
  publicKeyMaterialFromPrivate,
} from "../../signature";
import {
  assertHybridEncryptionPrivateKeyMaterial,
  computeHybridEncryptionKeyId,
  publicHybridEncryptionMaterialFromPrivate,
} from "../../hybrid-encryption";
import { parseJsonStrictBytes } from "../../jcs";
import { CryptoOperationError } from "../operation-error";
import { clearTransientKeys, clearTransientPuk, cloneTransientPuk } from "./transient";
import {
  dskEncrypt,
  dskDecrypt,
  type HandlerPayload,
  requireDeviceId,
  requireUmk,
  requireUserId,
  setDeviceFromPrivateKeys,
  setIdentityFromDecrypted,
} from "./utils";
import {
  hasStoredDskInWorker,
  loadDskStoreValueInWorker,
  loadStoredDskInitDataInWorker,
  deleteDskStoreValueInWorker,
  storeDskStoreValueInWorker,
} from "./dsk-idb";
type DskWrappedBlob = {
  ciphertext: ArrayBuffer;
  iv: ArrayBuffer;
};

const AUTH_BOOTSTRAP_KEY = "auth-bootstrap";

type KeyRestoreResponse = {
  encrypted_umk?: string;
  umk_nonce?: string;
  encrypted_identity_hybrid_encryption_private_key_material: string;
  identity_hybrid_encryption_private_key_material_nonce: string;
  identity_encryption_key_id: string;
  encrypted_identity_hybrid_signing_private_key_material: string;
  identity_hybrid_signing_private_key_material_nonce: string;
  identity_signing_key_id: string;
};

const keyRestoreEndpointRefs: Record<string, string> = {
  "auth-key-restore-v1": "/api/auth/key-restore",
};

async function resolveKeyRestorePayload(p: HandlerPayload): Promise<HandlerPayload> {
  const endpointRef = p.keyRestoreEndpointRef as string | null | undefined;
  if (!endpointRef) return p;

  const endpoint = keyRestoreEndpointRefs[endpointRef];
  if (!endpoint) throw new Error("unknown_key_restore_endpoint");

  const response = await fetch(endpoint, {
    method: "GET",
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) throw new Error("key_restore_failed");

  const body = (await response.json()) as KeyRestoreResponse;
  return {
    ...p,
    serverEncryptedUmk: body.encrypted_umk
      ? base64UrlDecode(body.encrypted_umk)
      : p.serverEncryptedUmk,
    serverUmkNonce: body.umk_nonce ? base64UrlDecode(body.umk_nonce) : p.serverUmkNonce,
    encryptedIdentityHybridEncryptionPrivateKeyMaterial: base64UrlDecode(
      body.encrypted_identity_hybrid_encryption_private_key_material,
    ),
    identityHybridEncryptionPrivateKeyMaterialNonce: base64UrlDecode(
      body.identity_hybrid_encryption_private_key_material_nonce,
    ),
    identityEncryptionKeyId: body.identity_encryption_key_id,
    encryptedIdentityHybridSigningPrivateKeyMaterial: base64UrlDecode(
      body.encrypted_identity_hybrid_signing_private_key_material,
    ),
    identityHybridSigningPrivateKeyMaterialNonce: base64UrlDecode(
      body.identity_hybrid_signing_private_key_material_nonce,
    ),
    identitySigningKeyId: body.identity_signing_key_id,
  };
}

async function resolveStoredDskPayload(p: HandlerPayload): Promise<HandlerPayload> {
  if (!p.useStoredDsk) return p;

  const stored = await loadStoredDskInitDataInWorker();
  if (!stored) return { ...p, dsk: null };

  return {
    ...p,
    dsk: stored.dsk,
    wrappedUmk: p.wrappedUmk ?? stored.wrappedUmk ?? undefined,
    wrappedDeviceEcdh: p.wrappedDeviceEcdh ?? stored.wrappedDeviceEcdh ?? undefined,
    wrappedDeviceMlkem: p.wrappedDeviceMlkem ?? stored.wrappedDeviceMlkem ?? undefined,
    wrappedDeviceSigning: p.wrappedDeviceSigning ?? stored.wrappedDeviceSigning ?? undefined,
    deviceSigningKeyId: p.deviceSigningKeyId,
  };
}

async function restoreKeysFromBlobs(
  state: WorkerKeyState,
  p: HandlerPayload,
  params: {
    dsk: CryptoKey | null;
    userId: string;
    localPuk: Uint8Array | null;
  },
): Promise<void> {
  const { dsk, userId, localPuk } = params;
  if (dsk) {
    state.dsk = dsk;
    const hasWrappedDeviceKeys = Boolean(
      p.wrappedDeviceEcdh || p.wrappedDeviceMlkem || p.wrappedDeviceSigning,
    );
    if (
      hasWrappedDeviceKeys &&
      !(p.wrappedDeviceEcdh && p.wrappedDeviceMlkem && p.wrappedDeviceSigning)
    ) {
      throw new Error("device_dsk_wrapped_keys_incomplete");
    }

    if (p.wrappedDeviceEcdh && p.wrappedDeviceMlkem && p.wrappedDeviceSigning) {
      try {
        const wrappedEcdh = p.wrappedDeviceEcdh as DskWrappedBlob;
        const wrappedMlkem = p.wrappedDeviceMlkem as DskWrappedBlob;
        const wrappedSigning = p.wrappedDeviceSigning as DskWrappedBlob & {
          signingKeyId: string;
        };
        if (!wrappedSigning.signingKeyId || typeof p.deviceSigningKeyId !== "string") {
          throw new Error("device_signing_key_id_missing");
        }
        if (wrappedSigning.signingKeyId !== p.deviceSigningKeyId) {
          throw new Error("device_signing_key_id_mismatch");
        }
        const encryptionKeyId = (wrappedEcdh as DskWrappedBlob & { encryptionKeyId?: unknown })
          .encryptionKeyId;
        if (typeof encryptionKeyId !== "string") {
          throw new Error("device_encryption_key_id_missing");
        }
        const ecdhPrivate = await dskDecrypt(
          dsk,
          wrappedEcdh.ciphertext,
          wrappedEcdh.iv,
          buildDskDeviceEcdhAad({ userId, deviceId: state.deviceId ?? "", encryptionKeyId }),
        );
        const signingPrivateKeyMaterial = parseJsonStrictBytes(
          await dskDecrypt(
            dsk,
            wrappedSigning.ciphertext,
            wrappedSigning.iv,
            buildDskDeviceSigningAad(userId, state.deviceId ?? "", p.deviceSigningKeyId),
          ),
        );
        const hybridEncryptionPrivateKeyMaterial = parseJsonStrictBytes(
          await dskDecrypt(
            dsk,
            wrappedMlkem.ciphertext,
            wrappedMlkem.iv,
            buildDskDeviceMlkem768Aad({ userId, deviceId: state.deviceId ?? "", encryptionKeyId }),
          ),
        );
        assertHybridEncryptionPrivateKeyMaterial(hybridEncryptionPrivateKeyMaterial);
        if (hybridEncryptionPrivateKeyMaterial.owner_id !== state.deviceId) {
          throw new Error("device_encryption_owner_mismatch");
        }
        const decryptedEncryptionKeyId = computeHybridEncryptionKeyId(
          publicHybridEncryptionMaterialFromPrivate(hybridEncryptionPrivateKeyMaterial),
        );
        if (decryptedEncryptionKeyId !== encryptionKeyId) {
          throw new Error("device_encryption_key_id_mismatch");
        }
        assertHybridSigningPrivateKeyMaterial(signingPrivateKeyMaterial);
        if (signingPrivateKeyMaterial.owner_id !== state.deviceId) {
          throw new Error("device_signing_owner_mismatch");
        }
        const signingKeyId = computeSigningKeyId(
          publicKeyMaterialFromPrivate(signingPrivateKeyMaterial),
        );
        if (signingKeyId !== p.deviceSigningKeyId) {
          throw new Error("device_signing_key_id_mismatch");
        }
        setDeviceFromPrivateKeys(
          state,
          ecdhPrivate,
          hybridEncryptionPrivateKeyMaterial,
          signingPrivateKeyMaterial,
          "device",
          state.deviceId,
        );
      } catch (error) {
        throw new Error(error instanceof Error ? error.message : "device_dsk_restore_failed");
      }
    }
    if (p.wrappedUmk) {
      try {
        const wrappedUmk = p.wrappedUmk as DskWrappedBlob;
        state.umk = await dskDecrypt(
          dsk,
          wrappedUmk.ciphertext,
          wrappedUmk.iv,
          buildDskUmkCacheAad(userId),
        );
      } catch {
        // Stale DSK data; fall through to server PUK restore.
      }
    }
  }
  if (!state.umk && p.serverEncryptedUmk && p.serverUmkNonce && localPuk) {
    state.umk = unwrapUmk(
      p.serverEncryptedUmk as Uint8Array,
      p.serverUmkNonce as Uint8Array,
      localPuk,
      userId,
    );
  }
  if (
    state.umk &&
    p.encryptedIdentityHybridEncryptionPrivateKeyMaterial &&
    p.identityHybridEncryptionPrivateKeyMaterialNonce &&
    p.identityEncryptionKeyId &&
    p.encryptedIdentityHybridSigningPrivateKeyMaterial &&
    p.identityHybridSigningPrivateKeyMaterialNonce &&
    p.identitySigningKeyId
  ) {
    setIdentityFromDecrypted(
      state,
      decryptIdentityPrivateKeys(
        {
          encryptedHybridEncryptionPrivateKeyMaterial:
            p.encryptedIdentityHybridEncryptionPrivateKeyMaterial as Uint8Array,
          hybridEncryptionPrivateKeyMaterialNonce:
            p.identityHybridEncryptionPrivateKeyMaterialNonce as Uint8Array,
          encryptionKeyId: p.identityEncryptionKeyId as string,
          encryptedHybridSigningPrivateKeyMaterial:
            p.encryptedIdentityHybridSigningPrivateKeyMaterial as Uint8Array,
          hybridSigningPrivateKeyMaterialNonce:
            p.identityHybridSigningPrivateKeyMaterialNonce as Uint8Array,
          signingKeyId: p.identitySigningKeyId as string,
        },
        state.umk,
        userId,
      ),
    );
  }
  const identityKeysRequested = Boolean(
    p.encryptedIdentityHybridEncryptionPrivateKeyMaterial &&
    p.identityHybridEncryptionPrivateKeyMaterialNonce &&
    p.identityEncryptionKeyId &&
    p.encryptedIdentityHybridSigningPrivateKeyMaterial &&
    p.identityHybridSigningPrivateKeyMaterialNonce &&
    p.identitySigningKeyId,
  );
  const identityRestored = state.identityHybridSigningState !== null;
  state.initialized =
    (state.deviceHybridSigningState !== null ||
      state.shareParticipantHybridSigningState !== null) &&
    state.umk !== null &&
    (!identityKeysRequested || identityRestored);
}
export async function handleInit(state: WorkerKeyState, p: HandlerPayload): Promise<unknown> {
  let localPuk = cloneTransientPuk();
  clearState(state);
  clearTransientPuk();
  try {
    p = await resolveStoredDskPayload(p);
    p = await resolveKeyRestorePayload(p);
    const dsk = p.dsk as CryptoKey | null;
    const userId = p.userId as string;
    const deviceId = p.deviceId as string;
    if (p.passwordParams) {
      const pp = p.passwordParams as {
        password: string;
        salt: Uint8Array;
        kdfParams: {
          memory: number;
          iterations: number;
          parallelism: number;
        };
      };
      const saltBase64 = base64UrlEncode(pp.salt);
      const derived = await deriveAuthKeys(pp.password, saltBase64, {
        algorithm: "argon2id",
        memory: pp.kdfParams.memory,
        iterations: pp.kdfParams.iterations,
        parallelism: pp.kdfParams.parallelism,
        hash_length: 32,
      });
      derived.puk.fill(0);
    }
    state.userId = userId;
    state.deviceId = deviceId;
    await restoreKeysFromBlobs(state, p, {
      dsk,
      userId,
      localPuk,
    });
    return { status: state.initialized ? "initialized" : "partial" };
  } finally {
    if (localPuk) {
      localPuk.fill(0);
      localPuk = null;
    }
  }
}
export async function handleInitFromPassword(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  clearState(state);
  clearTransientPuk();
  p = await resolveStoredDskPayload(p);
  p = await resolveKeyRestorePayload(p);
  const password = p.password as string;
  const salt = p.salt as Uint8Array;
  const kdfParams = p.kdfParams as {
    memory: number;
    iterations: number;
    parallelism: number;
  };
  const userId = p.userId as string;
  const deviceId = p.deviceId as string;
  const dsk = p.dsk as CryptoKey | null;
  const saltBase64 = base64UrlEncode(salt);
  const derived = await deriveAuthKeys(password, saltBase64, {
    algorithm: "argon2id",
    memory: kdfParams.memory,
    iterations: kdfParams.iterations,
    parallelism: kdfParams.parallelism,
    hash_length: 32,
  });
  state.userId = userId;
  state.deviceId = deviceId;
  let localPuk: Uint8Array | null = derived.puk;
  try {
    await restoreKeysFromBlobs(state, p, {
      dsk,
      userId,
      localPuk,
    });
    return { authKey: base64UrlDecode(derived.authKeyBase64) };
  } finally {
    if (localPuk) {
      localPuk.fill(0);
      localPuk = null;
    }
  }
}
export function handleLock(state: WorkerKeyState): unknown {
  clearState(state);
  clearTransientKeys();
  return { status: "locked" };
}
export function handleGetPublicKeys(state: WorkerKeyState): unknown {
  const deviceHybridSigningPublicKeyMaterialKeyMaterial =
    state.deviceHybridSigningState?.publicKeyMaterial ??
    state.shareParticipantHybridSigningState?.publicKeyMaterial;
  const identityHybridSigningPublicKeyMaterialKeyMaterial =
    state.identityHybridSigningState?.publicKeyMaterial;

  return {
    deviceHybridSigningPublicKeyMaterial: deviceHybridSigningPublicKeyMaterialKeyMaterial,
    deviceSigningKeyId:
      state.deviceHybridSigningState?.signingKeyId ??
      state.shareParticipantHybridSigningState?.signingKeyId ??
      null,
    deviceEcdhPublic: state.deviceEcdhPublic,
    deviceHybridEncryptionPublicKeyMaterial: state.deviceHybridEncryptionPublicKeyMaterial,
    deviceEncryptionKeyId: state.deviceHybridEncryptionPublicKeyMaterial
      ? computeHybridEncryptionKeyId(state.deviceHybridEncryptionPublicKeyMaterial)
      : null,
    identityHybridSigningPublicKeyMaterial: identityHybridSigningPublicKeyMaterialKeyMaterial,
    identityEcdhPublic: state.identityEcdhPublic,
    identityHybridEncryptionPublicKeyMaterial: state.identityHybridEncryptionPublicKeyMaterial,
    identityEncryptionKeyId: state.identityHybridEncryptionPublicKeyMaterial
      ? computeHybridEncryptionKeyId(state.identityHybridEncryptionPublicKeyMaterial)
      : null,
  };
}
export function handleGetDeviceId(state: WorkerKeyState): unknown {
  return { deviceId: requireDeviceId(state) };
}
export async function handleHasStoredDsk(): Promise<unknown> {
  return { available: await hasStoredDskInWorker() };
}
export async function handleLoadStoredDsk(state: WorkerKeyState): Promise<unknown> {
  const stored = await loadStoredDskInitDataInWorker();
  if (!stored) return { loaded: false };
  state.dsk = stored.dsk;
  return { loaded: true };
}
export async function handleLoadAuthBootstrap(state: WorkerKeyState): Promise<unknown> {
  const stored = await loadStoredDskInitDataInWorker();
  if (!stored) return { bootstrap: null };
  const wrapped = await loadDskStoreValueInWorker<DskWrappedBlob>(AUTH_BOOTSTRAP_KEY);
  if (!wrapped) return { bootstrap: null };
  const plaintext = await dskDecrypt(
    stored.dsk,
    wrapped.ciphertext,
    wrapped.iv,
    buildDskAuthBootstrapAad(),
  );
  state.dsk = stored.dsk;
  return { bootstrap: JSON.parse(new TextDecoder().decode(plaintext)) };
}
export async function handleStoreAuthBootstrap(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const dsk = state.dsk ?? (await loadStoredDskInitDataInWorker())?.dsk;
  if (!dsk) return { stored: false };
  const wrapped = await dskEncrypt(
    dsk,
    new TextEncoder().encode(JSON.stringify(p.bootstrap)),
    buildDskAuthBootstrapAad(),
  );
  await storeDskStoreValueInWorker(AUTH_BOOTSTRAP_KEY, wrapped);
  state.dsk = dsk;
  return { stored: true };
}

async function deleteDskStoreValue(key: string): Promise<unknown> {
  await deleteDskStoreValueInWorker(key);
  return {};
}

export async function handleDeleteWrappedUmkWithDsk(): Promise<unknown> {
  return deleteDskStoreValue("wrapped-umk");
}

export async function handleDeleteAuthBootstrapWithDsk(): Promise<unknown> {
  return deleteDskStoreValue("auth-bootstrap");
}

export async function handleImportIdentityKeysFromKeyRestore(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const payload = await resolveKeyRestorePayload(p);
  setIdentityFromDecrypted(
    state,
    decryptIdentityPrivateKeys(
      {
        encryptedHybridEncryptionPrivateKeyMaterial:
          payload.encryptedIdentityHybridEncryptionPrivateKeyMaterial as Uint8Array,
        hybridEncryptionPrivateKeyMaterialNonce:
          payload.identityHybridEncryptionPrivateKeyMaterialNonce as Uint8Array,
        encryptionKeyId: payload.identityEncryptionKeyId as string,
        encryptedHybridSigningPrivateKeyMaterial:
          payload.encryptedIdentityHybridSigningPrivateKeyMaterial as Uint8Array,
        hybridSigningPrivateKeyMaterialNonce:
          payload.identityHybridSigningPrivateKeyMaterialNonce as Uint8Array,
        signingKeyId: payload.identitySigningKeyId as string,
      },
      requireUmk(state),
      requireUserId(state),
    ),
  );
  return handleGetPublicKeys(state);
}
export function handleIsReady(state: WorkerKeyState): unknown {
  return { ready: state.initialized };
}
export function handleSetUserContext(state: WorkerKeyState, p: HandlerPayload): unknown {
  state.userId = p.userId as string;
  state.deviceId = (p.deviceId as string) ?? state.deviceId;
  return { status: "ok" };
}
export function handleSetInitialized(state: WorkerKeyState): unknown {
  const signingState = state.deviceHybridSigningState ?? state.shareParticipantHybridSigningState;
  if (
    !state.userId ||
    !state.deviceId ||
    !state.deviceEcdhPrivate ||
    !state.deviceHybridEncryptionPrivateKeyMaterial ||
    !state.deviceHybridEncryptionPublicKeyMaterial ||
    !signingState
  ) {
    throw new CryptoOperationError("not_initialized", "Hybrid device state incomplete");
  }
  state.initialized = true;
  return { status: "ok" };
}
export function handleClearTransientKeys(): unknown {
  clearTransientKeys();
  return { status: "ok" };
}
