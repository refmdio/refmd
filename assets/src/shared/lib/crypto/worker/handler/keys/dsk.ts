import type { WorkerKeyState } from "../../state";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { CryptoOperationError } from "../../operation-error";
import {
  buildDskDeviceEcdhAad,
  buildDskDeviceMlkem768Aad,
  buildDskDeviceSigningAad,
  buildDskPluginCredentialAad,
  buildDskShareParticipantDeviceEcdhAad,
  buildDskShareParticipantDeviceMlkem768Aad,
  buildDskStoreValueAad,
  buildDskShareParticipantSigningAad,
  buildDskUmkCacheAad,
  buildDskUiStateAad,
  buildGuestInviteRedeemMaterialAad,
  buildOfflineDocumentCacheAad,
  buildShareManageAccessAad,
} from "../../../aad";
import {
  currentDeviceHybridSigningState,
  deriveDskXChaCha20Poly1305KeyBytes,
  dskDecrypt,
  dskEncrypt,
  requireDsk,
  requireUmk,
  setDeviceFromPrivateKeys,
} from "../utils";
import type { HandlerPayload } from "../utils";
import { canonicalizeStrictBytes, parseJsonStrictBytes, type StrictJsonValue } from "../../../jcs";
import {
  assertHybridSigningPrivateKeyMaterial,
  computeSigningKeyId,
  publicKeyMaterialFromPrivate,
} from "../../../signature";
import {
  assertHybridEncryptionPrivateKeyMaterial,
  computeHybridEncryptionKeyId,
  publicHybridEncryptionMaterialFromPrivate,
} from "../../../hybrid-encryption";
import { randomBytes } from "../../../encoding";
import {
  SHARE_PARTICIPANT_DEVICE_KEY_PREFIX,
  deleteDskStoreValuesByPrefixInWorker,
  deleteDskStoreValueInWorker,
  loadDskStoreValueInWorker,
  loadShareParticipantDeviceKeysInWorker,
  storeDskInWorker,
  storeDskStoreValueInWorker,
  storeShareParticipantDeviceKeysInWorker,
} from "../dsk-idb";

const WRAPPED_UMK_KEY = "wrapped-umk";
const WRAPPED_DEVICE_ECDH_KEY = "wrapped-device-ecdh";
const WRAPPED_DEVICE_MLKEM_KEY = "wrapped-device-mlkem768-material";
const WRAPPED_DEVICE_SIGNING_KEY = "wrapped-device-hybrid-signing";

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

async function dskXChaChaEncrypt(
  dsk: CryptoKey,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<{ ciphertext: ArrayBuffer; nonce: ArrayBuffer }> {
  const nonce = randomBytes(24);
  const keyBytes = await deriveDskXChaCha20Poly1305KeyBytes(dsk);
  try {
    const cipher = xchacha20poly1305(keyBytes, nonce, aad);
    return { ciphertext: arrayBuffer(cipher.encrypt(plaintext)), nonce: arrayBuffer(nonce) };
  } finally {
    keyBytes.fill(0);
  }
}

async function dskXChaChaDecrypt(
  dsk: CryptoKey,
  ciphertext: ArrayBuffer,
  nonce: ArrayBuffer,
  aad: Uint8Array,
): Promise<Uint8Array> {
  const keyBytes = await deriveDskXChaCha20Poly1305KeyBytes(dsk);
  try {
    const cipher = xchacha20poly1305(keyBytes, new Uint8Array(nonce), aad);
    return cipher.decrypt(new Uint8Array(ciphertext));
  } finally {
    keyBytes.fill(0);
  }
}
const SHARE_PARTICIPANT_SESSION_INDEX_KEY = "refmd-share-participant-session:index";
const SHARE_PARTICIPANT_SESSION_KEY_PREFIX = "refmd-share-participant-session:";
const SHARE_SESSION_TRUST_ANCHOR_KEY_PREFIX = "refmd-share-access:trust-anchor:";
const SHARE_SECRET_KEY_PREFIX = "share-secret:";
const MOUNT_TRUST_ANCHOR_KEY_PREFIX = "refmd-mount-trust-anchor:";
const PLUGIN_USER_LOCAL_KEY_PREFIX = "refmd-plugin-user-local:";
const PLUGIN_CACHE_KEY_PREFIX = "refmd-plugin-cache:";
const PLUGIN_CREDENTIAL_KEY_PREFIX = "refmd-plugin-credential:";

type DskWrappedBlob = {
  ciphertext: ArrayBuffer;
  iv: ArrayBuffer;
};

export async function handleWrapOfflineDocumentTitleWithDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const plaintext = payload.plaintext as Uint8Array;
  const documentId = requiredString(payload.documentId, "document_id");
  const keyVersion = requiredNumber(payload.keyVersion, "key_version");
  return dskEncrypt(dsk, plaintext, buildOfflineDocumentCacheAad(documentId, keyVersion));
}

export async function handleUnwrapOfflineDocumentTitleWithDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const documentId = requiredString(payload.documentId, "document_id");
  const keyVersion = requiredNumber(payload.keyVersion, "key_version");
  const ciphertext = payload.ciphertext as ArrayBuffer;
  const iv = payload.iv as ArrayBuffer;
  return {
    plaintext: await dskDecrypt(
      dsk,
      ciphertext,
      iv,
      buildOfflineDocumentCacheAad(documentId, keyVersion),
    ),
  };
}

export async function handleStoreShareManagementTokenWithDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const plaintext = payload.plaintext as Uint8Array;
  const documentId = requiredString(payload.documentId, "document_id");
  const shareId = requiredString(payload.shareId, "share_id");
  await storeDskWrappedValue(
    state,
    shareManagementTokenKey(documentId, shareId),
    plaintext,
    buildShareManageAccessAad(documentId, shareId),
  );
  return { stored: true };
}

export async function handleLoadShareManagementTokenWithDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const documentId = requiredString(payload.documentId, "document_id");
  const shareId = requiredString(payload.shareId, "share_id");
  return loadDskWrappedValue(
    state,
    shareManagementTokenKey(documentId, shareId),
    buildShareManageAccessAad(documentId, shareId),
  );
}

export async function handleDeleteShareManagementTokenWithDsk(
  payload: HandlerPayload,
): Promise<unknown> {
  const documentId = requiredString(payload.documentId, "document_id");
  const shareId = requiredString(payload.shareId, "share_id");
  await deleteDskStoreValueInWorker(shareManagementTokenKey(documentId, shareId));
  return {};
}

export async function handleStoreUiStateWithDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const plaintext = payload.plaintext as Uint8Array;
  const storageKey = requiredString(payload.storageKey, "storage_key");
  const aadRecord = requiredRecord(payload.aadRecord, "aad_record");
  await storeDskWrappedValue(state, storageKey, plaintext, buildDskUiStateAad(aadRecord));
  return { stored: true };
}

export async function handleLoadUiStateWithDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const storageKey = requiredString(payload.storageKey, "storage_key");
  const aadRecord = requiredRecord(payload.aadRecord, "aad_record");
  return loadDskWrappedValue(state, storageKey, buildDskUiStateAad(aadRecord));
}

export async function handleDeleteUiStateWithDsk(payload: HandlerPayload): Promise<unknown> {
  const storageKey = requiredString(payload.storageKey, "storage_key");
  await deleteDskStoreValueInWorker(storageKey);
  return {};
}

export async function handleStorePluginCredentialWithDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const params = pluginCredentialParams(payload);
  await storeDskWrappedValue(
    state,
    pluginCredentialStorageKey(params),
    payload.plaintext as Uint8Array,
    buildDskPluginCredentialAad(params),
  );
  return { stored: true };
}

export async function handleLoadPluginCredentialWithDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const params = pluginCredentialParams(payload);
  return loadDskWrappedValue(
    state,
    pluginCredentialStorageKey(params),
    buildDskPluginCredentialAad(params),
  );
}

export async function handleDeletePluginCredentialWithDsk(
  payload: HandlerPayload,
): Promise<unknown> {
  await deleteDskStoreValueInWorker(pluginCredentialStorageKey(pluginCredentialParams(payload)));
  return {};
}

export async function handleClearPluginDataWithDsk(): Promise<unknown> {
  await Promise.all([
    deleteDskStoreValuesByPrefixInWorker(PLUGIN_USER_LOCAL_KEY_PREFIX),
    deleteDskStoreValuesByPrefixInWorker(PLUGIN_CACHE_KEY_PREFIX),
    deleteDskStoreValuesByPrefixInWorker(PLUGIN_CREDENTIAL_KEY_PREFIX),
  ]);
  return {};
}

export async function handleClearPluginApplicationDataWithDsk(
  payload: HandlerPayload,
): Promise<unknown> {
  const workspaceId = requiredString(payload.workspaceId, "workspace_id");
  const packageId = requiredString(payload.packageId, "package_id");
  const applicationId = requiredString(payload.applicationId, "application_id");
  const activationId = requiredString(payload.activationId, "activation_id");
  const userId = requiredString(payload.userId, "user_id");
  const deviceId = requiredString(payload.deviceId, "device_id");
  const keyPrefixes = pluginApplicationStorageKeyPrefixes({
    workspaceId,
    packageId,
    applicationId,
    activationId,
    userId,
    deviceId,
  });
  await Promise.all([
    deleteDskStoreValuesByPrefixInWorker(keyPrefixes.userLocal),
    deleteDskStoreValuesByPrefixInWorker(keyPrefixes.cache),
    deleteDskStoreValuesByPrefixInWorker(keyPrefixes.credential),
  ]);
  return {};
}

export async function handleStoreGuestInvitationMaterialWithDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const tokenHash = requiredString(payload.tokenHash, "token_hash");
  await storeDskWrappedValue(
    state,
    tokenHash,
    payload.plaintext as Uint8Array,
    buildGuestInviteRedeemMaterialAad(tokenHash),
  );
  return { stored: true };
}

export async function handleLoadGuestInvitationMaterialWithDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const tokenHash = requiredString(payload.tokenHash, "token_hash");
  return loadDskWrappedValue(state, tokenHash, buildGuestInviteRedeemMaterialAad(tokenHash));
}

export async function handleDeleteGuestInvitationMaterialWithDsk(
  payload: HandlerPayload,
): Promise<unknown> {
  await deleteDskStoreValueInWorker(requiredString(payload.tokenHash, "token_hash"));
  return {};
}

export async function handleStoreMountTrustAnchorWithDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const mountId = requiredString(payload.mountId, "mount_id");
  const aadRecord = assertAadRecord(payload.aadRecord, "mount_trust_anchor_aad", [
    "authenticated_source_kind",
    "created_at_ms",
    "mount_id",
    "mount_owner_device_id",
    "mount_owner_user_id",
    "protocol",
    "share_id",
    "share_session_key",
    "target_kind",
    "target_token_hash",
    "version",
    "workspace_pin_bootstrap_hash",
  ]);
  const wrapped = await dskEncrypt(
    requireDsk(state),
    payload.plaintext as Uint8Array,
    canonicalizeStrictBytes(aadRecord),
  );
  await storeDskStoreValueInWorker(mountTrustAnchorKey(mountId), { ...wrapped, aadRecord });
  return { stored: true };
}

export async function handleLoadMountTrustAnchorWithDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const mountId = requiredString(payload.mountId, "mount_id");
  const stored = await loadDskStoreValueInWorker<DskWrappedBlob & { aadRecord: StrictJsonValue }>(
    mountTrustAnchorKey(mountId),
  );
  if (!stored) return { plaintext: null };
  return {
    plaintext: await dskDecrypt(
      requireDsk(state),
      stored.ciphertext,
      stored.iv,
      canonicalizeStrictBytes(stored.aadRecord),
    ),
  };
}

export async function handleDeleteMountTrustAnchorWithDsk(
  payload: HandlerPayload,
): Promise<unknown> {
  await deleteDskStoreValueInWorker(
    mountTrustAnchorKey(requiredString(payload.mountId, "mount_id")),
  );
  return {};
}

export async function handleClearMountTrustAnchorsWithDsk(): Promise<unknown> {
  await deleteDskStoreValuesByPrefixInWorker(MOUNT_TRUST_ANCHOR_KEY_PREFIX);
  return {};
}

export async function handleStoreShareSessionTrustAnchorWithDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const shareSlug = requiredString(payload.shareSlug, "share_slug");
  const aadRecord = assertAadRecord(payload.aadRecord, "share_session_aad", [
    "capability_context_hash",
    "created_event_hash",
    "password_capability_secret_commitment",
    "permission",
    "protocol",
    "scope_id",
    "scope_kind",
    "share_capability_secret_commitment",
    "share_id",
    "share_participant_device_id",
    "share_participant_principal_id",
    "token_hash",
    "version",
    "workspace_pin_bootstrap_hash",
  ]);
  const wrapped = await dskEncrypt(
    requireDsk(state),
    payload.plaintext as Uint8Array,
    canonicalizeStrictBytes(aadRecord),
  );
  await storeDskStoreValueInWorker(shareSessionTrustAnchorKey(shareSlug), {
    ...wrapped,
    aadRecord,
  });
  return { stored: true };
}

export async function handleLoadShareSessionTrustAnchorWithDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const shareSlug = requiredString(payload.shareSlug, "share_slug");
  const stored = await loadDskStoreValueInWorker<DskWrappedBlob & { aadRecord: StrictJsonValue }>(
    shareSessionTrustAnchorKey(shareSlug),
  );
  if (!stored) return { plaintext: null };
  return {
    plaintext: await dskDecrypt(
      requireDsk(state),
      stored.ciphertext,
      stored.iv,
      canonicalizeStrictBytes(stored.aadRecord),
    ),
  };
}

export async function handleDeleteShareSessionTrustAnchorWithDsk(
  payload: HandlerPayload,
): Promise<unknown> {
  await deleteDskStoreValueInWorker(
    shareSessionTrustAnchorKey(requiredString(payload.shareSlug, "share_slug")),
  );
  return {};
}

export async function handleStoreShareParticipantSessionWithDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const session = assertShareParticipantSession(payload.session);
  const sessionKey = shareParticipantSessionKey(session);
  await storeDskJsonValue(state, sessionKey, session);
  const index = await loadShareParticipantSessionIndex(state);
  if (!index.includes(sessionKey)) {
    await storeShareParticipantSessionIndex(state, [...index, sessionKey]);
  }
  return { stored: true };
}

export async function handleListShareParticipantSessionsWithDsk(
  state: WorkerKeyState,
): Promise<unknown> {
  const index = await loadShareParticipantSessionIndex(state);
  const sessions = await Promise.all(index.map((key) => loadDskJsonValue(state, key)));
  return {
    sessions: sessions.filter((session): session is StrictJsonValue => Boolean(session)),
  };
}

export async function handleDeleteShareParticipantSessionWithDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const shareSlug = requiredString(payload.shareSlug, "share_slug");
  const index = await loadShareParticipantSessionIndex(state);
  const remaining: string[] = [];
  await Promise.all(
    index.map(async (key) => {
      const session = await loadDskJsonValue(state, key);
      if (
        session &&
        typeof session === "object" &&
        !Array.isArray(session) &&
        (session as Record<string, unknown>).shareSlug === shareSlug
      ) {
        await deleteDskStoreValueInWorker(key);
      } else {
        remaining.push(key);
      }
    }),
  );
  await storeShareParticipantSessionIndex(state, remaining);
  await deleteDskStoreValueInWorker(shareSessionTrustAnchorKey(shareSlug));
  return {};
}

export async function handleClearShareParticipantSessionsWithDsk(): Promise<unknown> {
  await Promise.all([
    deleteDskStoreValuesByPrefixInWorker(SHARE_PARTICIPANT_SESSION_KEY_PREFIX),
    deleteDskStoreValuesByPrefixInWorker(SHARE_SESSION_TRUST_ANCHOR_KEY_PREFIX),
    deleteDskStoreValuesByPrefixInWorker(SHARE_SECRET_KEY_PREFIX),
    deleteDskStoreValuesByPrefixInWorker(`${SHARE_PARTICIPANT_DEVICE_KEY_PREFIX}:`),
  ]);
  return {};
}

export async function handleWrapUmkWithDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const umk = requireUmk(state);
  const userId = payload.userId as string;
  return dskEncrypt(dsk, umk, buildDskUmkCacheAad(userId));
}

export async function handleUnwrapUmkFromDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const ciphertext = payload.ciphertext as ArrayBuffer;
  const iv = payload.iv as ArrayBuffer;
  const userId = payload.userId as string;
  state.umk = await dskDecrypt(dsk, ciphertext, iv, buildDskUmkCacheAad(userId));
  return { status: "ok" };
}

function requiredString(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new CryptoOperationError("invalid_payload", `${name}_invalid`);
  }
  return value;
}

async function storeDskWrappedValue(
  state: WorkerKeyState,
  key: string,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<void> {
  await storeDskStoreValueInWorker(key, await dskEncrypt(requireDsk(state), plaintext, aad));
}

async function loadDskWrappedValue(
  state: WorkerKeyState,
  key: string,
  aad: Uint8Array,
): Promise<unknown> {
  const wrapped = await loadDskStoreValueInWorker<DskWrappedBlob>(key);
  if (!wrapped) return { plaintext: null };
  return {
    plaintext: await dskDecrypt(requireDsk(state), wrapped.ciphertext, wrapped.iv, aad),
  };
}

function shareManagementTokenKey(documentId: string, shareId: string): string {
  return `refmd-share-access:${documentId}:${shareId}`;
}

function pluginCredentialParams(payload: HandlerPayload): {
  workspaceId: string;
  packageId: string;
  applicationId: string;
  activationId: string;
  userId: string;
  deviceId: string;
  credentialId: string;
} {
  return {
    workspaceId: requiredString(payload.workspaceId, "workspace_id"),
    packageId: requiredString(payload.packageId, "package_id"),
    applicationId: requiredString(payload.applicationId, "application_id"),
    activationId: requiredString(payload.activationId, "activation_id"),
    userId: requiredString(payload.userId, "user_id"),
    deviceId: requiredString(payload.deviceId, "device_id"),
    credentialId: requiredString(payload.credentialId, "credential_id"),
  };
}

export function pluginCredentialStorageKey(params: {
  workspaceId: string;
  packageId: string;
  applicationId: string;
  activationId: string;
  userId: string;
  deviceId: string;
  credentialId: string;
}): string {
  return [
    PLUGIN_CREDENTIAL_KEY_PREFIX.slice(0, -1),
    params.packageId,
    params.applicationId,
    params.activationId,
    params.workspaceId,
    params.userId,
    params.deviceId,
    params.credentialId,
  ].join(":");
}

export function pluginApplicationStorageKeyPrefixes(params: {
  workspaceId: string;
  packageId: string;
  applicationId: string;
  activationId: string;
  userId: string;
  deviceId: string;
}): { userLocal: string; cache: string; credential: string } {
  const namespace = [
    params.packageId,
    params.applicationId,
    params.activationId,
    params.workspaceId,
    params.userId,
    params.deviceId,
  ].join(":");

  return {
    userLocal: `${PLUGIN_USER_LOCAL_KEY_PREFIX}${namespace}:`,
    cache: `${PLUGIN_CACHE_KEY_PREFIX}${namespace}:`,
    credential: `${PLUGIN_CREDENTIAL_KEY_PREFIX}${namespace}:`,
  };
}

function mountTrustAnchorKey(mountId: string): string {
  return `${MOUNT_TRUST_ANCHOR_KEY_PREFIX}${mountId}`;
}

function shareSessionTrustAnchorKey(shareSlug: string): string {
  return `${SHARE_SESSION_TRUST_ANCHOR_KEY_PREFIX}${shareSlug}`;
}

type ShareParticipantSessionRecord = Record<string, unknown> &
  StrictJsonValue & {
    deviceId: string;
    shareId: string;
    shareSlug: string;
  };

function shareParticipantSessionKey(session: ShareParticipantSessionRecord): string {
  return `${SHARE_PARTICIPANT_SESSION_KEY_PREFIX}${session.shareSlug}:${session.shareId}:${session.deviceId}`;
}

function assertShareParticipantSession(value: unknown): ShareParticipantSessionRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new CryptoOperationError("invalid_payload", "share_participant_session_invalid");
  }
  const session = value as Record<string, unknown>;
  const expectedKeys = [
    "deviceId",
    "displayName",
    "encryptionPublicKey",
    "hybridSigningPublicKeyMaterial",
    "passwordProtected",
    "principalId",
    "redeemAttemptId",
    "sessionId",
    "shareId",
    "shareSlug",
    "signingKeyId",
  ];
  if (
    JSON.stringify(Object.keys(session).sort((a, b) => a.localeCompare(b))) !==
    JSON.stringify(expectedKeys)
  ) {
    throw new CryptoOperationError("invalid_payload", "share_participant_session_unexpected_keys");
  }
  for (const field of expectedKeys.filter((field) => field !== "hybridSigningPublicKeyMaterial")) {
    if (field === "passwordProtected") continue;
    requiredString(session[field], field);
  }
  if (typeof session.passwordProtected !== "boolean") {
    throw new CryptoOperationError("invalid_payload", "password_protected_invalid");
  }
  if (
    !session.hybridSigningPublicKeyMaterial ||
    typeof session.hybridSigningPublicKeyMaterial !== "object" ||
    Array.isArray(session.hybridSigningPublicKeyMaterial)
  ) {
    throw new CryptoOperationError("invalid_payload", "hybrid_signing_public_key_material_invalid");
  }
  return session as ShareParticipantSessionRecord;
}

async function loadShareParticipantSessionIndex(state: WorkerKeyState): Promise<string[]> {
  const raw = await loadDskJsonValue(state, SHARE_PARTICIPANT_SESSION_INDEX_KEY);
  if (
    raw &&
    typeof raw === "object" &&
    !Array.isArray(raw) &&
    (raw as Record<string, unknown>).protocol === "refmd.share-participant-session-index" &&
    (raw as Record<string, unknown>).version === 1 &&
    Array.isArray((raw as Record<string, unknown>).sessions)
  ) {
    return (raw as { sessions: unknown[] }).sessions.filter(
      (value): value is string => typeof value === "string",
    );
  }
  return [];
}

async function storeShareParticipantSessionIndex(
  state: WorkerKeyState,
  index: string[],
): Promise<void> {
  await storeDskJsonValue(state, SHARE_PARTICIPANT_SESSION_INDEX_KEY, {
    protocol: "refmd.share-participant-session-index",
    version: 1,
    sessions: index,
  });
}

async function storeDskJsonValue(
  state: WorkerKeyState,
  key: string,
  value: StrictJsonValue,
): Promise<void> {
  await storeDskStoreValueInWorker(
    key,
    await dskEncrypt(requireDsk(state), canonicalizeStrictBytes(value), buildDskStoreValueAad(key)),
  );
}

async function loadDskJsonValue(
  state: WorkerKeyState,
  key: string,
): Promise<StrictJsonValue | null> {
  const wrapped = await loadDskStoreValueInWorker<DskWrappedBlob>(key);
  if (!wrapped) return null;
  return parseJsonStrictBytes(
    await dskDecrypt(requireDsk(state), wrapped.ciphertext, wrapped.iv, buildDskStoreValueAad(key)),
  );
}

function requiredNumber(value: unknown, name: string): number {
  if (!Number.isInteger(value)) {
    throw new CryptoOperationError("invalid_payload", `${name}_invalid`);
  }
  return value as number;
}

function requiredRecord(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new CryptoOperationError("invalid_payload", `${name}_invalid`);
  }
  return value as Record<string, unknown>;
}

function assertAadRecord(value: unknown, name: string, expectedKeys: string[]): StrictJsonValue {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new CryptoOperationError("invalid_payload", `${name}_invalid`);
  }
  const actualKeys = Object.keys(value).sort();
  if (JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)) {
    throw new CryptoOperationError("invalid_payload", `${name}_unexpected_keys`);
  }
  return value as StrictJsonValue;
}

export async function handleWrapDeviceKeysWithDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const userId = payload.userId as string;
  const signingState = state.deviceHybridSigningState;

  if (
    !state.deviceEcdhPrivate ||
    !state.deviceHybridEncryptionPrivateKeyMaterial ||
    !signingState
  ) {
    throw new CryptoOperationError("not_initialized", "Device keys not available");
  }

  const encryptionKeyId = computeHybridEncryptionKeyId(
    publicHybridEncryptionMaterialFromPrivate(state.deviceHybridEncryptionPrivateKeyMaterial),
  );
  const deviceId = state.deviceHybridEncryptionPrivateKeyMaterial.owner_id;
  const wrappedEcdh = {
    ...(await dskEncrypt(
      dsk,
      state.deviceEcdhPrivate,
      buildDskDeviceEcdhAad({ userId, deviceId, encryptionKeyId }),
    )),
    encryptionKeyId,
  };
  const wrappedMlkem = await dskEncrypt(
    dsk,
    canonicalizeStrictBytes(
      state.deviceHybridEncryptionPrivateKeyMaterial as unknown as StrictJsonValue,
    ),
    buildDskDeviceMlkem768Aad({ userId, deviceId, encryptionKeyId }),
  );
  const wrappedSigning = {
    ...(await dskEncrypt(
      dsk,
      canonicalizeStrictBytes(signingState.privateKeyMaterial as unknown as StrictJsonValue),
      buildDskDeviceSigningAad(
        userId,
        signingState.privateKeyMaterial.owner_id,
        signingState.signingKeyId,
      ),
    )),
    signingKeyId: signingState.signingKeyId,
  };

  return {
    wrappedEcdh,
    wrappedMlkem,
    wrappedSigning,
  };
}

export async function handlePersistShareParticipantKeysWithDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const principalId = requiredString(payload.principalId, "principal_id");
  const shareId = requiredString(payload.shareId, "share_id");
  const shareParticipantDeviceId = requiredString(
    payload.shareParticipantDeviceId,
    "share_participant_device_id",
  );
  const expectedSigningKeyId = requiredString(payload.signingKeyId, "signing_key_id");
  const signingState = state.shareParticipantHybridSigningState;

  if (
    !state.deviceEcdhPrivate ||
    !state.deviceHybridEncryptionPrivateKeyMaterial ||
    !signingState ||
    signingState.privateKeyMaterial.owner_kind !== "share_participant_device" ||
    signingState.privateKeyMaterial.owner_id !== shareParticipantDeviceId
  ) {
    throw new CryptoOperationError("not_initialized", "Share participant keys not available");
  }
  if (signingState.signingKeyId !== expectedSigningKeyId) {
    throw new CryptoOperationError("invalid_key", "Share participant signing key id mismatch");
  }

  const encryptionKeyId = computeHybridEncryptionKeyId(
    publicHybridEncryptionMaterialFromPrivate(state.deviceHybridEncryptionPrivateKeyMaterial),
  );
  const wrappedEcdh = {
    ...(await dskEncrypt(
      dsk,
      state.deviceEcdhPrivate,
      buildDskShareParticipantDeviceEcdhAad({
        principalId,
        shareId,
        shareParticipantDeviceId,
        encryptionKeyId,
      }),
    )),
    encryptionKeyId,
  };
  const wrappedMlkem = await dskEncrypt(
    dsk,
    canonicalizeStrictBytes(
      state.deviceHybridEncryptionPrivateKeyMaterial as unknown as StrictJsonValue,
    ),
    buildDskShareParticipantDeviceMlkem768Aad({
      principalId,
      shareId,
      shareParticipantDeviceId,
      encryptionKeyId,
    }),
  );
  const wrappedSigning = {
    ...(await dskXChaChaEncrypt(
      dsk,
      canonicalizeStrictBytes(signingState.privateKeyMaterial as unknown as StrictJsonValue),
      buildDskShareParticipantSigningAad(
        shareId,
        shareParticipantDeviceId,
        signingState.signingKeyId,
      ),
    )),
    signingKeyId: signingState.signingKeyId,
  };

  await storeShareParticipantDeviceKeysInWorker(shareId, shareParticipantDeviceId, {
    wrappedEcdh,
    wrappedMlkem,
    wrappedSigning,
  });

  return { stored: true };
}

export async function handlePersistCurrentKeysWithDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const userId = payload.userId as string;
  let storedUmk = false;
  let storedDeviceKeys = false;

  if (payload.persistUmk !== false) {
    const wrappedUmk = await handleWrapUmkWithDsk(state, { userId });
    await storeDskStoreValueInWorker(WRAPPED_UMK_KEY, wrappedUmk);
    storedUmk = true;
  } else {
    await deleteDskStoreValueInWorker(WRAPPED_UMK_KEY);
  }

  if (
    state.deviceEcdhPrivate &&
    state.deviceHybridEncryptionPrivateKeyMaterial &&
    currentDeviceHybridSigningState(state)
  ) {
    const wrapped = (await handleWrapDeviceKeysWithDsk(state, { userId })) as {
      wrappedEcdh: unknown;
      wrappedMlkem: unknown;
      wrappedSigning: unknown;
    };
    await storeDskStoreValueInWorker(WRAPPED_DEVICE_ECDH_KEY, wrapped.wrappedEcdh);
    await storeDskStoreValueInWorker(WRAPPED_DEVICE_MLKEM_KEY, wrapped.wrappedMlkem);
    await storeDskStoreValueInWorker(WRAPPED_DEVICE_SIGNING_KEY, wrapped.wrappedSigning);
    storedDeviceKeys = true;
  }

  return { storedUmk, storedDeviceKeys };
}

export async function handleUnwrapDeviceKeysFromDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const wrappedEcdh = payload.wrappedEcdh as {
    ciphertext: ArrayBuffer;
    iv: ArrayBuffer;
    encryptionKeyId: string;
  };
  const wrappedMlkem = payload.wrappedMlkem as { ciphertext: ArrayBuffer; iv: ArrayBuffer };
  const wrappedSigning = payload.wrappedSigning as {
    ciphertext: ArrayBuffer;
    iv: ArrayBuffer;
    signingKeyId: string;
  };
  const userId = payload.userId as string;
  const expectedSigningKeyId = requiredString(payload.signingKeyId, "signing_key_id");
  if (!wrappedSigning.signingKeyId) {
    throw new CryptoOperationError("invalid_key", "Device signing key id missing");
  }
  if (wrappedSigning.signingKeyId !== expectedSigningKeyId) {
    throw new CryptoOperationError("invalid_key", "Device signing key id mismatch");
  }
  if (typeof wrappedEcdh.encryptionKeyId !== "string") {
    throw new CryptoOperationError("invalid_key", "Device encryption key id missing");
  }

  const ecdhPrivate = await dskDecrypt(
    dsk,
    wrappedEcdh.ciphertext,
    wrappedEcdh.iv,
    buildDskDeviceEcdhAad({
      userId,
      deviceId: state.deviceId ?? "",
      encryptionKeyId: wrappedEcdh.encryptionKeyId,
    }),
  );
  const signingPrivateKeyMaterial = parseJsonStrictBytes(
    await dskDecrypt(
      dsk,
      wrappedSigning.ciphertext,
      wrappedSigning.iv,
      buildDskDeviceSigningAad(userId, state.deviceId ?? "", expectedSigningKeyId),
    ),
  );
  const hybridEncryptionPrivateKeyMaterial = parseJsonStrictBytes(
    await dskDecrypt(
      dsk,
      wrappedMlkem.ciphertext,
      wrappedMlkem.iv,
      buildDskDeviceMlkem768Aad({
        userId,
        deviceId: state.deviceId ?? "",
        encryptionKeyId: wrappedEcdh.encryptionKeyId,
      }),
    ),
  );
  assertHybridEncryptionPrivateKeyMaterial(hybridEncryptionPrivateKeyMaterial);
  assertHybridSigningPrivateKeyMaterial(signingPrivateKeyMaterial);
  const signingPublicKeyMaterial = publicKeyMaterialFromPrivate(signingPrivateKeyMaterial);
  const signingKeyId = computeSigningKeyId(signingPublicKeyMaterial);
  if (state.deviceId && hybridEncryptionPrivateKeyMaterial.owner_id !== state.deviceId) {
    throw new CryptoOperationError("invalid_key", "Device encryption material owner mismatch");
  }
  const encryptionKeyId = computeHybridEncryptionKeyId(
    publicHybridEncryptionMaterialFromPrivate(hybridEncryptionPrivateKeyMaterial),
  );
  if (encryptionKeyId !== wrappedEcdh.encryptionKeyId) {
    throw new CryptoOperationError("invalid_key", "Device encryption key id mismatch");
  }
  if (
    signingPrivateKeyMaterial.owner_kind !== "device" ||
    (state.deviceId && signingPrivateKeyMaterial.owner_id !== state.deviceId)
  ) {
    throw new CryptoOperationError("invalid_key", "Device signing material owner mismatch");
  }
  if (signingKeyId !== expectedSigningKeyId) {
    throw new CryptoOperationError("invalid_key", "Device signing key id mismatch");
  }
  setDeviceFromPrivateKeys(
    state,
    ecdhPrivate,
    hybridEncryptionPrivateKeyMaterial,
    signingPrivateKeyMaterial,
    "device",
    signingPrivateKeyMaterial.owner_id,
  );

  return { status: "ok" };
}

export async function handleRestoreShareParticipantKeysFromDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const principalId = requiredString(payload.principalId, "principal_id");
  const shareId = requiredString(payload.shareId, "share_id");
  const shareParticipantDeviceId = requiredString(
    payload.shareParticipantDeviceId,
    "share_participant_device_id",
  );
  const expectedSigningKeyId = requiredString(payload.signingKeyId, "signing_key_id");
  const wrapped = await loadShareParticipantDeviceKeysInWorker(shareId, shareParticipantDeviceId);
  if (!wrapped) {
    throw new CryptoOperationError("key_not_found", "Share participant wrapped keys not available");
  }
  const wrappedEcdh = wrapped.wrappedEcdh as {
    ciphertext: ArrayBuffer;
    iv: ArrayBuffer;
    encryptionKeyId: string;
  };
  const wrappedMlkem = wrapped.wrappedMlkem as { ciphertext: ArrayBuffer; iv: ArrayBuffer };
  const wrappedSigning = wrapped.wrappedSigning as {
    ciphertext: ArrayBuffer;
    nonce: ArrayBuffer;
    signingKeyId: string;
  };
  if (!wrappedSigning.signingKeyId) {
    throw new CryptoOperationError("invalid_key", "Share participant signing key id missing");
  }
  if (wrappedSigning.signingKeyId !== expectedSigningKeyId) {
    throw new CryptoOperationError("invalid_key", "Share participant signing key id mismatch");
  }
  if (typeof wrappedEcdh.encryptionKeyId !== "string") {
    throw new CryptoOperationError("invalid_key", "Share participant encryption key id missing");
  }

  const ecdhPrivate = await dskDecrypt(
    dsk,
    wrappedEcdh.ciphertext,
    wrappedEcdh.iv,
    buildDskShareParticipantDeviceEcdhAad({
      principalId,
      shareId,
      shareParticipantDeviceId,
      encryptionKeyId: wrappedEcdh.encryptionKeyId,
    }),
  );
  const signingPrivateKeyMaterial = parseJsonStrictBytes(
    await dskXChaChaDecrypt(
      dsk,
      wrappedSigning.ciphertext,
      wrappedSigning.nonce,
      buildDskShareParticipantSigningAad(shareId, shareParticipantDeviceId, expectedSigningKeyId),
    ),
  );
  const hybridEncryptionPrivateKeyMaterial = parseJsonStrictBytes(
    await dskDecrypt(
      dsk,
      wrappedMlkem.ciphertext,
      wrappedMlkem.iv,
      buildDskShareParticipantDeviceMlkem768Aad({
        principalId,
        shareId,
        shareParticipantDeviceId,
        encryptionKeyId: wrappedEcdh.encryptionKeyId,
      }),
    ),
  );
  assertHybridEncryptionPrivateKeyMaterial(hybridEncryptionPrivateKeyMaterial);
  assertHybridSigningPrivateKeyMaterial(signingPrivateKeyMaterial);
  const signingPublicKeyMaterial = publicKeyMaterialFromPrivate(signingPrivateKeyMaterial);
  const signingKeyId = computeSigningKeyId(signingPublicKeyMaterial);
  if (hybridEncryptionPrivateKeyMaterial.owner_id !== shareParticipantDeviceId) {
    throw new CryptoOperationError(
      "invalid_key",
      "Share participant encryption material owner mismatch",
    );
  }
  const encryptionKeyId = computeHybridEncryptionKeyId(
    publicHybridEncryptionMaterialFromPrivate(hybridEncryptionPrivateKeyMaterial),
  );
  if (encryptionKeyId !== wrappedEcdh.encryptionKeyId) {
    throw new CryptoOperationError("invalid_key", "Share participant encryption key id mismatch");
  }
  if (
    signingPrivateKeyMaterial.owner_kind !== "share_participant_device" ||
    signingPrivateKeyMaterial.owner_id !== shareParticipantDeviceId
  ) {
    throw new CryptoOperationError(
      "invalid_key",
      "Share participant signing material owner mismatch",
    );
  }
  if (signingKeyId !== expectedSigningKeyId) {
    throw new CryptoOperationError("invalid_key", "Share participant signing key id mismatch");
  }
  setDeviceFromPrivateKeys(
    state,
    ecdhPrivate,
    hybridEncryptionPrivateKeyMaterial,
    signingPrivateKeyMaterial,
    "share_participant_device",
    shareParticipantDeviceId,
  );

  return { status: "ok" };
}

export async function handleGenerateDskKey(state: WorkerKeyState): Promise<unknown> {
  const keyMaterial = randomBytes(32);
  try {
    const dsk = await crypto.subtle.importKey("raw", arrayBuffer(keyMaterial), "HKDF", false, [
      "deriveKey",
      "deriveBits",
    ]);
    state.dsk = dsk;
    await storeDskInWorker(dsk);
    return { status: "ok" };
  } finally {
    keyMaterial.fill(0);
  }
}
