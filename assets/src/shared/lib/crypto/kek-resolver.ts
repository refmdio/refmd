import { encryptionApi, ApiError } from "@/shared/api";
import { getCryptoWorker } from "./worker/client";
import { KekResolutionError } from "./kek-resolver-error";
import { verifySenderDeviceIdentityAndTofu } from "./sender-device-verification";
import type { HybridSigningPublicKeyMaterial } from "./signature-types";
import {
  computeHybridEncryptionKeyId,
  type HybridEncryptionPublicKeyMaterial,
} from "./hybrid-encryption";
import { canonicalizeStrictBytes, type StrictJsonValue } from "./jcs";
import { verifyWorkspaceSignedPqWrapOperation } from "@/shared/lib/anti-rollback/key-directory-pin/wrap-operation-proof";
import { recoverKekFromCache } from "@/shared/lib/offline/cache/manager/keys";
import { acknowledgeWorkspaceWipeIfRequired } from "./workspace-kek-wipe";
const pendingActiveKekResolutions = new Map<
  string,
  Promise<{
    kekVersion: number;
  }>
>();
interface KekResolverAuthState {
  user: {
    id: string;
  };
  identityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial | null;
  identityEcdhPublic: Uint8Array | null;
}
interface KekResolverDeviceState {
  deviceId: string;
  deviceEcdhPublic: Uint8Array | null;
}
export interface KekResolverSession {
  auth: KekResolverAuthState | null;
  device: KekResolverDeviceState | null;
}
function requireKekResolverSession(session: KekResolverSession): {
  auth: KekResolverAuthState;
  device: KekResolverDeviceState;
} {
  if (!session.auth || !session.device?.deviceId) {
    throw new Error("Not authenticated");
  }
  return {
    auth: session.auth,
    device: session.device,
  };
}
export async function resolveActiveKek(
  workspaceId: string,
  session: KekResolverSession,
  signal?: AbortSignal,
): Promise<{
  kekVersion: number;
}> {
  const worker = getCryptoWorker();
  const { auth, device } = requireKekResolverSession(session);
  await acknowledgeWorkspaceWipeIfRequired({
    workspaceId,
    userId: auth.user.id,
    deviceId: device.deviceId,
  });
  const cached = await worker.resolveKek(workspaceId);
  if (cached.found && cached.keyVersion !== undefined) {
    await worker.setActiveKekVersion(workspaceId, cached.keyVersion);
    return { kekVersion: cached.keyVersion };
  }
  const pending = pendingActiveKekResolutions.get(workspaceId);
  if (pending) return pending;
  const resolution = doResolveActiveKek(workspaceId, auth, device, worker, signal);
  pendingActiveKekResolutions.set(workspaceId, resolution);
  try {
    return await resolution;
  } finally {
    pendingActiveKekResolutions.delete(workspaceId);
  }
}
async function doResolveActiveKek(
  workspaceId: string,
  auth: KekResolverAuthState,
  device: KekResolverDeviceState,
  worker: ReturnType<typeof getCryptoWorker>,
  signal?: AbortSignal,
): Promise<{
  kekVersion: number;
}> {
  const userId = auth.user.id;
  const deviceId = device.deviceId;
  let keys: Awaited<ReturnType<typeof encryptionApi.getWorkspaceKeysWithRrp>>["keys"] = [];
  let currentKekVersion = 0;
  try {
    const keysResponse = await encryptionApi.getWorkspaceKeysWithRrp(workspaceId, deviceId, {
      signal,
    });
    keys = keysResponse.keys;
    currentKekVersion = keysResponse.current_kek_version;
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) {
      const details = (e.body as Record<string, unknown>)?.details as
        | Record<string, unknown>
        | undefined;
      currentKekVersion = (details?.current_kek_version as number) ?? 0;
    } else {
      throw e;
    }
  }
  if (currentKekVersion === 0) {
    throw new KekResolutionError(workspaceId, "Encryption not set up for this workspace");
  }
  const activeKey = keys.find((k) => k.key_version === currentKekVersion);
  if (activeKey) {
    await verifyWorkspaceSignedPqWrapOperation(
      workspaceId,
      activeKey as unknown as Record<string, unknown>,
    );
    assertWorkspaceSenderKeyAdmission(workspaceId, activeKey as Record<string, unknown>);
    const senderUserId = activeKey.sender_user_id ?? userId;
    try {
      await verifySenderDeviceIdentityAndTofu({
        sender: activeKey,
        senderUserId,
        expectedIdentityHybridSigningPublicKeyMaterial:
          senderUserId === userId ? auth.identityHybridSigningPublicKeyMaterial : null,
        expectedIdentityEcdhPublic: senderUserId === userId ? auth.identityEcdhPublic : null,
        allowFirstSeenIdentity: senderUserId !== userId,
      });
    } catch {
      throw new KekResolutionError(workspaceId, "Key verification failed for KEK sender device.");
    }
    await worker.openSignedPqDeviceKekWrap({
      operationProof: activeKey as unknown as Record<string, unknown>,
      senderSigningPublicKeyMaterial:
        activeKey.sender_hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial,
    });
    await worker.setActiveKekVersion(workspaceId, currentKekVersion);
  } else {
    const recovered = await recoverKekFromCache(workspaceId).catch(() => false);
    if (!recovered) {
      throw new KekResolutionError(
        workspaceId,
        "KEK recovery requires a verified device envelope.",
      );
    }
  }
  await worker.setActiveKekVersion(workspaceId, currentKekVersion);
  return { kekVersion: currentKekVersion };
}
/**
 * Resolve a specific KEK version for a workspace.
 * Used when unwrapping old DEKs that were wrapped with a previous KEK version.
 * Priority: worker cache → device envelope
 */
export async function resolveKekByVersion(
  workspaceId: string,
  keyVersion: number,
  session: KekResolverSession,
  signal?: AbortSignal,
): Promise<void> {
  const worker = getCryptoWorker();
  const { auth, device } = requireKekResolverSession(session);
  // 1. Check cache
  const cached = await worker.resolveKek(workspaceId, keyVersion);
  if (cached.found) return;
  const userId = auth.user.id;
  const deviceId = device.deviceId;
  // 2. Try device envelope (includes TOFU verification)
  const resolved = await tryDecryptKekViaDeviceEnvelope(
    worker,
    workspaceId,
    userId,
    deviceId,
    keyVersion,
    auth.identityHybridSigningPublicKeyMaterial,
    auth.identityEcdhPublic,
    signal,
  );
  if (resolved) return;
  throw new KekResolutionError(
    workspaceId,
    "KEK version recovery requires a verified device envelope.",
  );
}
async function tryDecryptKekViaDeviceEnvelope(
  worker: ReturnType<typeof getCryptoWorker>,
  workspaceId: string,
  userId: string,
  deviceId: string,
  keyVersion: number,
  expectedIdentityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial | null,
  expectedIdentityEcdhPublic: Uint8Array | null,
  signal?: AbortSignal,
): Promise<boolean> {
  let envelopeFound = false;
  try {
    const keysResponse = await encryptionApi.getWorkspaceKeysWithRrp(workspaceId, deviceId, {
      signal,
    });
    const matchingKey = keysResponse.keys.find((k) => k.key_version === keyVersion);
    if (!matchingKey) {
      return false;
    }
    envelopeFound = true;
    await verifyWorkspaceSignedPqWrapOperation(
      workspaceId,
      matchingKey as unknown as Record<string, unknown>,
    );
    assertWorkspaceSenderKeyAdmission(workspaceId, matchingKey as Record<string, unknown>);
    const senderUserId = matchingKey.sender_user_id ?? userId;
    try {
      await verifySenderDeviceIdentityAndTofu({
        sender: matchingKey,
        senderUserId,
        expectedIdentityHybridSigningPublicKeyMaterial:
          senderUserId === userId ? expectedIdentityHybridSigningPublicKeyMaterial : null,
        expectedIdentityEcdhPublic: senderUserId === userId ? expectedIdentityEcdhPublic : null,
        allowFirstSeenIdentity: senderUserId !== userId,
      });
    } catch {
      throw new KekResolutionError(workspaceId, "Key verification failed for KEK sender device.");
    }
    await worker.openSignedPqDeviceKekWrap({
      operationProof: matchingKey as unknown as Record<string, unknown>,
      senderSigningPublicKeyMaterial:
        matchingKey.sender_hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial,
    });
    return true;
  } catch (err) {
    if (envelopeFound) throw err;
    return false;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function assertWorkspaceSenderKeyAdmission(
  workspaceId: string,
  wrapRecord: Record<string, unknown>,
): void {
  const checkpoint = wrapRecord.workspace_key_directory_checkpoint;
  if (!isRecord(checkpoint) || !isRecord(checkpoint.payload)) {
    throw new Error("workspace_sender_checkpoint_invalid");
  }
  const sender = wrapRecord.sender;
  if (!isRecord(sender)) throw new Error("workspace_sender_record_invalid");

  const senderDeviceId = stringField(wrapRecord.sender_device_id);
  const senderSigningKeyId = stringField(sender.signing_key_id);
  const senderMaterial = wrapRecord.sender_hybrid_signing_public_key_material;
  if (!isRecord(senderMaterial)) throw new Error("workspace_sender_signing_material_invalid");
  const operationCheckpoint = wrapRecord.operation_checkpoint;
  if (!isRecord(operationCheckpoint)) throw new Error("workspace_operation_checkpoint_invalid");
  const event = wrapRecord.event;
  if (!isRecord(event)) throw new Error("workspace_wrap_event_invalid");
  const wrapEventSequence = numberField(event.wrap_event_sequence);
  const eventScope = wrapRecord.event_scope;
  if (!isRecord(eventScope)) throw new Error("workspace_event_scope_invalid");

  if (
    checkpoint.payload.scope_kind !== "workspace" ||
    checkpoint.payload.scope_id !== workspaceId ||
    eventScope.scope_kind !== "workspace" ||
    eventScope.scope_id !== workspaceId ||
    sender.signer_kind !== "device" ||
    sender.key_scope_kind !== "workspace" ||
    sender.key_scope_id !== workspaceId ||
    sender.device_id !== senderDeviceId ||
    (typeof wrapRecord.sender_user_id === "string" && sender.user_id !== wrapRecord.sender_user_id)
  ) {
    throw new Error("workspace_sender_record_mismatch");
  }

  assertActiveCheckpointKey({
    checkpointPayload: checkpoint.payload,
    keySet: "device_keys",
    keyId: senderSigningKeyId,
    ownerKind: "device",
    ownerId: senderDeviceId,
    keyMaterial: senderMaterial,
    operationSequence: wrapEventSequence,
    errorPrefix: "workspace_sender_signing",
  });

  const senderEncryptionMaterial = wrapRecord.sender_hybrid_encryption_public_key_material;
  if (isRecord(senderEncryptionMaterial)) {
    assertActiveCheckpointKey({
      checkpointPayload: checkpoint.payload,
      keySet: "device_keys",
      keyId: computeHybridEncryptionKeyId(
        senderEncryptionMaterial as unknown as HybridEncryptionPublicKeyMaterial,
      ),
      ownerKind: "device",
      ownerId: senderDeviceId,
      keyMaterial: senderEncryptionMaterial,
      operationSequence: wrapEventSequence,
      errorPrefix: "workspace_sender_encryption",
    });
  }
}

export async function openAdmittedWorkspaceMemberKekEnvelope(
  workspaceId: string,
  envelope: Record<string, unknown>,
): Promise<void> {
  await verifyWorkspaceSignedPqWrapOperation(workspaceId, envelope);
  assertWorkspaceSenderKeyAdmission(workspaceId, envelope);
  const senderSigningPublicKeyMaterial = envelope.sender_hybrid_signing_public_key_material;
  if (!isRecord(senderSigningPublicKeyMaterial)) {
    throw new Error("workspace_sender_signing_material_invalid");
  }
  await getCryptoWorker().openSignedPqMemberKekWrap({
    operationProof: envelope,
    senderSigningPublicKeyMaterial:
      senderSigningPublicKeyMaterial as unknown as HybridSigningPublicKeyMaterial,
  });
}

function assertActiveCheckpointKey(params: {
  checkpointPayload: Record<string, unknown>;
  keySet: "identity_keys" | "device_keys" | "share_participant_keys";
  keyId: string;
  ownerKind: string;
  ownerId: string;
  keyMaterial: Record<string, unknown>;
  operationSequence: number;
  errorPrefix: string;
}): void {
  const entries = params.checkpointPayload[params.keySet];
  if (!Array.isArray(entries)) throw new Error(`${params.errorPrefix}_key_set_invalid`);
  const matches = entries.filter(
    (candidate) => isRecord(candidate) && candidate.key_id === params.keyId,
  );
  if (matches.length !== 1 || !isRecord(matches[0])) {
    throw new Error(
      matches.length === 0
        ? `${params.errorPrefix}_key_missing`
        : `${params.errorPrefix}_key_duplicate`,
    );
  }
  const entry = matches[0];
  const validFromSequence = assertWorkspaceEventReference(
    entry.valid_from,
    params.checkpointPayload.scope_id,
    `${params.errorPrefix}_valid_from`,
  );
  if (validFromSequence > params.operationSequence) {
    throw new Error(`${params.errorPrefix}_key_not_yet_valid`);
  }
  if (entry.revoked_at !== undefined) {
    const revokedAtSequence = assertWorkspaceEventReference(
      entry.revoked_at,
      params.checkpointPayload.scope_id,
      `${params.errorPrefix}_revoked_at`,
    );
    if (revokedAtSequence <= params.operationSequence) {
      throw new Error(`${params.errorPrefix}_key_revoked`);
    }
  }
  const material = entry.key_material;
  if (!isRecord(material)) throw new Error(`${params.errorPrefix}_material_missing`);
  if (material.owner_kind !== params.ownerKind || material.owner_id !== params.ownerId) {
    throw new Error(`${params.errorPrefix}_owner_mismatch`);
  }
  if (!sameStrictJson(material, params.keyMaterial)) {
    throw new Error(`${params.errorPrefix}_material_mismatch`);
  }
}

function assertWorkspaceEventReference(
  value: unknown,
  workspaceId: unknown,
  errorPrefix: string,
): number {
  if (
    !isRecord(value) ||
    value.scope_kind !== "workspace" ||
    value.scope_id !== workspaceId ||
    typeof value.event_hash !== "string" ||
    value.event_hash.length === 0
  ) {
    throw new Error(`${errorPrefix}_invalid`);
  }
  return numberField(value.event_sequence);
}

function sameStrictJson(left: Record<string, unknown>, right: Record<string, unknown>): boolean {
  const leftBytes = canonicalizeStrictBytes(left as StrictJsonValue);
  const rightBytes = canonicalizeStrictBytes(right as StrictJsonValue);
  if (leftBytes.length !== rightBytes.length) return false;
  return leftBytes.every((byte, index) => byte === rightBytes[index]);
}

function stringField(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("workspace_sender_string_invalid");
  }
  return value;
}

function numberField(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
    throw new Error("workspace_sender_number_invalid");
  }
  return value;
}
