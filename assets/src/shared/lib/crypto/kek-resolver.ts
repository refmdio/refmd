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
import {
  getKeyDirectoryPin,
  hashKeyDirectoryCheckpointEnvelope,
  advanceKeyDirectoryPinWithProof,
} from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { recoverKekFromCache } from "@/shared/lib/offline/cache/manager/keys";
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
  let keys: Awaited<ReturnType<typeof encryptionApi.getWorkspaceKeysWithPop>>["keys"] = [];
  let currentKekVersion = 0;
  try {
    const keysResponse = await encryptionApi.getWorkspaceKeysWithPop(workspaceId, deviceId, {
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
    const expectedOperationCheckpoint = await installWorkspaceOperationCheckpointPin(
      workspaceId,
      activeKey as Record<string, unknown>,
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
      record: activeKey as never,
      senderSigningPublicKeyMaterial:
        activeKey.sender_hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial,
      expectedOperationCheckpoint,
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
    const keysResponse = await encryptionApi.getWorkspaceKeysWithPop(workspaceId, deviceId, {
      signal,
    });
    const matchingKey = keysResponse.keys.find((k) => k.key_version === keyVersion);
    if (!matchingKey) {
      return false;
    }
    envelopeFound = true;
    const expectedOperationCheckpoint = await installWorkspaceOperationCheckpointPin(
      workspaceId,
      matchingKey as Record<string, unknown>,
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
      record: matchingKey as never,
      senderSigningPublicKeyMaterial:
        matchingKey.sender_hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial,
      expectedOperationCheckpoint,
    });
    return true;
  } catch (err) {
    if (envelopeFound) throw err;
    return false;
  }
}

export async function installWorkspaceOperationCheckpointPin(
  workspaceId: string,
  wrapRecord: Record<string, unknown>,
): Promise<{ sequence: number; checkpointHash: string }> {
  const checkpoint = wrapRecord.workspace_key_directory_checkpoint;
  if (!isRecord(checkpoint)) {
    throw new Error("workspace_key_directory_checkpoint_missing");
  }

  const operationCheckpoint = wrapRecord.operation_checkpoint;
  if (!isRecord(operationCheckpoint)) {
    throw new Error("workspace_key_directory_checkpoint_missing");
  }
  const operationCheckpointSequence = operationCheckpoint.checkpoint_sequence;
  if (typeof operationCheckpointSequence !== "number") {
    throw new Error("workspace_key_directory_checkpoint_sequence_invalid");
  }

  const expectedHash = operationCheckpoint.checkpoint_hash;
  if (
    typeof expectedHash !== "string" ||
    hashKeyDirectoryCheckpointEnvelope(checkpoint) !== expectedHash
  ) {
    throw new Error("workspace_key_directory_checkpoint_hash_mismatch");
  }

  const existing = await getKeyDirectoryPin("workspace", workspaceId);
  if (existing) {
    if (
      existing.checkpointSequence === operationCheckpointSequence &&
      existing.checkpointHash !== expectedHash
    ) {
      throw new Error("workspace_key_directory_checkpoint_pin_mismatch");
    }
    if (existing.checkpointSequence < operationCheckpointSequence) {
      const checkpointAncestry = wrapRecord.workspace_key_directory_checkpoint_ancestry;
      const eventAncestry = wrapRecord.workspace_key_directory_event_ancestry;
      if (!Array.isArray(checkpointAncestry) || !Array.isArray(eventAncestry)) {
        throw new Error("workspace_key_directory_checkpoint_ancestry_required");
      }
      const eventAncestryRecords = eventAncestry.filter((entry): entry is Record<string, unknown> =>
        isRecord(entry),
      );
      await advanceKeyDirectoryPinWithProof({
        scopeKind: "workspace",
        scopeId: workspaceId,
        checkpointEnvelope: checkpoint,
        checkpointAncestry: checkpointAncestry
          .filter((entry): entry is Record<string, unknown> => isRecord(entry))
          .filter((entry) => checkpointEnvelopeSequence(entry) >= existing.checkpointSequence),
        eventAncestry: eventAncestryRecords.filter(
          (entry) => eventEnvelopeSequence(entry) > existing.eventHeadSequence,
        ),
        authorityEventAncestry: eventAncestryRecords,
      });
      const advanced = await getKeyDirectoryPin("workspace", workspaceId);
      if (
        !advanced ||
        advanced.checkpointSequence !== operationCheckpointSequence ||
        advanced.checkpointHash !== expectedHash
      ) {
        throw new Error("workspace_key_directory_checkpoint_pin_advance_failed");
      }
    }
    return { sequence: operationCheckpointSequence, checkpointHash: expectedHash };
  }

  throw new Error("workspace_key_directory_pin_required");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function checkpointEnvelopeSequence(envelope: Record<string, unknown>): number {
  const payload = envelope.payload;
  if (!isRecord(payload) || typeof payload.sequence !== "number") {
    throw new Error("workspace_key_directory_checkpoint_sequence_invalid");
  }
  return payload.sequence;
}

function eventEnvelopeSequence(envelope: Record<string, unknown>): number {
  const payload = envelope.payload;
  if (!isRecord(payload) || typeof payload.sequence !== "number") {
    throw new Error("workspace_key_directory_event_sequence_invalid");
  }
  return payload.sequence;
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
  const operationSequence = numberField(operationCheckpoint.covered_event_head_sequence);

  if (
    sender.key_scope_kind !== "workspace" ||
    sender.key_scope_id !== workspaceId ||
    sender.device_id !== senderDeviceId ||
    sender.signing_key_id !== senderSigningKeyId
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
    operationSequence,
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
      operationSequence,
      errorPrefix: "workspace_sender_encryption",
    });
  }
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
  const entry = entries.find(
    (candidate) => isRecord(candidate) && candidate.key_id === params.keyId,
  );
  if (!isRecord(entry)) throw new Error(`${params.errorPrefix}_key_missing`);
  if (isRevokedAtOrBefore(entry.revoked_at, params.operationSequence)) {
    throw new Error(`${params.errorPrefix}_key_revoked`);
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

function isRevokedAtOrBefore(value: unknown, operationSequence: number): boolean {
  if (!isRecord(value)) return false;
  const eventSequence = value.event_sequence;
  return typeof eventSequence === "number" && eventSequence <= operationSequence;
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
