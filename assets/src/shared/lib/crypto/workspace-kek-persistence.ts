import { encryptionApi } from "@/shared/api/encryption";
import { ApiError } from "@/shared/api/core";
import type { HybridEncryptionPublicKeyMaterial } from "./hybrid-encryption";
import { getCryptoWorker } from "./worker/client";
import type { SignedPqWrapRecord } from "./signed-pq-wrap";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import { hashKeyDirectoryCheckpointEnvelope } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { buildWrapIssuedKeyDirectoryAppend } from "./key-directory/wrap-events";
import type { KeyDirectoryEnvelope } from "./key-directory/types";
import { blake3Base64Url } from "./hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "./jcs";
interface ConflictHandlingOptions {
  ignoreConflict?: boolean;
}
interface PersistWorkspaceKekForDeviceParams extends ConflictHandlingOptions {
  workspaceId: string;
  userId: string;
  targetUserId?: string;
  senderDeviceId: string;
  targetDeviceId: string;
  targetDeviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  keyVersion: number;
  isActive?: boolean;
  rrpDeviceId?: string;
  keyDirectoryCheckpoint?: KeyDirectoryEnvelope;
}
interface PersistWorkspaceKekLocallyParams extends ConflictHandlingOptions {
  workspaceId: string;
  userId: string;
  deviceId: string;
  deviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial | null;
  keyVersion: number;
  isActive?: boolean;
  keyDirectoryCheckpoint?: KeyDirectoryEnvelope;
}
interface PersistWorkspaceKekForMemberParams extends ConflictHandlingOptions {
  workspaceId: string;
  userId: string;
  senderDeviceId: string;
  targetUserId: string;
  targetIdentityHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  keyVersion: number;
  rrpDeviceId?: string;
  keyDirectoryCheckpoint?: KeyDirectoryEnvelope;
}
export interface IdentityRotationWorkspaceRewrap extends Record<string, StrictJsonValue> {
  workspace_id: string;
  workspace_checkpoint_hash: string;
  member_envelope_manifest_hash: string;
  affected_member_envelope_ids_hash: string;
  new_identity_recipient_key_id: string;
}
function shouldIgnoreConflict(error: unknown, ignoreConflict: boolean): boolean {
  return ignoreConflict && error instanceof ApiError && error.status === 409;
}
export async function persistWorkspaceKekForDevice({
  workspaceId,
  userId,
  targetUserId,
  senderDeviceId,
  targetDeviceId,
  targetDeviceHybridEncryptionPublicKeyMaterial,
  keyVersion,
  isActive,
  rrpDeviceId,
  keyDirectoryCheckpoint,
  ignoreConflict = false,
}: PersistWorkspaceKekForDeviceParams): Promise<void> {
  const recipientUserId = targetUserId ?? userId;
  const worker = getCryptoWorker();
  const checkpointEnvelope =
    keyDirectoryCheckpoint ??
    (
      await fetchVerifiedKeyDirectory({
        scopeKind: "workspace",
        scopeId: workspaceId,
        rrpDeviceId: rrpDeviceId ?? senderDeviceId,
      })
    ).checkpoint;
  const operationCheckpoint = operationCheckpointFromEnvelope(checkpointEnvelope);
  let wrap = await worker.createSignedPqKekWrap({
    purpose: "workspace_device_kek_wrap",
    workspaceId,
    keyVersion,
    recipientPublicKeyMaterial: targetDeviceHybridEncryptionPublicKeyMaterial,
    senderUserId: userId,
    senderDeviceId,
    resource: {
      workspace_id: workspaceId,
      target_user_id: recipientUserId,
      target_device_id: targetDeviceId,
      kek_version: keyVersion,
    },
    eventScope: {
      scope_kind: "workspace",
      scope_id: workspaceId,
    },
    operationCheckpoint,
  });
  const keyDirectoryAppend = await buildWrapIssuedKeyDirectoryAppend({
    scopeKind: "workspace",
    scopeId: workspaceId,
    checkpointEnvelope,
    wrapRecord: wrap,
  });
  wrap = await worker.finalizeSignedPqWrapOperationCheckpoint({
    record: wrap,
    operationCheckpoint: operationCheckpointFromEnvelope(keyDirectoryAppend.checkpoint),
  });
  try {
    await encryptionApi.createWorkspaceKeyWithRrp(
      workspaceId,
      signedWrapWorkspaceKeyRequest({
        wrap,
        target_user_id: recipientUserId,
        device_id: targetDeviceId,
        sender_device_id: senderDeviceId,
        key_version: keyVersion,
        is_active: isActive,
        workspace_key_directory_events: keyDirectoryAppend.events,
        workspace_key_directory_checkpoint: keyDirectoryAppend.checkpoint,
      }),
      {
        rrpDeviceId,
      },
    );
  } catch (error) {
    if (!shouldIgnoreConflict(error, ignoreConflict)) {
      throw error;
    }
  }
}
export async function persistWorkspaceKekLocally({
  workspaceId,
  userId,
  deviceId,
  deviceHybridEncryptionPublicKeyMaterial,
  keyVersion,
  isActive,
  keyDirectoryCheckpoint,
  ignoreConflict = false,
}: PersistWorkspaceKekLocallyParams): Promise<void> {
  if (!deviceHybridEncryptionPublicKeyMaterial) {
    throw new Error("Device hybrid encryption public key material not available");
  }
  await persistWorkspaceKekForDevice({
    workspaceId,
    userId,
    senderDeviceId: deviceId,
    targetDeviceId: deviceId,
    targetDeviceHybridEncryptionPublicKeyMaterial: deviceHybridEncryptionPublicKeyMaterial,
    keyVersion,
    isActive,
    rrpDeviceId: deviceId,
    keyDirectoryCheckpoint,
    ignoreConflict,
  });
}

export async function persistWorkspaceKekForMember({
  workspaceId,
  userId,
  senderDeviceId,
  targetUserId,
  targetIdentityHybridEncryptionPublicKeyMaterial,
  keyVersion,
  rrpDeviceId,
  keyDirectoryCheckpoint,
  ignoreConflict = false,
}: PersistWorkspaceKekForMemberParams): Promise<IdentityRotationWorkspaceRewrap> {
  const worker = getCryptoWorker();
  const checkpointEnvelope =
    keyDirectoryCheckpoint ??
    (
      await fetchVerifiedKeyDirectory({
        scopeKind: "workspace",
        scopeId: workspaceId,
        rrpDeviceId: rrpDeviceId ?? senderDeviceId,
      })
    ).checkpoint;
  const operationCheckpoint = operationCheckpointFromEnvelope(checkpointEnvelope);
  let wrap = await worker.createSignedPqKekWrap({
    purpose: "workspace_member_kek_wrap",
    workspaceId,
    keyVersion,
    recipientPublicKeyMaterial: targetIdentityHybridEncryptionPublicKeyMaterial,
    senderUserId: userId,
    senderDeviceId,
    resource: {
      workspace_id: workspaceId,
      target_user_id: targetUserId,
      kek_version: keyVersion,
    },
    eventScope: {
      scope_kind: "workspace",
      scope_id: workspaceId,
    },
    operationCheckpoint,
  });
  const keyDirectoryAppend = await buildWrapIssuedKeyDirectoryAppend({
    scopeKind: "workspace",
    scopeId: workspaceId,
    checkpointEnvelope,
    wrapRecord: wrap,
  });
  wrap = await worker.finalizeSignedPqWrapOperationCheckpoint({
    record: wrap,
    operationCheckpoint: operationCheckpointFromEnvelope(keyDirectoryAppend.checkpoint),
  });
  try {
    await encryptionApi.saveMemberEnvelopes(
      workspaceId,
      {
        envelopes: [
          {
            target_user_id: targetUserId,
            sender_device_id: senderDeviceId,
            key_version: keyVersion,
            ...wrap,
          } as never,
        ],
        workspace_key_directory_events: keyDirectoryAppend.events,
        workspace_key_directory_checkpoint: keyDirectoryAppend.checkpoint,
      },
      {
        rrpDeviceId,
      },
    );
  } catch (error) {
    if (!shouldIgnoreConflict(error, ignoreConflict)) {
      throw error;
    }
  }

  const envelopeId = {
    workspace_id: workspaceId,
    target_user_id: targetUserId,
    key_version: keyVersion,
  };
  return {
    workspace_id: workspaceId,
    workspace_checkpoint_hash: hashKeyDirectoryCheckpointEnvelope(keyDirectoryAppend.checkpoint),
    member_envelope_manifest_hash: blake3Base64Url(
      canonicalizeStrictBytes({
        member_envelopes: [
          {
            ...envelopeId,
            wrap_event_body_hash: wrap.event.wrap_event_body_hash,
          },
        ],
      }),
    ),
    affected_member_envelope_ids_hash: blake3Base64Url(
      canonicalizeStrictBytes({ member_envelope_ids: [envelopeId] }),
    ),
    new_identity_recipient_key_id: wrap.recipient.encryption_key_id,
  };
}

function operationCheckpointFromEnvelope(checkpointEnvelope: KeyDirectoryEnvelope) {
  const payload = checkpointEnvelope.payload as Record<string, unknown> | undefined;
  const covered = payload?.covered_event_head as Record<string, unknown> | undefined;
  if (!payload || !covered) throw new Error("key_directory_checkpoint_invalid");
  return {
    sequence: numberField(payload.sequence),
    checkpointHash: hashField(checkpointEnvelope),
    coveredHeadSequence: numberField(covered.head_sequence),
    coveredHeadHash: stringField(covered.head_hash),
  };
}

function signedWrapWorkspaceKeyRequest(params: {
  wrap: SignedPqWrapRecord;
  target_user_id: string;
  device_id: string;
  sender_device_id: string;
  key_version: number;
  is_active?: boolean;
  workspace_key_directory_events: KeyDirectoryEnvelope[];
  workspace_key_directory_checkpoint: KeyDirectoryEnvelope;
}) {
  return {
    target_user_id: params.target_user_id,
    device_id: params.device_id,
    key_version: params.key_version,
    sender_device_id: params.sender_device_id,
    is_active: params.is_active,
    workspace_key_directory_events: params.workspace_key_directory_events,
    workspace_key_directory_checkpoint: params.workspace_key_directory_checkpoint,
    ...params.wrap,
  } as never;
}

function hashField(value: KeyDirectoryEnvelope): string {
  return hashKeyDirectoryCheckpointEnvelope(value);
}

function numberField(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
    throw new Error("number_field_invalid");
  }
  return value;
}

function stringField(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) throw new Error("string_field_invalid");
  return value;
}
