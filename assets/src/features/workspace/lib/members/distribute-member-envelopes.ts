import {
  authState,
  cryptoWorkerReady,
  deviceState,
  getKekResolverSession,
} from "@/entities/session";
import { encryptionApi, workspacesApi } from "@/shared/api";
import {
  buildDeviceKeyDirectoryAppend,
  buildIdentityKeyDirectoryAppend,
} from "@/shared/lib/crypto/key-directory/device-events";
import type {
  KeyDirectoryAppendArtifacts,
  KeyDirectoryEnvelope,
} from "@/shared/lib/crypto/key-directory/types";
import { resolveActiveKek } from "@/shared/lib/crypto/kek-resolver";
import {
  computeHybridEncryptionKeyId,
  type HybridEncryptionPublicKeyMaterial,
} from "@/shared/lib/crypto/hybrid-encryption";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import {
  persistWorkspaceKekForDevice,
  persistWorkspaceKekForMember,
} from "@/shared/lib/crypto/workspace-kek-persistence";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";

export async function distributeWorkspaceMemberEnvelopes(workspaceId: string): Promise<void> {
  const existing = distributionInFlight.get(workspaceId);
  if (existing) return existing;

  const task = runWorkspaceMemberEnvelopeDistribution(workspaceId).finally(() => {
    distributionInFlight.delete(workspaceId);
  });
  distributionInFlight.set(workspaceId, task);
  return task;
}

const distributionInFlight = new Map<string, Promise<void>>();

async function runWorkspaceMemberEnvelopeDistribution(workspaceId: string): Promise<void> {
  const auth = authState();
  const device = deviceState();
  if (!cryptoWorkerReady() || !auth || !device?.deviceId) return;

  const [{ kekVersion }, memberKeys, members] = await Promise.all([
    resolveActiveKek(workspaceId, getKekResolverSession()),
    encryptionApi.getWorkspaceMemberKeys(workspaceId),
    workspacesApi.listMembers(workspaceId),
  ]);
  const memberRoleByUserId = new Map(members.members.map((member) => [member.user_id, member]));
  const currentMemberRole = memberRoleByUserId.get(auth.user.id)?.base_role;
  if (currentMemberRole !== "owner" && currentMemberRole !== "admin") return;

  for (const member of members.members) {
    if (member.user_id === auth.user.id) continue;

    const devices = await workspacesApi
      .listMemberDevices(workspaceId, member.user_id)
      .then((result) => result.devices)
      .catch(() => []);

    for (const memberDevice of devices) {
      if (memberDevice.revoked_at) continue;

      await persistWorkspaceDeviceKek({
        workspaceId,
        ownerUserId: auth.user.id,
        ownerDeviceId: device.deviceId,
        targetUserId: member.user_id,
        targetDeviceId: memberDevice.device_id,
        targetDeviceHybridSigningPublicKeyMaterial:
          memberDevice.hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial,
        targetDeviceHybridEncryptionPublicKeyMaterial:
          memberDevice.hybrid_encryption_public_key_material as unknown as HybridEncryptionPublicKeyMaterial,
        targetDeviceEncryptionKeyId: memberDevice.encryption_key_id,
        keyVersion: kekVersion,
      }).catch(() => {
        // Other devices are retried independently on later sync passes.
      });
    }
  }

  for (const member of memberKeys.members) {
    if (member.user_id === auth.user.id) continue;
    if (memberRoleByUserId.get(member.user_id)?.base_role === "guest") {
      continue;
    }
    const material = member.hybrid_encryption_public_key_material as unknown as
      | HybridEncryptionPublicKeyMaterial
      | undefined;
    if (!material) continue;
    const directory = await ensureWorkspaceIdentityKey({
      workspaceId,
      ownerUserId: auth.user.id,
      ownerDeviceId: device.deviceId,
      targetUserId: member.user_id,
      targetIdentityHybridEncryptionPublicKeyMaterial: material,
    }).catch(() => null);
    if (!directory) continue;

    await persistWorkspaceKekForMember({
      workspaceId,
      userId: auth.user.id,
      senderDeviceId: device.deviceId,
      targetUserId: member.user_id,
      targetIdentityHybridEncryptionPublicKeyMaterial: material,
      keyVersion: kekVersion,
      popDeviceId: device.deviceId,
      keyDirectoryCheckpoint: directory.checkpoint,
      ignoreConflict: true,
    });
  }
}

async function ensureWorkspaceIdentityKey(params: {
  workspaceId: string;
  ownerUserId: string;
  ownerDeviceId: string;
  targetUserId: string;
  targetIdentityHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
}): Promise<{ checkpoint: KeyDirectoryEnvelope }> {
  let directory = await fetchVerifiedKeyDirectory({
    scopeKind: "workspace",
    scopeId: params.workspaceId,
    popDeviceId: params.ownerDeviceId,
  });
  const targetKeyId = computeHybridEncryptionKeyId(
    params.targetIdentityHybridEncryptionPublicKeyMaterial,
  );
  if (checkpointHasIdentityKey(directory.checkpoint, targetKeyId)) {
    return directory;
  }

  const append = await buildIdentityKeyDirectoryAppend({
    scopeKind: "workspace",
    scopeId: params.workspaceId,
    userId: params.ownerUserId,
    actorDeviceId: params.ownerDeviceId,
    checkpointEnvelope: directory.checkpoint,
    recipientHybridEncryptionPublicKeyMaterial:
      params.targetIdentityHybridEncryptionPublicKeyMaterial,
  });
  await appendWorkspaceKeyDirectory({
    workspaceId: params.workspaceId,
    popDeviceId: params.ownerDeviceId,
    events: append.events,
    checkpoint: append.checkpoint,
  });
  directory = { checkpoint: append.checkpoint };
  return directory;
}

async function persistWorkspaceDeviceKek(params: {
  workspaceId: string;
  ownerUserId: string;
  ownerDeviceId: string;
  targetUserId: string;
  targetDeviceId: string;
  targetDeviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  targetDeviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  targetDeviceEncryptionKeyId: string;
  keyVersion: number;
}): Promise<void> {
  let directory = await fetchVerifiedKeyDirectory({
    scopeKind: "workspace",
    scopeId: params.workspaceId,
    popDeviceId: params.ownerDeviceId,
  });
  let deviceAppend: KeyDirectoryAppendArtifacts | null = null;

  if (!checkpointHasKey(directory.checkpoint, params.targetDeviceEncryptionKeyId)) {
    deviceAppend = await buildDeviceKeyDirectoryAppend({
      scopeKind: "workspace",
      scopeId: params.workspaceId,
      userId: params.ownerUserId,
      recipientUserId: params.targetUserId,
      actorDeviceId: params.ownerDeviceId,
      checkpointEnvelope: directory.checkpoint,
      recipientDeviceId: params.targetDeviceId,
      recipientHybridSigningPublicKeyMaterial: params.targetDeviceHybridSigningPublicKeyMaterial,
      recipientHybridEncryptionPublicKeyMaterial:
        params.targetDeviceHybridEncryptionPublicKeyMaterial,
    });
    await appendWorkspaceKeyDirectory({
      workspaceId: params.workspaceId,
      popDeviceId: params.ownerDeviceId,
      events: deviceAppend.events,
      checkpoint: deviceAppend.checkpoint,
    });
    directory = { checkpoint: deviceAppend.checkpoint };
  }

  await persistWorkspaceKekForDevice({
    workspaceId: params.workspaceId,
    userId: params.ownerUserId,
    targetUserId: params.targetUserId,
    senderDeviceId: params.ownerDeviceId,
    targetDeviceId: params.targetDeviceId,
    targetDeviceHybridEncryptionPublicKeyMaterial:
      params.targetDeviceHybridEncryptionPublicKeyMaterial,
    keyVersion: params.keyVersion,
    isActive: true,
    popDeviceId: params.ownerDeviceId,
    keyDirectoryCheckpoint: directory.checkpoint,
    ignoreConflict: true,
  });
}

async function appendWorkspaceKeyDirectory(params: {
  workspaceId: string;
  popDeviceId: string;
  events: KeyDirectoryEnvelope[];
  checkpoint: KeyDirectoryEnvelope;
}): Promise<void> {
  await encryptionApi.appendWorkspaceKeyDirectory(
    params.workspaceId,
    { events: params.events, checkpoint: params.checkpoint },
    { popDeviceId: params.popDeviceId, ignoreConflict: true },
  );
}

function checkpointHasKey(checkpointEnvelope: KeyDirectoryEnvelope, keyId: string): boolean {
  const payload = checkpointEnvelope.payload as Record<string, unknown> | undefined;
  const deviceKeys = payload?.device_keys as Array<Record<string, unknown>> | undefined;
  return deviceKeys?.some((entry) => entry.key_id === keyId && !entry["revoked_at"]) ?? false;
}

function checkpointHasIdentityKey(
  checkpointEnvelope: KeyDirectoryEnvelope,
  keyId: string,
): boolean {
  const payload = checkpointEnvelope.payload as Record<string, unknown> | undefined;
  const identityKeys = payload?.identity_keys as Array<Record<string, unknown>> | undefined;
  return identityKeys?.some((entry) => entry.key_id === keyId && !entry["revoked_at"]) ?? false;
}
