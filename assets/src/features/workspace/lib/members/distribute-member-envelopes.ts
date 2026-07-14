import {
  authState,
  cryptoWorkerReady,
  deviceState,
  getKekResolverSession,
} from "@/entities/session";
import { encryptionApi, workspacesApi } from "@/shared/api";
import { buildDeviceKeyDirectoryAppend } from "@/shared/lib/crypto/key-directory/device-events";
import type {
  KeyDirectoryAppendArtifacts,
  KeyDirectoryEnvelope,
} from "@/shared/lib/crypto/key-directory/types";
import { resolveActiveKek } from "@/shared/lib/crypto/kek-resolver";
import type { HybridEncryptionPublicKeyMaterial } from "@/shared/lib/crypto/hybrid-encryption";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import {
  persistWorkspaceKekForDevice,
  persistWorkspaceKekForMember,
} from "@/shared/lib/crypto/workspace-kek-persistence";
import { ensureWorkspaceIdentityKey } from "@/shared/lib/crypto/workspace-identity-directory";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";

const DISTRIBUTION_STABLE_TTL_MS = 60_000;

interface WorkspaceMemberEnvelopeDistributionOptions {
  force?: boolean;
  membershipFingerprint?: string | null;
}

interface WorkspaceMemberEnvelopeDistributionStamp {
  completedAtMs: number;
  membershipFingerprint: string | null;
}

export async function distributeWorkspaceMemberEnvelopes(
  workspaceId: string,
  options: WorkspaceMemberEnvelopeDistributionOptions = {},
): Promise<void> {
  if (shouldSkipStableDistribution(workspaceId, options)) return;

  const existing = distributionInFlight.get(workspaceId);
  if (existing) return existing;

  const task = runWorkspaceMemberEnvelopeDistribution(workspaceId)
    .then((completed) => {
      if (!completed) return;
      const previous = distributionCompleted.get(workspaceId);
      distributionCompleted.set(workspaceId, {
        completedAtMs: Date.now(),
        membershipFingerprint:
          options.membershipFingerprint ?? previous?.membershipFingerprint ?? null,
      });
    })
    .finally(() => {
      distributionInFlight.delete(workspaceId);
    });
  distributionInFlight.set(workspaceId, task);
  return task;
}

const distributionInFlight = new Map<string, Promise<void>>();
const distributionCompleted = new Map<string, WorkspaceMemberEnvelopeDistributionStamp>();

function shouldSkipStableDistribution(
  workspaceId: string,
  options: WorkspaceMemberEnvelopeDistributionOptions,
): boolean {
  if (options.force) return false;

  const previous = distributionCompleted.get(workspaceId);
  if (!previous) return false;

  if (
    options.membershipFingerprint &&
    previous.membershipFingerprint !== options.membershipFingerprint
  ) {
    return false;
  }

  return Date.now() - previous.completedAtMs < DISTRIBUTION_STABLE_TTL_MS;
}

async function runWorkspaceMemberEnvelopeDistribution(workspaceId: string): Promise<boolean> {
  const auth = authState();
  const device = deviceState();
  if (!cryptoWorkerReady() || !auth || !device?.deviceId) return false;
  if (auth.user.accountType === "guest") return true;

  const [{ kekVersion }, memberKeys, members] = await Promise.all([
    resolveActiveKek(workspaceId, getKekResolverSession()),
    encryptionApi.getWorkspaceMemberKeys(workspaceId),
    workspacesApi.listMembers(workspaceId),
  ]);
  const memberRoleByUserId = new Map(members.members.map((member) => [member.user_id, member]));
  const currentMemberRole = memberRoleByUserId.get(auth.user.id)?.base_role;
  if (currentMemberRole !== "owner" && currentMemberRole !== "admin") return true;

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
    const signingMaterial = member.hybrid_signing_public_key_material as unknown as
      | HybridSigningPublicKeyMaterial
      | undefined;
    if (!signingMaterial) continue;
    const directory = await ensureWorkspaceIdentityKey({
      workspaceId,
      ownerUserId: auth.user.id,
      ownerDeviceId: device.deviceId,
      targetUserId: member.user_id,
      targetIdentityHybridEncryptionPublicKeyMaterial: material,
      targetIdentityHybridSigningPublicKeyMaterial: signingMaterial,
    }).catch(() => null);
    if (!directory) continue;

    await persistWorkspaceKekForMember({
      workspaceId,
      userId: auth.user.id,
      senderDeviceId: device.deviceId,
      targetUserId: member.user_id,
      targetIdentityHybridEncryptionPublicKeyMaterial: material,
      keyVersion: kekVersion,
      rrpDeviceId: device.deviceId,
      keyDirectoryCheckpoint: directory.checkpoint,
      ignoreConflict: true,
    });
  }
  return true;
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
    rrpDeviceId: params.ownerDeviceId,
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
      rrpDeviceId: params.ownerDeviceId,
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
    rrpDeviceId: params.ownerDeviceId,
    keyDirectoryCheckpoint: directory.checkpoint,
    ignoreConflict: true,
  });
}

async function appendWorkspaceKeyDirectory(params: {
  workspaceId: string;
  rrpDeviceId: string;
  events: KeyDirectoryEnvelope[];
  checkpoint: KeyDirectoryEnvelope;
}): Promise<void> {
  await encryptionApi.appendWorkspaceKeyDirectory(
    params.workspaceId,
    { events: params.events, checkpoint: params.checkpoint },
    { rrpDeviceId: params.rrpDeviceId, ignoreConflict: true },
  );
}

function checkpointHasKey(checkpointEnvelope: KeyDirectoryEnvelope, keyId: string): boolean {
  const payload = checkpointEnvelope.payload as Record<string, unknown> | undefined;
  const deviceKeys = payload?.device_keys as Array<Record<string, unknown>> | undefined;
  return deviceKeys?.some((entry) => entry.key_id === keyId && !entry["revoked_at"]) ?? false;
}
