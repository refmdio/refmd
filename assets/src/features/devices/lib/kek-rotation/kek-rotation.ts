import { ApiError, devicesApi, encryptionApi, workspacesApi } from "@/shared/api";
import type { WorkspaceRotationInfo } from "@/shared/api/devices";
import type { components } from "@/shared/api/schema";
import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import type { HybridEncryptionPublicKeyMaterial } from "@/shared/lib/crypto/hybrid-encryption";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import {
  persistWorkspaceKekForDevice,
  persistWorkspaceKekForMember,
} from "@/shared/lib/crypto/workspace-kek-persistence";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import {
  buildKekOldKeyDeletionManifestHash,
  buildKekRotationCompletionKeyDirectoryAppend,
  buildKekRotationStartKeyDirectoryAppend,
  kekRotationCompletedEventHash,
} from "@/shared/lib/crypto/key-directory/rotation-events";
import { advanceKeyDirectoryPinWithProof } from "@/shared/lib/anti-rollback/key-directory-pin/pins";

type TriggerKekRotationFn = (rotationList: WorkspaceRotationInfo[]) => Promise<void>;
type DeviceKeyDeletionProof =
  components["schemas"]["KekRotationCompleteRequest"]["device_key_deletion_proofs"][number];

export function createWorkspaceKekRotationTrigger(): TriggerKekRotationFn {
  return async (rotationList) => {
    if (rotationList.length === 0) return;

    const auth = authState();
    const device = deviceState();
    if (!cryptoWorkerReady() || !auth || !device?.deviceId) {
      throw new Error("KEK rotation prerequisites not met: crypto worker or device not ready");
    }

    await performKekRotation(rotationList, auth.user.id, device.deviceId);
  };
}

export async function performKekRotation(
  workspaces: WorkspaceRotationInfo[],
  userId: string,
  currentDeviceId: string,
): Promise<void> {
  const worker = getCryptoWorker();
  const activeDevices = await devicesApi.list();

  for (const device of activeDevices.devices) {
    const deviceHybridSigningPublicKeyMaterial =
      device.hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial;
    const ecdhPk = base64UrlDecode(device.hybrid_encryption_public_key_material.x25519_public);
    const tofuResult = await worker.tofuVerify({
      userId,
      deviceId: device.id,
      hybridSigningPublicKeyMaterial: deviceHybridSigningPublicKeyMaterial,
      ecdhPublicKey: ecdhPk,
    });
    if (tofuResult.status === "ecdh_key_mismatch" || tofuResult.status === "identity_key_changed") {
      throw new Error("Device key verification failed. Aborting KEK rotation.");
    }

    if (!device.approval_signature || !device.client_nonce) {
      throw new Error(`Device ${device.name}: Missing identity signature. Aborting KEK rotation.`);
    }
    const nonce = base64UrlDecode(device.client_nonce);
    const verificationParams = {
      deviceId: device.id,
      deviceHybridSigningPublicKeyMaterial,
      deviceHybridEncryptionPublicKeyMaterial:
        device.hybrid_encryption_public_key_material as unknown as HybridEncryptionPublicKeyMaterial,
      deviceEcdhPublic: ecdhPk,
      clientNonce: nonce,
      identitySignature: device.approval_signature,
      identitySignatureContext: device.approval_proof as Record<string, unknown>,
      approvalDeliveryCommitments: device.approval_delivery_commitments,
      approvalDeliveryArtifacts: device.approval_delivery_artifacts,
    };
    const sigValid =
      device.approval_signature_surface === "genesis_device_bootstrap"
        ? await worker.verifyGenesisDeviceBootstrapSignature(verificationParams)
        : device.approval_signature_surface === "device_approval"
          ? await worker.verifyDeviceApprovalSignature(verificationParams)
          : device.approval_signature_surface === "recovery_device_approval"
            ? await worker.verifyRecoveryDeviceApprovalSignature(verificationParams)
            : false;
    if (!sigValid) {
      throw new Error(`Device ${device.name}: Invalid identity signature. Aborting KEK rotation.`);
    }

    if (tofuResult.status === "known_trusted") {
      await worker.tofuUpdateLastSeen({ userId, deviceId: device.id });
    }
  }

  const failedWorkspaces: string[] = [];

  for (const workspace of workspaces) {
    const workspaceId = workspace.workspace_id;
    try {
      const newVersion = workspace.current_kek_version + 1;

      const startDirectory = await fetchVerifiedKeyDirectory({
        scopeKind: "workspace",
        scopeId: workspaceId,
        rrpDeviceId: currentDeviceId,
      });
      const startAppend = await buildKekRotationStartKeyDirectoryAppend({
        workspaceId,
        actorUserId: userId,
        actorDeviceId: currentDeviceId,
        checkpointEnvelope: startDirectory.checkpoint,
        oldKeyVersion: workspace.current_kek_version,
        newKeyVersion: newVersion,
        reason: "security",
      });
      try {
        await encryptionApi.startKekRotation(workspaceId, {
          workspace_key_directory_events: startAppend.events,
          workspace_key_directory_checkpoint: startAppend.checkpoint,
        });
        await advanceKeyDirectoryPinWithProof({
          scopeKind: "workspace",
          scopeId: workspaceId,
          checkpointEnvelope: startAppend.checkpoint,
          checkpointAncestry: [startDirectory.checkpoint],
          eventAncestry: startAppend.events,
        });
      } catch (error) {
        if (
          !(error instanceof ApiError) ||
          error.status !== 409 ||
          error.code !== "kek_rotation_already_in_progress"
        ) {
          throw error;
        }
      }

      await worker.generateKek(workspaceId, newVersion);

      const workspaceDirectory = await fetchVerifiedKeyDirectory({
        scopeKind: "workspace",
        scopeId: workspaceId,
        rrpDeviceId: currentDeviceId,
      });
      const memberDevices = await listWorkspaceActiveDevices(workspaceId);
      const directoryDeviceKeys = activeWorkspaceDeviceEncryptionKeys(
        workspaceDirectory.checkpoint,
      );
      for (const memberDevice of memberDevices) {
        const directoryKey = directoryDeviceKeys.get(memberDevice.device_id);
        if (!directoryKey || directoryKey.keyId !== memberDevice.encryption_key_id) {
          throw new Error("Workspace device key is not active in key directory.");
        }
        await persistWorkspaceKekForDevice({
          workspaceId,
          userId,
          targetUserId: memberDevice.user_id,
          senderDeviceId: currentDeviceId,
          targetDeviceId: memberDevice.device_id,
          targetDeviceHybridEncryptionPublicKeyMaterial: directoryKey.material,
          keyVersion: newVersion,
          isActive: true,
        });
      }
      const memberIdentityKeys = await encryptionApi.getWorkspaceMemberKeys(workspaceId);
      for (const member of memberIdentityKeys.members) {
        await persistWorkspaceKekForMember({
          workspaceId,
          userId,
          senderDeviceId: currentDeviceId,
          targetUserId: member.user_id,
          targetIdentityHybridEncryptionPublicKeyMaterial:
            member.hybrid_encryption_public_key_material as unknown as HybridEncryptionPublicKeyMaterial,
          keyVersion: newVersion,
          rrpDeviceId: currentDeviceId,
        });
      }

      const completionDirectory = await fetchVerifiedKeyDirectory({
        scopeKind: "workspace",
        scopeId: workspaceId,
        rrpDeviceId: currentDeviceId,
      });
      const manifestMaterials = await encryptionApi.prepareKekRotationCompletion(
        workspaceId,
        newVersion,
      );
      if (
        manifestMaterials.old_kek_version !== workspace.current_kek_version ||
        manifestMaterials.new_kek_version !== newVersion
      ) {
        throw new Error("kek_rotation_manifest_version_mismatch");
      }
      const rotationCompletedEventHash = kekRotationCompletedEventHash({
        workspaceId,
        actorUserId: userId,
        actorDeviceId: currentDeviceId,
        checkpointEnvelope: completionDirectory.checkpoint,
        oldKeyVersion: workspace.current_kek_version,
        newKeyVersion: newVersion,
        completionManifestHash: manifestMaterials.completion_manifest_hash,
      });
      const deletionProof = await buildCurrentDeviceDeletionProof({
        workspaceId,
        userId,
        currentDeviceId,
        oldKeyVersion: workspace.current_kek_version,
        rotationCompletedEventHash,
        checkpointEnvelope: completionDirectory.checkpoint,
      });
      const wipeRequiredDeviceIds = memberDevices
        .map((memberDevice) => memberDevice.device_id)
        .filter((deviceId) => deviceId !== currentDeviceId);
      const deletionManifestHash = buildKekOldKeyDeletionManifestHash({
        workspaceId,
        oldKeyVersion: workspace.current_kek_version,
        rotationCompletedEventHash,
        deletedSecretIdsHash: manifestMaterials.deleted_secret_ids_hash,
        deletedWrapIdsHash: manifestMaterials.deleted_wrap_ids_hash,
        deviceKeyDeletionProofs: [deletionProof],
        wipeRequiredDeviceIds: wipeRequiredDeviceIds,
        serverRejectsOldKeyUploadsAfterSequence:
          manifestMaterials.server_rejects_old_key_uploads_after_sequence,
      });
      const completionAppend = await buildKekRotationCompletionKeyDirectoryAppend({
        workspaceId,
        actorUserId: userId,
        actorDeviceId: currentDeviceId,
        checkpointEnvelope: completionDirectory.checkpoint,
        oldKeyVersion: workspace.current_kek_version,
        newKeyVersion: newVersion,
        completionManifestHash: manifestMaterials.completion_manifest_hash,
        deletionManifestHash,
      });

      await encryptionApi.completeKekRotation(workspaceId, {
        new_kek_version: newVersion,
        workspace_key_directory_events: completionAppend.events,
        workspace_key_directory_checkpoint: completionAppend.checkpoint,
        device_key_deletion_proofs: [deletionProof as DeviceKeyDeletionProof],
        wipe_required_device_ids: wipeRequiredDeviceIds,
      });
      await fetchVerifiedKeyDirectory({
        scopeKind: "workspace",
        scopeId: workspaceId,
        rrpDeviceId: currentDeviceId,
      });
    } catch {
      failedWorkspaces.push(workspaceId);
    }
  }

  if (failedWorkspaces.length > 0) {
    throw new Error(
      `KEK rotation failed for ${failedWorkspaces.length} workspace(s). Keys will be rotated on next access.`,
    );
  }
}

async function buildCurrentDeviceDeletionProof(params: {
  workspaceId: string;
  userId: string;
  currentDeviceId: string;
  oldKeyVersion: number;
  rotationCompletedEventHash: string;
  checkpointEnvelope: Record<string, unknown>;
}): Promise<Record<string, unknown>> {
  const worker = getCryptoWorker();
  const checkpointPayload = params.checkpointEnvelope.payload as
    | Record<string, unknown>
    | undefined;
  if (!checkpointPayload) throw new Error("key_directory_checkpoint_payload_invalid");
  const signingKeyId = activeDeviceSigningKeyId(checkpointPayload, params.currentDeviceId);
  const proofNonce = new Uint8Array(32);
  crypto.getRandomValues(proofNonce);
  return worker.signDeviceKeyDeletionProof({
    payload: {
      protocol: "refmd.device-key-deletion-proof",
      version: 1,
      workspace_id: params.workspaceId,
      device_id: params.currentDeviceId,
      rotation_kind: "kek",
      scope_kind: "workspace",
      scope_id: params.workspaceId,
      old_key_version: params.oldKeyVersion,
      rotation_completed_event_hash: params.rotationCompletedEventHash,
      deleted_secret_ids_hash: deletedWorkspaceKekSecretIdsHash(
        params.workspaceId,
        params.oldKeyVersion,
      ),
      deleted_storage_classes: [
        "crypto_worker_state",
        "indexeddb_cache",
        "local_encrypted_key_store",
        "offline_cache",
        "pending_queue",
      ],
      local_cache_epoch: 1,
      proof_nonce: base64UrlEncode(proofNonce),
    },
    actor: {
      signer_kind: "workspace_device",
      user_id: params.userId,
      device_id: params.currentDeviceId,
      signing_key_id: signingKeyId,
      key_scope_kind: "workspace",
      key_scope_id: params.workspaceId,
      key_checkpoint_sequence: checkpointPayload.sequence,
      key_checkpoint_hash: blake3Base64Url(
        canonicalizeStrictBytes(checkpointPayload as StrictJsonValue),
      ),
    },
  });
}

function deletedWorkspaceKekSecretIdsHash(workspaceId: string, oldKeyVersion: number): string {
  return blake3Base64Url(
    canonicalizeStrictBytes({
      secret_ids: [`workspace:kek:${workspaceId}:${oldKeyVersion}`],
    }),
  );
}

async function listWorkspaceActiveDevices(workspaceId: string) {
  const { members } = await workspacesApi.listMembers(workspaceId);
  const perMember = await Promise.all(
    members.map(async (member) => {
      const result = await workspacesApi.listMemberDevices(workspaceId, member.user_id, false);
      return result.devices.map((device) => ({ ...device, user_id: member.user_id }));
    }),
  );
  return perMember.flat();
}

function activeWorkspaceDeviceEncryptionKeys(
  checkpointEnvelope: Record<string, unknown>,
): Map<string, { keyId: string; material: HybridEncryptionPublicKeyMaterial }> {
  const payload = checkpointEnvelope.payload as Record<string, unknown> | undefined;
  const deviceKeys = payload?.device_keys;
  if (!Array.isArray(deviceKeys)) throw new Error("key_directory_device_keys_invalid");
  const result = new Map<string, { keyId: string; material: HybridEncryptionPublicKeyMaterial }>();
  for (const entry of deviceKeys) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
    const record = entry as Record<string, unknown>;
    if ("revoked_at" in record) continue;
    const material = record.key_material as Record<string, unknown> | undefined;
    if (material?.protocol !== "refmd.hybrid-encryption-key-material") continue;
    if (material.owner_kind !== "device") continue;
    if (typeof material.owner_id !== "string") {
      continue;
    }
    if (typeof record.key_id !== "string") continue;
    result.set(material.owner_id, {
      keyId: record.key_id,
      material: material as unknown as HybridEncryptionPublicKeyMaterial,
    });
  }
  return result;
}

function activeDeviceSigningKeyId(
  checkpointPayload: Record<string, unknown>,
  deviceId: string,
): string {
  const deviceKeys = checkpointPayload.device_keys;
  if (!Array.isArray(deviceKeys)) throw new Error("key_directory_device_keys_invalid");
  for (const entry of deviceKeys) {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
    const record = entry as Record<string, unknown>;
    if ("revoked_at" in record) continue;
    const material = record.key_material as Record<string, unknown> | undefined;
    if (
      material?.protocol === "refmd.hybrid-signing-key-material" &&
      material.owner_kind === "device" &&
      material.owner_id === deviceId &&
      typeof record.key_id === "string"
    ) {
      return record.key_id;
    }
  }
  throw new Error("key_directory_device_signing_key_missing");
}
