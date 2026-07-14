import { ApiError, devicesApi, documentsApi, encryptionApi, workspacesApi } from "@/shared/api";
import type { WorkspaceRotationInfo } from "@/shared/api/devices";
import {
  authState,
  cryptoWorkerReady,
  deviceState,
  getKekResolverSession,
} from "@/entities/session";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import type { HybridEncryptionPublicKeyMaterial } from "@/shared/lib/crypto/hybrid-encryption";
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
import { acknowledgeWorkspaceWipeIfRequired } from "@/shared/lib/crypto/workspace-kek-wipe";
import { resolveKekByVersion } from "@/shared/lib/crypto/kek-resolver";

type TriggerKekRotationFn = (rotationList: WorkspaceRotationInfo[]) => Promise<void>;
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

  const failedWorkspaces: Array<{ workspaceId: string; reason: string }> = [];

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
      let rotationAlreadyInProgress = false;
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
        rotationAlreadyInProgress = true;
      }

      let pendingKek = await worker.resolveKek(workspaceId, newVersion);
      if (!pendingKek.found) {
        const offlineKek = await worker.loadOfflineKekMetadata(workspaceId);
        if (offlineKek?.keyVersion === newVersion) {
          const restored = await worker.restoreKekFromOffline({
            workspaceId,
            keyVersion: newVersion,
            isActive: true,
          });
          pendingKek = { found: restored.restored, keyVersion: restored.keyVersion };
        }
      }
      if (pendingKek.found) {
        await worker.setActiveKekVersion(workspaceId, newVersion);
      } else {
        if (rotationAlreadyInProgress) {
          throw new Error("pending_kek_unavailable_for_active_rotation");
        }
        await worker.generateKek(workspaceId, newVersion);
        await worker.storeKekForOffline({ workspaceId, keyVersion: newVersion });
      }

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

      await rewrapWorkspaceDocumentKeys(workspaceId, newVersion);

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
      const wipeRequiredDeviceIds = memberDevices.map((memberDevice) => memberDevice.device_id);
      const deletionManifestHash = buildKekOldKeyDeletionManifestHash({
        workspaceId,
        oldKeyVersion: workspace.current_kek_version,
        rotationCompletedEventHash,
        deletedSecretIdsHash: manifestMaterials.deleted_secret_ids_hash,
        deletedWrapIdsHash: manifestMaterials.deleted_wrap_ids_hash,
        deviceKeyDeletionProofs: [],
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
        device_key_deletion_proofs: [],
        wipe_required_device_ids: wipeRequiredDeviceIds,
      });
      await fetchVerifiedKeyDirectory({
        scopeKind: "workspace",
        scopeId: workspaceId,
        rrpDeviceId: currentDeviceId,
      });
      await acknowledgeWorkspaceWipeIfRequired({
        workspaceId,
        userId,
        deviceId: currentDeviceId,
      });
    } catch (error) {
      failedWorkspaces.push({
        workspaceId,
        reason: error instanceof Error ? error.message : String(error),
      });
    }
  }

  if (failedWorkspaces.length > 0) {
    throw new Error(
      `KEK rotation failed: ${failedWorkspaces
        .map(({ workspaceId, reason }) => `${workspaceId}: ${reason}`)
        .join("; ")}`,
    );
  }
}

async function rewrapWorkspaceDocumentKeys(
  workspaceId: string,
  newKekVersion: number,
): Promise<void> {
  const worker = getCryptoWorker();
  const { documents } = await documentsApi.list(workspaceId);

  for (const document of documents) {
    const { keys } = await encryptionApi.getDocumentKeys(document.id);
    for (const key of keys) {
      await resolveKekByVersion(workspaceId, key.kek_version, getKekResolverSession());
      await worker.unwrapDek({
        encryptedDek: base64UrlDecode(key.encrypted_dek),
        nonce: base64UrlDecode(key.nonce),
        documentId: document.id,
        workspaceId,
        keyVersion: key.key_version,
        isActive: key.is_active,
        kekVersion: key.kek_version,
      });
      const rewrapped = await worker.wrapDek({
        documentId: document.id,
        workspaceId,
        keyVersion: key.key_version,
      });
      await encryptionApi.rewrapDocumentKeyForKekRotation(document.id, {
        encrypted_dek: base64UrlEncode(rewrapped.encryptedDek),
        nonce: base64UrlEncode(rewrapped.nonce),
        key_version: key.key_version,
        new_kek_version: newKekVersion,
      });
    }
  }
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
