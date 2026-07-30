import { devicesApi, documentsApi, encryptionApi, workspacesApi } from "@/shared/api";
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
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import {
  buildKekOldKeyDeletionManifest,
  buildKekRotationStartKeyDirectoryAppend,
} from "@/shared/lib/crypto/key-directory/rotation-events";
import { advanceKeyDirectoryPinWithProof } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { acknowledgeWorkspaceWipeIfRequired } from "@/shared/lib/crypto/workspace-kek-wipe";
import { resolveKekByVersion } from "@/shared/lib/crypto/kek-resolver";
import { createWorkspaceAuthorityAuthorization } from "@/shared/lib/crypto/workspace-authority-authorization";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";

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
      const rotationId = workspace.rotation_id ?? crypto.randomUUID();
      const newVersion = workspace.pending_kek_version ?? workspace.current_kek_version + 1;

      const startDirectory = await fetchVerifiedKeyDirectory({
        scopeKind: "workspace",
        scopeId: workspaceId,
        rrpDeviceId: currentDeviceId,
      });
      if (!workspace.rotation_id) {
        const startAppend = await buildKekRotationStartKeyDirectoryAppend({
          workspaceId,
          actorUserId: userId,
          actorDeviceId: currentDeviceId,
          checkpointEnvelope: startDirectory.checkpoint,
          oldKeyVersion: workspace.current_kek_version,
          newKeyVersion: newVersion,
          reason: "manual",
        });
        const intent = await encryptionApi.prepareKekRotationStart(workspaceId, {
          rotation_id: rotationId,
          old_key_version: workspace.current_kek_version,
          new_key_version: newVersion,
          reason: "manual",
          events: startAppend.events,
          checkpoint: startAppend.checkpoint,
        });
        const authorization = await createWorkspaceAuthorityAuthorization({
          worker,
          intent: intent as unknown as StrictJsonValue,
        });
        await encryptionApi.commitKekRotationStart(workspaceId, authorization);
        await advanceKeyDirectoryPinWithProof({
          scopeKind: "workspace",
          scopeId: workspaceId,
          checkpointEnvelope: startAppend.checkpoint,
          checkpointAncestry: [startDirectory.checkpoint],
          eventAncestry: startAppend.events,
        });
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
        if (workspace.rotation_id) {
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
      const checkpointBinding = keyDirectoryCheckpointBinding(workspaceDirectory.checkpoint);
      const deviceWrapPrecommits = [];
      for (const memberDevice of memberDevices) {
        const directoryKey = directoryDeviceKeys.get(memberDevice.device_id);
        if (!directoryKey || directoryKey.keyId !== memberDevice.encryption_key_id) {
          throw new Error("Workspace device key is not active in key directory.");
        }
        const wrap = await worker.createPqKekWrapPrecommit({
          purpose: "workspace_device_kek_wrap",
          workspaceId,
          keyVersion: newVersion,
          recipientPublicKeyMaterial: directoryKey.material,
          senderUserId: userId,
          senderDeviceId: currentDeviceId,
          resource: {
            workspace_id: workspaceId,
            target_user_id: memberDevice.user_id,
            target_device_id: memberDevice.device_id,
            kek_version: newVersion,
          },
          eventScope: { scope_kind: "workspace", scope_id: workspaceId },
          senderKeyCheckpoint: checkpointBinding,
          recipientKeyCheckpoint: {
            scopeKind: "workspace",
            scopeId: workspaceId,
            ...checkpointBinding,
          },
        });
        deviceWrapPrecommits.push({
          target_user_id: memberDevice.user_id,
          target_device_id: memberDevice.device_id,
          wrap,
        });
      }
      const memberIdentityKeys = await encryptionApi.getWorkspaceMemberKeys(workspaceId);
      const memberEnvelopePrecommits = [];
      for (const member of [...memberIdentityKeys.members].sort((a, b) =>
        a.user_id.localeCompare(b.user_id),
      )) {
        const recipientPublicKeyMaterial =
          member.hybrid_encryption_public_key_material as unknown as HybridEncryptionPublicKeyMaterial;
        const wrap = await worker.createPqKekWrapPrecommit({
          purpose: "workspace_member_kek_wrap",
          workspaceId,
          keyVersion: newVersion,
          recipientPublicKeyMaterial,
          senderUserId: userId,
          senderDeviceId: currentDeviceId,
          resource: {
            workspace_id: workspaceId,
            target_user_id: member.user_id,
            kek_version: newVersion,
          },
          eventScope: { scope_kind: "workspace", scope_id: workspaceId },
          senderKeyCheckpoint: checkpointBinding,
          recipientKeyCheckpoint: {
            scopeKind: "workspace",
            scopeId: workspaceId,
            ...checkpointBinding,
          },
        });
        memberEnvelopePrecommits.push({
          protocol: "refmd.workspace-member-envelope" as const,
          version: 1 as const,
          workspace_id: workspaceId,
          target_user_id: member.user_id,
          kek_version: newVersion,
          target_identity_encryption_key_id: wrap.recipient.encryption_key_id,
          target_identity_key_material_hash: blake3Base64Url(
            canonicalizeStrictBytes(recipientPublicKeyMaterial as unknown as StrictJsonValue),
          ),
          authorization_key_directory_checkpoint_sequence: checkpointBinding.sequence,
          authorization_key_directory_checkpoint_hash: checkpointBinding.checkpointHash,
          wrap,
        });
      }

      await rewrapWorkspaceDocumentKeys(workspaceId, newVersion);
      const workspaceInvitationUpdates = await buildWorkspaceInvitationUpdates({
        worker,
        workspaceId,
        oldKeyVersion: workspace.current_kek_version,
        newKeyVersion: newVersion,
      });
      const guestInvitationUpdates = await buildGuestInvitationUpdates({
        worker,
        workspaceId,
        oldKeyVersion: workspace.current_kek_version,
        newKeyVersion: newVersion,
      });
      const completionIntent = await encryptionApi.prepareKekRotationCompletion(
        workspaceId,
        rotationId,
        {
          old_key_version: workspace.current_kek_version,
          new_key_version: newVersion,
          device_wrap_precommits: deviceWrapPrecommits,
          member_envelope_precommits: memberEnvelopePrecommits,
          workspace_invitation_updates: workspaceInvitationUpdates,
          guest_invitation_updates: guestInvitationUpdates,
        } as unknown as StrictJsonValue,
      );
      const completionAuthorization = await createWorkspaceAuthorityAuthorization({
        worker,
        intent: completionIntent as unknown as StrictJsonValue,
      });
      const completion = (await encryptionApi.completeKekRotation(
        workspaceId,
        rotationId,
        completionAuthorization,
      )) as unknown as KekRotationCompletionCommitResponse;
      await fetchVerifiedKeyDirectory({
        scopeKind: "workspace",
        scopeId: workspaceId,
        rrpDeviceId: currentDeviceId,
      });

      const wipeRequiredDeviceIds = memberDevices.map((memberDevice) => memberDevice.device_id);
      const deletionManifest = buildKekOldKeyDeletionManifest({
        workspaceId,
        oldKeyVersion: workspace.current_kek_version,
        rotationCompletedEventHash: completion.rotation_completed_event_hash,
        deletedSecretIdsHash: completion.deleted_secret_ids_hash,
        deletedWrapIdsHash: completion.deleted_wrap_ids_hash,
        deviceKeyDeletionProofs: [],
        wipeRequiredDeviceIds,
        serverRejectsOldKeyUploadsAfterSequence:
          completion.server_rejects_old_key_uploads_after_sequence,
      });
      const deletionIntent = await encryptionApi.prepareOldKekDeletion(workspaceId, rotationId, {
        old_key_version: workspace.current_kek_version,
        deletion_manifest: deletionManifest,
        device_key_deletion_proofs: [],
        wipe_required_device_ids: wipeRequiredDeviceIds,
      } as StrictJsonValue);
      const deletionAuthorization = await createWorkspaceAuthorityAuthorization({
        worker,
        intent: deletionIntent as unknown as StrictJsonValue,
      });
      await encryptionApi.deleteOldKek(workspaceId, rotationId, deletionAuthorization);
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

interface KekRotationCompletionCommitResponse {
  rotation_completed_event_hash: string;
  deleted_secret_ids_hash: string;
  deleted_wrap_ids_hash: string;
  server_rejects_old_key_uploads_after_sequence: number;
}

function keyDirectoryCheckpointBinding(checkpointEnvelope: Record<string, unknown>): {
  sequence: number;
  checkpointHash: string;
} {
  const payload = asRecord(checkpointEnvelope.payload, "key_directory_checkpoint_payload_invalid");
  const sequence = payload.sequence;
  const checkpointHash = checkpointEnvelope.checkpoint_hash;
  if (!Number.isSafeInteger(sequence) || (sequence as number) < 1) {
    throw new Error("key_directory_checkpoint_sequence_invalid");
  }
  if (typeof checkpointHash !== "string" || checkpointHash.length === 0) {
    throw new Error("key_directory_checkpoint_hash_invalid");
  }
  return { sequence: sequence as number, checkpointHash };
}

async function buildWorkspaceInvitationUpdates(params: {
  worker: ReturnType<typeof getCryptoWorker>;
  workspaceId: string;
  oldKeyVersion: number;
  newKeyVersion: number;
}): Promise<Record<string, unknown>[]> {
  const { invitations } = await workspacesApi.listInvitations(params.workspaceId);
  return Promise.all(
    invitations
      .filter((invitation) => invitation.kek_version === params.oldKeyVersion)
      .sort((a, b) => a.invitation_id.localeCompare(b.invitation_id))
      .map(async (invitation) => ({
        invitation_id: invitation.invitation_id,
        ...(await buildInvitationUpdate(params, invitation as unknown as Record<string, unknown>)),
      })),
  );
}

async function buildGuestInvitationUpdates(params: {
  worker: ReturnType<typeof getCryptoWorker>;
  workspaceId: string;
  oldKeyVersion: number;
  newKeyVersion: number;
}): Promise<Record<string, unknown>[]> {
  const { invitations } = await workspacesApi.listGuestInvitations(params.workspaceId);
  const now = Date.now();
  const records = invitations.map((invitation) => invitation as unknown as Record<string, unknown>);
  return Promise.all(
    records
      .filter(
        (invitation) =>
          invitation.kek_version === params.oldKeyVersion &&
          invitation.scope_kind === "workspace" &&
          invitation.revoked_at === null &&
          typeof invitation.redemption_count === "number" &&
          typeof invitation.max_redemptions === "number" &&
          invitation.redemption_count < invitation.max_redemptions &&
          typeof invitation.expires_at === "string" &&
          Date.parse(invitation.expires_at) > now,
      )
      .sort((a, b) =>
        requiredString(a.invitation_id, "guest_invitation_id_missing").localeCompare(
          requiredString(b.invitation_id, "guest_invitation_id_missing"),
        ),
      )
      .map(async (invitation) => ({
        guest_invitation_id: requiredString(
          invitation.invitation_id,
          "guest_invitation_id_missing",
        ),
        scope_kind: invitation.scope_kind,
        scope_id: invitation.scope_id,
        ...(await buildInvitationUpdate(params, invitation)),
      })),
  );
}

async function buildInvitationUpdate(
  params: {
    worker: ReturnType<typeof getCryptoWorker>;
    workspaceId: string;
    oldKeyVersion: number;
    newKeyVersion: number;
  },
  invitation: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const bootstrap = asRecord(
    invitation.encrypted_bootstrap_package,
    "invitation_bootstrap_package_missing",
  );
  const previousHash = requiredString(
    invitation.bootstrap_package_hash,
    "invitation_bootstrap_package_hash_missing",
  );
  const nextBootstrap = await params.worker.rewrapInvitationBootstrapForKekRotation({
    bootstrap,
    workspaceId: params.workspaceId,
    oldKeyVersion: params.oldKeyVersion,
    newKeyVersion: params.newKeyVersion,
  });
  const maintenanceWrap = asRecord(
    nextBootstrap.package_key_maintenance_wrap,
    "invitation_bootstrap_maintenance_wrap_missing",
  );
  const aad = asRecord(nextBootstrap.aad, "invitation_bootstrap_aad_missing");
  return {
    kek_version: params.newKeyVersion,
    encrypted_bootstrap_package: nextBootstrap,
    previous_bootstrap_package_hash: previousHash,
    bootstrap_package_hash: blake3Base64Url(
      canonicalizeStrictBytes(nextBootstrap as StrictJsonValue),
    ),
    bootstrap_package_key_maintenance_wrap: maintenanceWrap,
    bootstrap_package_key_maintenance_wrap_hash: blake3Base64Url(
      canonicalizeStrictBytes(maintenanceWrap as StrictJsonValue),
    ),
    key_version_context: asRecord(
      aad.key_version_context,
      "invitation_bootstrap_key_version_context_missing",
    ),
    bootstrap_suite_id: requiredString(
      nextBootstrap.suite_id,
      "invitation_bootstrap_suite_id_missing",
    ),
  };
}

function asRecord(value: unknown, code: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(code);
  return value as Record<string, unknown>;
}

function requiredString(value: unknown, code: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(code);
  return value;
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
  return perMember
    .flat()
    .sort((a, b) => a.user_id.localeCompare(b.user_id) || a.device_id.localeCompare(b.device_id));
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
