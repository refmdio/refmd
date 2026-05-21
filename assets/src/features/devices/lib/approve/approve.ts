import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { devicesApi, encryptionApi } from "@/shared/api";
import type { DeviceRegistrationInfo } from "@/shared/api/devices";
import type { components } from "@/shared/api/schema";
import {
  advanceKeyDirectoryPinWithProof,
  hashKeyDirectoryCheckpointEnvelope,
} from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import {
  canonicalizeStrict,
  canonicalizeStrictBytes,
  type StrictJsonValue,
} from "@/shared/lib/crypto/jcs";
import type { HybridEncryptionPublicKeyMaterial } from "@/shared/lib/crypto/hybrid-encryption";
import { buildDeviceKeyDirectoryAppend } from "@/shared/lib/crypto/key-directory/device-events";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import { verifySenderDeviceIdentityAndTofu } from "@/shared/lib/crypto/sender-device-verification";
import {
  assertWorkspaceSenderKeyAdmission,
  installWorkspaceOperationCheckpointPin,
} from "@/shared/lib/crypto/kek-resolver";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
type InitialAkeArtifactSchema = components["schemas"]["InitialAkeArtifact"];
type InitialKeyDeliveryRecordSchema = components["schemas"]["InitialKeyDeliveryRecord"];
type InitialAkeDeliveryPairSchema = components["schemas"]["InitialAkeDeliveryPair"];

interface PendingDeviceApprovalKeys {
  clientNonce: Uint8Array;
  deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  deviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  deviceEcdhPublic: Uint8Array;
}

function initialAkeDeliveryPairWire(delivery: {
  initialAke: InitialAkeArtifactSchema;
  initialKeyDelivery: InitialKeyDeliveryRecordSchema;
}): InitialAkeDeliveryPairSchema {
  return {
    initial_ake: delivery.initialAke,
    initial_key_delivery: delivery.initialKeyDelivery,
  };
}
type DeviceApprovalStep = "verify" | "distributing";
export function decodePendingDeviceApprovalKeys(
  device: DeviceRegistrationInfo,
): PendingDeviceApprovalKeys {
  return {
    clientNonce: base64UrlDecode(device.client_nonce),
    deviceHybridSigningPublicKeyMaterial:
      device.hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial,
    deviceHybridEncryptionPublicKeyMaterial:
      device.hybrid_encryption_public_key_material as unknown as HybridEncryptionPublicKeyMaterial,
    deviceEcdhPublic: base64UrlDecode(device.hybrid_encryption_public_key_material.x25519_public),
  };
}
export async function checkPendingDeviceApprovalTofu(
  device: DeviceRegistrationInfo,
): Promise<string | null> {
  const auth = authState();
  if (!auth) {
    return null;
  }
  const worker = getCryptoWorker();
  const decoded = decodePendingDeviceApprovalKeys(device);
  const result = await worker.tofuVerify({
    userId: auth.user.id,
    deviceId: device.id,
    hybridSigningPublicKeyMaterial: decoded.deviceHybridSigningPublicKeyMaterial,
    ecdhPublicKey: decoded.deviceEcdhPublic,
  });
  if (result.status === "identity_key_changed") {
    return "Identity key changed for this device. This may indicate tampering.";
  }
  if (result.status === "ecdh_key_mismatch") {
    return "ECDH key mismatch for this device. This may indicate tampering.";
  }
  return null;
}
export async function approveDeviceRegistration(params: {
  device: DeviceRegistrationInfo;
  onStepChange?: (step: DeviceApprovalStep) => void;
}): Promise<void> {
  const auth = authState();
  const currentDevice = deviceState();
  if (
    !cryptoWorkerReady() ||
    !auth ||
    !auth.identityHybridSigningPublicKeyMaterial ||
    !currentDevice?.deviceId ||
    !currentDevice.deviceHybridSigningPublicKeyMaterial
  ) {
    throw new Error("Identity keys or device not available");
  }
  const worker = getCryptoWorker();
  const decoded = decodePendingDeviceApprovalKeys(params.device);
  const { workspace_ids: workspaceIds } = await encryptionApi.getWorkspaceIds();
  const userDirectory = await fetchVerifiedKeyDirectory({
    scopeKind: "user",
    scopeId: auth.user.id,
    popDeviceId: currentDevice.deviceId,
  });
  const userAppend = await buildDeviceKeyDirectoryAppend({
    scopeKind: "user",
    scopeId: auth.user.id,
    userId: auth.user.id,
    checkpointEnvelope: userDirectory.checkpoint,
    recipientDeviceId: params.device.id,
    recipientHybridSigningPublicKeyMaterial: decoded.deviceHybridSigningPublicKeyMaterial,
    recipientHybridEncryptionPublicKeyMaterial: decoded.deviceHybridEncryptionPublicKeyMaterial,
  });
  const workspaceAppends = await Promise.all(
    workspaceIds.map(async (workspaceId) => {
      const directory = await fetchVerifiedKeyDirectory({
        scopeKind: "workspace",
        scopeId: workspaceId,
        popDeviceId: currentDevice.deviceId,
      });
      const append = await buildDeviceKeyDirectoryAppend({
        scopeKind: "workspace",
        scopeId: workspaceId,
        userId: auth.user.id,
        actorDeviceId: currentDevice.deviceId,
        checkpointEnvelope: directory.checkpoint,
        recipientDeviceId: params.device.id,
        recipientHybridSigningPublicKeyMaterial: decoded.deviceHybridSigningPublicKeyMaterial,
        recipientHybridEncryptionPublicKeyMaterial: decoded.deviceHybridEncryptionPublicKeyMaterial,
      });
      return {
        workspace_id: workspaceId,
        events: append.events,
        checkpoint: append.checkpoint,
        previousCheckpoint: directory.checkpoint,
      };
    }),
  );
  const trustStateBundle = buildTrustStateBundle({
    userId: auth.user.id,
    targetDeviceId: params.device.id,
    userCheckpoint: userAppend.checkpoint,
    workspaceAppends,
  });
  const trustStateBundleHash = blake3Base64Url(
    canonicalizeStrictBytes(trustStateBundle as unknown as StrictJsonValue),
  );
  const pendingRegistrationBindingHash = buildPendingRegistrationBindingHash({
    userId: auth.user.id,
    device: params.device,
    targetKeyCheckpoint: userAppend.checkpoint,
  });
  params.onStepChange?.("distributing");
  const responderPrekeys = akeResponderPrekeys(params.device);
  const operationCheckpoint = operationCheckpointFromEnvelope(userAppend.checkpoint);
  const initialDelivery = await worker.createInitialAkeUmkDelivery({
    userId: auth.user.id,
    senderDeviceId: currentDevice.deviceId,
    recipientDeviceId: params.device.id,
    recipientEncryptionKeyId: params.device.encryption_key_id,
    responderPrekey: responderPrekeys.umkDistribution,
    responderSigningPublicKeyMaterial: decoded.deviceHybridSigningPublicKeyMaterial,
    resourceHash: trustStateBundleHash,
    keyCheckpointHash: operationCheckpoint.checkpointHash,
    keyEventHeadHash: operationCheckpoint.coveredHeadHash,
    pendingRegistrationBindingHash,
  });
  const initialKeyDeliveryHash = blake3Base64Url(
    canonicalizeStrictBytes(initialDelivery.initialKeyDelivery as unknown as StrictJsonValue),
  );
  const documentRollbackPinSetHash = blake3Base64Url(
    canonicalizeStrictBytes({
      user_checkpoint: userAppend.checkpoint,
      workspace_checkpoints: workspaceAppends.map((append) => ({
        workspace_id: append.workspace_id,
        checkpoint: append.checkpoint,
      })),
    } as unknown as StrictJsonValue),
  );
  const trustDelivery = await worker.createInitialAkeDeviceStateTransferDelivery({
    deviceStateBundle: trustStateBundle,
    userId: auth.user.id,
    senderDeviceId: currentDevice.deviceId,
    recipientDeviceId: params.device.id,
    recipientEncryptionKeyId: params.device.encryption_key_id,
    responderPrekey: responderPrekeys.trustTransfer,
    responderSigningPublicKeyMaterial: decoded.deviceHybridSigningPublicKeyMaterial,
    resourceHash: trustStateBundleHash,
    keyCheckpointHash: operationCheckpoint.checkpointHash,
    keyEventHeadHash: operationCheckpoint.coveredHeadHash,
    workspacePinsHash: blake3Base64Url(
      canonicalizeStrictBytes({
        workspace_pins: workspaceAppends.map((append) => ({
          workspace_id: append.workspace_id,
          checkpoint_hash: hashKeyDirectoryCheckpointEnvelope(append.checkpoint),
          event_head_hash: operationCheckpointFromEnvelope(append.checkpoint).coveredHeadHash,
        })),
      } as unknown as StrictJsonValue),
    ),
    documentRollbackPinSetHash,
    pendingRegistrationBindingHash,
  });
  const trustTransferDeliveryHash = blake3Base64Url(
    canonicalizeStrictBytes(trustDelivery.initialKeyDelivery as unknown as StrictJsonValue),
  );
  const initialKekDeliveries: Record<string, InitialAkeDeliveryPairSchema> = {};
  const deviceApprovalKekInitialDeliveryCommitments: components["schemas"]["DeviceApprovalKekInitialDeliveryCommitment"][] =
    [];
  for (const append of workspaceAppends) {
    const keyVersion = await ensureWorkspaceKekCachedForInitialDelivery({
      workspaceId: append.workspace_id,
      userId: auth.user.id,
      senderDeviceId: currentDevice.deviceId,
    });
    const kekPrekey = responderPrekeys.kekByWorkspace[append.workspace_id];
    if (!kekPrekey) throw new Error("initial_ake_kek_responder_prekey_missing");
    const kekDelivery = await worker.createInitialAkeKekDelivery({
      workspaceId: append.workspace_id,
      keyVersion,
      userId: auth.user.id,
      senderDeviceId: currentDevice.deviceId,
      recipientDeviceId: params.device.id,
      recipientEncryptionKeyId: params.device.encryption_key_id,
      responderPrekey: kekPrekey,
      responderSigningPublicKeyMaterial: decoded.deviceHybridSigningPublicKeyMaterial,
      resourceHash: trustStateBundleHash,
      keyCheckpointHash: hashKeyDirectoryCheckpointEnvelope(append.checkpoint),
      keyEventHeadHash: operationCheckpointFromEnvelope(append.checkpoint).coveredHeadHash,
      userCheckpointHash: operationCheckpoint.checkpointHash,
      workspaceCheckpointHash: hashKeyDirectoryCheckpointEnvelope(append.checkpoint),
      workspaceEventHeadHash: operationCheckpointFromEnvelope(append.checkpoint).coveredHeadHash,
      pendingRegistrationBindingHash,
    });
    const deliveryRecordHash = blake3Base64Url(
      canonicalizeStrictBytes(kekDelivery.initialKeyDelivery as unknown as StrictJsonValue),
    );
    initialKekDeliveries[append.workspace_id] = initialAkeDeliveryPairWire({
      initialAke: kekDelivery.initialAke as unknown as InitialAkeArtifactSchema,
      initialKeyDelivery:
        kekDelivery.initialKeyDelivery as unknown as InitialKeyDeliveryRecordSchema,
    });
    deviceApprovalKekInitialDeliveryCommitments.push({
      purpose: "device_approval_kek_initial",
      variant: "device_approval_kek_initial",
      delivery_id: stringField(
        (kekDelivery.initialKeyDelivery.metadata as Record<string, unknown>).delivery_id,
      ),
      recipient_device_id: params.device.id,
      sender_device_id: currentDevice.deviceId,
      workspace_id: append.workspace_id,
      key_version: keyVersion,
      delivery_record_hash: deliveryRecordHash,
      key_checkpoint_hash: hashKeyDirectoryCheckpointEnvelope(append.checkpoint),
    });
  }
  deviceApprovalKekInitialDeliveryCommitments.sort((left, right) =>
    canonicalizeStrict(left as unknown as StrictJsonValue).localeCompare(
      canonicalizeStrict(right as unknown as StrictJsonValue),
    ),
  );
  const umkDistributionDeliveryCommitment: components["schemas"]["UmkDistributionDeliveryCommitment"] =
    {
      purpose: "umk_distribution",
      variant: "umk_distribution",
      delivery_id: stringField(
        (initialDelivery.initialKeyDelivery.metadata as Record<string, unknown>).delivery_id,
      ),
      recipient_device_id: params.device.id,
      sender_device_id: currentDevice.deviceId,
      delivery_record_hash: initialKeyDeliveryHash,
      key_checkpoint_hash: operationCheckpoint.checkpointHash,
    };
  const trustTransferDeliveryCommitment: components["schemas"]["TrustTransferDeliveryCommitment"] =
    {
      purpose: "trust_transfer",
      variant: "trust_transfer",
      ake_session_id: stringField(
        (
          (trustDelivery.initialAke.transcript as Record<string, unknown>).context as Record<
            string,
            unknown
          >
        ).operation_id,
      ),
      delivery_id: stringField(
        (trustDelivery.initialKeyDelivery.metadata as Record<string, unknown>).delivery_id,
      ),
      recipient_device_id: params.device.id,
      sender_device_id: currentDevice.deviceId,
      delivery_record_hash: trustTransferDeliveryHash,
      key_checkpoint_hash: operationCheckpoint.checkpointHash,
      document_rollback_pin_set_hash: documentRollbackPinSetHash,
    };
  const approvedDeviceRegistrationSas = await worker.computeSas({
    deviceId: params.device.id,
    identityHybridSigningPublicKeyMaterial: auth.identityHybridSigningPublicKeyMaterial,
    deviceHybridSigningPublicKeyMaterial: decoded.deviceHybridSigningPublicKeyMaterial,
    deviceHybridEncryptionPublicKeyMaterial: decoded.deviceHybridEncryptionPublicKeyMaterial,
    clientNonce: decoded.clientNonce,
  });
  const approvalBindingContext = {
    approvedDeviceRegistrationSasHash: base64UrlEncode(approvedDeviceRegistrationSas.hash),
    pendingRegistrationId: params.device.id,
    pendingRegistrationChallengeHash: stringField(
      params.device.pending_registration_challenge_hash,
    ),
    approvingSigningKeyId: stringField(currentDevice.deviceSigningKeyId),
    approvingKeyCheckpointSequence: numberField(
      (userDirectory.checkpoint.payload as Record<string, unknown>).sequence,
    ),
    approvingKeyCheckpointHash: hashKeyDirectoryCheckpointEnvelope(userDirectory.checkpoint),
    approvingDeviceKeyDirectoryProofHash: hashKeyDirectoryCheckpointEnvelope(
      userDirectory.checkpoint,
    ),
    targetDeviceId: params.device.id,
    targetDeviceSigningKeyId: params.device.signing_key_id,
    targetDeviceHybridSigningPublicKeyMaterialHash: blake3Base64Url(
      canonicalizeStrictBytes(
        params.device.hybrid_signing_public_key_material as unknown as StrictJsonValue,
      ),
    ),
    targetDeviceHybridEncryptionPublicKeyMaterialHash: blake3Base64Url(
      canonicalizeStrictBytes(
        params.device.hybrid_encryption_public_key_material as unknown as StrictJsonValue,
      ),
    ),
    targetDeviceEncryptionKeyId: params.device.encryption_key_id,
    targetDeviceClientNonceHash: blake3Base64Url(decoded.clientNonce),
    targetKeyCheckpointSequence: operationCheckpoint.sequence,
    targetKeyCheckpointHash: operationCheckpoint.checkpointHash,
  };
  const { signature } = await worker.createDeviceApprovalSignature({
    approverDeviceId: currentDevice.deviceId,
    deviceId: params.device.id,
    deviceHybridSigningPublicKeyMaterial: decoded.deviceHybridSigningPublicKeyMaterial,
    deviceHybridEncryptionPublicKeyMaterial: decoded.deviceHybridEncryptionPublicKeyMaterial,
    deviceEcdhPublic: decoded.deviceEcdhPublic,
    clientNonce: decoded.clientNonce,
    ...approvalBindingContext,
    umkDistributionDeliveryCommitment,
    trustTransferDeliveryCommitment,
    deviceApprovalKekInitialDeliveryCommitments,
  });
  const approvalProof = {
    protocol: "refmd.device-approval-proof",
    version: 1,
    approval_signature_surface: "device_approval",
    approval_transcript_hash: signature.transcript_hash,
    approval_transcript_owner: "refmd.device.approval",
    approval_surface_id: "device_approval",
    approval_surface_variant: "none",
    approving_owner_kind: "device",
    approving_owner_id: currentDevice.deviceId,
    approving_signing_key_id: approvalBindingContext.approvingSigningKeyId,
    approving_key_checkpoint_sequence: approvalBindingContext.approvingKeyCheckpointSequence,
    approving_key_checkpoint_hash: approvalBindingContext.approvingKeyCheckpointHash,
    target_device_id: approvalBindingContext.targetDeviceId,
    target_device_signing_key_id: approvalBindingContext.targetDeviceSigningKeyId,
    target_device_hybrid_signing_public_key_material_hash:
      approvalBindingContext.targetDeviceHybridSigningPublicKeyMaterialHash,
    target_device_hybrid_encryption_public_key_material_hash:
      approvalBindingContext.targetDeviceHybridEncryptionPublicKeyMaterialHash,
    target_device_encryption_key_id: approvalBindingContext.targetDeviceEncryptionKeyId,
    target_device_client_nonce_hash: approvalBindingContext.targetDeviceClientNonceHash,
    target_key_checkpoint_sequence: approvalBindingContext.targetKeyCheckpointSequence,
    target_key_checkpoint_hash: approvalBindingContext.targetKeyCheckpointHash,
    surface_details: {
      kind: "device_approval",
      pending_registration_id: approvalBindingContext.pendingRegistrationId,
      pending_registration_challenge_hash: approvalBindingContext.pendingRegistrationChallengeHash,
      trust_transfer_delivery_commitment: trustTransferDeliveryCommitment,
      umk_distribution_delivery_commitment: umkDistributionDeliveryCommitment,
      device_approval_kek_initial_delivery_commitments: deviceApprovalKekInitialDeliveryCommitments,
      approving_device_key_directory_proof_hash:
        approvalBindingContext.approvingDeviceKeyDirectoryProofHash,
      approved_device_registration_sas_hash:
        approvalBindingContext.approvedDeviceRegistrationSasHash,
    },
  } satisfies components["schemas"]["DeviceApprovalProof"];
  await devicesApi.approve(params.device.id, {
    approval_signature_surface: "device_approval",
    approval_signature: signature,
    approval_proof: approvalProof,
    user_key_directory_events: userAppend.events,
    user_key_directory_checkpoint: userAppend.checkpoint,
    workspace_key_directory_appends: workspaceAppends.map(
      ({ workspace_id, events, checkpoint }) => ({
        workspace_id,
        events,
        checkpoint,
      }),
    ),
  });
  await devicesApi.distributeUmk(params.device.id, currentDevice.deviceId, {
    initial_ake: initialDelivery.initialAke as unknown as InitialAkeArtifactSchema,
    initial_key_delivery:
      initialDelivery.initialKeyDelivery as unknown as InitialKeyDeliveryRecordSchema,
    initial_kek_deliveries: initialKekDeliveries,
    device_state_delivery: initialAkeDeliveryPairWire({
      initialAke: trustDelivery.initialAke as unknown as InitialAkeArtifactSchema,
      initialKeyDelivery:
        trustDelivery.initialKeyDelivery as unknown as InitialKeyDeliveryRecordSchema,
    }),
  });
  await advanceKeyDirectoryPinWithProof({
    scopeKind: "user",
    scopeId: auth.user.id,
    checkpointEnvelope: userAppend.checkpoint,
    checkpointAncestry: [userDirectory.checkpoint],
    eventAncestry: userAppend.events,
  });
  for (const append of workspaceAppends) {
    await advanceKeyDirectoryPinWithProof({
      scopeKind: "workspace",
      scopeId: append.workspace_id,
      checkpointEnvelope: append.checkpoint,
      checkpointAncestry: [append.previousCheckpoint],
      eventAncestry: append.events,
    });
  }
  await verifyApprovedDeviceFromServer({
    approvedDeviceId: params.device.id,
    originalDevice: params.device,
    userId: auth.user.id,
    identityHybridSigningPublicKeyMaterial: auth.identityHybridSigningPublicKeyMaterial,
    approvalHybridSigningPublicKeyMaterial: currentDevice.deviceHybridSigningPublicKeyMaterial,
  });
}

function buildTrustStateBundle(params: {
  userId: string;
  targetDeviceId: string;
  userCheckpoint: Record<string, unknown>;
  workspaceAppends: {
    workspace_id: string;
    checkpoint: Record<string, unknown>;
  }[];
}): Record<string, unknown> {
  return {
    protocol: "refmd.trust-state-bundle",
    version: 1,
    purpose: "trust_transfer",
    user_id: params.userId,
    target_device_id: params.targetDeviceId,
    user_checkpoint: params.userCheckpoint,
    workspace_checkpoints: params.workspaceAppends.map((append) => ({
      workspace_id: append.workspace_id,
      checkpoint: append.checkpoint,
    })),
  };
}

function buildPendingRegistrationBindingHash(params: {
  userId: string;
  device: DeviceRegistrationInfo;
  targetKeyCheckpoint: Record<string, unknown>;
}): string {
  if (!params.device.pending_registration_challenge_hash) {
    throw new Error("pending_registration_challenge_hash_required");
  }
  const checkpointPayload = params.targetKeyCheckpoint.payload as
    | Record<string, unknown>
    | undefined;
  if (!checkpointPayload || typeof checkpointPayload.sequence !== "number") {
    throw new Error("pending_registration_checkpoint_invalid");
  }

  return blake3Base64Url(
    canonicalizeStrictBytes({
      protocol: "refmd.pending-registration-binding",
      version: 1,
      user_id: params.userId,
      pending_registration_id: params.device.id,
      pending_registration_challenge_hash: params.device.pending_registration_challenge_hash,
      target_device_id: params.device.id,
      target_device_signing_key_id: params.device.signing_key_id,
      target_device_hybrid_signing_public_key_material_hash: blake3Base64Url(
        canonicalizeStrictBytes(
          params.device.hybrid_signing_public_key_material as unknown as StrictJsonValue,
        ),
      ),
      target_device_hybrid_encryption_public_key_material_hash: blake3Base64Url(
        canonicalizeStrictBytes(
          params.device.hybrid_encryption_public_key_material as unknown as StrictJsonValue,
        ),
      ),
      target_device_encryption_key_id: params.device.encryption_key_id,
      target_device_client_nonce_hash: blake3Base64Url(base64UrlDecode(params.device.client_nonce)),
      target_key_checkpoint_sequence: checkpointPayload.sequence,
      target_key_checkpoint_hash: hashKeyDirectoryCheckpointEnvelope(params.targetKeyCheckpoint),
    } as unknown as StrictJsonValue),
  );
}

function akeResponderPrekeys(device: DeviceRegistrationInfo): {
  umkDistribution: {
    payload: StrictJsonValue;
    signature: never;
  };
  trustTransfer: {
    payload: StrictJsonValue;
    signature: never;
  };
  kekByWorkspace: Record<string, { payload: StrictJsonValue; signature: never }>;
} {
  const prekeys = device.ake_responder_prekeys as Record<string, unknown> | undefined | null;
  if (!prekeys || typeof prekeys !== "object") {
    throw new Error("initial_ake_responder_prekeys_missing");
  }
  const umkDistribution = prekeys.umk_distribution;
  if (!isRecord(umkDistribution)) throw new Error("initial_ake_umk_responder_prekey_missing");
  const trustTransfer = prekeys.trust_transfer;
  if (!isRecord(trustTransfer)) throw new Error("initial_ake_trust_responder_prekey_missing");
  const kekByWorkspace: Record<string, { payload: StrictJsonValue; signature: never }> = {};
  const deviceApprovalPrekeys = prekeys.device_approval_kek_initial;
  if (!Array.isArray(deviceApprovalPrekeys)) {
    throw new Error("initial_ake_device_approval_responder_prekeys_missing");
  }
  for (const entry of deviceApprovalPrekeys) {
    if (!isRecord(entry) || typeof entry.workspace_id !== "string" || !isRecord(entry.prekey)) {
      continue;
    }
    kekByWorkspace[entry.workspace_id] = entry.prekey as never;
  }
  return {
    umkDistribution: umkDistribution as never,
    trustTransfer: trustTransfer as never,
    kekByWorkspace,
  };
}

async function ensureWorkspaceKekCachedForInitialDelivery(params: {
  workspaceId: string;
  userId: string;
  senderDeviceId: string;
}): Promise<number> {
  const worker = getCryptoWorker();
  const { keys, current_kek_version: currentKekVersion } =
    await encryptionApi.getWorkspaceKeysWithPop(params.workspaceId, params.senderDeviceId);
  const activeKey = keys.find((key) => key.key_version === currentKekVersion);
  if (!activeKey) throw new Error("active_workspace_kek_missing");
  const expectedOperationCheckpoint = await installWorkspaceOperationCheckpointPin(
    params.workspaceId,
    activeKey as Record<string, unknown>,
  );
  assertWorkspaceSenderKeyAdmission(params.workspaceId, activeKey as Record<string, unknown>);
  await verifySenderDeviceIdentityAndTofu({
    sender: activeKey,
    senderUserId: params.userId,
    expectedIdentityHybridSigningPublicKeyMaterial:
      authState()?.identityHybridSigningPublicKeyMaterial,
    expectedIdentityEcdhPublic: authState()?.identityEcdhPublic,
  });
  await worker.openSignedPqDeviceKekWrap({
    record: activeKey as never,
    senderSigningPublicKeyMaterial:
      activeKey.sender_hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial,
    expectedOperationCheckpoint,
  });
  return currentKekVersion;
}

export async function rejectDeviceRegistration(deviceId: string): Promise<void> {
  try {
    await devicesApi.rejectRegistration(deviceId);
  } catch {
    // Already deleted or expired.
  }
}
async function verifyApprovedDeviceFromServer(params: {
  approvedDeviceId: string;
  originalDevice: DeviceRegistrationInfo;
  userId: string;
  identityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  approvalHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
}): Promise<{
  id: string;
  ecdhPublicKey: Uint8Array;
}> {
  const worker = getCryptoWorker();
  const { devices } = await devicesApi.list();
  const approvedDevice = devices.find((device) => device.id === params.approvedDeviceId);
  if (!approvedDevice) {
    throw new Error("Approved device not found on server");
  }
  if (
    approvedDevice.signing_key_id !== params.originalDevice.signing_key_id ||
    approvedDevice.encryption_key_id !== params.originalDevice.encryption_key_id
  ) {
    throw new Error(
      "Server returned different keys after approval. Possible key substitution. Aborting.",
    );
  }
  if (!approvedDevice.approval_signature || !approvedDevice.client_nonce) {
    throw new Error("Approved device missing identity signature. Aborting.");
  }
  const approvedDeviceHybridSigningPublicKeyMaterial =
    approvedDevice.hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial;
  const ecdhPublicKey = base64UrlDecode(
    approvedDevice.hybrid_encryption_public_key_material.x25519_public,
  );
  const verificationParams = {
    deviceId: approvedDevice.id,
    deviceHybridSigningPublicKeyMaterial: approvedDeviceHybridSigningPublicKeyMaterial,
    deviceHybridEncryptionPublicKeyMaterial:
      approvedDevice.hybrid_encryption_public_key_material as unknown as HybridEncryptionPublicKeyMaterial,
    deviceEcdhPublic: ecdhPublicKey,
    clientNonce: base64UrlDecode(approvedDevice.client_nonce),
    identitySignature: approvedDevice.approval_signature,
    identityHybridSigningPublicKeyMaterial: params.identityHybridSigningPublicKeyMaterial,
    approvalHybridSigningPublicKeyMaterial: params.approvalHybridSigningPublicKeyMaterial,
    identitySignatureContext: approvedDevice.approval_proof as Record<string, unknown>,
    approvalDeliveryCommitments: approvedDevice.approval_delivery_commitments,
    approvalDeliveryArtifacts: approvedDevice.approval_delivery_artifacts,
  };
  const signatureValid =
    approvedDevice.approval_signature_surface === "genesis_device_bootstrap"
      ? await worker.verifyGenesisDeviceBootstrapSignature(verificationParams)
      : approvedDevice.approval_signature_surface === "device_approval"
        ? await worker.verifyDeviceApprovalSignature(verificationParams)
        : approvedDevice.approval_signature_surface === "recovery_device_approval"
          ? await worker.verifyRecoveryDeviceApprovalSignature(verificationParams)
          : false;
  if (!signatureValid) {
    throw new Error(
      "Identity signature verification failed. Possible server-side tampering. Aborting.",
    );
  }
  const tofuResult = await worker.tofuVerify({
    userId: params.userId,
    deviceId: approvedDevice.id,
    hybridSigningPublicKeyMaterial: approvedDeviceHybridSigningPublicKeyMaterial,
    ecdhPublicKey,
  });
  if (tofuResult.status === "ecdh_key_mismatch" || tofuResult.status === "identity_key_changed") {
    throw new Error("Key verification failed before key distribution. Aborting.");
  }
  if (tofuResult.status === "first_seen") {
    await worker.tofuTrustDevice({
      userId: params.userId,
      deviceId: approvedDevice.id,
      hybridSigningPublicKeyMaterial: approvedDeviceHybridSigningPublicKeyMaterial,
      ecdhPublicKey,
    });
  } else if (tofuResult.status === "known_trusted") {
    await worker.tofuUpdateLastSeen({
      userId: params.userId,
      deviceId: approvedDevice.id,
    });
  }
  return {
    id: approvedDevice.id,
    ecdhPublicKey,
  };
}

function operationCheckpointFromEnvelope(checkpointEnvelope: Record<string, unknown>) {
  const payload = checkpointEnvelope.payload as Record<string, unknown> | undefined;
  const covered = payload?.covered_event_head as Record<string, unknown> | undefined;
  if (!payload || !covered) throw new Error("key_directory_checkpoint_invalid");
  return {
    sequence: numberField(payload.sequence),
    checkpointHash: hashKeyDirectoryCheckpointEnvelope(checkpointEnvelope),
    coveredHeadSequence: numberField(covered.head_sequence),
    coveredHeadHash: stringField(covered.head_hash),
  };
}

function numberField(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
    throw new Error("number_field_invalid");
  }
  return value;
}

function stringField(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("string_field_invalid");
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
