import { authState, cryptoWorkerReady, deviceState } from "@/entities/session";
import { devicesApi, encryptionApi, securityCheckpointsApi } from "@/shared/api";
import type { DeviceRegistrationInfo } from "@/shared/api/devices";
import type { components } from "@/shared/api/schema";
import {
  advanceKeyDirectoryPinWithProof,
  hashKeyDirectoryCheckpointEnvelope,
  lookupVerifiedKeyDirectoryCheckpointBodies,
  lookupVerifiedKeyDirectoryEventBodies,
} from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import {
  buildAuditCheckpointPinSet,
  getAuditCheckpointPin,
  verifyAndPinAuditCheckpoint,
} from "@/shared/lib/anti-rollback/audit-checkpoint-pin";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import type { InitialAkeResponderConfirmation } from "@/shared/lib/crypto/initial-ake";
import {
  canonicalizeStrict,
  canonicalizeStrictBytes,
  type StrictJsonValue,
} from "@/shared/lib/crypto/jcs";
import type { HybridEncryptionPublicKeyMaterial } from "@/shared/lib/crypto/hybrid-encryption";
import { buildDeviceKeyDirectoryAppend } from "@/shared/lib/crypto/key-directory/device-events";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import { verifySenderDeviceIdentityAndTofu } from "@/shared/lib/crypto/sender-device-verification";
import { assertWorkspaceSenderKeyAdmission } from "@/shared/lib/crypto/kek-resolver";
import { verifyWorkspaceSignedPqWrapOperation } from "@/shared/lib/anti-rollback/key-directory-pin/wrap-operation-proof";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
type InitialAkeArtifactSchema = components["schemas"]["InitialAkeArtifact"];
type InitialKeyDeliveryRecordSchema = components["schemas"]["InitialKeyDeliveryRecord"];
type InitialAkeDeliveryPairSchema = components["schemas"]["InitialAkeDeliveryPair"];
type InitialAkeResponseBundle = {
  umk_distribution: InitialAkeResponderConfirmation;
  trust_transfer: InitialAkeResponderConfirmation;
  device_approval_kek_initial: Record<string, InitialAkeResponderConfirmation>;
};

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
    rrpDeviceId: currentDevice.deviceId,
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
        rrpDeviceId: currentDevice.deviceId,
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
  const auditCheckpointProofs = await securityCheckpointsApi.current();
  const proofWorkspaceIds = auditCheckpointProofs.workspace_audit_checkpoints
    .map((entry) => entry.workspace_id)
    .sort();
  if (
    proofWorkspaceIds.length !== workspaceIds.length ||
    [...workspaceIds].sort().some((workspaceId, index) => workspaceId !== proofWorkspaceIds[index])
  ) {
    throw new Error("audit_checkpoint_proof_scope_mismatch");
  }
  await verifyAndPinAuditCheckpoint(auditCheckpointProofs.user_audit_checkpoint);
  for (const entry of auditCheckpointProofs.workspace_audit_checkpoints) {
    await verifyAndPinAuditCheckpoint(entry.audit_checkpoint);
  }

  const userAuditPin = await getAuditCheckpointPin("user", auth.user.id);
  if (!userAuditPin) throw new Error("user_audit_checkpoint_pin_required");
  const workspaceAuditPins = await Promise.all(
    workspaceAppends.map(async (append) => {
      const pin = await getAuditCheckpointPin("workspace", append.workspace_id);
      if (!pin) throw new Error("workspace_audit_checkpoint_pin_required");
      return pin;
    }),
  );
  const responderPrekeys = akeResponderPrekeys(params.device);
  const trustTransferPrekeyPayload = responderPrekeys.trustTransfer.payload;
  if (!isRecord(trustTransferPrekeyPayload)) {
    throw new Error("initial_ake_trust_responder_prekey_missing");
  }
  const auditCheckpointPinSet = buildAuditCheckpointPinSet({
    trustTransferId: stringField(trustTransferPrekeyPayload.operation_id),
    sourceDeviceId: currentDevice.deviceId,
    targetDeviceId: params.device.id,
    ownerUserId: auth.user.id,
    pins: [userAuditPin, ...workspaceAuditPins],
  });
  const trustStateBundle = buildTrustStateBundle({
    userId: auth.user.id,
    targetDeviceId: params.device.id,
    userPreviousCheckpoint: userDirectory.checkpoint,
    userCheckpoint: userAppend.checkpoint,
    userEvents: userAppend.events,
    workspaceAppends,
    auditCheckpointPinSet: auditCheckpointPinSet.pinSet,
    auditCheckpointProofs,
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
  const operationCheckpoint = operationCheckpointFromEnvelope(userAppend.checkpoint);
  const initialOffer = await worker.beginInitialAkeUmkDelivery({
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
  const initialPendingDeliveryHash = blake3Base64Url(
    canonicalizeStrictBytes(initialOffer.pending_delivery as unknown as StrictJsonValue),
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
  const trustOffer = await worker.beginInitialAkeDeviceStateTransferDelivery({
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
    transferScopeHash: auditCheckpointPinSet.transferScopeHash,
    auditCheckpointPinSetHash: auditCheckpointPinSet.pinSetHash,
    documentRollbackPinSetHash,
    pendingRegistrationBindingHash,
  });
  const trustPendingDeliveryHash = blake3Base64Url(
    canonicalizeStrictBytes(trustOffer.pending_delivery as unknown as StrictJsonValue),
  );
  const kekOffers: Record<
    string,
    Awaited<ReturnType<typeof worker.beginInitialAkeKekDelivery>>
  > = {};
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
    const kekOffer = await worker.beginInitialAkeKekDelivery({
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
    const pendingDeliveryHash = blake3Base64Url(
      canonicalizeStrictBytes(kekOffer.pending_delivery as unknown as StrictJsonValue),
    );
    kekOffers[append.workspace_id] = kekOffer;
    deviceApprovalKekInitialDeliveryCommitments.push({
      purpose: "device_approval_kek_initial",
      variant: "device_approval_kek_initial",
      delivery_id: stringField(
        (kekOffer.pending_delivery.metadata as Record<string, unknown>).delivery_id,
      ),
      recipient_device_id: params.device.id,
      sender_device_id: currentDevice.deviceId,
      workspace_id: append.workspace_id,
      key_version: keyVersion,
      delivery_record_hash: pendingDeliveryHash,
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
        (initialOffer.pending_delivery.metadata as Record<string, unknown>).delivery_id,
      ),
      recipient_device_id: params.device.id,
      sender_device_id: currentDevice.deviceId,
      delivery_record_hash: initialPendingDeliveryHash,
      key_checkpoint_hash: operationCheckpoint.checkpointHash,
    };
  const trustTransferDeliveryCommitment: components["schemas"]["TrustTransferDeliveryCommitment"] =
    {
      purpose: "trust_transfer",
      variant: "trust_transfer",
      ake_session_id: stringField(
        ((trustOffer.transcript as Record<string, unknown>).context as Record<string, unknown>)
          .operation_id,
      ),
      delivery_id: stringField(
        (trustOffer.pending_delivery.metadata as Record<string, unknown>).delivery_id,
      ),
      recipient_device_id: params.device.id,
      sender_device_id: currentDevice.deviceId,
      delivery_record_hash: trustPendingDeliveryHash,
      key_checkpoint_hash: operationCheckpoint.checkpointHash,
      document_rollback_pin_set_hash: documentRollbackPinSetHash,
      transfer_scope_hash: auditCheckpointPinSet.transferScopeHash,
      audit_checkpoint_pin_set_hash: auditCheckpointPinSet.pinSetHash,
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
    initial_ake_offers: {
      umk_distribution: initialOffer,
      trust_transfer: trustOffer,
      device_approval_kek_initial: kekOffers,
    },
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
  const responses = await retryInitialAkeResponses(params.device.id);
  const initialDelivery = await worker.finalizeInitialAkeDelivery({
    response: responses.umk_distribution,
  });
  const trustDelivery = await worker.finalizeInitialAkeDelivery({
    response: responses.trust_transfer,
  });
  const initialKekDeliveries: Record<string, InitialAkeDeliveryPairSchema> = {};
  for (const [workspaceId, response] of Object.entries(responses.device_approval_kek_initial)) {
    const delivery = await worker.finalizeInitialAkeDelivery({ response });
    initialKekDeliveries[workspaceId] = initialAkeDeliveryPairWire({
      initialAke: delivery.initialAke as unknown as InitialAkeArtifactSchema,
      initialKeyDelivery: delivery.initialKeyDelivery as unknown as InitialKeyDeliveryRecordSchema,
    });
  }
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
  userPreviousCheckpoint: Record<string, unknown>;
  userCheckpoint: Record<string, unknown>;
  userEvents: Record<string, unknown>[];
  workspaceAppends: {
    workspace_id: string;
    previousCheckpoint: Record<string, unknown>;
    events: Record<string, unknown>[];
    checkpoint: Record<string, unknown>;
  }[];
  auditCheckpointPinSet: ReturnType<typeof buildAuditCheckpointPinSet>["pinSet"];
  auditCheckpointProofs: Awaited<ReturnType<typeof securityCheckpointsApi.current>>;
}): Record<string, unknown> {
  const userLineage = buildTransferredKeyDirectoryLineage({
    scopeKind: "user",
    scopeId: params.userId,
    previousCheckpoint: params.userPreviousCheckpoint,
    checkpoint: params.userCheckpoint,
    events: params.userEvents,
  });
  return {
    protocol: "refmd.trust-state-bundle",
    version: 1,
    purpose: "trust_transfer",
    user_id: params.userId,
    target_device_id: params.targetDeviceId,
    user_lineage: userLineage,
    workspace_checkpoints: params.workspaceAppends.map((append) => ({
      workspace_id: append.workspace_id,
      lineage: buildTransferredKeyDirectoryLineage({
        scopeKind: "workspace",
        scopeId: append.workspace_id,
        previousCheckpoint: append.previousCheckpoint,
        checkpoint: append.checkpoint,
        events: append.events,
      }),
    })),
    audit_checkpoint_pin_set: params.auditCheckpointPinSet,
    audit_checkpoint_proofs: [
      {
        chain_scope_kind: "user",
        chain_scope_id: params.userId,
        proof: params.auditCheckpointProofs.user_audit_checkpoint,
      },
      ...params.auditCheckpointProofs.workspace_audit_checkpoints
        .sort((left, right) => left.workspace_id.localeCompare(right.workspace_id))
        .map((entry) => ({
          chain_scope_kind: "workspace",
          chain_scope_id: entry.workspace_id,
          proof: entry.audit_checkpoint,
        })),
    ],
  };
}

function buildTransferredKeyDirectoryLineage(params: {
  scopeKind: "user" | "workspace";
  scopeId: string;
  previousCheckpoint: Record<string, unknown>;
  checkpoint: Record<string, unknown>;
  events: Record<string, unknown>[];
}): Record<string, unknown> {
  const checkpointBySequence = new Map<number, Record<string, unknown>>();
  for (const checkpoint of [
    ...lookupVerifiedKeyDirectoryCheckpointBodies(params.scopeKind, params.scopeId),
    params.previousCheckpoint,
  ]) {
    const checkpointRecord = checkpoint as unknown as Record<string, unknown>;
    checkpointBySequence.set(
      operationCheckpointFromEnvelope(checkpointRecord).sequence,
      checkpointRecord,
    );
  }
  const checkpoints = [...checkpointBySequence.values()].sort(
    (left, right) =>
      operationCheckpointFromEnvelope(left).sequence -
      operationCheckpointFromEnvelope(right).sequence,
  );
  const anchor = params.previousCheckpoint;

  const anchorState = operationCheckpointFromEnvelope(anchor);
  const previousState = operationCheckpointFromEnvelope(params.previousCheckpoint);
  const candidateState = operationCheckpointFromEnvelope(params.checkpoint);
  const checkpointAncestry = checkpoints.filter((checkpoint) => {
    const sequence = operationCheckpointFromEnvelope(checkpoint).sequence;
    return sequence >= anchorState.sequence && sequence <= previousState.sequence;
  });
  if (checkpointAncestry.length !== previousState.sequence - anchorState.sequence + 1) {
    throw new Error("audit_checkpoint_authority_lineage_incomplete");
  }

  const eventBySequence = new Map<number, Record<string, unknown>>();
  for (const event of [
    ...lookupVerifiedKeyDirectoryEventBodies(params.scopeKind, params.scopeId),
    ...params.events,
  ]) {
    if (!isRecord(event.payload)) throw new Error("key_directory_event_invalid");
    eventBySequence.set(
      numberField(event.payload.sequence),
      event as unknown as Record<string, unknown>,
    );
  }
  const events = [...eventBySequence.values()]
    .filter((event) => {
      const sequence = numberField((event.payload as Record<string, unknown>).sequence);
      return (
        sequence > anchorState.coveredHeadSequence && sequence <= candidateState.coveredHeadSequence
      );
    })
    .sort(
      (left, right) =>
        numberField((left.payload as Record<string, unknown>).sequence) -
        numberField((right.payload as Record<string, unknown>).sequence),
    );
  if (events.length !== candidateState.coveredHeadSequence - anchorState.coveredHeadSequence) {
    throw new Error("audit_checkpoint_event_lineage_incomplete");
  }

  return {
    checkpoint_ancestry: checkpointAncestry,
    events,
    checkpoint: params.checkpoint,
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
    await encryptionApi.getWorkspaceKeysWithRrp(params.workspaceId, params.senderDeviceId);
  const activeKey = keys.find((key) => key.key_version === currentKekVersion);
  if (!activeKey) throw new Error("active_workspace_kek_missing");
  await verifyWorkspaceSignedPqWrapOperation(
    params.workspaceId,
    activeKey as unknown as Record<string, unknown>,
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
    operationProof: activeKey as unknown as Record<string, unknown>,
    senderSigningPublicKeyMaterial:
      activeKey.sender_hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial,
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

async function retryInitialAkeResponses(deviceId: string): Promise<InitialAkeResponseBundle> {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const result = await devicesApi.getInitialAkeResponses(deviceId);
      return result.responses as unknown as InitialAkeResponseBundle;
    } catch (error) {
      if (attempt === 59) throw error;
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }
  throw new Error("initial_ake_responses_not_ready");
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
