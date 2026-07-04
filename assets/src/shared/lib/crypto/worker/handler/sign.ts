import { blake3 } from "@noble/hashes/blake3.js";
import { base64UrlDecode, base64UrlEncode } from "../../encoding";
import { canonicalizeStrict, canonicalizeStrictBytes, type StrictJsonValue } from "../../jcs";
import { calculateFingerprint, formatFingerprint } from "../../fingerprint";
import { computeSas } from "../../sas";
import {
  computeHybridEncryptionKeyId,
  type HybridEncryptionPublicKeyMaterial,
} from "../../hybrid-encryption";
import { validateDeviceApprovalProofEnvelope } from "../../approval-proof-validation";
import {
  buildDeviceApprovalTranscript,
  buildDeviceKeyDeletionProofTranscript,
  buildDeviceRevocationTranscript,
  buildDocumentSnapshotTranscript,
  buildDocumentUpdateTranscript,
  buildEditorEphemeralSessionTranscript,
  buildEditorEphemeralTranscript,
  buildGenesisDeviceBootstrapTranscript,
  buildKeyDirectoryCheckpointTranscript,
  buildKeyDirectoryEventTranscript,
  buildPluginBundleApprovalTranscript,
  buildPluginConsentEventTranscript,
  buildPluginNetworkProxyRequestTranscript,
  buildWorkspacePinBootstrapTranscript,
  buildPendingRegistrationBindingHash,
  buildPopTranscript,
  buildRecoveryDeviceApprovalTranscript,
  buildRecoveryAuthorizationProofTranscript,
  buildRecoverySessionTranscript,
  buildRecipientBoundAuthorizationTranscript,
  buildShareCapabilityAuthorizationTranscript,
  buildShareParticipantDeviceAuthorizationTranscript,
  computeSigningKeyId,
  createDeviceApprovalSignature,
  createDeviceRevocationSignature,
  createPopRequestSignature,
  generateHybridSigningPrivateKeyMaterial,
  publicKeyMaterialFromPrivate,
  shareCapabilityPublicKeyMaterialFromPrivate,
  signDeviceKeyDeletionProofSignature,
  signDocumentSnapshotSignature,
  signDocumentUpdateSignature,
  signEditorEphemeralSessionSignature,
  signEditorEphemeralSignature,
  signGenesisDeviceBootstrapSignature,
  signKeyDirectoryCheckpointSignature,
  signKeyDirectoryEventSignature,
  signPluginBundleApprovalSignature,
  signPluginConsentEventSignature,
  signPluginNetworkProxyRequestSignature,
  signWorkspacePinBootstrapSignature,
  signRecipientBoundAuthorizationSignature,
  signRecoveryAuthorizationProofSignature,
  signRecoveryDeviceApprovalSignature,
  signRecoverySessionSignature,
  signShareCapabilityAuthorizationSignature,
  signShareParticipantDeviceAuthorizationSignature,
  verifyDeviceApprovalSignature,
  verifyDocumentUpdateEd25519SignatureAsync,
  verifyDocumentSnapshotSignature,
  verifyDocumentUpdateSignature,
  verifyEditorEphemeralSessionSignature,
  verifyEditorEphemeralSignature,
  verifyGenesisDeviceBootstrapSignature,
  verifyKeyDirectoryCheckpointSignature,
  verifyKeyDirectoryEventSignature,
  verifyWorkspacePinBootstrapSignature,
  verifyRecoveryDeviceApprovalSignature,
  type AnyHybridSigningPublicKeyMaterial,
  type HybridSignature,
  type HybridSigningPrivateKeyMaterial,
  type HybridSigningPublicKeyMaterial,
  deriveShareCapabilitySigningPrivateKeyMaterial,
} from "../../signature";
import {
  requireDeviceHybridSigningPrivateKeyMaterial,
  requireDeviceHybridSigningPublicKeyMaterial,
  requireDeviceId,
  requireIdentityHybridSigningPrivateKeyMaterial,
  requireShareParticipantHybridSigningPrivateKeyMaterial,
  requireUserId,
  type HandlerPayload,
} from "./utils";
import type { HybridSigningState, WorkerKeyState } from "../state";
import { blake3Base64Url } from "../../hash";

function invitationRedeemAuthority(state: WorkerKeyState, invitationId: string) {
  const privateMaterial = state.invitationRedeemAuthorities.get(invitationId);
  if (!privateMaterial) throw new Error("invitation_redeem_authority_missing");
  if (
    privateMaterial.owner_kind !== "invitation_redeem_authority" ||
    privateMaterial.owner_id !== invitationId
  ) {
    throw new Error("invitation_redeem_authority_owner_mismatch");
  }
  return privateMaterial;
}

function requireDocumentSigningState(
  state: WorkerKeyState,
  ownerKind: "device" | "share_participant_device",
): HybridSigningState {
  const signingState =
    ownerKind === "share_participant_device"
      ? state.shareParticipantHybridSigningState
      : state.deviceHybridSigningState;
  if (!signingState) throw new Error("document_signing_key_missing");
  return signingState;
}

function requireSigningPrivateKeyMaterial(
  state: WorkerKeyState,
  ownerKind: "device" | "share_participant_device",
) {
  return ownerKind === "share_participant_device"
    ? requireShareParticipantHybridSigningPrivateKeyMaterial(state)
    : requireDeviceHybridSigningPrivateKeyMaterial(state);
}

function requireDocumentSigningOwnerKind(value: unknown): "device" | "share_participant_device" {
  if (value === "device" || value === "share_participant_device") return value;
  throw new Error("document_signing_owner_kind_missing");
}

function invitationRedeemSigner(privateMaterial: ReturnType<typeof invitationRedeemAuthority>) {
  const publicMaterial = publicKeyMaterialFromPrivate(privateMaterial);
  return {
    signer_kind: "invitation_redeem_authority",
    invitation_id: privateMaterial.owner_id,
    signing_key_id: computeSigningKeyId(publicMaterial),
  };
}

function signedSurfaceArtifact(
  privateMaterial: HybridSigningPrivateKeyMaterial,
  transcript: StrictJsonValue,
  signature: HybridSignature,
  signingState?: HybridSigningState,
): {
  transcript: StrictJsonValue;
  signature: HybridSignature;
  signing_key_id: string;
  hybrid_signing_public_key_material: AnyHybridSigningPublicKeyMaterial;
} {
  const publicMaterial =
    signingState?.publicKeyMaterial ??
    (privateMaterial.owner_kind === "share_capability"
      ? shareCapabilityPublicKeyMaterialFromPrivate(privateMaterial)
      : publicKeyMaterialFromPrivate(privateMaterial));
  return {
    transcript,
    signature,
    signing_key_id: signingState?.signingKeyId ?? computeSigningKeyId(publicMaterial),
    hybrid_signing_public_key_material: publicMaterial,
  };
}

function requireShareCapabilitySigningPrivateKeyMaterial(
  state: WorkerKeyState,
  shareSlug: string,
  shareTokenHash: string,
): HybridSigningPrivateKeyMaterial {
  const capabilitySecret = state.shareSecrets.get(shareSlug)?.capabilitySecret;
  if (!capabilitySecret) throw new Error("share_capability_secret_required");
  return deriveShareCapabilitySigningPrivateKeyMaterial(capabilitySecret, shareTokenHash);
}

function deviceApprovalContextParams(value: Record<string, unknown>): {
  approvedDeviceRegistrationSasHash: string;
  pendingRegistrationId: string;
  pendingRegistrationChallengeHash: string;
  approvingOwnerKind: "device";
  approvingOwnerId: string;
  approvingSigningKeyId: string;
  approvingKeyCheckpointSequence: number;
  approvingKeyCheckpointHash: string;
  approvingDeviceKeyDirectoryProofHash: string;
  targetKeyCheckpointSequence: number;
  targetKeyCheckpointHash: string;
  umkDistributionDeliveryCommitment: StrictJsonValue;
  trustTransferDeliveryCommitment: StrictJsonValue;
  deviceApprovalKekInitialDeliveryCommitments: StrictJsonValue[];
} {
  const details = isRecord(value.surface_details) ? value.surface_details : value;
  return {
    approvedDeviceRegistrationSasHash: details.approved_device_registration_sas_hash as string,
    pendingRegistrationId: details.pending_registration_id as string,
    pendingRegistrationChallengeHash: details.pending_registration_challenge_hash as string,
    approvingOwnerKind: value.approving_owner_kind as "device",
    approvingOwnerId: value.approving_owner_id as string,
    approvingSigningKeyId: value.approving_signing_key_id as string,
    approvingKeyCheckpointSequence: value.approving_key_checkpoint_sequence as number,
    approvingKeyCheckpointHash: value.approving_key_checkpoint_hash as string,
    approvingDeviceKeyDirectoryProofHash:
      details.approving_device_key_directory_proof_hash as string,
    targetKeyCheckpointSequence: value.target_key_checkpoint_sequence as number,
    targetKeyCheckpointHash: value.target_key_checkpoint_hash as string,
    umkDistributionDeliveryCommitment:
      details.umk_distribution_delivery_commitment as StrictJsonValue,
    trustTransferDeliveryCommitment: details.trust_transfer_delivery_commitment as StrictJsonValue,
    deviceApprovalKekInitialDeliveryCommitments:
      details.device_approval_kek_initial_delivery_commitments as StrictJsonValue[],
  };
}

function targetApprovalFields(params: {
  targetDeviceId: string;
  targetDeviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  targetDeviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  targetDeviceClientNonce: string;
}): {
  targetDeviceId: string;
  targetDeviceSigningKeyId: string;
  targetDeviceHybridSigningPublicKeyMaterialHash: string;
  targetDeviceHybridEncryptionPublicKeyMaterialHash: string;
  targetDeviceEncryptionKeyId: string;
  targetDeviceClientNonceHash: string;
} {
  return {
    targetDeviceId: params.targetDeviceId,
    targetDeviceSigningKeyId: computeSigningKeyId(
      params.targetDeviceHybridSigningPublicKeyMaterial,
    ),
    targetDeviceHybridSigningPublicKeyMaterialHash: blake3Base64Url(
      canonicalizeStrictBytes(
        params.targetDeviceHybridSigningPublicKeyMaterial as unknown as StrictJsonValue,
      ),
    ),
    targetDeviceHybridEncryptionPublicKeyMaterialHash: blake3Base64Url(
      canonicalizeStrictBytes(
        params.targetDeviceHybridEncryptionPublicKeyMaterial as unknown as StrictJsonValue,
      ),
    ),
    targetDeviceEncryptionKeyId: computeHybridEncryptionKeyId(
      params.targetDeviceHybridEncryptionPublicKeyMaterial,
    ),
    targetDeviceClientNonceHash: blake3Base64Url(base64UrlDecode(params.targetDeviceClientNonce)),
  };
}

export function handleGenerateInvitationRedeemAuthority(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const invitationId = p.invitationId as string;
  if (!invitationId) throw new Error("invitation_id_invalid");
  const privateMaterial = generateHybridSigningPrivateKeyMaterial(
    "invitation_redeem_authority",
    invitationId,
  );
  const publicMaterial = publicKeyMaterialFromPrivate(privateMaterial);
  state.invitationRedeemAuthorities.set(invitationId, privateMaterial);
  return {
    signer: invitationRedeemSigner(privateMaterial),
    hybridSigningPublicKeyMaterial: publicMaterial,
  };
}

export function handleComputeUpdateHash(p: HandlerPayload): unknown {
  const bytes = canonicalizeStrictBytes(p as StrictJsonValue);
  const hash = blake3(bytes);
  return { hash: base64UrlEncode(hash) };
}

export function handleCreatePopSignature(state: WorkerKeyState, p: HandlerPayload): unknown {
  const requestedDeviceId = (p.deviceId as string | undefined) ?? requireDeviceId(state);
  const scope = p.scope === "share" ? "share" : "user";
  const transport = p.transport === "phoenix_channel" ? "phoenix_channel" : "http";
  const actorKind = scope === "share" ? "share_participant_device" : "user_device";
  const privateMaterial = requireSigningPrivateKeyMaterial(
    state,
    actorKind === "share_participant_device" ? "share_participant_device" : "device",
  );
  if (privateMaterial.owner_id !== requestedDeviceId) {
    throw new Error("pop_device_owner_mismatch");
  }
  const variant =
    transport === "phoenix_channel"
      ? actorKind === "share_participant_device"
        ? "channel_share_participant_device"
        : "channel_user_device"
      : actorKind === "share_participant_device"
        ? "http_share_participant_device"
        : "http_user_device";

  const transcript = buildPopTranscript({
    variant,
    ownerKind: privateMaterial.owner_kind,
    ownerId: privateMaterial.owner_id,
    actor: p.actor as Record<string, StrictJsonValue>,
    challenge: p.challenge as string,
    session: p.session as Record<string, StrictJsonValue>,
    resource: p.resource as never,
  });
  const signature = createPopRequestSignature({
    privateKeyMaterial: privateMaterial,
    transcript,
  });

  return signedSurfaceArtifact(privateMaterial, transcript, signature);
}

export function handleSignPluginConsentEvent(state: WorkerKeyState, p: HandlerPayload): unknown {
  const privateMaterial = requireDeviceHybridSigningPrivateKeyMaterial(state);
  const userId = requireUserId(state);
  const deviceId = requireDeviceId(state);
  const publicMaterial = publicKeyMaterialFromPrivate(privateMaterial);
  const consent = p.consent as Record<string, StrictJsonValue>;
  const workspaceId = consent.workspace_id;
  if (typeof workspaceId !== "string" || workspaceId.length === 0) {
    throw new Error("plugin_consent_event_actor_invalid");
  }
  const keyCheckpointSequence = p.keyCheckpointSequence;
  const keyCheckpointHash = p.keyCheckpointHash;
  if (
    typeof keyCheckpointSequence !== "number" ||
    !Number.isInteger(keyCheckpointSequence) ||
    keyCheckpointSequence < 1 ||
    typeof keyCheckpointHash !== "string" ||
    keyCheckpointHash.length === 0
  ) {
    throw new Error("plugin_consent_event_key_checkpoint_required");
  }
  const actor = {
    signer_kind: "device",
    user_id: userId,
    device_id: deviceId,
    key_scope_kind: "workspace",
    key_scope_id: workspaceId,
    signing_key_id: computeSigningKeyId(publicMaterial),
    key_checkpoint_sequence: keyCheckpointSequence,
    key_checkpoint_hash: keyCheckpointHash,
  };
  const transcript = buildPluginConsentEventTranscript({
    actor,
    consent,
  });
  const signature = signPluginConsentEventSignature({
    privateKeyMaterial: privateMaterial,
    transcript,
  });

  return {
    actor,
    ...signedSurfaceArtifact(privateMaterial, transcript, signature),
  };
}

export function handleSignPluginBundleApproval(state: WorkerKeyState, p: HandlerPayload): unknown {
  const privateMaterial = requireDeviceHybridSigningPrivateKeyMaterial(state);
  const userId = requireUserId(state);
  const deviceId = requireDeviceId(state);
  const actor = p.actor as Record<string, StrictJsonValue>;
  const approval = p.approval as Record<string, StrictJsonValue>;

  if (actor.user_id !== userId || actor.device_id !== deviceId) {
    throw new Error("plugin_bundle_approval_actor_mismatch");
  }

  const transcript = buildPluginBundleApprovalTranscript({
    actor,
    approval,
  });
  const signature = signPluginBundleApprovalSignature({
    privateKeyMaterial: privateMaterial,
    transcript,
  });

  return {
    actor,
    ...signedSurfaceArtifact(privateMaterial, transcript, signature),
  };
}

function signDocumentEnvelope(
  state: WorkerKeyState,
  p: HandlerPayload,
  kind: "update" | "snapshot" | "ephemeral",
): unknown {
  const publicData = p.publicData as Record<string, unknown>;
  const ownerKind = requireDocumentSigningOwnerKind(publicData.ownerKind);
  const signingState = requireDocumentSigningState(state, ownerKind);
  const privateMaterial = signingState.privateKeyMaterial;
  const userId = requireUserId(state);
  const deviceId = requireDeviceId(state);
  const common = {
    ownerKind: privateMaterial.owner_kind,
    ownerId: privateMaterial.owner_id,
    actorUserId: userId,
    actorDeviceId: deviceId,
    signingKeyId: signingState.signingKeyId,
    workspaceId: p.workspaceId as string,
    publicData,
    authorityBoundary: p.authorityBoundary as Record<string, unknown>,
    ciphertext: p.ciphertext as string,
    nonce: p.nonce as string,
  };

  const transcript =
    kind === "update"
      ? buildDocumentUpdateTranscript(common)
      : kind === "snapshot"
        ? buildDocumentSnapshotTranscript(common)
        : buildEditorEphemeralTranscript(common);

  const signature =
    kind === "update"
      ? signDocumentUpdateSignature({ privateKeyMaterial: privateMaterial, transcript })
      : kind === "snapshot"
        ? signDocumentSnapshotSignature({ privateKeyMaterial: privateMaterial, transcript })
        : signEditorEphemeralSignature({ privateKeyMaterial: privateMaterial, transcript });

  return signedSurfaceArtifact(privateMaterial, transcript, signature, signingState);
}

export function handleSignDocumentUpdate(state: WorkerKeyState, p: HandlerPayload): unknown {
  return signDocumentEnvelope(state, p, "update");
}

export function handleSignDocumentSnapshot(state: WorkerKeyState, p: HandlerPayload): unknown {
  return signDocumentEnvelope(state, p, "snapshot");
}

export function handleSignEditorEphemeral(state: WorkerKeyState, p: HandlerPayload): unknown {
  return signDocumentEnvelope(state, p, "ephemeral");
}

export function handleCreateGenesisDeviceBootstrapSignature(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const privateMaterial = requireIdentityHybridSigningPrivateKeyMaterial(state);
  const userId = requireUserId(state);
  const deviceId = requireDeviceId(state);
  const devicePublicMaterial = requireDevicePublicMaterial(state);
  const deviceHybridEncryptionPublicKeyMaterial =
    requireDeviceHybridEncryptionPublicMaterial(state);
  const deviceEcdhPublicKey = base64UrlEncode(p.deviceEcdhPublic as Uint8Array);
  const clientNonce = base64UrlEncode(p.clientNonce as Uint8Array);
  const transcript = buildGenesisDeviceBootstrapTranscript({
    ownerId: userId,
    deviceId,
    deviceHybridSigningPublicKeyMaterial: devicePublicMaterial,
    deviceEcdhPublicKey,
    deviceHybridEncryptionPublicKeyMaterial,
    clientNonce,
    registrationChallengeHash: p.registrationChallengeHash as string,
    identitySigningKeyId: p.identitySigningKeyId as string,
    userIdentityPublicKeyHash: p.userIdentityPublicKeyHash as string,
  });

  const signature = signGenesisDeviceBootstrapSignature({
    privateKeyMaterial: privateMaterial,
    transcript,
  });

  return signedSurfaceArtifact(privateMaterial, transcript, signature);
}

export function handleCreateRecoveryDeviceApprovalSignature(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const privateMaterial = requireIdentityHybridSigningPrivateKeyMaterial(state);
  const userId = requireUserId(state);
  const deviceId = requireDeviceId(state);
  const devicePublicMaterial = requireDevicePublicMaterial(state);
  const deviceHybridEncryptionPublicKeyMaterial =
    requireDeviceHybridEncryptionPublicMaterial(state);
  const deviceEcdhPublicKey = base64UrlEncode(p.deviceEcdhPublic as Uint8Array);
  const clientNonce = base64UrlEncode(p.clientNonce as Uint8Array);
  const transcript = buildRecoveryDeviceApprovalTranscript({
    ownerId: userId,
    approvingSigningKeyId: computeSigningKeyId(publicKeyMaterialFromPrivate(privateMaterial)),
    approvingKeyCheckpointSequence: p.approvingKeyCheckpointSequence as number,
    approvingKeyCheckpointHash: p.approvingKeyCheckpointHash as string,
    pendingRegistrationId: p.pendingRegistrationId as string,
    pendingRegistrationChallengeHash: p.pendingRegistrationChallengeHash as string,
    recoverySessionTranscriptHash: p.recoverySessionTranscriptHash as string,
    recoveryCapabilityHash: p.recoveryCapabilityHash as string,
    pendingRegistrationBindingHash: p.pendingRegistrationBindingHash as string,
    approvedDeviceId: deviceId,
    approvedDeviceHybridSigningPublicKeyMaterial: devicePublicMaterial,
    approvedDeviceEcdhPublicKey: deviceEcdhPublicKey,
    approvedDeviceHybridEncryptionPublicKeyMaterial: deviceHybridEncryptionPublicKeyMaterial,
    clientNonce,
    targetKeyCheckpointSequence: p.targetKeyCheckpointSequence as number,
    targetKeyCheckpointHash: p.targetKeyCheckpointHash as string,
  });
  const signature = signRecoveryDeviceApprovalSignature({
    privateKeyMaterial: privateMaterial,
    transcript,
  });

  return signedSurfaceArtifact(privateMaterial, transcript, signature);
}

export function handleCreateDeviceApprovalSignature(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const privateMaterial = requireDeviceHybridSigningPrivateKeyMaterial(state);
  const userId = requireUserId(state);
  const devicePublicMaterial =
    p.deviceHybridSigningPublicKeyMaterial as HybridSigningPublicKeyMaterial;
  const deviceHybridEncryptionPublicKeyMaterial =
    p.deviceHybridEncryptionPublicKeyMaterial as HybridEncryptionPublicKeyMaterial;
  const deviceEcdhPublicKey = base64UrlEncode(p.deviceEcdhPublic as Uint8Array);
  const clientNonce = base64UrlEncode(p.clientNonce as Uint8Array);

  const transcript = buildDeviceApprovalTranscript({
    ownerId: userId,
    approverDeviceId: p.approverDeviceId as string,
    approvedDeviceId: p.deviceId as string,
    approvedDeviceHybridSigningPublicKeyMaterial: devicePublicMaterial,
    approvedDeviceEcdhPublicKey: deviceEcdhPublicKey,
    approvedDeviceHybridEncryptionPublicKeyMaterial: deviceHybridEncryptionPublicKeyMaterial,
    clientNonce,
    approvedDeviceRegistrationSasHash: p.approvedDeviceRegistrationSasHash as string,
    pendingRegistrationId: p.pendingRegistrationId as string,
    pendingRegistrationChallengeHash: p.pendingRegistrationChallengeHash as string,
    approvingOwnerKind: "device",
    approvingOwnerId: p.approverDeviceId as string,
    approvingSigningKeyId: p.approvingSigningKeyId as string,
    approvingKeyCheckpointSequence: p.approvingKeyCheckpointSequence as number,
    approvingKeyCheckpointHash: p.approvingKeyCheckpointHash as string,
    approvingDeviceKeyDirectoryProofHash: p.approvingDeviceKeyDirectoryProofHash as string,
    targetDeviceId: p.deviceId as string,
    targetDeviceSigningKeyId: p.targetDeviceSigningKeyId as string,
    targetDeviceHybridSigningPublicKeyMaterialHash:
      p.targetDeviceHybridSigningPublicKeyMaterialHash as string,
    targetDeviceHybridEncryptionPublicKeyMaterialHash:
      p.targetDeviceHybridEncryptionPublicKeyMaterialHash as string,
    targetDeviceEncryptionKeyId: p.targetDeviceEncryptionKeyId as string,
    targetDeviceClientNonceHash: p.targetDeviceClientNonceHash as string,
    targetKeyCheckpointSequence: p.targetKeyCheckpointSequence as number,
    targetKeyCheckpointHash: p.targetKeyCheckpointHash as string,
    umkDistributionDeliveryCommitment: p.umkDistributionDeliveryCommitment as StrictJsonValue,
    trustTransferDeliveryCommitment: p.trustTransferDeliveryCommitment as StrictJsonValue,
    deviceApprovalKekInitialDeliveryCommitments:
      p.deviceApprovalKekInitialDeliveryCommitments as StrictJsonValue[],
  });

  const signature = createDeviceApprovalSignature({
    privateKeyMaterial: privateMaterial,
    transcript,
  });

  return signedSurfaceArtifact(privateMaterial, transcript, signature);
}

export function handleCreateDeviceRevocationSignature(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const privateMaterial = requireDeviceHybridSigningPrivateKeyMaterial(state);
  const userId = requireUserId(state);
  const deviceId = requireDeviceId(state);
  const publicMaterial = publicKeyMaterialFromPrivate(privateMaterial);

  const transcript = buildDeviceRevocationTranscript({
    ownerId: userId,
    actorUserId: userId,
    actorDeviceId: deviceId,
    signingKeyId: computeSigningKeyId(publicMaterial),
    revokedDeviceId: p.revokedDeviceId as string,
    revocationMode: p.revocationMode as string,
    revokedAtMs: p.revokedAtMs as number,
  });
  const signature = createDeviceRevocationSignature({
    privateKeyMaterial: privateMaterial,
    transcript,
  });

  return signedSurfaceArtifact(privateMaterial, transcript, signature);
}

export function handleSignDeviceKeyDeletionProof(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const privateMaterial = requireDeviceHybridSigningPrivateKeyMaterial(state);
  const payload = p.payload as Record<string, unknown>;
  const actor = p.actor as Record<string, unknown>;
  const transcript = buildDeviceKeyDeletionProofTranscript({ payload, actor });
  const signature = signDeviceKeyDeletionProofSignature({
    privateKeyMaterial: privateMaterial,
    transcript,
  });

  return { payload, ...signedSurfaceArtifact(privateMaterial, transcript, signature) };
}

function signOwnerKeyDirectoryCheckpoint(
  state: WorkerKeyState,
  p: HandlerPayload,
  ownerKind: "identity" | "device" | "share_participant_device",
): unknown {
  const privateMaterial =
    ownerKind === "identity"
      ? requireIdentityHybridSigningPrivateKeyMaterial(state)
      : requireSigningPrivateKeyMaterial(state, ownerKind);
  const publicMaterial = publicKeyMaterialFromPrivate(privateMaterial);
  const signingKeyId = computeSigningKeyId(publicMaterial);
  const checkpointPayload = p.checkpointPayload as Record<string, unknown>;
  const signer = keyDirectoryCheckpointSignerAuthority(
    keyDirectorySigner(ownerKind, state, signingKeyId, p.shareId),
    checkpointPayload,
  );

  const transcript = buildKeyDirectoryCheckpointTranscript({
    variant: p.variant as
      | "identity_initial"
      | "workspace_initial"
      | "identity_active"
      | "identity_rotation"
      | "workspace_authorized"
      | "invitation_redeem_authority"
      | "share_participant_document_operation"
      | "device_authorized",
    ownerKind: privateMaterial.owner_kind,
    ownerId: privateMaterial.owner_id,
    checkpointPayload: checkpointPayload as StrictJsonValue,
    signer: signer as StrictJsonValue,
  });
  const signature = signKeyDirectoryCheckpointSignature({
    privateKeyMaterial: privateMaterial,
    transcript,
  });

  return {
    signer,
    transcript,
    signature,
    signing_key_id: signingKeyId,
    hybrid_signing_public_key_material: publicMaterial,
  };
}

export function handleSignIdentityKeyDirectoryCheckpoint(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  return signOwnerKeyDirectoryCheckpoint(state, p, "identity");
}

export function handleSignDeviceKeyDirectoryCheckpoint(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  return signOwnerKeyDirectoryCheckpoint(state, p, "device");
}

export function handleSignShareParticipantDeviceKeyDirectoryCheckpoint(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  return signOwnerKeyDirectoryCheckpoint(state, p, "share_participant_device");
}

function signOwnerKeyDirectoryEvent(
  state: WorkerKeyState,
  p: HandlerPayload,
  ownerKind: "identity" | "device" | "share_participant_device",
): unknown {
  const privateMaterial =
    ownerKind === "identity"
      ? requireIdentityHybridSigningPrivateKeyMaterial(state)
      : requireSigningPrivateKeyMaterial(state, ownerKind);
  const publicMaterial = publicKeyMaterialFromPrivate(privateMaterial);
  const eventPayload = p.eventPayload as Record<string, unknown>;

  const transcript = buildKeyDirectoryEventTranscript({
    eventType: p.eventType as Parameters<typeof buildKeyDirectoryEventTranscript>[0]["eventType"],
    ownerKind: privateMaterial.owner_kind,
    ownerId: privateMaterial.owner_id,
    eventPayload: eventPayload as StrictJsonValue,
  });
  const signingKeyId = computeSigningKeyId(publicMaterial);
  const signer = keyDirectoryEventSignerAuthority(
    keyDirectorySigner(ownerKind, state, signingKeyId, p.shareId),
    eventPayload,
  );
  const signature = signKeyDirectoryEventSignature({
    privateKeyMaterial: privateMaterial,
    transcript,
  });

  return {
    signer,
    transcript,
    signature,
    signing_key_id: signingKeyId,
    hybrid_signing_public_key_material: publicMaterial,
  };
}

export function handleSignIdentityKeyDirectoryEvent(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  return signOwnerKeyDirectoryEvent(state, p, "identity");
}

export function handleSignDeviceKeyDirectoryEvent(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  return signOwnerKeyDirectoryEvent(state, p, "device");
}

export function handleSignShareParticipantDeviceKeyDirectoryEvent(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  return signOwnerKeyDirectoryEvent(state, p, "share_participant_device");
}

export function handleSignInvitationRedeemKeyDirectoryEvent(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const invitationId = p.invitationId as string;
  const privateMaterial = invitationRedeemAuthority(state, invitationId);
  const eventPayload = p.eventPayload as Record<string, unknown>;
  const publicMaterial = publicKeyMaterialFromPrivate(privateMaterial);
  const transcript = buildKeyDirectoryEventTranscript({
    eventType: p.eventType as Parameters<typeof buildKeyDirectoryEventTranscript>[0]["eventType"],
    ownerKind: privateMaterial.owner_kind,
    ownerId: privateMaterial.owner_id,
    eventPayload: eventPayload as StrictJsonValue,
  });
  const signingKeyId = computeSigningKeyId(publicMaterial);
  const signer = keyDirectoryEventSignerAuthority(
    invitationRedeemSigner(privateMaterial),
    eventPayload,
  );
  const signature = signKeyDirectoryEventSignature({
    privateKeyMaterial: privateMaterial,
    transcript,
  });
  return {
    signer,
    transcript,
    signature,
    signing_key_id: signingKeyId,
    hybrid_signing_public_key_material: publicMaterial,
  };
}

export function handleSignInvitationRedeemKeyDirectoryCheckpoint(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const invitationId = p.invitationId as string;
  const privateMaterial = invitationRedeemAuthority(state, invitationId);
  const publicMaterial = publicKeyMaterialFromPrivate(privateMaterial);
  const checkpointPayload = p.checkpointPayload as Record<string, unknown>;
  const signer = keyDirectoryCheckpointSignerAuthority(
    invitationRedeemSigner(privateMaterial),
    checkpointPayload,
  );
  const transcript = buildKeyDirectoryCheckpointTranscript({
    variant: "invitation_redeem_authority",
    ownerKind: privateMaterial.owner_kind,
    ownerId: privateMaterial.owner_id,
    checkpointPayload: checkpointPayload as StrictJsonValue,
    signer: signer as StrictJsonValue,
  });
  const signingKeyId = computeSigningKeyId(publicMaterial);
  const signature = signKeyDirectoryCheckpointSignature({
    privateKeyMaterial: privateMaterial,
    transcript,
  });
  return {
    signer,
    transcript,
    signature,
    signing_key_id: signingKeyId,
    hybrid_signing_public_key_material: publicMaterial,
  };
}

export function handleSignWorkspacePinBootstrap(state: WorkerKeyState, p: HandlerPayload): unknown {
  const privateMaterial = requireDeviceHybridSigningPrivateKeyMaterial(state);
  const publicMaterial = publicKeyMaterialFromPrivate(privateMaterial);
  const signingKeyId = computeSigningKeyId(publicMaterial);
  const workspaceId = p.workspaceId as string;
  const bootstrapPayload = p.bootstrapPayload as Record<string, unknown>;
  const issuer = bootstrapPayload.issuer as Record<string, unknown> | undefined;
  if (
    !issuer ||
    issuer.signing_key_id !== signingKeyId ||
    issuer.device_id !== privateMaterial.owner_id
  ) {
    throw new Error("workspace_pin_bootstrap_issuer_mismatch");
  }

  const transcript = buildWorkspacePinBootstrapTranscript({
    ownerDeviceId: privateMaterial.owner_id,
    workspaceId,
    bootstrap: bootstrapPayload as StrictJsonValue,
  });
  const signature = signWorkspacePinBootstrapSignature({
    privateKeyMaterial: privateMaterial,
    transcript,
  });

  return {
    signer: issuer,
    transcript,
    signature,
    signing_key_id: signingKeyId,
    hybrid_signing_public_key_material: publicMaterial,
  };
}

export function handleSignPluginNetworkProxyRequest(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const privateMaterial = requireDeviceHybridSigningPrivateKeyMaterial(state);
  const subject = p.subject as Record<string, StrictJsonValue>;
  const transcript = buildPluginNetworkProxyRequestTranscript({
    subject,
  });
  const signature = signPluginNetworkProxyRequestSignature({
    privateKeyMaterial: privateMaterial,
    transcript,
  });

  return signedSurfaceArtifact(privateMaterial, transcript, signature);
}

export function handleSignRecipientBoundAuthorization(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const privateMaterial = requireDeviceHybridSigningPrivateKeyMaterial(state);
  const userId = requireUserId(state);
  const deviceId = requireDeviceId(state);
  const publicMaterial = publicKeyMaterialFromPrivate(privateMaterial);

  const signingKeyId = computeSigningKeyId(publicMaterial);
  const transcript = buildRecipientBoundAuthorizationTranscript({
    ownerId: privateMaterial.owner_id,
    actorUserId: userId,
    actorDeviceId: deviceId,
    signingKeyId,
    authorizationPayload: p.authorizationPayload as Record<string, unknown>,
  });
  const signature = signRecipientBoundAuthorizationSignature({
    privateKeyMaterial: privateMaterial,
    transcript,
  });

  return {
    transcript,
    signature,
    signing_key_id: signingKeyId,
    hybrid_signing_public_key_material: publicMaterial,
  };
}

export function handleSignRecoverySession(state: WorkerKeyState, p: HandlerPayload): unknown {
  const privateMaterial = requireIdentityHybridSigningPrivateKeyMaterial(state);
  const userId = requireUserId(state);
  const recoveryAuthorizationSigningState = state.recoveryAuthorizationHybridSigningState;
  if (!recoveryAuthorizationSigningState) {
    throw new Error("recovery_authorization_key_missing");
  }
  const identitySigningKeyId = computeSigningKeyId(publicKeyMaterialFromPrivate(privateMaterial));
  const recoveryAuthorizationProofTranscript = buildRecoveryAuthorizationProofTranscript({
    ownerId: userId,
    recoveryAuthorizationKeyId: recoveryAuthorizationSigningState.signingKeyId,
    recipientDeviceId: p.recipientDeviceId as string,
    pendingRegistrationBindingHash: p.pendingRegistrationBindingHash as string,
    serverChallengeHash: p.serverChallengeHash as string,
  });
  const recoveryAuthorizationProof = signRecoveryAuthorizationProofSignature({
    privateKeyMaterial: recoveryAuthorizationSigningState.privateKeyMaterial,
    transcript: recoveryAuthorizationProofTranscript,
  });
  const recoveryCapabilityHash = blake3Base64Url(
    canonicalizeStrictBytes({
      protocol: "refmd.recovery-capability",
      version: 1,
      recovery_authorization_key_id: recoveryAuthorizationSigningState.signingKeyId,
      recovery_authorization_proof: recoveryAuthorizationProof,
      recovery_authorization_proof_transcript_hash: recoveryAuthorizationProof.transcript_hash,
      pending_registration_binding_hash: p.pendingRegistrationBindingHash as string,
      recipient_device_id: p.recipientDeviceId as string,
      server_challenge_hash: p.serverChallengeHash as string,
    } as unknown as StrictJsonValue),
  );
  const transcript = buildRecoverySessionTranscript({
    ownerId: userId,
    recoverySessionId: p.recoverySessionId as string,
    serverChallengeHash: p.serverChallengeHash as string,
    recipientDeviceId: p.recipientDeviceId as string,
    pendingRegistrationId: p.pendingRegistrationId as string,
    pendingRegistrationBindingHash: p.pendingRegistrationBindingHash as string,
    recoveredIdentitySigningKeyId: identitySigningKeyId,
    recoveryAuthorizationKeyId: recoveryAuthorizationSigningState.signingKeyId,
    candidateUserCheckpointSequence: p.candidateUserCheckpointSequence as number,
    candidateUserCheckpointHash: p.candidateUserCheckpointHash as string,
    candidateUserEventHeadSequence: p.candidateUserEventHeadSequence as number,
    candidateUserEventHeadHash: p.candidateUserEventHeadHash as string,
    recoveryCapabilityHash,
  });

  const signature = signRecoverySessionSignature({
    privateKeyMaterial: privateMaterial,
    transcript,
  });

  return {
    transcript,
    signature,
    signing_key_id: identitySigningKeyId,
    hybrid_signing_public_key_material: publicKeyMaterialFromPrivate(privateMaterial),
    recoveryAuthorizationKeyId: recoveryAuthorizationSigningState.signingKeyId,
    recoveryAuthorizationProof,
    recoveryCapabilityHash,
    recoverySessionTranscriptHash: blake3Base64Url(
      canonicalizeStrictBytes(transcript as StrictJsonValue),
    ),
  };
}

export function handleSignShareParticipantDeviceAuthorization(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const privateMaterial = requireShareParticipantHybridSigningPrivateKeyMaterial(state);
  const publicMaterial = publicKeyMaterialFromPrivate(privateMaterial);
  const deviceId = requireDeviceId(state);
  const encryptionPublicMaterial = requireDeviceHybridEncryptionPublicMaterial(state);

  const transcript = buildShareParticipantDeviceAuthorizationTranscript({
    shareId: p.shareId as string,
    shareSessionId: p.shareSessionId as string,
    shareParticipantPrincipalId: p.shareParticipantPrincipalId as string,
    shareParticipantDeviceId: deviceId,
    participantSigningKeyId: computeSigningKeyId(publicMaterial),
    participantEncryptionKeyId: computeHybridEncryptionKeyId(encryptionPublicMaterial),
    capabilityContextHash: p.capabilityContextHash as string,
    shareCreatedEventHash: p.shareCreatedEventHash as string,
    latestBootstrapEventHash: p.latestBootstrapEventHash as string,
    scopeKind: p.scopeKind as "document" | "folder",
    scopeId: p.scopeId as string,
    permission: p.permission as "view" | "edit",
  });
  const signature = signShareParticipantDeviceAuthorizationSignature({
    privateKeyMaterial: privateMaterial,
    transcript,
  });

  return signedSurfaceArtifact(privateMaterial, transcript, signature);
}

export function handleSignShareCapabilityAuthorization(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const shareSlug = p.shareSlug as string;
  const shareTokenHash = p.shareTokenHash as string;
  const privateMaterial = requireShareCapabilitySigningPrivateKeyMaterial(
    state,
    shareSlug,
    shareTokenHash,
  );
  const transcript = buildShareCapabilityAuthorizationTranscript({
    shareTokenHash,
    workspacePinBootstrapHash: p.workspacePinBootstrapHash as string,
    shareId: p.shareId as string,
    scopeKind: p.scopeKind as "document" | "folder",
    scopeId: p.scopeId as string,
    permission: p.permission as "view" | "edit",
    passwordProtected: p.passwordProtected as boolean,
    createdEventHash: p.createdEventHash as string,
    latestBootstrapEventHash: p.latestBootstrapEventHash as string,
    capabilityContextHash: p.capabilityContextHash as string,
    shareCapabilitySecretCommitment: p.shareCapabilitySecretCommitment as string,
    passwordCapabilitySecretCommitment: p.passwordCapabilitySecretCommitment as string,
  });
  const signature = signShareCapabilityAuthorizationSignature({
    privateKeyMaterial: privateMaterial,
    transcript,
  });

  return signedSurfaceArtifact(privateMaterial, transcript, signature);
}

export function handleCreateEditorEphemeralSessionProof(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const ownerKind = requireDocumentSigningOwnerKind(p.ownerKind);
  const privateMaterial = requireSigningPrivateKeyMaterial(state, ownerKind);
  const userId = requireUserId(state);
  const deviceId = requireDeviceId(state);
  const publicMaterial = publicKeyMaterialFromPrivate(privateMaterial);

  const transcript = buildEditorEphemeralSessionTranscript({
    ownerKind: privateMaterial.owner_kind,
    ownerId: privateMaterial.owner_id,
    workspaceId: p.workspaceId as string,
    documentId: p.documentId as string,
    channelId: p.channelId as string,
    actorUserId: userId,
    actorDeviceId: deviceId,
    signingKeyId: computeSigningKeyId(publicMaterial),
    sessionId: p.sessionId as string,
    proofDirection: p.proofDirection as string,
    proofType: p.proofType as string,
    sessionNonce: p.sessionNonce as string,
    counter: p.counter as number,
    expiresEventSequence: p.expiresEventSequence as number,
    keyCheckpointSequence: p.keyCheckpointSequence as number,
    keyCheckpointHash: p.keyCheckpointHash as string,
    authorityBoundary: p.authorityBoundary as Record<string, unknown>,
  });
  const signature = signEditorEphemeralSessionSignature({
    privateKeyMaterial: privateMaterial,
    transcript,
  });

  return signedSurfaceArtifact(privateMaterial, transcript, signature);
}

export function handleVerifyEditorEphemeralSessionProof(
  _state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const publicKeyMaterial = p.publicKeyMaterial as HybridSigningPublicKeyMaterial;
  const signature = p.signature as never;

  return {
    valid: verifyEditorEphemeralSessionSignature({
      publicKeyMaterial,
      signature,
      transcript: buildEditorEphemeralSessionTranscript({
        ownerKind: publicKeyMaterial.owner_kind,
        ownerId: publicKeyMaterial.owner_id,
        workspaceId: p.workspaceId as string,
        documentId: p.documentId as string,
        channelId: p.channelId as string,
        actorUserId: p.actorUserId as string,
        actorDeviceId: publicKeyMaterial.owner_id,
        signingKeyId: computeSigningKeyId(publicKeyMaterial),
        sessionId: p.sessionId as string,
        proofDirection: p.proofDirection as string,
        proofType: p.proofType as string,
        sessionNonce: p.sessionNonce as string,
        counter: p.counter as number,
        expiresEventSequence: p.expiresEventSequence as number,
        keyCheckpointSequence: p.keyCheckpointSequence as number,
        keyCheckpointHash: p.keyCheckpointHash as string,
        authorityBoundary: p.authorityBoundary as Record<string, unknown>,
      }),
    }),
  };
}

export function handleVerifyGenesisDeviceBootstrapProof(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  return verifyDeviceApprovalSurfaceProof(state, p, "genesis_device_bootstrap");
}

export function handleVerifyDeviceApprovalProof(state: WorkerKeyState, p: HandlerPayload): unknown {
  return verifyDeviceApprovalSurfaceProof(state, p, "device_approval");
}

export function handleVerifyRecoveryDeviceApprovalProof(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  return verifyDeviceApprovalSurfaceProof(state, p, "recovery_device_approval");
}

function verifyDeviceApprovalSurfaceProof(
  state: WorkerKeyState,
  p: HandlerPayload,
  purpose: "genesis_device_bootstrap" | "device_approval" | "recovery_device_approval",
): unknown {
  const identityPublicMaterial =
    (p.identityHybridSigningPublicKeyMaterial as HybridSigningPublicKeyMaterial | undefined) ??
    state.identityHybridSigningState?.publicKeyMaterial;
  if (!identityPublicMaterial) {
    return { valid: false };
  }

  const devicePublicMaterial =
    p.deviceHybridSigningPublicKeyMaterial as HybridSigningPublicKeyMaterial;
  const deviceHybridEncryptionPublicKeyMaterial =
    p.deviceHybridEncryptionPublicKeyMaterial as HybridEncryptionPublicKeyMaterial;
  const deviceEcdhPublicKey = base64UrlEncode(p.deviceEcdhPublic as Uint8Array);
  const clientNonce = base64UrlEncode(p.clientNonce as Uint8Array);
  const deviceId = p.deviceId as string;
  const signature = p.identitySignature as never;
  if (!isRecord(p.identitySignatureContext)) {
    return { valid: false };
  }
  const context = p.identitySignatureContext;

  const candidate =
    purpose === "genesis_device_bootstrap"
      ? {
          signingPurpose: "genesis_device_bootstrap",
          publicKeyMaterial: identityPublicMaterial,
          transcript: buildGenesisDeviceBootstrapTranscript({
            ownerId: identityPublicMaterial.owner_id,
            deviceId,
            deviceHybridSigningPublicKeyMaterial: devicePublicMaterial,
            deviceEcdhPublicKey,
            deviceHybridEncryptionPublicKeyMaterial,
            clientNonce,
            registrationChallengeHash: (
              context.surface_details as Record<string, unknown> | undefined
            )?.registration_challenge_hash as string,
            identitySigningKeyId: context.approving_signing_key_id as string,
            userIdentityPublicKeyHash: (
              context.surface_details as Record<string, unknown> | undefined
            )?.user_identity_public_key_hash as string,
          }),
        }
      : purpose === "device_approval"
        ? {
            signingPurpose: "device_approval",
            publicKeyMaterial:
              (p.approvalHybridSigningPublicKeyMaterial as
                | HybridSigningPublicKeyMaterial
                | undefined) ??
              (state.deviceId === context.approving_owner_id
                ? requireDeviceHybridSigningPublicKeyMaterial(state)
                : null),
            transcript: buildDeviceApprovalTranscript({
              ownerId: identityPublicMaterial.owner_id,
              approverDeviceId: context.approving_owner_id as string,
              approvedDeviceId: deviceId,
              approvedDeviceHybridSigningPublicKeyMaterial: devicePublicMaterial,
              approvedDeviceEcdhPublicKey: deviceEcdhPublicKey,
              approvedDeviceHybridEncryptionPublicKeyMaterial:
                deviceHybridEncryptionPublicKeyMaterial,
              clientNonce,
              ...deviceApprovalContextParams(context),
              ...targetApprovalFields({
                targetDeviceId: deviceId,
                targetDeviceHybridSigningPublicKeyMaterial: devicePublicMaterial,
                targetDeviceHybridEncryptionPublicKeyMaterial:
                  deviceHybridEncryptionPublicKeyMaterial,
                targetDeviceClientNonce: clientNonce,
              }),
            }),
          }
        : purpose === "recovery_device_approval"
          ? {
              signingPurpose: "recovery_device_approval",
              publicKeyMaterial: identityPublicMaterial,
              transcript: buildRecoveryDeviceApprovalTranscript({
                ownerId: identityPublicMaterial.owner_id,
                approvingSigningKeyId: context.approving_signing_key_id as string,
                approvingKeyCheckpointSequence: context.approving_key_checkpoint_sequence as number,
                approvingKeyCheckpointHash: context.approving_key_checkpoint_hash as string,
                pendingRegistrationId: (isRecord(context.surface_details)
                  ? context.surface_details
                  : context
                ).pending_registration_id as string,
                pendingRegistrationChallengeHash: (isRecord(context.surface_details)
                  ? context.surface_details
                  : context
                ).pending_registration_challenge_hash as string,
                recoverySessionTranscriptHash: (isRecord(context.surface_details)
                  ? context.surface_details
                  : context
                ).recovery_session_transcript_hash as string,
                recoveryCapabilityHash: (isRecord(context.surface_details)
                  ? context.surface_details
                  : context
                ).recovery_capability_hash as string,
                pendingRegistrationBindingHash: buildPendingRegistrationBindingHash({
                  userId: identityPublicMaterial.owner_id,
                  pendingRegistrationId: (isRecord(context.surface_details)
                    ? context.surface_details
                    : context
                  ).pending_registration_id as string,
                  pendingRegistrationChallengeHash: (isRecord(context.surface_details)
                    ? context.surface_details
                    : context
                  ).pending_registration_challenge_hash as string,
                  targetDeviceId: deviceId,
                  targetDeviceSigningKeyId: computeSigningKeyId(devicePublicMaterial),
                  targetDeviceHybridSigningPublicKeyMaterial: devicePublicMaterial,
                  targetDeviceHybridEncryptionPublicKeyMaterial:
                    deviceHybridEncryptionPublicKeyMaterial,
                  targetDeviceEncryptionKeyId: computeHybridEncryptionKeyId(
                    deviceHybridEncryptionPublicKeyMaterial,
                  ),
                  targetDeviceClientNonce: clientNonce,
                  targetKeyCheckpointSequence: context.target_key_checkpoint_sequence as number,
                  targetKeyCheckpointHash: context.target_key_checkpoint_hash as string,
                }),
                approvedDeviceId: deviceId,
                approvedDeviceHybridSigningPublicKeyMaterial: devicePublicMaterial,
                approvedDeviceEcdhPublicKey: deviceEcdhPublicKey,
                approvedDeviceHybridEncryptionPublicKeyMaterial:
                  deviceHybridEncryptionPublicKeyMaterial,
                clientNonce,
                targetKeyCheckpointSequence: context.target_key_checkpoint_sequence as number,
                targetKeyCheckpointHash: context.target_key_checkpoint_hash as string,
              }),
            }
          : null;

  if (
    !candidate ||
    !candidate.publicKeyMaterial ||
    !validateDeviceApprovalProofEnvelope({
      proof: context,
      purpose,
      transcript: candidate.transcript as StrictJsonValue,
      targetDeviceId: deviceId,
      targetDeviceHybridSigningPublicKeyMaterial: devicePublicMaterial,
      targetDeviceHybridEncryptionPublicKeyMaterial: deviceHybridEncryptionPublicKeyMaterial,
      targetDeviceClientNonce: clientNonce,
      approvingHybridSigningPublicKeyMaterial: candidate.publicKeyMaterial,
      approvalDeliveryCommitments: isRecord(p.approvalDeliveryCommitments)
        ? p.approvalDeliveryCommitments
        : null,
      approvalDeliveryArtifacts: isRecord(p.approvalDeliveryArtifacts)
        ? p.approvalDeliveryArtifacts
        : null,
    }) ||
    (typeof context.approval_transcript_hash === "string"
      ? context.approval_transcript_hash !==
        blake3Base64Url(canonicalizeStrictBytes(candidate.transcript as StrictJsonValue))
      : !strictJsonEqual(context, candidate.transcript))
  ) {
    return { valid: false };
  }

  const verificationParams = {
    transcript: candidate.transcript,
    signature,
    publicKeyMaterial: candidate.publicKeyMaterial,
  };
  const valid =
    candidate.signingPurpose === "genesis_device_bootstrap"
      ? verifyGenesisDeviceBootstrapSignature(verificationParams)
      : candidate.signingPurpose === "device_approval"
        ? verifyDeviceApprovalSignature(verificationParams)
        : verifyRecoveryDeviceApprovalSignature(verificationParams);

  return { valid };
}

export function handleVerifyKeyDirectoryCheckpointSignature(
  _state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const publicKeyMaterial = p.publicKeyMaterial as HybridSigningPublicKeyMaterial;

  return {
    valid: verifyKeyDirectoryCheckpointSignature({
      publicKeyMaterial,
      signature: p.signature as never,
      transcript: buildKeyDirectoryCheckpointTranscript({
        variant: p.variant as never,
        ownerKind: publicKeyMaterial.owner_kind,
        ownerId: publicKeyMaterial.owner_id,
        checkpointPayload: p.checkpointPayload as StrictJsonValue,
        signer: p.signer as StrictJsonValue,
      }),
    }),
  };
}

export function handleVerifyKeyDirectoryEventSignature(
  _state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const publicKeyMaterial = p.publicKeyMaterial as HybridSigningPublicKeyMaterial;

  return {
    valid: verifyKeyDirectoryEventSignature({
      publicKeyMaterial,
      signature: p.signature as never,
      transcript: buildKeyDirectoryEventTranscript({
        eventType: p.eventType as never,
        ownerKind: publicKeyMaterial.owner_kind,
        ownerId: publicKeyMaterial.owner_id,
        eventPayload: p.eventPayload as StrictJsonValue,
      }),
    }),
  };
}

export function handleVerifyWorkspacePinBootstrapSignature(
  _state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const publicKeyMaterial = p.publicKeyMaterial as HybridSigningPublicKeyMaterial;
  const bootstrapPayload = p.bootstrapPayload as StrictJsonValue;

  return {
    valid: verifyWorkspacePinBootstrapSignature({
      publicKeyMaterial,
      signature: p.signature as never,
      transcript: buildWorkspacePinBootstrapTranscript({
        ownerDeviceId: publicKeyMaterial.owner_id,
        workspaceId: p.workspaceId as string,
        bootstrap: bootstrapPayload,
      }),
    }),
  };
}

export function handleVerifyDocumentUpdateSignature(
  _state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const publicKeyMaterial = p.publicKeyMaterial as HybridSigningPublicKeyMaterial;
  const publicData = p.publicData as Record<string, unknown>;
  validatePublicDataOwner(publicKeyMaterial, publicData);

  return {
    valid: verifyDocumentUpdateSignature({
      publicKeyMaterial,
      signature: p.signature as never,
      transcript: buildDocumentUpdateTranscript({
        ownerKind: publicKeyMaterial.owner_kind,
        ownerId: publicKeyMaterial.owner_id,
        actorUserId: p.actorUserId as string,
        actorDeviceId: publicData.ownerId as string,
        signingKeyId: publicData.signingKeyId as string,
        workspaceId: p.workspaceId as string,
        publicData,
        authorityBoundary: p.authorityBoundary as Record<string, unknown>,
        ciphertext: p.ciphertext as string,
        nonce: p.nonce as string,
      }),
    }),
  };
}

export function handleVerifyDocumentUpdateEd25519Signature(
  _state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const publicKeyMaterial = p.publicKeyMaterial as HybridSigningPublicKeyMaterial;
  const publicData = p.publicData as Record<string, unknown>;
  validatePublicDataOwner(publicKeyMaterial, publicData);

  return verifyDocumentUpdateEd25519SignatureAsync({
    publicKeyMaterial,
    signature: p.signature as never,
    transcript: buildDocumentUpdateTranscript({
      ownerKind: publicKeyMaterial.owner_kind,
      ownerId: publicKeyMaterial.owner_id,
      actorUserId: p.actorUserId as string,
      actorDeviceId: publicData.ownerId as string,
      signingKeyId: publicData.signingKeyId as string,
      workspaceId: p.workspaceId as string,
      publicData,
      authorityBoundary: p.authorityBoundary as Record<string, unknown>,
      ciphertext: p.ciphertext as string,
      nonce: p.nonce as string,
    }),
  }).then((valid) => ({ valid }));
}

export function handleVerifyDocumentSnapshotSignature(
  _state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const publicKeyMaterial = p.publicKeyMaterial as HybridSigningPublicKeyMaterial;
  const publicData = p.publicData as Record<string, unknown>;
  validatePublicDataOwner(publicKeyMaterial, publicData);

  return {
    valid: verifyDocumentSnapshotSignature({
      publicKeyMaterial,
      signature: p.signature as never,
      transcript: buildDocumentSnapshotTranscript({
        ownerKind: publicKeyMaterial.owner_kind,
        ownerId: publicKeyMaterial.owner_id,
        actorUserId: p.actorUserId as string,
        actorDeviceId: publicData.ownerId as string,
        signingKeyId: publicData.signingKeyId as string,
        workspaceId: p.workspaceId as string,
        publicData,
        authorityBoundary: p.authorityBoundary as Record<string, unknown>,
        ciphertext: p.ciphertext as string,
        nonce: p.nonce as string,
      }),
    }),
  };
}

export function handleVerifyEditorEphemeralSignature(
  _state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const publicKeyMaterial = p.publicKeyMaterial as HybridSigningPublicKeyMaterial;
  const publicData = p.publicData as Record<string, unknown>;
  validatePublicDataOwner(publicKeyMaterial, publicData);

  return {
    valid: verifyEditorEphemeralSignature({
      publicKeyMaterial,
      signature: p.signature as never,
      transcript: buildEditorEphemeralTranscript({
        ownerKind: publicKeyMaterial.owner_kind,
        ownerId: publicKeyMaterial.owner_id,
        actorUserId: p.actorUserId as string,
        actorDeviceId: publicData.ownerId as string,
        signingKeyId: publicData.signingKeyId as string,
        workspaceId: p.workspaceId as string,
        publicData,
        authorityBoundary: p.authorityBoundary as Record<string, unknown>,
        ciphertext: p.ciphertext as string,
        nonce: p.nonce as string,
      }),
    }),
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validatePublicDataOwner(
  publicKeyMaterial: HybridSigningPublicKeyMaterial,
  publicData: Record<string, unknown>,
): void {
  if (publicData.ownerKind !== publicKeyMaterial.owner_kind) {
    throw new Error("document_signature_owner_kind_mismatch");
  }
  if (publicData.ownerId !== publicKeyMaterial.owner_id) {
    throw new Error("document_signature_owner_id_mismatch");
  }
}

function strictJsonEqual(left: unknown, right: StrictJsonValue): boolean {
  try {
    return canonicalizeStrict(left as StrictJsonValue) === canonicalizeStrict(right);
  } catch {
    return false;
  }
}

function requireDevicePublicMaterial(state: WorkerKeyState): HybridSigningPublicKeyMaterial {
  return requireDeviceHybridSigningPublicKeyMaterial(state);
}

function requireDeviceHybridEncryptionPublicMaterial(
  state: WorkerKeyState,
): HybridEncryptionPublicKeyMaterial {
  if (!state.deviceHybridEncryptionPublicKeyMaterial) {
    throw new Error("device_hybrid_encryption_public_key_material_not_available");
  }
  return state.deviceHybridEncryptionPublicKeyMaterial;
}

function keyDirectorySigner(
  ownerKind: "identity" | "device" | "share_participant_device",
  state: WorkerKeyState,
  signingKeyId: string,
  shareId?: unknown,
): Record<string, string> {
  const userId = requireUserId(state);

  if (ownerKind === "identity") {
    return {
      signer_kind: "identity",
      user_id: userId,
      signing_key_id: signingKeyId,
    };
  }

  if (ownerKind === "share_participant_device") {
    if (typeof shareId !== "string" || shareId.length === 0) {
      throw new Error("share_participant_key_directory_share_id_required");
    }
    return {
      signer_kind: "share_participant_device",
      share_id: shareId,
      share_participant_principal_id: userId,
      share_participant_device_id: requireDeviceId(state),
      signing_key_id: signingKeyId,
    };
  }

  return {
    signer_kind: "device",
    user_id: userId,
    device_id: requireDeviceId(state),
    signing_key_id: signingKeyId,
  };
}

function keyDirectoryCheckpointSignerAuthority<T extends Record<string, unknown>>(
  signer: T,
  checkpointPayload: Record<string, unknown>,
): T & {
  authorizing_checkpoint_sequence?: number;
  authorizing_checkpoint_hash?: string;
} {
  const sequence = checkpointPayload.sequence;
  if (sequence === 1) return signer;
  if (typeof sequence !== "number" || !Number.isInteger(sequence) || sequence < 2) {
    throw new Error("key_directory_checkpoint_sequence_invalid");
  }

  const previousCheckpointHash = checkpointPayload.previous_checkpoint_hash;
  if (typeof previousCheckpointHash !== "string" || previousCheckpointHash.length === 0) {
    throw new Error("key_directory_previous_checkpoint_hash_required");
  }

  return {
    ...signer,
    authorizing_checkpoint_sequence: sequence - 1,
    authorizing_checkpoint_hash: previousCheckpointHash,
  };
}

function keyDirectoryEventSignerAuthority<T extends Record<string, unknown>>(
  signer: T,
  eventPayload: Record<string, unknown>,
): T {
  const actor = eventPayload.actor;
  const sequence = eventPayload.sequence;
  if (!isRecord(actor) || sequence === 1) return signer;

  const authorityKeys = [
    "key_scope_kind",
    "key_scope_id",
    "key_checkpoint_sequence",
    "key_checkpoint_hash",
    "authorizing_checkpoint_sequence",
    "authorizing_checkpoint_hash",
    "role_at_event",
  ] as const;
  const authority: Record<string, unknown> = {};
  for (const key of authorityKeys) {
    if (Object.prototype.hasOwnProperty.call(actor, key)) authority[key] = actor[key];
  }
  return { ...signer, ...authority };
}

export function handleBlake3Hash(p: HandlerPayload): unknown {
  const data = p.data as Uint8Array;
  return blake3(data);
}

export function handleComputeSas(p: HandlerPayload): unknown {
  const identityHybridSigningPublicKeyMaterial =
    p.identityHybridSigningPublicKeyMaterial as HybridSigningPublicKeyMaterial;
  const deviceHybridSigningPublicKeyMaterial =
    p.deviceHybridSigningPublicKeyMaterial as HybridSigningPublicKeyMaterial;
  const deviceHybridEncryptionPublicKeyMaterial =
    p.deviceHybridEncryptionPublicKeyMaterial as HybridEncryptionPublicKeyMaterial;
  const clientNonce = p.clientNonce as Uint8Array;

  const result = computeSas(
    p.deviceId as string,
    identityHybridSigningPublicKeyMaterial,
    deviceHybridSigningPublicKeyMaterial,
    deviceHybridEncryptionPublicKeyMaterial,
    clientNonce,
  );
  return {
    emojis: result.emojis.map((emoji) => ({ emoji, name: "" })),
    hash: result.hash,
  };
}

export function handleCalculateFingerprint(p: HandlerPayload): unknown {
  const publicKeyMaterial = p.publicKeyMaterial as HybridSigningPublicKeyMaterial;
  const ed25519Public = base64UrlDecode(publicKeyMaterial.ed25519_public);
  const raw = calculateFingerprint(ed25519Public);
  return { fingerprint: formatFingerprint(raw) };
}
