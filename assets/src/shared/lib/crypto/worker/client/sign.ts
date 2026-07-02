import type { SasResultData } from "../types";
import { workerSend, type CryptoWorkerClientMethodContext } from "./shared";
import type { HybridEncryptionPublicKeyMaterial } from "../../hybrid-encryption";
import type { HybridSignature, HybridSigningPublicKeyMaterial } from "../../signature";
import type { StrictJsonValue } from "../../jcs";

export interface SignedSurfaceArtifact extends Record<string, unknown> {
  transcript: StrictJsonValue;
  signature: HybridSignature;
  signing_key_id: string;
  hybrid_signing_public_key_material: HybridSigningPublicKeyMaterial;
}

interface VerifyDeviceApprovalSurfaceParams {
  deviceId: string;
  deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  deviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  deviceEcdhPublic: Uint8Array;
  clientNonce: Uint8Array;
  identitySignature: unknown;
  identitySignatureContext: Record<string, unknown>;
  identityHybridSigningPublicKeyMaterial?: HybridSigningPublicKeyMaterial;
  approvalHybridSigningPublicKeyMaterial?: HybridSigningPublicKeyMaterial;
  approvalDeliveryCommitments?: Record<string, unknown> | null;
  approvalDeliveryArtifacts?: Record<string, unknown> | null;
}

type KeyDirectoryCheckpointVariant =
  | "identity_initial"
  | "workspace_initial"
  | "identity_active"
  | "identity_rotation"
  | "workspace_authorized"
  | "invitation_redeem_authority"
  | "share_participant_document_operation"
  | "device_authorized";

interface KeyDirectorySignedArtifact {
  signer: Record<string, string>;
  transcript: StrictJsonValue;
  signature: HybridSignature;
  signing_key_id: string;
  hybrid_signing_public_key_material: HybridSigningPublicKeyMaterial;
}

interface KeyDirectoryEventSignParams {
  eventType: string;
  eventPayload: Record<string, unknown>;
  shareId?: string;
}

interface KeyDirectoryCheckpointSignParams {
  variant: KeyDirectoryCheckpointVariant;
  checkpointPayload: Record<string, unknown>;
  shareId?: string;
}

export interface SignWorkerClientMethods {
  createPopSignature(params: {
    challenge: string;
    deviceId: string;
    scope?: "user" | "share";
    transport?: "http" | "phoenix_channel";
    actor: Record<string, StrictJsonValue>;
    session: Record<string, StrictJsonValue>;
    resource?: Record<string, unknown>;
  }): Promise<SignedSurfaceArtifact>;
  signDocumentUpdate(params: {
    ciphertext: string;
    nonce: string;
    workspaceId: string;
    publicData: object;
    authorityBoundary: Record<string, unknown>;
  }): Promise<SignedSurfaceArtifact>;
  signDocumentSnapshot(params: {
    ciphertext: string;
    nonce: string;
    workspaceId: string;
    publicData: object;
    authorityBoundary: Record<string, unknown>;
  }): Promise<SignedSurfaceArtifact>;
  signEditorEphemeral(params: {
    ciphertext: string;
    nonce: string;
    workspaceId: string;
    publicData: object;
    authorityBoundary: Record<string, unknown>;
  }): Promise<SignedSurfaceArtifact>;
  createDeviceApprovalSignature(params: {
    approverDeviceId: string;
    deviceId: string;
    deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
    deviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
    deviceEcdhPublic: Uint8Array;
    clientNonce: Uint8Array;
    approvedDeviceRegistrationSasHash: string;
    pendingRegistrationId: string;
    pendingRegistrationChallengeHash: string;
    approvingSigningKeyId: string;
    approvingKeyCheckpointSequence: number;
    approvingKeyCheckpointHash: string;
    approvingDeviceKeyDirectoryProofHash: string;
    targetDeviceSigningKeyId: string;
    targetDeviceHybridSigningPublicKeyMaterialHash: string;
    targetDeviceHybridEncryptionPublicKeyMaterialHash: string;
    targetDeviceEncryptionKeyId: string;
    targetDeviceClientNonceHash: string;
    targetKeyCheckpointSequence: number;
    targetKeyCheckpointHash: string;
    umkDistributionDeliveryCommitment: Record<string, unknown>;
    trustTransferDeliveryCommitment: Record<string, unknown>;
    deviceApprovalKekInitialDeliveryCommitments: Record<string, unknown>[];
  }): Promise<SignedSurfaceArtifact>;
  createGenesisDeviceBootstrapSignature(params: {
    deviceEcdhPublic: Uint8Array;
    clientNonce: Uint8Array;
    registrationChallengeHash: string;
    identitySigningKeyId: string;
    userIdentityPublicKeyHash: string;
  }): Promise<SignedSurfaceArtifact>;
  createRecoveryDeviceApprovalSignature(params: {
    deviceEcdhPublic: Uint8Array;
    clientNonce: Uint8Array;
    recoverySessionTranscriptHash: string;
    recoveryCapabilityHash: string;
    pendingRegistrationId: string;
    pendingRegistrationChallengeHash: string;
    pendingRegistrationBindingHash: string;
    approvingKeyCheckpointSequence: number;
    approvingKeyCheckpointHash: string;
    targetKeyCheckpointSequence: number;
    targetKeyCheckpointHash: string;
  }): Promise<SignedSurfaceArtifact>;
  createDeviceRevocationSignature(params: {
    revokedDeviceId: string;
    revocationMode: "security" | "retire";
    revokedAtMs: number;
  }): Promise<SignedSurfaceArtifact>;
  signDeviceKeyDeletionProof(params: {
    payload: Record<string, unknown>;
    actor: Record<string, unknown>;
  }): Promise<
    {
      payload: Record<string, unknown>;
    } & SignedSurfaceArtifact
  >;
  signIdentityKeyDirectoryCheckpoint(
    params: KeyDirectoryCheckpointSignParams,
  ): Promise<KeyDirectorySignedArtifact>;
  signDeviceKeyDirectoryCheckpoint(
    params: KeyDirectoryCheckpointSignParams,
  ): Promise<KeyDirectorySignedArtifact>;
  signShareParticipantDeviceKeyDirectoryCheckpoint(
    params: KeyDirectoryCheckpointSignParams,
  ): Promise<KeyDirectorySignedArtifact>;
  generateInvitationRedeemAuthority(params: { invitationId: string }): Promise<{
    signer: Record<string, string>;
    hybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  }>;
  signInvitationRedeemKeyDirectoryCheckpoint(params: {
    invitationId: string;
    checkpointPayload: Record<string, unknown>;
  }): Promise<KeyDirectorySignedArtifact>;
  signInvitationRedeemKeyDirectoryEvent(params: {
    invitationId: string;
    eventType: string;
    eventPayload: Record<string, unknown>;
  }): Promise<KeyDirectorySignedArtifact>;
  signIdentityKeyDirectoryEvent(
    params: KeyDirectoryEventSignParams,
  ): Promise<KeyDirectorySignedArtifact>;
  signDeviceKeyDirectoryEvent(
    params: KeyDirectoryEventSignParams,
  ): Promise<KeyDirectorySignedArtifact>;
  signShareParticipantDeviceKeyDirectoryEvent(
    params: KeyDirectoryEventSignParams,
  ): Promise<KeyDirectorySignedArtifact>;
  signWorkspacePinBootstrap(params: {
    workspaceId: string;
    bootstrapPayload: Record<string, unknown>;
  }): Promise<KeyDirectorySignedArtifact>;
  signPluginConsentEvent(params: {
    consent: Record<string, StrictJsonValue>;
    keyCheckpointSequence: number;
    keyCheckpointHash: string;
  }): Promise<
    {
      actor: Record<string, StrictJsonValue>;
    } & SignedSurfaceArtifact
  >;
  signPluginBundleApproval(params: {
    actor: Record<string, StrictJsonValue>;
    approval: Record<string, StrictJsonValue>;
  }): Promise<
    {
      actor: Record<string, StrictJsonValue>;
    } & SignedSurfaceArtifact
  >;
  signPluginNetworkProxyRequest(params: {
    subject: Record<string, StrictJsonValue>;
  }): Promise<SignedSurfaceArtifact>;
  signRecipientBoundAuthorization(params: {
    authorizationPayload: Record<string, unknown>;
  }): Promise<{
    transcript: StrictJsonValue;
    signature: HybridSignature;
    signing_key_id: string;
    hybrid_signing_public_key_material: HybridSigningPublicKeyMaterial;
  }>;
  signRecoverySession(params: {
    recoverySessionId: string;
    serverChallengeHash: string;
    recipientDeviceId: string;
    pendingRegistrationId: string;
    pendingRegistrationBindingHash: string;
    candidateUserCheckpointSequence: number;
    candidateUserCheckpointHash: string;
    candidateUserEventHeadSequence: number;
    candidateUserEventHeadHash: string;
  }): Promise<{
    transcript: StrictJsonValue;
    signature: HybridSignature;
    signing_key_id: string;
    hybrid_signing_public_key_material: HybridSigningPublicKeyMaterial;
    recoveryAuthorizationKeyId: string;
    recoveryAuthorizationProof: HybridSignature;
    recoveryCapabilityHash: string;
    recoverySessionTranscriptHash: string;
  }>;
  signShareCapabilityAuthorization(params: {
    shareSlug: string;
    shareTokenHash: string;
    workspacePinBootstrapHash: string;
    shareId: string;
    scopeKind: "document" | "folder";
    scopeId: string;
    permission: "view" | "edit";
    passwordProtected: boolean;
    createdEventHash: string;
    latestBootstrapEventHash: string;
    capabilityContextHash: string;
    shareCapabilitySecretCommitment: string;
    passwordCapabilitySecretCommitment: string;
  }): Promise<SignedSurfaceArtifact>;
  signShareParticipantDeviceAuthorization(params: {
    shareId: string;
    shareSessionId: string;
    shareParticipantPrincipalId: string;
    capabilityContextHash: string;
    shareCreatedEventHash: string;
    latestBootstrapEventHash: string;
    scopeKind: "document" | "folder";
    scopeId: string;
    permission: "view" | "edit";
  }): Promise<SignedSurfaceArtifact>;
  createEditorEphemeralSessionProof(params: {
    ownerKind: "device" | "share_participant_device";
    workspaceId: string;
    documentId: string;
    channelId: string;
    sessionId: string;
    proofDirection: string;
    proofType: string;
    sessionNonce: string;
    counter: number;
    expiresEventSequence: number;
    keyCheckpointSequence: number;
    keyCheckpointHash: string;
    authorityBoundary: Record<string, unknown>;
  }): Promise<SignedSurfaceArtifact>;
  verifyEditorEphemeralSessionProof(params: {
    workspaceId: string;
    documentId: string;
    channelId: string;
    sessionId: string;
    proofDirection: string;
    proofType: string;
    sessionNonce: string;
    counter: number;
    expiresEventSequence: number;
    keyCheckpointSequence: number;
    keyCheckpointHash: string;
    authorityBoundary: Record<string, unknown>;
    signature: HybridSignature;
    publicKeyMaterial: HybridSigningPublicKeyMaterial;
    actorUserId: string;
  }): Promise<boolean>;
  verifyGenesisDeviceBootstrapSignature(
    params: VerifyDeviceApprovalSurfaceParams,
  ): Promise<boolean>;
  verifyDeviceApprovalSignature(params: VerifyDeviceApprovalSurfaceParams): Promise<boolean>;
  verifyRecoveryDeviceApprovalSignature(
    params: VerifyDeviceApprovalSurfaceParams,
  ): Promise<boolean>;
  verifyKeyDirectoryCheckpointSignature(params: {
    variant: Parameters<
      typeof import("../../signature").buildKeyDirectoryCheckpointTranscript
    >[0]["variant"];
    checkpointPayload: StrictJsonValue;
    signature: HybridSignature;
    publicKeyMaterial: HybridSigningPublicKeyMaterial;
    signer: StrictJsonValue;
  }): Promise<boolean>;
  verifyKeyDirectoryEventSignature(params: {
    eventType: Parameters<
      typeof import("../../signature").buildKeyDirectoryEventTranscript
    >[0]["eventType"];
    eventPayload: StrictJsonValue;
    signature: HybridSignature;
    publicKeyMaterial: HybridSigningPublicKeyMaterial;
  }): Promise<boolean>;
  verifyWorkspacePinBootstrapSignature(params: {
    workspaceId: string;
    bootstrapPayload: StrictJsonValue;
    signature: HybridSignature;
    publicKeyMaterial: HybridSigningPublicKeyMaterial;
  }): Promise<boolean>;
  verifyDocumentUpdateSignature(params: {
    publicKeyMaterial: HybridSigningPublicKeyMaterial;
    signature: HybridSignature;
    actorUserId: string;
    workspaceId: string;
    publicData: object;
    authorityBoundary: Record<string, unknown>;
    ciphertext: string;
    nonce: string;
  }): Promise<boolean>;
  verifyDocumentUpdateEd25519Signature(params: {
    publicKeyMaterial: HybridSigningPublicKeyMaterial;
    signature: HybridSignature;
    actorUserId: string;
    workspaceId: string;
    publicData: object;
    authorityBoundary: Record<string, unknown>;
    ciphertext: string;
    nonce: string;
  }): Promise<boolean>;
  verifyDocumentSnapshotSignature(params: {
    publicKeyMaterial: HybridSigningPublicKeyMaterial;
    signature: HybridSignature;
    actorUserId: string;
    workspaceId: string;
    publicData: object;
    authorityBoundary: Record<string, unknown>;
    ciphertext: string;
    nonce: string;
  }): Promise<boolean>;
  verifyEditorEphemeralSignature(params: {
    publicKeyMaterial: HybridSigningPublicKeyMaterial;
    signature: HybridSignature;
    actorUserId: string;
    workspaceId: string;
    publicData: object;
    authorityBoundary: Record<string, unknown>;
    ciphertext: string;
    nonce: string;
  }): Promise<boolean>;
  computeUpdateHash(params: object): Promise<string>;
  blake3Hash(data: Uint8Array): Promise<Uint8Array>;
  computeSas(params: {
    deviceId: string;
    identityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
    deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
    deviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
    clientNonce: Uint8Array;
  }): Promise<SasResultData>;
  calculateFingerprint(publicKeyMaterial: HybridSigningPublicKeyMaterial): Promise<string>;
}

export const signWorkerClientMethods: SignWorkerClientMethods &
  ThisType<CryptoWorkerClientMethodContext> = {
  async createPopSignature(params) {
    return (await this[workerSend]("create-pop-signature", params)) as SignedSurfaceArtifact;
  },

  async signDocumentUpdate(params) {
    return (await this[workerSend]("sign-document-update", params)) as SignedSurfaceArtifact;
  },

  async signDocumentSnapshot(params) {
    return (await this[workerSend]("sign-document-snapshot", params)) as SignedSurfaceArtifact;
  },

  async signEditorEphemeral(params) {
    return (await this[workerSend]("sign-editor-ephemeral", params)) as SignedSurfaceArtifact;
  },

  async createDeviceApprovalSignature(params) {
    return (await this[workerSend](
      "create-device-approval-signature",
      params,
    )) as SignedSurfaceArtifact;
  },

  async createGenesisDeviceBootstrapSignature(params) {
    return (await this[workerSend](
      "create-genesis-device-bootstrap-signature",
      params,
    )) as SignedSurfaceArtifact;
  },

  async createRecoveryDeviceApprovalSignature(params) {
    return (await this[workerSend](
      "create-recovery-device-approval-signature",
      params,
    )) as SignedSurfaceArtifact;
  },

  async createDeviceRevocationSignature(params) {
    return (await this[workerSend](
      "create-device-revocation-signature",
      params,
    )) as SignedSurfaceArtifact;
  },

  async signDeviceKeyDeletionProof(params) {
    return (await this[workerSend]("sign-device-key-deletion-proof", params)) as {
      payload: Record<string, unknown>;
    } & SignedSurfaceArtifact;
  },

  async signIdentityKeyDirectoryCheckpoint(params) {
    return (await this[workerSend]("sign-identity-key-directory-checkpoint", params)) as Awaited<
      ReturnType<SignWorkerClientMethods["signIdentityKeyDirectoryCheckpoint"]>
    >;
  },

  async signDeviceKeyDirectoryCheckpoint(params) {
    return (await this[workerSend]("sign-device-key-directory-checkpoint", params)) as Awaited<
      ReturnType<SignWorkerClientMethods["signDeviceKeyDirectoryCheckpoint"]>
    >;
  },

  async signShareParticipantDeviceKeyDirectoryCheckpoint(params) {
    return (await this[workerSend](
      "sign-share-participant-device-key-directory-checkpoint",
      params,
    )) as Awaited<
      ReturnType<SignWorkerClientMethods["signShareParticipantDeviceKeyDirectoryCheckpoint"]>
    >;
  },

  async generateInvitationRedeemAuthority(params) {
    return (await this[workerSend]("generate-invitation-redeem-authority", params)) as {
      signer: Record<string, string>;
      hybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
    };
  },

  async signInvitationRedeemKeyDirectoryCheckpoint(params) {
    return (await this[workerSend](
      "sign-invitation-redeem-key-directory-checkpoint",
      params,
    )) as Awaited<
      ReturnType<SignWorkerClientMethods["signInvitationRedeemKeyDirectoryCheckpoint"]>
    >;
  },

  async signInvitationRedeemKeyDirectoryEvent(params) {
    return (await this[workerSend](
      "sign-invitation-redeem-key-directory-event",
      params,
    )) as Awaited<ReturnType<SignWorkerClientMethods["signInvitationRedeemKeyDirectoryEvent"]>>;
  },

  async signIdentityKeyDirectoryEvent(params) {
    return (await this[workerSend]("sign-identity-key-directory-event", params)) as Awaited<
      ReturnType<SignWorkerClientMethods["signIdentityKeyDirectoryEvent"]>
    >;
  },

  async signDeviceKeyDirectoryEvent(params) {
    return (await this[workerSend]("sign-device-key-directory-event", params)) as Awaited<
      ReturnType<SignWorkerClientMethods["signDeviceKeyDirectoryEvent"]>
    >;
  },

  async signShareParticipantDeviceKeyDirectoryEvent(params) {
    return (await this[workerSend](
      "sign-share-participant-device-key-directory-event",
      params,
    )) as Awaited<
      ReturnType<SignWorkerClientMethods["signShareParticipantDeviceKeyDirectoryEvent"]>
    >;
  },

  async signWorkspacePinBootstrap(params) {
    return (await this[workerSend]("sign-workspace-pin-bootstrap", params)) as Awaited<
      ReturnType<SignWorkerClientMethods["signWorkspacePinBootstrap"]>
    >;
  },

  async signPluginConsentEvent(params) {
    return (await this[workerSend]("sign-plugin-consent-event", params)) as Awaited<
      ReturnType<SignWorkerClientMethods["signPluginConsentEvent"]>
    >;
  },

  async signPluginBundleApproval(params) {
    return (await this[workerSend]("sign-plugin-bundle-approval", params)) as Awaited<
      ReturnType<SignWorkerClientMethods["signPluginBundleApproval"]>
    >;
  },

  async signPluginNetworkProxyRequest(params) {
    return (await this[workerSend]("sign-plugin-network-proxy-request", params)) as Awaited<
      ReturnType<SignWorkerClientMethods["signPluginNetworkProxyRequest"]>
    >;
  },

  async signRecipientBoundAuthorization(params) {
    return (await this[workerSend]("sign-recipient-bound-authorization", params)) as Awaited<
      ReturnType<SignWorkerClientMethods["signRecipientBoundAuthorization"]>
    >;
  },

  async signRecoverySession(params) {
    return (await this[workerSend]("sign-recovery-session", params)) as Awaited<
      ReturnType<SignWorkerClientMethods["signRecoverySession"]>
    >;
  },

  async signShareCapabilityAuthorization(params) {
    return (await this[workerSend]("sign-share-capability-authorization", params)) as Awaited<
      ReturnType<SignWorkerClientMethods["signShareCapabilityAuthorization"]>
    >;
  },

  async signShareParticipantDeviceAuthorization(params) {
    return (await this[workerSend](
      "sign-share-participant-device-authorization",
      params,
    )) as SignedSurfaceArtifact;
  },

  async createEditorEphemeralSessionProof(params) {
    return (await this[workerSend](
      "create-editor-ephemeral-session-proof",
      params,
    )) as SignedSurfaceArtifact;
  },

  async verifyEditorEphemeralSessionProof(params) {
    const result = (await this[workerSend]("verify-editor-ephemeral-session-proof", params)) as {
      valid: boolean;
    };
    return result.valid;
  },

  async verifyGenesisDeviceBootstrapSignature(params) {
    const result = (await this[workerSend](
      "verify-genesis-device-bootstrap-signature",
      params,
    )) as {
      valid: boolean;
    };
    return result.valid;
  },

  async verifyDeviceApprovalSignature(params) {
    const result = (await this[workerSend]("verify-device-approval-signature", params)) as {
      valid: boolean;
    };
    return result.valid;
  },

  async verifyRecoveryDeviceApprovalSignature(params) {
    const result = (await this[workerSend](
      "verify-recovery-device-approval-signature",
      params,
    )) as {
      valid: boolean;
    };
    return result.valid;
  },

  async verifyKeyDirectoryCheckpointSignature(params) {
    const result = (await this[workerSend](
      "verify-key-directory-checkpoint-signature",
      params,
    )) as {
      valid: boolean;
    };
    return result.valid;
  },

  async verifyKeyDirectoryEventSignature(params) {
    const result = (await this[workerSend]("verify-key-directory-event-signature", params)) as {
      valid: boolean;
    };
    return result.valid;
  },

  async verifyWorkspacePinBootstrapSignature(params) {
    const result = (await this[workerSend]("verify-workspace-pin-bootstrap-signature", params)) as {
      valid: boolean;
    };
    return result.valid;
  },

  async verifyDocumentUpdateSignature(params) {
    const result = (await this[workerSend]("verify-document-update-signature", params)) as {
      valid: boolean;
    };
    return result.valid;
  },

  async verifyDocumentUpdateEd25519Signature(params) {
    const result = (await this[workerSend](
      "verify-document-update-ed25519-signature",
      params,
    )) as {
      valid: boolean;
    };
    return result.valid;
  },

  async verifyDocumentSnapshotSignature(params) {
    const result = (await this[workerSend]("verify-document-snapshot-signature", params)) as {
      valid: boolean;
    };
    return result.valid;
  },

  async verifyEditorEphemeralSignature(params) {
    const result = (await this[workerSend]("verify-editor-ephemeral-signature", params)) as {
      valid: boolean;
    };
    return result.valid;
  },

  async computeUpdateHash(params) {
    const result = (await this[workerSend]("compute-update-hash", params)) as { hash: string };
    return result.hash;
  },

  async blake3Hash(data) {
    return (await this[workerSend]("blake3-hash", { data })) as Uint8Array;
  },

  async computeSas(params) {
    return (await this[workerSend]("compute-sas", params)) as SasResultData;
  },

  async calculateFingerprint(publicKeyMaterial) {
    const result = (await this[workerSend]("calculate-fingerprint", {
      publicKeyMaterial,
    })) as {
      fingerprint: string;
    };
    return result.fingerprint;
  },
};
