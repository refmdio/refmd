import { workerSend, type CryptoWorkerClientMethodContext } from "./shared";
import type { SignedPqWrapRecord } from "../../signed-pq-wrap";
import type { HybridEncryptionPublicKeyMaterial } from "../../hybrid-encryption";
import type { HybridSigningPublicKeyMaterial } from "../../signature";
import type {
  InitialAkeArtifact,
  InitialAkeResponderPrekeyRecord,
  InitialKeyDeliveryRecord,
} from "../../initial-ake";

export interface KekWorkerClientMethods {
  generateKek(workspaceId: string, keyVersion?: number): Promise<{ keyVersion: number }>;
  setActiveKekVersion(workspaceId: string, keyVersion: number): Promise<void>;
  resolveKek(
    workspaceId: string,
    keyVersion?: number,
  ): Promise<{ found: boolean; keyVersion?: number }>;
  createSignedPqKekWrap(params: {
    purpose?:
      | "workspace_device_kek_wrap"
      | "workspace_member_kek_wrap"
      | "share_participant_bootstrap_wrap"
      | "share_link_secret_backup_wrap"
      | "workspace_invitation_kek_wrap"
      | "guest_invitation_workspace_kek_wrap"
      | "guest_invitation_share_key_wrap";
    workspaceId: string;
    keyVersion: number;
    recipientPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
    senderUserId: string;
    senderDeviceId: string;
    resource: Record<string, unknown>;
    eventScope: Record<string, unknown>;
    operationCheckpoint: {
      sequence: number;
      checkpointHash: string;
      coveredHeadSequence: number;
      coveredHeadHash: string;
    };
  }): Promise<SignedPqWrapRecord>;
  finalizeSignedPqWrapOperationCheckpoint(params: {
    record: SignedPqWrapRecord;
    operationCheckpoint: {
      sequence: number;
      checkpointHash: string;
      coveredHeadSequence: number;
      coveredHeadHash: string;
    };
  }): Promise<SignedPqWrapRecord>;
  createSignedPqShareLinkSecretBackupWrap(params: {
    workspaceId: string;
    shareId: string;
    shareSlug: string;
    tokenHash: string;
    scopeKind: string;
    scopeId: string;
    permission: string;
    passwordProtected: boolean;
    createdEventHash: string;
    shareCapabilitySecretCommitment: string;
    passwordCapabilitySecretCommitment: string;
    workspacePinBootstrapHash: string;
    recipientPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
    senderUserId: string;
    senderDeviceId: string;
    resource: Record<string, unknown>;
    eventScope: Record<string, unknown>;
    operationCheckpoint: {
      sequence: number;
      checkpointHash: string;
      coveredHeadSequence: number;
      coveredHeadHash: string;
    };
  }): Promise<SignedPqWrapRecord>;
  openSignedPqDeviceKekWrap(params: {
    record: SignedPqWrapRecord;
    senderSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
    expectedOperationCheckpoint: {
      sequence: number;
      checkpointHash: string;
    };
  }): Promise<void>;
  openSignedPqMemberKekWrap(params: {
    record: SignedPqWrapRecord;
    senderSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
    expectedOperationCheckpoint: {
      sequence: number;
      checkpointHash: string;
    };
  }): Promise<void>;
  openSignedPqShareLinkSecretBackupWrap(params: {
    record: SignedPqWrapRecord;
    senderSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
    expectedShareId: string;
    expectedOperationCheckpoint: {
      sequence: number;
      checkpointHash: string;
    };
  }): Promise<{ sharePathWithFragment: string }>;
  generateInitialAkeResponderPrekey(params: {
    operationId: string;
    userId: string;
    deviceId: string;
    purpose: "umk_distribution" | "device_approval_kek_initial" | "trust_transfer";
    serverChallenge?: string;
    issuedAtEventSequence: number;
    expiresEventSequence: number;
  }): Promise<InitialAkeResponderPrekeyRecord>;
  createInitialAkeUmkDelivery(params: {
    userId: string;
    senderDeviceId: string;
    recipientDeviceId: string;
    recipientEncryptionKeyId: string;
    responderPrekey: InitialAkeResponderPrekeyRecord;
    responderSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
    resourceHash: string;
    keyCheckpointHash: string;
    keyEventHeadHash: string;
    pendingRegistrationBindingHash: string;
  }): Promise<{
    initialAke: InitialAkeArtifact;
    initialKeyDelivery: InitialKeyDeliveryRecord;
  }>;
  createInitialAkeKekDelivery(params: {
    workspaceId: string;
    keyVersion: number;
    userId: string;
    senderDeviceId: string;
    recipientDeviceId: string;
    recipientEncryptionKeyId: string;
    responderPrekey: InitialAkeResponderPrekeyRecord;
    responderSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
    resourceHash: string;
    keyCheckpointHash: string;
    keyEventHeadHash: string;
    userCheckpointHash: string;
    workspaceCheckpointHash: string;
    workspaceEventHeadHash: string;
    pendingRegistrationBindingHash: string;
  }): Promise<{
    initialAke: InitialAkeArtifact;
    initialKeyDelivery: InitialKeyDeliveryRecord;
  }>;
  createInitialAkeDeviceStateTransferDelivery(params: {
    deviceStateBundle: Record<string, unknown>;
    userId: string;
    senderDeviceId: string;
    recipientDeviceId: string;
    recipientEncryptionKeyId: string;
    responderPrekey: InitialAkeResponderPrekeyRecord;
    responderSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
    resourceHash: string;
    keyCheckpointHash: string;
    keyEventHeadHash: string;
    workspacePinsHash: string;
    documentRollbackPinSetHash: string;
    pendingRegistrationBindingHash: string;
  }): Promise<{
    initialAke: InitialAkeArtifact;
    initialKeyDelivery: InitialKeyDeliveryRecord;
  }>;
  openInitialAkeUmkDelivery(params: {
    initialAke: InitialAkeArtifact;
    initialKeyDelivery: InitialKeyDeliveryRecord;
    senderSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  }): Promise<void>;
  openInitialAkeKekDelivery(params: {
    initialAke: InitialAkeArtifact;
    initialKeyDelivery: InitialKeyDeliveryRecord;
    senderSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  }): Promise<void>;
  openInitialAkeDeviceStateTransferDelivery(params: {
    initialAke: InitialAkeArtifact;
    initialKeyDelivery: InitialKeyDeliveryRecord;
    senderSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  }): Promise<Record<string, unknown>>;
  wrapKekForInvitationBootstrap(params: {
    protocol: "refmd.workspace-invitation-bootstrap" | "refmd.guest-invitation-bootstrap";
    workspaceId: string;
    keyVersion: number;
    bootstrapSecret: string;
    aad: Record<string, unknown>;
    plaintext: Record<string, unknown>;
    redeemAuthorityInvitationId?: string;
    includeWorkspaceKek?: boolean;
    maintenanceWrapKey?: Uint8Array;
  }): Promise<Record<string, unknown>>;
  unwrapKekFromInvitationBootstrap(params: {
    bootstrap: Record<string, unknown>;
    bootstrapSecret: string;
  }): Promise<Record<string, unknown>>;
  cacheKek(params: { workspaceId: string; kek: Uint8Array; keyVersion: number }): Promise<void>;
  storeKekForOffline(params: { workspaceId: string; keyVersion: number }): Promise<void>;
  restoreKekFromOffline(params: {
    workspaceId: string;
    keyVersion?: number;
    isActive?: boolean;
  }): Promise<{ restored: boolean; keyVersion?: number; cachedAt?: number }>;
  loadOfflineKekMetadata(workspaceId: string): Promise<{
    workspaceId: string;
    keyVersion: number;
    cachedAt: number;
  } | null>;
  deleteKekForOffline(workspaceId: string): Promise<void>;
  deleteOrphanedKeksForOffline(activeWorkspaceIds: Iterable<string>): Promise<void>;
}

export const kekWorkerClientMethods: KekWorkerClientMethods &
  ThisType<CryptoWorkerClientMethodContext> = {
  async generateKek(workspaceId, keyVersion) {
    return (await this[workerSend]("generate-kek", { workspaceId, keyVersion })) as {
      keyVersion: number;
    };
  },

  async setActiveKekVersion(workspaceId, keyVersion) {
    await this[workerSend]("set-active-kek-version", { workspaceId, keyVersion });
  },

  async resolveKek(workspaceId, keyVersion) {
    return (await this[workerSend]("resolve-kek", { workspaceId, keyVersion })) as {
      found: boolean;
      keyVersion?: number;
    };
  },

  async createSignedPqKekWrap(params) {
    return (await this[workerSend]("create-signed-pq-kek-wrap", params)) as SignedPqWrapRecord;
  },

  async createSignedPqShareLinkSecretBackupWrap(params) {
    return (await this[workerSend](
      "create-signed-pq-share-link-secret-backup-wrap",
      params,
    )) as SignedPqWrapRecord;
  },

  async finalizeSignedPqWrapOperationCheckpoint(params) {
    return (await this[workerSend](
      "finalize-signed-pq-wrap-operation-checkpoint",
      params,
    )) as SignedPqWrapRecord;
  },

  async openSignedPqDeviceKekWrap(params) {
    await this[workerSend]("open-signed-pq-device-kek-wrap", params);
  },

  async openSignedPqMemberKekWrap(params) {
    await this[workerSend]("open-signed-pq-member-kek-wrap", params);
  },

  async openSignedPqShareLinkSecretBackupWrap(params) {
    return (await this[workerSend]("open-signed-pq-share-link-secret-backup-wrap", params)) as {
      sharePathWithFragment: string;
    };
  },

  async generateInitialAkeResponderPrekey(params) {
    return (await this[workerSend](
      "generate-initial-ake-responder-prekey",
      params,
    )) as InitialAkeResponderPrekeyRecord;
  },

  async createInitialAkeUmkDelivery(params) {
    return (await this[workerSend]("create-initial-ake-umk-delivery", params)) as {
      initialAke: InitialAkeArtifact;
      initialKeyDelivery: InitialKeyDeliveryRecord;
    };
  },

  async createInitialAkeKekDelivery(params) {
    return (await this[workerSend]("create-initial-ake-kek-delivery", params)) as {
      initialAke: InitialAkeArtifact;
      initialKeyDelivery: InitialKeyDeliveryRecord;
    };
  },

  async createInitialAkeDeviceStateTransferDelivery(params) {
    return (await this[workerSend](
      "create-initial-ake-device-state-transfer-delivery",
      params,
    )) as {
      initialAke: InitialAkeArtifact;
      initialKeyDelivery: InitialKeyDeliveryRecord;
    };
  },

  async openInitialAkeUmkDelivery(params) {
    await this[workerSend]("open-initial-ake-umk-delivery", params);
  },

  async openInitialAkeKekDelivery(params) {
    await this[workerSend]("open-initial-ake-kek-delivery", params);
  },

  async openInitialAkeDeviceStateTransferDelivery(params) {
    return (await this[workerSend](
      "open-initial-ake-device-state-transfer-delivery",
      params,
    )) as Record<string, unknown>;
  },

  async wrapKekForInvitationBootstrap(params) {
    return (await this[workerSend]("wrap-kek-for-invitation-bootstrap", params)) as Record<
      string,
      unknown
    >;
  },

  async unwrapKekFromInvitationBootstrap(params) {
    return (await this[workerSend]("unwrap-kek-from-invitation-bootstrap", params)) as Record<
      string,
      unknown
    >;
  },

  async cacheKek(params) {
    await this[workerSend]("cache-kek", params);
  },

  async storeKekForOffline(params) {
    await this[workerSend]("store-kek-for-offline", params);
  },

  async restoreKekFromOffline(params) {
    return (await this[workerSend]("restore-kek-from-offline", params)) as {
      restored: boolean;
      keyVersion?: number;
      cachedAt?: number;
    };
  },

  async loadOfflineKekMetadata(workspaceId) {
    const result = (await this[workerSend]("load-offline-kek-metadata", { workspaceId })) as {
      metadata: { workspaceId: string; keyVersion: number; cachedAt: number } | null;
    };
    return result.metadata;
  },

  async deleteKekForOffline(workspaceId) {
    await this[workerSend]("delete-kek-for-offline", { workspaceId });
  },

  async deleteOrphanedKeksForOffline(activeWorkspaceIds) {
    await this[workerSend]("delete-orphaned-keks-for-offline", {
      activeWorkspaceIds: [...activeWorkspaceIds],
    });
  },
};
