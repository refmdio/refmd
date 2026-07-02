import type { DekWorkerClientMethods } from "./dek";
import { dekWorkerClientMethods } from "./dek";
import type { KekWorkerClientMethods } from "./kek";
import { kekWorkerClientMethods } from "./kek";
import type { KeyWorkerClientMethods } from "./keys";
import { keyWorkerClientMethods } from "./keys";
import type { LifecycleWorkerClientMethods } from "./lifecycle";
import { lifecycleWorkerClientMethods } from "./lifecycle";
import type { SignWorkerClientMethods } from "./sign";
import { signWorkerClientMethods } from "./sign";
import type { TofuWorkerClientMethods } from "./tofu";
import { tofuWorkerClientMethods } from "./tofu";
import { WorkerTransport } from "./worker-transport";
import { workerSend } from "./shared";
import type { CryptoRequestType } from "../types/request";

export { CryptoWorkerError, isTofuHardFail } from "./worker-errors";

export class CryptoWorkerClient {
  declare init: LifecycleWorkerClientMethods["init"];
  declare initFromPassword: LifecycleWorkerClientMethods["initFromPassword"];
  declare importIdentityKeysFromKeyRestore: LifecycleWorkerClientMethods["importIdentityKeysFromKeyRestore"];
  declare lock: LifecycleWorkerClientMethods["lock"];
  declare isReady: LifecycleWorkerClientMethods["isReady"];
  declare getPublicKeys: LifecycleWorkerClientMethods["getPublicKeys"];
  declare getDeviceId: LifecycleWorkerClientMethods["getDeviceId"];
  declare hasStoredDeviceKeys: LifecycleWorkerClientMethods["hasStoredDeviceKeys"];
  declare hasStoredDsk: LifecycleWorkerClientMethods["hasStoredDsk"];
  declare deleteWrappedUmkWithDsk: LifecycleWorkerClientMethods["deleteWrappedUmkWithDsk"];
  declare deleteAuthBootstrapWithDsk: LifecycleWorkerClientMethods["deleteAuthBootstrapWithDsk"];
  declare loadAuthBootstrap: LifecycleWorkerClientMethods["loadAuthBootstrap"];
  declare storeAuthBootstrap: LifecycleWorkerClientMethods["storeAuthBootstrap"];
  declare loadStoredDsk: LifecycleWorkerClientMethods["loadStoredDsk"];
  declare setUserContext: LifecycleWorkerClientMethods["setUserContext"];
  declare setInitialized: LifecycleWorkerClientMethods["setInitialized"];
  declare clearTransientKeys: LifecycleWorkerClientMethods["clearTransientKeys"];

  declare importIdentityKeys: KeyWorkerClientMethods["importIdentityKeys"];
  declare importUmk: KeyWorkerClientMethods["importUmk"];
  declare generateIdentityKeys: KeyWorkerClientMethods["generateIdentityKeys"];
  declare generateDeviceKeys: KeyWorkerClientMethods["generateDeviceKeys"];
  declare generateUmk: KeyWorkerClientMethods["generateUmk"];
  declare generateClientNonce: KeyWorkerClientMethods["generateClientNonce"];
  declare generateRecoveryKey: KeyWorkerClientMethods["generateRecoveryKey"];
  declare deriveAuthKeys: KeyWorkerClientMethods["deriveAuthKeys"];
  declare validateMnemonic: KeyWorkerClientMethods["validateMnemonic"];
  declare deriveRuk: KeyWorkerClientMethods["deriveRuk"];
  declare wrapUmkForServer: KeyWorkerClientMethods["wrapUmkForServer"];
  declare wrapUmkWithRuk: KeyWorkerClientMethods["wrapUmkWithRuk"];
  declare unwrapUmkWithRuk: KeyWorkerClientMethods["unwrapUmkWithRuk"];
  declare wrapIdentityKeysForServer: KeyWorkerClientMethods["wrapIdentityKeysForServer"];
  declare persistCurrentKeysWithDsk: KeyWorkerClientMethods["persistCurrentKeysWithDsk"];
  declare wrapDeviceKeysWithDsk: KeyWorkerClientMethods["wrapDeviceKeysWithDsk"];
  declare wrapOfflineDocumentTitleWithDsk: KeyWorkerClientMethods["wrapOfflineDocumentTitleWithDsk"];
  declare unwrapOfflineDocumentTitleWithDsk: KeyWorkerClientMethods["unwrapOfflineDocumentTitleWithDsk"];
  declare storeMountTrustAnchorWithDsk: KeyWorkerClientMethods["storeMountTrustAnchorWithDsk"];
  declare loadMountTrustAnchorWithDsk: KeyWorkerClientMethods["loadMountTrustAnchorWithDsk"];
  declare deleteMountTrustAnchorWithDsk: KeyWorkerClientMethods["deleteMountTrustAnchorWithDsk"];
  declare clearMountTrustAnchorsWithDsk: KeyWorkerClientMethods["clearMountTrustAnchorsWithDsk"];
  declare storeShareSessionTrustAnchorWithDsk: KeyWorkerClientMethods["storeShareSessionTrustAnchorWithDsk"];
  declare loadShareSessionTrustAnchorWithDsk: KeyWorkerClientMethods["loadShareSessionTrustAnchorWithDsk"];
  declare deleteShareSessionTrustAnchorWithDsk: KeyWorkerClientMethods["deleteShareSessionTrustAnchorWithDsk"];
  declare storeShareParticipantSessionWithDsk: KeyWorkerClientMethods["storeShareParticipantSessionWithDsk"];
  declare listShareParticipantSessionsWithDsk: KeyWorkerClientMethods["listShareParticipantSessionsWithDsk"];
  declare deleteShareParticipantSessionWithDsk: KeyWorkerClientMethods["deleteShareParticipantSessionWithDsk"];
  declare clearShareParticipantSessionsWithDsk: KeyWorkerClientMethods["clearShareParticipantSessionsWithDsk"];
  declare persistShareParticipantKeysWithDsk: KeyWorkerClientMethods["persistShareParticipantKeysWithDsk"];
  declare restoreShareParticipantKeysFromDsk: KeyWorkerClientMethods["restoreShareParticipantKeysFromDsk"];
  declare storeUiStateWithDsk: KeyWorkerClientMethods["storeUiStateWithDsk"];
  declare loadUiStateWithDsk: KeyWorkerClientMethods["loadUiStateWithDsk"];
  declare deleteUiStateWithDsk: KeyWorkerClientMethods["deleteUiStateWithDsk"];
  declare storePluginCredentialWithDsk: KeyWorkerClientMethods["storePluginCredentialWithDsk"];
  declare loadPluginCredentialWithDsk: KeyWorkerClientMethods["loadPluginCredentialWithDsk"];
  declare deletePluginCredentialWithDsk: KeyWorkerClientMethods["deletePluginCredentialWithDsk"];
  declare clearPluginDataWithDsk: KeyWorkerClientMethods["clearPluginDataWithDsk"];
  declare clearPluginApplicationDataWithDsk: KeyWorkerClientMethods["clearPluginApplicationDataWithDsk"];
  declare storeShareManagementTokenWithDsk: KeyWorkerClientMethods["storeShareManagementTokenWithDsk"];
  declare loadShareManagementTokenWithDsk: KeyWorkerClientMethods["loadShareManagementTokenWithDsk"];
  declare deleteShareManagementTokenWithDsk: KeyWorkerClientMethods["deleteShareManagementTokenWithDsk"];
  declare storeGuestInvitationMaterialWithDsk: KeyWorkerClientMethods["storeGuestInvitationMaterialWithDsk"];
  declare loadGuestInvitationMaterialWithDsk: KeyWorkerClientMethods["loadGuestInvitationMaterialWithDsk"];
  declare deleteGuestInvitationMaterialWithDsk: KeyWorkerClientMethods["deleteGuestInvitationMaterialWithDsk"];
  declare unwrapUmkFromDsk: KeyWorkerClientMethods["unwrapUmkFromDsk"];
  declare unwrapDeviceKeysFromDsk: KeyWorkerClientMethods["unwrapDeviceKeysFromDsk"];
  declare generateDsk: KeyWorkerClientMethods["generateDsk"];
  declare generateInvitationToken: KeyWorkerClientMethods["generateInvitationToken"];
  declare sha256Hash: KeyWorkerClientMethods["sha256Hash"];

  declare generateDek: DekWorkerClientMethods["generateDek"];
  declare wrapDek: DekWorkerClientMethods["wrapDek"];
  declare wrapDekForShare: DekWorkerClientMethods["wrapDekForShare"];
  declare unwrapDek: DekWorkerClientMethods["unwrapDek"];
  declare encryptTitle: DekWorkerClientMethods["encryptTitle"];
  declare decryptTitle: DekWorkerClientMethods["decryptTitle"];
  declare decryptTitleBatch: DekWorkerClientMethods["decryptTitleBatch"];
  declare encryptContent: DekWorkerClientMethods["encryptContent"];
  declare decryptContent: DekWorkerClientMethods["decryptContent"];
  declare encryptPluginStorage: DekWorkerClientMethods["encryptPluginStorage"];
  declare decryptPluginStorage: DekWorkerClientMethods["decryptPluginStorage"];
  declare encryptSnapshot: DekWorkerClientMethods["encryptSnapshot"];
  declare decryptSnapshot: DekWorkerClientMethods["decryptSnapshot"];
  declare hasDek: DekWorkerClientMethods["hasDek"];
  declare hasDekBatch: DekWorkerClientMethods["hasDekBatch"];
  declare cacheDek: DekWorkerClientMethods["cacheDek"];
  declare unwrapShareDek: DekWorkerClientMethods["unwrapShareDek"];
  declare fetchShareDocumentBootstrap: DekWorkerClientMethods["fetchShareDocumentBootstrap"];
  declare prepareShareDocumentBootstrap: DekWorkerClientMethods["prepareShareDocumentBootstrap"];
  declare fetchShareFolderBootstrap: DekWorkerClientMethods["fetchShareFolderBootstrap"];
  declare fetchMountedShareDocumentBootstrap: DekWorkerClientMethods["fetchMountedShareDocumentBootstrap"];
  declare fetchMountedShareFolderBootstrap: DekWorkerClientMethods["fetchMountedShareFolderBootstrap"];
  declare prepareManagedShareSecrets: DekWorkerClientMethods["prepareManagedShareSecrets"];
  declare wrapPreparedShareDek: DekWorkerClientMethods["wrapPreparedShareDek"];
  declare prepareOpenShareSecrets: DekWorkerClientMethods["prepareOpenShareSecrets"];
  declare preparePasswordShareSecrets: DekWorkerClientMethods["preparePasswordShareSecrets"];
  declare preparePasswordShareChallenge: DekWorkerClientMethods["preparePasswordShareChallenge"];
  declare restoreShareSecretsFromDsk: DekWorkerClientMethods["restoreShareSecretsFromDsk"];
  declare hasShareDekEncryptionKey: DekWorkerClientMethods["hasShareDekEncryptionKey"];
  declare cloneShareDekEncryptionKey: DekWorkerClientMethods["cloneShareDekEncryptionKey"];
  declare clearShareSecrets: DekWorkerClientMethods["clearShareSecrets"];
  declare persistShareSecretsWithDsk: DekWorkerClientMethods["persistShareSecretsWithDsk"];
  declare persistMountedShareSecretsWithDsk: DekWorkerClientMethods["persistMountedShareSecretsWithDsk"];
  declare evictDek: DekWorkerClientMethods["evictDek"];
  declare encryptOfflineCache: DekWorkerClientMethods["encryptOfflineCache"];
  declare decryptOfflineCache: DekWorkerClientMethods["decryptOfflineCache"];
  declare encryptOfflinePending: DekWorkerClientMethods["encryptOfflinePending"];
  declare decryptOfflinePending: DekWorkerClientMethods["decryptOfflinePending"];
  declare storeDekForOffline: DekWorkerClientMethods["storeDekForOffline"];
  declare restoreDekFromOffline: DekWorkerClientMethods["restoreDekFromOffline"];
  declare loadOfflineDekMetadata: DekWorkerClientMethods["loadOfflineDekMetadata"];
  declare deleteDekForOffline: DekWorkerClientMethods["deleteDekForOffline"];

  declare generateKek: KekWorkerClientMethods["generateKek"];
  declare setActiveKekVersion: KekWorkerClientMethods["setActiveKekVersion"];
  declare resolveKek: KekWorkerClientMethods["resolveKek"];
  declare createSignedPqKekWrap: KekWorkerClientMethods["createSignedPqKekWrap"];
  declare createSignedPqShareLinkSecretBackupWrap: KekWorkerClientMethods["createSignedPqShareLinkSecretBackupWrap"];
  declare finalizeSignedPqWrapOperationCheckpoint: KekWorkerClientMethods["finalizeSignedPqWrapOperationCheckpoint"];
  declare openSignedPqDeviceKekWrap: KekWorkerClientMethods["openSignedPqDeviceKekWrap"];
  declare openSignedPqMemberKekWrap: KekWorkerClientMethods["openSignedPqMemberKekWrap"];
  declare openSignedPqShareLinkSecretBackupWrap: KekWorkerClientMethods["openSignedPqShareLinkSecretBackupWrap"];
  declare generateInitialAkeResponderPrekey: KekWorkerClientMethods["generateInitialAkeResponderPrekey"];
  declare createInitialAkeUmkDelivery: KekWorkerClientMethods["createInitialAkeUmkDelivery"];
  declare createInitialAkeKekDelivery: KekWorkerClientMethods["createInitialAkeKekDelivery"];
  declare createInitialAkeDeviceStateTransferDelivery: KekWorkerClientMethods["createInitialAkeDeviceStateTransferDelivery"];
  declare openInitialAkeUmkDelivery: KekWorkerClientMethods["openInitialAkeUmkDelivery"];
  declare openInitialAkeKekDelivery: KekWorkerClientMethods["openInitialAkeKekDelivery"];
  declare openInitialAkeDeviceStateTransferDelivery: KekWorkerClientMethods["openInitialAkeDeviceStateTransferDelivery"];
  declare wrapKekForInvitationBootstrap: KekWorkerClientMethods["wrapKekForInvitationBootstrap"];
  declare unwrapKekFromInvitationBootstrap: KekWorkerClientMethods["unwrapKekFromInvitationBootstrap"];
  declare cacheKek: KekWorkerClientMethods["cacheKek"];
  declare storeKekForOffline: KekWorkerClientMethods["storeKekForOffline"];
  declare restoreKekFromOffline: KekWorkerClientMethods["restoreKekFromOffline"];
  declare loadOfflineKekMetadata: KekWorkerClientMethods["loadOfflineKekMetadata"];
  declare deleteKekForOffline: KekWorkerClientMethods["deleteKekForOffline"];
  declare deleteOrphanedKeksForOffline: KekWorkerClientMethods["deleteOrphanedKeksForOffline"];

  declare createPopSignature: SignWorkerClientMethods["createPopSignature"];
  declare signDocumentUpdate: SignWorkerClientMethods["signDocumentUpdate"];
  declare signDocumentSnapshot: SignWorkerClientMethods["signDocumentSnapshot"];
  declare signEditorEphemeral: SignWorkerClientMethods["signEditorEphemeral"];
  declare createDeviceApprovalSignature: SignWorkerClientMethods["createDeviceApprovalSignature"];
  declare createGenesisDeviceBootstrapSignature: SignWorkerClientMethods["createGenesisDeviceBootstrapSignature"];
  declare createRecoveryDeviceApprovalSignature: SignWorkerClientMethods["createRecoveryDeviceApprovalSignature"];
  declare createDeviceRevocationSignature: SignWorkerClientMethods["createDeviceRevocationSignature"];
  declare signDeviceKeyDeletionProof: SignWorkerClientMethods["signDeviceKeyDeletionProof"];
  declare signIdentityKeyDirectoryCheckpoint: SignWorkerClientMethods["signIdentityKeyDirectoryCheckpoint"];
  declare signDeviceKeyDirectoryCheckpoint: SignWorkerClientMethods["signDeviceKeyDirectoryCheckpoint"];
  declare signShareParticipantDeviceKeyDirectoryCheckpoint: SignWorkerClientMethods["signShareParticipantDeviceKeyDirectoryCheckpoint"];
  declare generateInvitationRedeemAuthority: SignWorkerClientMethods["generateInvitationRedeemAuthority"];
  declare signInvitationRedeemKeyDirectoryCheckpoint: SignWorkerClientMethods["signInvitationRedeemKeyDirectoryCheckpoint"];
  declare signInvitationRedeemKeyDirectoryEvent: SignWorkerClientMethods["signInvitationRedeemKeyDirectoryEvent"];
  declare signIdentityKeyDirectoryEvent: SignWorkerClientMethods["signIdentityKeyDirectoryEvent"];
  declare signDeviceKeyDirectoryEvent: SignWorkerClientMethods["signDeviceKeyDirectoryEvent"];
  declare signShareParticipantDeviceKeyDirectoryEvent: SignWorkerClientMethods["signShareParticipantDeviceKeyDirectoryEvent"];
  declare signWorkspacePinBootstrap: SignWorkerClientMethods["signWorkspacePinBootstrap"];
  declare signPluginConsentEvent: SignWorkerClientMethods["signPluginConsentEvent"];
  declare signPluginBundleApproval: SignWorkerClientMethods["signPluginBundleApproval"];
  declare signPluginNetworkProxyRequest: SignWorkerClientMethods["signPluginNetworkProxyRequest"];
  declare signRecipientBoundAuthorization: SignWorkerClientMethods["signRecipientBoundAuthorization"];
  declare signRecoverySession: SignWorkerClientMethods["signRecoverySession"];
  declare signShareCapabilityAuthorization: SignWorkerClientMethods["signShareCapabilityAuthorization"];
  declare signShareParticipantDeviceAuthorization: SignWorkerClientMethods["signShareParticipantDeviceAuthorization"];
  declare createEditorEphemeralSessionProof: SignWorkerClientMethods["createEditorEphemeralSessionProof"];
  declare verifyEditorEphemeralSessionProof: SignWorkerClientMethods["verifyEditorEphemeralSessionProof"];
  declare verifyGenesisDeviceBootstrapSignature: SignWorkerClientMethods["verifyGenesisDeviceBootstrapSignature"];
  declare verifyDeviceApprovalSignature: SignWorkerClientMethods["verifyDeviceApprovalSignature"];
  declare verifyRecoveryDeviceApprovalSignature: SignWorkerClientMethods["verifyRecoveryDeviceApprovalSignature"];
  declare verifyKeyDirectoryCheckpointSignature: SignWorkerClientMethods["verifyKeyDirectoryCheckpointSignature"];
  declare verifyKeyDirectoryEventSignature: SignWorkerClientMethods["verifyKeyDirectoryEventSignature"];
  declare verifyWorkspacePinBootstrapSignature: SignWorkerClientMethods["verifyWorkspacePinBootstrapSignature"];
  declare verifyDocumentUpdateEd25519Signature: SignWorkerClientMethods["verifyDocumentUpdateEd25519Signature"];
  declare verifyDocumentUpdateSignature: SignWorkerClientMethods["verifyDocumentUpdateSignature"];
  declare verifyDocumentSnapshotSignature: SignWorkerClientMethods["verifyDocumentSnapshotSignature"];
  declare verifyEditorEphemeralSignature: SignWorkerClientMethods["verifyEditorEphemeralSignature"];
  declare computeUpdateHash: SignWorkerClientMethods["computeUpdateHash"];
  declare blake3Hash: SignWorkerClientMethods["blake3Hash"];
  declare computeSas: SignWorkerClientMethods["computeSas"];
  declare calculateFingerprint: SignWorkerClientMethods["calculateFingerprint"];

  declare tofuVerify: TofuWorkerClientMethods["tofuVerify"];
  declare tofuVerifyAllDevices: TofuWorkerClientMethods["tofuVerifyAllDevices"];
  declare tofuTrustDevice: TofuWorkerClientMethods["tofuTrustDevice"];
  declare tofuUpdateLastSeen: TofuWorkerClientMethods["tofuUpdateLastSeen"];
  declare tofuHandleResult: TofuWorkerClientMethods["tofuHandleResult"];
  declare tofuGetAllEntries: TofuWorkerClientMethods["tofuGetAllEntries"];
  declare tofuImportEntries: TofuWorkerClientMethods["tofuImportEntries"];

  private readonly transport = new WorkerTransport();

  terminate(): void {
    this.transport.terminate();
  }

  [workerSend](type: CryptoRequestType, payload: unknown): Promise<unknown> {
    return this.transport.send(type, payload);
  }
}

Object.assign(
  CryptoWorkerClient.prototype,
  lifecycleWorkerClientMethods,
  keyWorkerClientMethods,
  dekWorkerClientMethods,
  kekWorkerClientMethods,
  signWorkerClientMethods,
  tofuWorkerClientMethods,
);

let instance: CryptoWorkerClient | null = null;

export function getCryptoWorker(): CryptoWorkerClient {
  if (!instance) {
    instance = new CryptoWorkerClient();
  }
  return instance;
}

export function terminateCryptoWorker(): void {
  if (instance) {
    instance.terminate();
    instance = null;
  }
}
