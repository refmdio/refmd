import { workerSend, type CryptoWorkerClientMethodContext } from "./shared";
import type {
  DeviceHybridSigningPublicKeyMaterial,
  IdentityHybridSigningPublicKeyMaterial,
} from "../../signature";
import type {
  DeviceHybridEncryptionPublicKeyMaterial,
  IdentityHybridEncryptionPublicKeyMaterial,
} from "../../hybrid-encryption";

type DskWrapParams = {
  plaintext: Uint8Array;
};

type DskUnwrapParams = {
  ciphertext: ArrayBuffer;
  iv: ArrayBuffer;
};

type DskWrapResult = { ciphertext: ArrayBuffer; iv: ArrayBuffer };
type DskAadRecord = Record<string, unknown>;
type ShareParticipantSessionRecord = object;

export interface KeyWorkerClientMethods {
  importIdentityKeys(params: {
    encryptedHybridEncryptionPrivateKeyMaterial: Uint8Array;
    hybridEncryptionPrivateKeyMaterialNonce: Uint8Array;
    encryptionKeyId: string;
    encryptedHybridSigningPrivateKeyMaterial: Uint8Array;
    hybridSigningPrivateKeyMaterialNonce: Uint8Array;
    signingKeyId: string;
  }): Promise<{
    deviceEcdhPublic: Uint8Array;
    deviceHybridSigningPublicKeyMaterial: DeviceHybridSigningPublicKeyMaterial | null;
    identityHybridSigningPublicKeyMaterial: IdentityHybridSigningPublicKeyMaterial;
    identityEcdhPublic: Uint8Array;
    identityHybridEncryptionPublicKeyMaterial: IdentityHybridEncryptionPublicKeyMaterial;
    identityEncryptionKeyId: string;
  }>;
  importUmk(umk: Uint8Array): Promise<void>;
  generateIdentityKeys(): Promise<{
    ecdhPublic: Uint8Array;
    hybridEncryptionPublicKeyMaterial: IdentityHybridEncryptionPublicKeyMaterial;
    encryptionKeyId: string;
    hybridSigningPublicKeyMaterial: IdentityHybridSigningPublicKeyMaterial;
  }>;
  generateDeviceKeys(params?: {
    deviceId?: string;
    ownerKind?: "device" | "share_participant_device";
  }): Promise<{
    ecdhPublic: Uint8Array;
    hybridEncryptionPublicKeyMaterial: DeviceHybridEncryptionPublicKeyMaterial;
    encryptionKeyId: string;
    hybridSigningPublicKeyMaterial: DeviceHybridSigningPublicKeyMaterial;
    signingKeyId: string;
  }>;
  generateUmk(): Promise<void>;
  generateClientNonce(): Promise<Uint8Array>;
  generateRecoveryKey(): Promise<{
    mnemonic: string;
    encryptedUmk: Uint8Array;
    nonce: Uint8Array;
    recoveryAuthorizationPublicKey: IdentityHybridSigningPublicKeyMaterial;
    recoveryAuthorizationKeyId: string;
  }>;
  deriveAuthKeys(params: {
    password: string;
    salt: Uint8Array;
    kdfParams: { memory: number; iterations: number; parallelism: number };
  }): Promise<{ authKey: Uint8Array }>;
  validateMnemonic(mnemonic: string): Promise<boolean>;
  deriveRuk(mnemonic: string): Promise<void>;
  wrapUmkForServer(userId: string): Promise<{ encrypted: Uint8Array; nonce: Uint8Array }>;
  wrapUmkWithRuk(): Promise<{ encrypted: Uint8Array; nonce: Uint8Array }>;
  unwrapUmkWithRuk(params: {
    encrypted: Uint8Array;
    nonce: Uint8Array;
    userId: string;
  }): Promise<void>;
  wrapIdentityKeysForServer(userId: string): Promise<{
    encryptedHybridEncryptionPrivateKeyMaterial: Uint8Array;
    hybridEncryptionPrivateKeyMaterialNonce: Uint8Array;
    encryptionKeyId: string;
    encryptedHybridSigningPrivateKeyMaterial: Uint8Array;
    hybridSigningPrivateKeyMaterialNonce: Uint8Array;
    signingKeyId: string;
  }>;
  persistCurrentKeysWithDsk(
    userId: string,
    options?: { persistUmk?: boolean },
  ): Promise<{ storedUmk: boolean; storedDeviceKeys: boolean }>;
  wrapDeviceKeysWithDsk(userId: string): Promise<{
    wrappedEcdh: { ciphertext: ArrayBuffer; iv: ArrayBuffer };
    wrappedMlkem: { ciphertext: ArrayBuffer; iv: ArrayBuffer };
    wrappedSigning: { ciphertext: ArrayBuffer; iv: ArrayBuffer; signingKeyId: string };
  }>;
  persistShareParticipantKeysWithDsk(params: {
    principalId: string;
    shareId: string;
    shareParticipantDeviceId: string;
    signingKeyId: string;
  }): Promise<void>;
  wrapOfflineDocumentTitleWithDsk(
    params: DskWrapParams & { documentId: string; keyVersion: number },
  ): Promise<DskWrapResult>;
  unwrapOfflineDocumentTitleWithDsk(
    params: DskUnwrapParams & { documentId: string; keyVersion: number },
  ): Promise<Uint8Array>;
  storeMountTrustAnchorWithDsk(
    params: DskWrapParams & { mountId: string; aadRecord: DskAadRecord },
  ): Promise<void>;
  loadMountTrustAnchorWithDsk(mountId: string): Promise<Uint8Array | null>;
  deleteMountTrustAnchorWithDsk(mountId: string): Promise<void>;
  clearMountTrustAnchorsWithDsk(): Promise<void>;
  storeShareSessionTrustAnchorWithDsk(
    params: DskWrapParams & { shareSlug: string; aadRecord: DskAadRecord },
  ): Promise<void>;
  loadShareSessionTrustAnchorWithDsk(shareSlug: string): Promise<Uint8Array | null>;
  deleteShareSessionTrustAnchorWithDsk(shareSlug: string): Promise<void>;
  storeShareParticipantSessionWithDsk(session: ShareParticipantSessionRecord): Promise<void>;
  listShareParticipantSessionsWithDsk(): Promise<ShareParticipantSessionRecord[]>;
  deleteShareParticipantSessionWithDsk(shareSlug: string): Promise<void>;
  clearShareParticipantSessionsWithDsk(): Promise<void>;
  storeUiStateWithDsk(
    params: DskWrapParams & { storageKey: string; aadRecord: DskAadRecord },
  ): Promise<void>;
  loadUiStateWithDsk(params: {
    storageKey: string;
    aadRecord: DskAadRecord;
  }): Promise<Uint8Array | null>;
  storeShareManagementTokenWithDsk(
    params: DskWrapParams & { documentId: string; shareId: string },
  ): Promise<void>;
  loadShareManagementTokenWithDsk(params: {
    documentId: string;
    shareId: string;
  }): Promise<Uint8Array | null>;
  deleteShareManagementTokenWithDsk(params: { documentId: string; shareId: string }): Promise<void>;
  storeGuestInvitationMaterialWithDsk(params: DskWrapParams & { tokenHash: string }): Promise<void>;
  loadGuestInvitationMaterialWithDsk(tokenHash: string): Promise<Uint8Array | null>;
  deleteGuestInvitationMaterialWithDsk(tokenHash: string): Promise<void>;
  unwrapUmkFromDsk(params: {
    ciphertext: ArrayBuffer;
    iv: ArrayBuffer;
    userId: string;
  }): Promise<void>;
  unwrapDeviceKeysFromDsk(params: {
    wrappedEcdh: { ciphertext: ArrayBuffer; iv: ArrayBuffer };
    wrappedMlkem: { ciphertext: ArrayBuffer; iv: ArrayBuffer };
    wrappedSigning: { ciphertext: ArrayBuffer; iv: ArrayBuffer; signingKeyId: string };
    signingKeyId: string;
    userId: string;
  }): Promise<void>;
  restoreShareParticipantKeysFromDsk(params: {
    principalId: string;
    shareId: string;
    shareParticipantDeviceId: string;
    signingKeyId: string;
  }): Promise<void>;
  generateDsk(): Promise<void>;
  generateInvitationToken(): Promise<{ token: string; tokenHash: string; tokenPrefix: string }>;
  sha256Hash(data: Uint8Array): Promise<string>;
}

export const keyWorkerClientMethods: KeyWorkerClientMethods &
  ThisType<CryptoWorkerClientMethodContext> = {
  async importIdentityKeys(params) {
    return (await this[workerSend]("import-identity-keys", params)) as {
      deviceEcdhPublic: Uint8Array;
      deviceHybridSigningPublicKeyMaterial: DeviceHybridSigningPublicKeyMaterial | null;
      deviceSigningKeyId: string | null;
      identityHybridSigningPublicKeyMaterial: IdentityHybridSigningPublicKeyMaterial;
      identityEcdhPublic: Uint8Array;
      identityHybridEncryptionPublicKeyMaterial: IdentityHybridEncryptionPublicKeyMaterial;
      identityEncryptionKeyId: string;
    };
  },

  async importUmk(umk) {
    await this[workerSend]("import-umk", { umk });
  },

  async generateIdentityKeys() {
    return (await this[workerSend]("generate-identity-keys", {})) as {
      ecdhPublic: Uint8Array;
      hybridEncryptionPublicKeyMaterial: IdentityHybridEncryptionPublicKeyMaterial;
      encryptionKeyId: string;
      hybridSigningPublicKeyMaterial: IdentityHybridSigningPublicKeyMaterial;
    };
  },

  async generateDeviceKeys(params) {
    return (await this[workerSend]("generate-device-keys", params ?? {})) as {
      ecdhPublic: Uint8Array;
      hybridEncryptionPublicKeyMaterial: DeviceHybridEncryptionPublicKeyMaterial;
      encryptionKeyId: string;
      hybridSigningPublicKeyMaterial: DeviceHybridSigningPublicKeyMaterial;
      signingKeyId: string;
    };
  },

  async generateUmk() {
    await this[workerSend]("generate-umk", {});
  },

  async generateClientNonce() {
    return (await this[workerSend]("generate-client-nonce", {})) as Uint8Array;
  },

  async generateRecoveryKey() {
    return (await this[workerSend]("generate-recovery-key", {})) as {
      mnemonic: string;
      encryptedUmk: Uint8Array;
      nonce: Uint8Array;
      recoveryAuthorizationPublicKey: IdentityHybridSigningPublicKeyMaterial;
      recoveryAuthorizationKeyId: string;
    };
  },

  async deriveAuthKeys(params) {
    return (await this[workerSend]("derive-auth-keys", params)) as { authKey: Uint8Array };
  },

  async validateMnemonic(mnemonic) {
    const result = (await this[workerSend]("validate-mnemonic", { mnemonic })) as {
      valid: boolean;
    };
    return result.valid;
  },

  async deriveRuk(mnemonic) {
    await this[workerSend]("derive-ruk", { mnemonic });
  },

  async wrapUmkForServer(userId) {
    return (await this[workerSend]("wrap-umk-for-server", { userId })) as {
      encrypted: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async wrapUmkWithRuk() {
    return (await this[workerSend]("wrap-umk-with-ruk", {})) as {
      encrypted: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async unwrapUmkWithRuk(params) {
    await this[workerSend]("unwrap-umk-with-ruk", params);
  },

  async wrapIdentityKeysForServer(userId) {
    return (await this[workerSend]("wrap-identity-keys-for-server", { userId })) as {
      encryptedHybridEncryptionPrivateKeyMaterial: Uint8Array;
      hybridEncryptionPrivateKeyMaterialNonce: Uint8Array;
      encryptionKeyId: string;
      encryptedHybridSigningPrivateKeyMaterial: Uint8Array;
      hybridSigningPrivateKeyMaterialNonce: Uint8Array;
      signingKeyId: string;
    };
  },

  async persistCurrentKeysWithDsk(userId, options) {
    return (await this[workerSend]("persist-current-keys-with-dsk", {
      userId,
      persistUmk: options?.persistUmk,
    })) as { storedUmk: boolean; storedDeviceKeys: boolean };
  },

  async wrapDeviceKeysWithDsk(userId) {
    return (await this[workerSend]("wrap-device-keys-with-dsk", { userId })) as {
      wrappedEcdh: { ciphertext: ArrayBuffer; iv: ArrayBuffer };
      wrappedMlkem: { ciphertext: ArrayBuffer; iv: ArrayBuffer };
      wrappedSigning: { ciphertext: ArrayBuffer; iv: ArrayBuffer; signingKeyId: string };
    };
  },

  async persistShareParticipantKeysWithDsk(params) {
    await this[workerSend]("persist-share-participant-keys-with-dsk", params);
  },

  async wrapOfflineDocumentTitleWithDsk(params) {
    return (await this[workerSend](
      "wrap-offline-document-title-with-dsk",
      params,
    )) as DskWrapResult;
  },

  async unwrapOfflineDocumentTitleWithDsk(params) {
    return unwrapDskPlaintext(
      await this[workerSend]("unwrap-offline-document-title-with-dsk", params),
    );
  },

  async storeMountTrustAnchorWithDsk(params) {
    await this[workerSend]("store-mount-trust-anchor-with-dsk", params);
  },

  async loadMountTrustAnchorWithDsk(mountId) {
    return unwrapNullableDskPlaintext(
      await this[workerSend]("load-mount-trust-anchor-with-dsk", { mountId }),
    );
  },

  async deleteMountTrustAnchorWithDsk(mountId) {
    await this[workerSend]("delete-mount-trust-anchor-with-dsk", { mountId });
  },

  async clearMountTrustAnchorsWithDsk() {
    await this[workerSend]("clear-mount-trust-anchors-with-dsk", {});
  },

  async storeShareSessionTrustAnchorWithDsk(params) {
    await this[workerSend]("store-share-session-trust-anchor-with-dsk", params);
  },

  async loadShareSessionTrustAnchorWithDsk(shareSlug) {
    return unwrapNullableDskPlaintext(
      await this[workerSend]("load-share-session-trust-anchor-with-dsk", { shareSlug }),
    );
  },

  async deleteShareSessionTrustAnchorWithDsk(shareSlug) {
    await this[workerSend]("delete-share-session-trust-anchor-with-dsk", { shareSlug });
  },

  async storeShareParticipantSessionWithDsk(session) {
    await this[workerSend]("store-share-participant-session-with-dsk", { session });
  },

  async listShareParticipantSessionsWithDsk() {
    const result = (await this[workerSend]("list-share-participant-sessions-with-dsk", {})) as {
      sessions: ShareParticipantSessionRecord[];
    };
    return result.sessions;
  },

  async deleteShareParticipantSessionWithDsk(shareSlug) {
    await this[workerSend]("delete-share-participant-session-with-dsk", { shareSlug });
  },

  async clearShareParticipantSessionsWithDsk() {
    await this[workerSend]("clear-share-participant-sessions-with-dsk", {});
  },

  async storeUiStateWithDsk(params) {
    await this[workerSend]("store-ui-state-with-dsk", params);
  },

  async loadUiStateWithDsk(params) {
    return unwrapNullableDskPlaintext(await this[workerSend]("load-ui-state-with-dsk", params));
  },

  async storeShareManagementTokenWithDsk(params) {
    await this[workerSend]("store-share-management-token-with-dsk", params);
  },

  async loadShareManagementTokenWithDsk(params) {
    return unwrapNullableDskPlaintext(
      await this[workerSend]("load-share-management-token-with-dsk", params),
    );
  },

  async deleteShareManagementTokenWithDsk(params) {
    await this[workerSend]("delete-share-management-token-with-dsk", params);
  },

  async storeGuestInvitationMaterialWithDsk(params) {
    await this[workerSend]("store-guest-invitation-material-with-dsk", params);
  },

  async loadGuestInvitationMaterialWithDsk(tokenHash) {
    return unwrapNullableDskPlaintext(
      await this[workerSend]("load-guest-invitation-material-with-dsk", { tokenHash }),
    );
  },

  async deleteGuestInvitationMaterialWithDsk(tokenHash) {
    await this[workerSend]("delete-guest-invitation-material-with-dsk", { tokenHash });
  },

  async unwrapUmkFromDsk(params) {
    await this[workerSend]("unwrap-umk-from-dsk", params);
  },

  async unwrapDeviceKeysFromDsk(params) {
    await this[workerSend]("unwrap-device-keys-from-dsk", params);
  },

  async restoreShareParticipantKeysFromDsk(params) {
    await this[workerSend]("restore-share-participant-keys-from-dsk", params);
  },

  async generateDsk() {
    await this[workerSend]("generate-dsk", {});
  },

  async generateInvitationToken() {
    return (await this[workerSend]("generate-invitation-token", {})) as {
      token: string;
      tokenHash: string;
      tokenPrefix: string;
    };
  },

  async sha256Hash(data) {
    const result = (await this[workerSend]("sha256-hash", { data })) as { hash: string };
    return result.hash;
  },
};

function unwrapDskPlaintext(result: unknown): Uint8Array {
  return (
    result as {
      plaintext: Uint8Array;
    }
  ).plaintext;
}

function unwrapNullableDskPlaintext(result: unknown): Uint8Array | null {
  return (
    result as {
      plaintext: Uint8Array | null;
    }
  ).plaintext;
}
