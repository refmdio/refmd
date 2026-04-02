import type { CryptoWorkerClientMethodContext } from "./client-shared";

export interface KeyWorkerClientMethods {
  importIdentityKeys(params: {
    encryptedEcdhPrivate: Uint8Array;
    ecdhPrivateNonce: Uint8Array;
    encryptedSigningPrivate: Uint8Array;
    signingPrivateNonce: Uint8Array;
  }): Promise<{
    deviceSigningPublic: Uint8Array;
    deviceEcdhPublic: Uint8Array;
    identitySigningPublic: Uint8Array;
    identityEcdhPublic: Uint8Array;
  }>;
  importDeviceKeys(params: {
    ecdhPrivate: Uint8Array;
    signingPrivate: Uint8Array;
  }): Promise<{ ecdhPublic: Uint8Array; signingPublic: Uint8Array }>;
  importUmk(umk: Uint8Array): Promise<void>;
  generateIdentityKeys(): Promise<{ ecdhPublic: Uint8Array; signingPublic: Uint8Array }>;
  generateDeviceKeys(): Promise<{ ecdhPublic: Uint8Array; signingPublic: Uint8Array }>;
  generateUmk(): Promise<void>;
  generateClientNonce(): Promise<Uint8Array>;
  generateRecoveryKey(): Promise<{
    mnemonic: string;
    encryptedUmk: Uint8Array;
    nonce: Uint8Array;
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
    encryptedEcdhPrivate: Uint8Array;
    ecdhPrivateNonce: Uint8Array;
    encryptedSigningPrivate: Uint8Array;
    signingPrivateNonce: Uint8Array;
  }>;
  wrapWithPdk(params: {
    passwordParams: {
      password: string;
      salt: Uint8Array;
      kdfParams: { memory: number; iterations: number; parallelism: number };
    };
  }): Promise<{
    wrappedUmk: { ciphertext: string; nonce: string } | null;
    wrappedDeviceKeys: {
      ecdh: { ciphertext: string; nonce: string };
      signing: { ciphertext: string; nonce: string };
    } | null;
  }>;
  unwrapWithPdk(params: {
    userId: string;
    passwordParams: {
      password: string;
      salt: Uint8Array;
      kdfParams: { memory: number; iterations: number; parallelism: number };
    };
    wrappedUmk?: { ciphertext: string; nonce: string };
    wrappedDeviceEcdh?: { ciphertext: string; nonce: string };
    wrappedDeviceSigning?: { ciphertext: string; nonce: string };
  }): Promise<{ umkRestored: boolean; deviceKeysRestored: boolean }>;
  wrapUmkWithDsk(userId: string): Promise<{ ciphertext: ArrayBuffer; iv: ArrayBuffer }>;
  wrapDeviceKeysWithDsk(userId: string): Promise<{
    wrappedEcdh: { ciphertext: ArrayBuffer; iv: ArrayBuffer };
    wrappedSigning: { ciphertext: ArrayBuffer; iv: ArrayBuffer };
  }>;
  wrapWithDsk(params: {
    plaintext: Uint8Array;
    aad: Uint8Array;
  }): Promise<{ ciphertext: ArrayBuffer; iv: ArrayBuffer }>;
  unwrapWithDsk(params: {
    ciphertext: ArrayBuffer;
    iv: ArrayBuffer;
    aad: Uint8Array;
  }): Promise<Uint8Array>;
  unwrapUmkFromDsk(params: {
    ciphertext: ArrayBuffer;
    iv: ArrayBuffer;
    userId: string;
  }): Promise<void>;
  unwrapDeviceKeysFromDsk(params: {
    wrappedEcdh: { ciphertext: ArrayBuffer; iv: ArrayBuffer };
    wrappedSigning: { ciphertext: ArrayBuffer; iv: ArrayBuffer };
    userId: string;
  }): Promise<void>;
  generateDsk(): Promise<void>;
  generateInvitationToken(): Promise<{ token: string; tokenHash: string; tokenPrefix: string }>;
  sha256Hash(data: Uint8Array): Promise<string>;
}

export const keyWorkerClientMethods: KeyWorkerClientMethods &
  ThisType<CryptoWorkerClientMethodContext> = {
  async importIdentityKeys(params) {
    return (await this.send("import-identity-keys", params)) as {
      deviceSigningPublic: Uint8Array;
      deviceEcdhPublic: Uint8Array;
      identitySigningPublic: Uint8Array;
      identityEcdhPublic: Uint8Array;
    };
  },

  async importDeviceKeys(params) {
    return (await this.send("import-device-keys", params)) as {
      ecdhPublic: Uint8Array;
      signingPublic: Uint8Array;
    };
  },

  async importUmk(umk) {
    await this.send("import-umk", { umk });
  },

  async generateIdentityKeys() {
    return (await this.send("generate-identity-keys", {})) as {
      ecdhPublic: Uint8Array;
      signingPublic: Uint8Array;
    };
  },

  async generateDeviceKeys() {
    return (await this.send("generate-device-keys", {})) as {
      ecdhPublic: Uint8Array;
      signingPublic: Uint8Array;
    };
  },

  async generateUmk() {
    await this.send("generate-umk", {});
  },

  async generateClientNonce() {
    return (await this.send("generate-client-nonce", {})) as Uint8Array;
  },

  async generateRecoveryKey() {
    return (await this.send("generate-recovery-key", {})) as {
      mnemonic: string;
      encryptedUmk: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async deriveAuthKeys(params) {
    return (await this.send("derive-auth-keys", params)) as { authKey: Uint8Array };
  },

  async validateMnemonic(mnemonic) {
    const result = (await this.send("validate-mnemonic", { mnemonic })) as { valid: boolean };
    return result.valid;
  },

  async deriveRuk(mnemonic) {
    await this.send("derive-ruk", { mnemonic });
  },

  async wrapUmkForServer(userId) {
    return (await this.send("wrap-umk-for-server", { userId })) as {
      encrypted: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async wrapUmkWithRuk() {
    return (await this.send("wrap-umk-with-ruk", {})) as {
      encrypted: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async unwrapUmkWithRuk(params) {
    await this.send("unwrap-umk-with-ruk", params);
  },

  async wrapIdentityKeysForServer(userId) {
    return (await this.send("wrap-identity-keys-for-server", { userId })) as {
      encryptedEcdhPrivate: Uint8Array;
      ecdhPrivateNonce: Uint8Array;
      encryptedSigningPrivate: Uint8Array;
      signingPrivateNonce: Uint8Array;
    };
  },

  async wrapWithPdk(params) {
    return (await this.send("wrap-with-pdk", params)) as {
      wrappedUmk: { ciphertext: string; nonce: string } | null;
      wrappedDeviceKeys: {
        ecdh: { ciphertext: string; nonce: string };
        signing: { ciphertext: string; nonce: string };
      } | null;
    };
  },

  async unwrapWithPdk(params) {
    return (await this.send("unwrap-with-pdk", params)) as {
      umkRestored: boolean;
      deviceKeysRestored: boolean;
    };
  },

  async wrapUmkWithDsk(userId) {
    return (await this.send("wrap-umk-with-dsk", { userId })) as {
      ciphertext: ArrayBuffer;
      iv: ArrayBuffer;
    };
  },

  async wrapDeviceKeysWithDsk(userId) {
    return (await this.send("wrap-device-keys-with-dsk", { userId })) as {
      wrappedEcdh: { ciphertext: ArrayBuffer; iv: ArrayBuffer };
      wrappedSigning: { ciphertext: ArrayBuffer; iv: ArrayBuffer };
    };
  },

  async wrapWithDsk(params) {
    return (await this.send("wrap-with-dsk", params)) as {
      ciphertext: ArrayBuffer;
      iv: ArrayBuffer;
    };
  },

  async unwrapWithDsk(params) {
    const result = (await this.send("unwrap-with-dsk", params)) as { plaintext: Uint8Array };
    return result.plaintext;
  },

  async unwrapUmkFromDsk(params) {
    await this.send("unwrap-umk-from-dsk", params);
  },

  async unwrapDeviceKeysFromDsk(params) {
    await this.send("unwrap-device-keys-from-dsk", params);
  },

  async generateDsk() {
    await this.send("generate-dsk", {});
  },

  async generateInvitationToken() {
    return (await this.send("generate-invitation-token", {})) as {
      token: string;
      tokenHash: string;
      tokenPrefix: string;
    };
  },

  async sha256Hash(data) {
    const result = (await this.send("sha256-hash", { data })) as { hash: string };
    return result.hash;
  },
};
