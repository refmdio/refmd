import type {
  KekBackupParams,
  KekForDeviceParams,
  KekForInvitationParams,
  KekForMemberParams,
  KekFromBackupParams,
  KekFromDeviceEnvelopeParams,
  KekFromInvitationParams,
  KekFromMemberEnvelopeParams,
} from "./types";
import type { CryptoWorkerClientMethodContext } from "./client-shared";

export interface KekWorkerClientMethods {
  generateKek(workspaceId: string, keyVersion?: number): Promise<{ keyVersion: number }>;
  encryptKekForDevice(
    params: KekForDeviceParams,
  ): Promise<{ encrypted: Uint8Array; nonce: Uint8Array }>;
  decryptKekFromDeviceEnvelope(params: KekFromDeviceEnvelopeParams): Promise<void>;
  encryptKekForMember(
    params: KekForMemberParams,
  ): Promise<{ encrypted: Uint8Array; nonce: Uint8Array }>;
  decryptKekFromMemberEnvelope(params: KekFromMemberEnvelopeParams): Promise<void>;
  wrapKekWithUmk(params: KekBackupParams): Promise<{ encrypted: Uint8Array; nonce: Uint8Array }>;
  unwrapKekFromBackup(params: KekFromBackupParams): Promise<void>;
  encryptKekForInvitation(
    params: KekForInvitationParams,
  ): Promise<{ encrypted: Uint8Array; nonce: Uint8Array }>;
  decryptKekFromInvitation(params: KekFromInvitationParams): Promise<void>;
  setActiveKekVersion(workspaceId: string, keyVersion: number): Promise<void>;
  resolveKek(
    workspaceId: string,
    keyVersion?: number,
  ): Promise<{ found: boolean; keyVersion?: number }>;
  cacheKek(params: { workspaceId: string; kek: Uint8Array; keyVersion: number }): Promise<void>;
  wrapKekForOffline(params: {
    workspaceId: string;
    keyVersion: number;
  }): Promise<{ ciphertext: ArrayBuffer; iv: ArrayBuffer }>;
  unwrapKekFromOffline(params: {
    ciphertext: ArrayBuffer;
    iv: ArrayBuffer;
    workspaceId: string;
    keyVersion: number;
    isActive?: boolean;
  }): Promise<void>;
}

export const kekWorkerClientMethods: KekWorkerClientMethods &
  ThisType<CryptoWorkerClientMethodContext> = {
  async generateKek(workspaceId, keyVersion) {
    return (await this.send("generate-kek", { workspaceId, keyVersion })) as {
      keyVersion: number;
    };
  },

  async encryptKekForDevice(params) {
    return (await this.send("encrypt-kek-for-device", params)) as {
      encrypted: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async decryptKekFromDeviceEnvelope(params) {
    await this.send("decrypt-kek-from-device-envelope", params);
  },

  async encryptKekForMember(params) {
    return (await this.send("encrypt-kek-for-member", params)) as {
      encrypted: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async decryptKekFromMemberEnvelope(params) {
    await this.send("decrypt-kek-from-member-envelope", params);
  },

  async wrapKekWithUmk(params) {
    return (await this.send("wrap-kek-with-umk", params)) as {
      encrypted: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async unwrapKekFromBackup(params) {
    await this.send("unwrap-kek-from-backup", params);
  },

  async encryptKekForInvitation(params) {
    return (await this.send("encrypt-kek-for-invitation", params)) as {
      encrypted: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async decryptKekFromInvitation(params) {
    await this.send("decrypt-kek-from-invitation", params);
  },

  async setActiveKekVersion(workspaceId, keyVersion) {
    await this.send("set-active-kek-version", { workspaceId, keyVersion });
  },

  async resolveKek(workspaceId, keyVersion) {
    return (await this.send("resolve-kek", { workspaceId, keyVersion })) as {
      found: boolean;
      keyVersion?: number;
    };
  },

  async cacheKek(params) {
    await this.send("cache-kek", params);
  },

  async wrapKekForOffline(params) {
    return (await this.send("wrap-kek-for-offline", params)) as {
      ciphertext: ArrayBuffer;
      iv: ArrayBuffer;
    };
  },

  async unwrapKekFromOffline(params) {
    await this.send("unwrap-kek-from-offline", params);
  },
};
