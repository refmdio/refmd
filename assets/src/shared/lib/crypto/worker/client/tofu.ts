import type { CryptoWorkerClientMethodContext } from "./shared";

type TofuEntry = {
  userId: string;
  deviceId: string;
  signingPublicKey: Uint8Array;
  ecdhPublicKey: Uint8Array;
  firstSeenAt: number;
  lastSeenAt: number;
};

export interface TofuWorkerClientMethods {
  tofuVerify(params: {
    userId: string;
    deviceId: string;
    signingPublicKey: Uint8Array;
    ecdhPublicKey: Uint8Array;
    namespace?: string;
  }): Promise<{ status: string }>;
  tofuVerifyAllDevices(params: {
    devices: Array<{
      userId: string;
      deviceId: string;
      signingPublicKey: Uint8Array;
      ecdhPublicKey: Uint8Array;
    }>;
  }): Promise<{ errors: string[] }>;
  tofuTrustDevice(params: {
    userId: string;
    deviceId: string;
    signingPublicKey: Uint8Array;
    ecdhPublicKey: Uint8Array;
    namespace?: string;
  }): Promise<void>;
  tofuUpdateLastSeen(params: {
    userId: string;
    deviceId: string;
    namespace?: string;
  }): Promise<void>;
  tofuHandleResult(params: {
    status: string;
    newEntry?: TofuEntry;
    namespace?: string;
  }): Promise<void>;
  tofuGetAllEntries(params?: { namespace?: string }): Promise<TofuEntry[]>;
  tofuImportEntries(entries: TofuEntry[], namespace?: string): Promise<void>;
}

export const tofuWorkerClientMethods: TofuWorkerClientMethods &
  ThisType<CryptoWorkerClientMethodContext> = {
  async tofuVerify(params) {
    return (await this.send("tofu-verify", params)) as { status: string };
  },

  async tofuVerifyAllDevices(params) {
    return (await this.send("tofu-verify-all-devices", params)) as { errors: string[] };
  },

  async tofuTrustDevice(params) {
    await this.send("tofu-trust-device", params);
  },

  async tofuUpdateLastSeen(params) {
    await this.send("tofu-update-last-seen", params);
  },

  async tofuHandleResult(result) {
    await this.send("tofu-handle-result", result);
  },

  async tofuGetAllEntries(params) {
    const result = (await this.send("tofu-get-all-entries", params ?? {})) as {
      entries: TofuEntry[];
    };
    return result.entries;
  },

  async tofuImportEntries(entries, namespace) {
    await this.send("tofu-import-entries", { entries, namespace });
  },
};
