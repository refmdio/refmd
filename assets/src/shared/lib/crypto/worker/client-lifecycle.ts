import type { InitFromPasswordPayload, InitPdkResult, InitPayload, PublicKeys } from "./types";
import type { CryptoWorkerClientMethodContext } from "./client-shared";

export interface LifecycleWorkerClientMethods {
  init(payload: InitPayload): Promise<{ status: string; pdkWrapped: InitPdkResult | null }>;
  initFromPassword(
    payload: InitFromPasswordPayload,
  ): Promise<{ authKey: Uint8Array; pdkWrapped: InitPdkResult | null }>;
  lock(): Promise<void>;
  isReady(): Promise<boolean>;
  getPublicKeys(): Promise<PublicKeys>;
  getDeviceId(): Promise<string>;
  setUserContext(userId: string, deviceId?: string): Promise<void>;
  setDsk(dsk: CryptoKey): Promise<void>;
  setInitialized(): Promise<void>;
  clearTransientKeys(): Promise<void>;
}

export const lifecycleWorkerClientMethods: LifecycleWorkerClientMethods &
  ThisType<CryptoWorkerClientMethodContext> = {
  async init(payload) {
    return (await this.send("init", payload)) as {
      status: string;
      pdkWrapped: InitPdkResult | null;
    };
  },

  async initFromPassword(payload) {
    return (await this.send("init-from-password", payload)) as {
      authKey: Uint8Array;
      pdkWrapped: InitPdkResult | null;
    };
  },

  async lock() {
    await this.send("lock", {});
  },

  async isReady() {
    const result = (await this.send("is-ready", {})) as { ready: boolean };
    return result.ready;
  },

  async getPublicKeys() {
    return (await this.send("get-public-keys", {})) as PublicKeys;
  },

  async getDeviceId() {
    const result = (await this.send("get-device-id", {})) as { deviceId: string };
    return result.deviceId;
  },

  async setUserContext(userId, deviceId) {
    await this.send("set-user-context", { userId, deviceId });
  },

  async setDsk(dsk) {
    await this.send("set-dsk", { dsk });
  },

  async setInitialized() {
    await this.send("set-initialized", {});
  },

  async clearTransientKeys() {
    await this.send("clear-transient-keys", {});
  },
};
