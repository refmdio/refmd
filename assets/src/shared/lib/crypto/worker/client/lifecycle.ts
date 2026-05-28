import type { InitFromPasswordPayload, InitPayload, PublicKeys } from "../types";
import { workerSend, type CryptoWorkerClientMethodContext } from "./shared";

export interface AuthBootstrapData {
  userId: string;
  email: string;
  name: string;
  deviceId: string;
  deviceSigningKeyId: string;
  cachedAt: number;
}

export interface LifecycleWorkerClientMethods {
  init(payload: InitPayload): Promise<{ status: string }>;
  initFromPassword(payload: InitFromPasswordPayload): Promise<{ authKey: Uint8Array }>;
  importIdentityKeysFromKeyRestore(keyRestoreEndpointRef: string): Promise<PublicKeys>;
  lock(): Promise<void>;
  isReady(): Promise<boolean>;
  getPublicKeys(): Promise<PublicKeys>;
  getDeviceId(): Promise<string>;
  hasStoredDeviceKeys(): Promise<boolean>;
  hasStoredDsk(): Promise<boolean>;
  deleteWrappedUmkWithDsk(): Promise<void>;
  deleteAuthBootstrapWithDsk(): Promise<void>;
  loadAuthBootstrap(): Promise<AuthBootstrapData | null>;
  storeAuthBootstrap(data: AuthBootstrapData): Promise<boolean>;
  loadStoredDsk(): Promise<boolean>;
  setUserContext(userId: string, deviceId?: string): Promise<void>;
  setInitialized(): Promise<void>;
  clearTransientKeys(): Promise<void>;
}

export const lifecycleWorkerClientMethods: LifecycleWorkerClientMethods &
  ThisType<CryptoWorkerClientMethodContext> = {
  async init(payload) {
    return (await this[workerSend]("init", payload)) as {
      status: string;
    };
  },

  async initFromPassword(payload) {
    return (await this[workerSend]("init-from-password", payload)) as {
      authKey: Uint8Array;
    };
  },

  async importIdentityKeysFromKeyRestore(keyRestoreEndpointRef) {
    return (await this[workerSend]("import-identity-keys-from-key-restore", {
      keyRestoreEndpointRef,
    })) as PublicKeys;
  },

  async lock() {
    await this[workerSend]("lock", {});
  },

  async isReady() {
    const result = (await this[workerSend]("is-ready", {})) as { ready: boolean };
    return result.ready;
  },

  async getPublicKeys() {
    return (await this[workerSend]("get-public-keys", {})) as PublicKeys;
  },

  async getDeviceId() {
    const result = (await this[workerSend]("get-device-id", {})) as { deviceId: string };
    return result.deviceId;
  },

  async hasStoredDsk() {
    const result = (await this[workerSend]("has-stored-dsk", {})) as { available: boolean };
    return result.available;
  },

  async hasStoredDeviceKeys() {
    const result = (await this[workerSend]("has-stored-device-keys", {})) as {
      available: boolean;
    };
    return result.available;
  },

  async deleteWrappedUmkWithDsk() {
    await this[workerSend]("delete-wrapped-umk-with-dsk", {});
  },

  async deleteAuthBootstrapWithDsk() {
    await this[workerSend]("delete-auth-bootstrap-with-dsk", {});
  },

  async loadAuthBootstrap() {
    const result = (await this[workerSend]("load-auth-bootstrap", {})) as {
      bootstrap: AuthBootstrapData | null;
    };
    return result.bootstrap;
  },

  async storeAuthBootstrap(data) {
    const result = (await this[workerSend]("store-auth-bootstrap", { bootstrap: data })) as {
      stored: boolean;
    };
    return result.stored;
  },

  async loadStoredDsk() {
    const result = (await this[workerSend]("load-stored-dsk", {})) as { loaded: boolean };
    return result.loaded;
  },

  async setUserContext(userId, deviceId) {
    await this[workerSend]("set-user-context", { userId, deviceId });
  },

  async setInitialized() {
    await this[workerSend]("set-initialized", {});
  },

  async clearTransientKeys() {
    await this[workerSend]("clear-transient-keys", {});
  },
};
