import { workerSend, type CryptoWorkerClientMethodContext } from "./shared";
import type { HybridSigningPublicKeyMaterial } from "../../signature-types";

type TofuEntry = {
  userId: string;
  deviceId: string;
  hybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  ecdhPublicKey: Uint8Array;
  firstSeenAt: number;
  lastSeenAt: number;
};

type TofuDeviceVerificationInput = {
  name?: string;
  userId: string;
  deviceId: string;
  ecdhPublicKey: Uint8Array;
  deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  deviceHybridEncryptionPublicKeyMaterial: Record<string, unknown>;
  identitySignature: Record<string, unknown>;
  identitySignaturePurpose: string;
  identitySignatureContext: Record<string, unknown>;
  approvalDeliveryCommitments?: Record<string, unknown> | null;
  approvalDeliveryArtifacts?: Record<string, unknown> | null;
  clientNonce: string;
};

export interface TofuWorkerClientMethods {
  tofuVerify(params: {
    userId: string;
    deviceId: string;
    hybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
    ecdhPublicKey: Uint8Array;
    namespace?: string;
  }): Promise<{ status: string }>;
  tofuVerifyAllDevices(params: {
    devices: TofuDeviceVerificationInput[];
  }): Promise<{ errors: string[] }>;
  tofuTrustDevice(params: {
    userId: string;
    deviceId: string;
    hybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
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
    return (await this[workerSend]("tofu-verify", params)) as { status: string };
  },

  async tofuVerifyAllDevices(params) {
    return (await this[workerSend]("tofu-verify-all-devices", params)) as { errors: string[] };
  },

  async tofuTrustDevice(params) {
    await this[workerSend]("tofu-trust-device", params);
  },

  async tofuUpdateLastSeen(params) {
    await this[workerSend]("tofu-update-last-seen", params);
  },

  async tofuHandleResult(result) {
    await this[workerSend]("tofu-handle-result", result);
  },

  async tofuGetAllEntries(params) {
    const result = (await this[workerSend]("tofu-get-all-entries", params ?? {})) as {
      entries: TofuEntry[];
    };
    return result.entries;
  },

  async tofuImportEntries(entries, namespace) {
    await this[workerSend]("tofu-import-entries", { entries, namespace });
  },
};
