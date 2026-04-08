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

export { CryptoWorkerError, isTofuHardFail } from "./worker-errors";

export class CryptoWorkerClient {
  declare init: LifecycleWorkerClientMethods["init"];
  declare initFromPassword: LifecycleWorkerClientMethods["initFromPassword"];
  declare lock: LifecycleWorkerClientMethods["lock"];
  declare isReady: LifecycleWorkerClientMethods["isReady"];
  declare getPublicKeys: LifecycleWorkerClientMethods["getPublicKeys"];
  declare getDeviceId: LifecycleWorkerClientMethods["getDeviceId"];
  declare setUserContext: LifecycleWorkerClientMethods["setUserContext"];
  declare setDsk: LifecycleWorkerClientMethods["setDsk"];
  declare setInitialized: LifecycleWorkerClientMethods["setInitialized"];
  declare clearTransientKeys: LifecycleWorkerClientMethods["clearTransientKeys"];

  declare importIdentityKeys: KeyWorkerClientMethods["importIdentityKeys"];
  declare importDeviceKeys: KeyWorkerClientMethods["importDeviceKeys"];
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
  declare wrapWithPdk: KeyWorkerClientMethods["wrapWithPdk"];
  declare unwrapWithPdk: KeyWorkerClientMethods["unwrapWithPdk"];
  declare wrapUmkWithDsk: KeyWorkerClientMethods["wrapUmkWithDsk"];
  declare wrapDeviceKeysWithDsk: KeyWorkerClientMethods["wrapDeviceKeysWithDsk"];
  declare wrapWithDsk: KeyWorkerClientMethods["wrapWithDsk"];
  declare unwrapWithDsk: KeyWorkerClientMethods["unwrapWithDsk"];
  declare unwrapUmkFromDsk: KeyWorkerClientMethods["unwrapUmkFromDsk"];
  declare unwrapDeviceKeysFromDsk: KeyWorkerClientMethods["unwrapDeviceKeysFromDsk"];
  declare generateDsk: KeyWorkerClientMethods["generateDsk"];
  declare generateInvitationToken: KeyWorkerClientMethods["generateInvitationToken"];
  declare sha256Hash: KeyWorkerClientMethods["sha256Hash"];

  declare generateDek: DekWorkerClientMethods["generateDek"];
  declare wrapDek: DekWorkerClientMethods["wrapDek"];
  declare unwrapDek: DekWorkerClientMethods["unwrapDek"];
  declare encryptTitle: DekWorkerClientMethods["encryptTitle"];
  declare decryptTitle: DekWorkerClientMethods["decryptTitle"];
  declare decryptTitleBatch: DekWorkerClientMethods["decryptTitleBatch"];
  declare encryptContent: DekWorkerClientMethods["encryptContent"];
  declare decryptContent: DekWorkerClientMethods["decryptContent"];
  declare encryptSnapshot: DekWorkerClientMethods["encryptSnapshot"];
  declare decryptSnapshot: DekWorkerClientMethods["decryptSnapshot"];
  declare hasDek: DekWorkerClientMethods["hasDek"];
  declare cacheDek: DekWorkerClientMethods["cacheDek"];
  declare evictDek: DekWorkerClientMethods["evictDek"];
  declare encryptOfflineCache: DekWorkerClientMethods["encryptOfflineCache"];
  declare decryptOfflineCache: DekWorkerClientMethods["decryptOfflineCache"];
  declare encryptOfflinePending: DekWorkerClientMethods["encryptOfflinePending"];
  declare decryptOfflinePending: DekWorkerClientMethods["decryptOfflinePending"];
  declare wrapDekForOffline: DekWorkerClientMethods["wrapDekForOffline"];
  declare unwrapDekFromOffline: DekWorkerClientMethods["unwrapDekFromOffline"];

  declare generateKek: KekWorkerClientMethods["generateKek"];
  declare encryptKekForDevice: KekWorkerClientMethods["encryptKekForDevice"];
  declare decryptKekFromDeviceEnvelope: KekWorkerClientMethods["decryptKekFromDeviceEnvelope"];
  declare encryptKekForMember: KekWorkerClientMethods["encryptKekForMember"];
  declare decryptKekFromMemberEnvelope: KekWorkerClientMethods["decryptKekFromMemberEnvelope"];
  declare wrapKekWithUmk: KekWorkerClientMethods["wrapKekWithUmk"];
  declare unwrapKekFromBackup: KekWorkerClientMethods["unwrapKekFromBackup"];
  declare encryptKekForInvitation: KekWorkerClientMethods["encryptKekForInvitation"];
  declare decryptKekFromInvitation: KekWorkerClientMethods["decryptKekFromInvitation"];
  declare setActiveKekVersion: KekWorkerClientMethods["setActiveKekVersion"];
  declare resolveKek: KekWorkerClientMethods["resolveKek"];
  declare cacheKek: KekWorkerClientMethods["cacheKek"];
  declare wrapKekForOffline: KekWorkerClientMethods["wrapKekForOffline"];
  declare unwrapKekFromOffline: KekWorkerClientMethods["unwrapKekFromOffline"];

  declare signPop: SignWorkerClientMethods["signPop"];
  declare signWsEnvelope: SignWorkerClientMethods["signWsEnvelope"];
  declare signMessage: SignWorkerClientMethods["signMessage"];
  declare signDeviceApproval: SignWorkerClientMethods["signDeviceApproval"];
  declare signDeviceRegistration: SignWorkerClientMethods["signDeviceRegistration"];
  declare signRecoveryChallenge: SignWorkerClientMethods["signRecoveryChallenge"];
  declare signSessionProof: SignWorkerClientMethods["signSessionProof"];
  declare verifySessionProof: SignWorkerClientMethods["verifySessionProof"];
  declare verifyWsSignature: SignWorkerClientMethods["verifyWsSignature"];
  declare verifyEd25519: SignWorkerClientMethods["verifyEd25519"];
  declare verifyDeviceIdentitySignature: SignWorkerClientMethods["verifyDeviceIdentitySignature"];
  declare computeUpdateHash: SignWorkerClientMethods["computeUpdateHash"];
  declare computeSnapshotProof: SignWorkerClientMethods["computeSnapshotProof"];
  declare blake3Hash: SignWorkerClientMethods["blake3Hash"];
  declare computeSas: SignWorkerClientMethods["computeSas"];
  declare calculateFingerprint: SignWorkerClientMethods["calculateFingerprint"];
  declare ecdhEncrypt: SignWorkerClientMethods["ecdhEncrypt"];
  declare ecdhDecrypt: SignWorkerClientMethods["ecdhDecrypt"];
  declare ecdhEncryptUmkForDevice: SignWorkerClientMethods["ecdhEncryptUmkForDevice"];
  declare ecdhDecryptUmkFromDevice: SignWorkerClientMethods["ecdhDecryptUmkFromDevice"];
  declare encryptTrustState: SignWorkerClientMethods["encryptTrustState"];
  declare decryptTrustState: SignWorkerClientMethods["decryptTrustState"];

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

  send(type: string, payload: unknown): Promise<unknown> {
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
