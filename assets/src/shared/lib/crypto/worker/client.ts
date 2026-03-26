// CryptoWorkerClient - Main thread API for communicating with the Crypto Worker.
// All crypto operations go through this client. Keys never appear in the main thread.

import type {
  CryptoRequest,
  CryptoRequestType,
  CryptoResponse,
  CryptoError,
  InitPayload,
  InitFromPasswordPayload,
  PublicKeys,
  TitleDecryptItem,
  TitleDecryptResult,
  KekForDeviceParams,
  KekFromDeviceEnvelopeParams,
  KekForMemberParams,
  KekFromMemberEnvelopeParams,
  KekBackupParams,
  KekFromBackupParams,
  KekForInvitationParams,
  KekFromInvitationParams,
  SasResultData,
  InitPdkResult,
} from "./types";

export class CryptoWorkerError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "CryptoWorkerError";
    this.code = code;
  }
}

type PendingRequest = {
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
};

export class CryptoWorkerClient {
  private worker: Worker;
  private pending = new Map<string, PendingRequest>();
  private terminated = false;

  constructor() {
    this.worker = new Worker(new URL("./index.ts", import.meta.url), { type: "module" });
    this.worker.onmessage = (event: MessageEvent<CryptoResponse>) => {
      const { id, type, payload } = event.data;
      const pending = this.pending.get(id);
      if (!pending) return;
      this.pending.delete(id);

      if (type === "error") {
        const err = payload as CryptoError;
        pending.reject(new CryptoWorkerError(err.code, err.message));
      } else {
        pending.resolve(payload);
      }
    };

    this.worker.onerror = (event) => {
      for (const [id, pending] of this.pending) {
        pending.reject(new Error(`Worker error: ${event.message}`));
        this.pending.delete(id);
      }
    };
  }

  // ── Lifecycle ─────────────────────────────────────────

  async init(payload: InitPayload): Promise<{ status: string; pdkWrapped: InitPdkResult | null }> {
    return (await this.send("init", payload as unknown as Record<string, unknown>)) as {
      status: string;
      pdkWrapped: InitPdkResult | null;
    };
  }

  async initFromPassword(
    payload: InitFromPasswordPayload,
  ): Promise<{ authKey: Uint8Array; pdkWrapped: InitPdkResult | null }> {
    return (await this.send(
      "init-from-password",
      payload as unknown as Record<string, unknown>,
    )) as { authKey: Uint8Array; pdkWrapped: InitPdkResult | null };
  }

  async lock(): Promise<void> {
    await this.send("lock", {});
  }

  async isReady(): Promise<boolean> {
    const result = (await this.send("is-ready", {})) as { ready: boolean };
    return result.ready;
  }

  async getPublicKeys(): Promise<PublicKeys> {
    return (await this.send("get-public-keys", {})) as PublicKeys;
  }

  async getDeviceId(): Promise<string> {
    const result = (await this.send("get-device-id", {})) as { deviceId: string };
    return result.deviceId;
  }

  async setUserContext(userId: string, deviceId?: string): Promise<void> {
    await this.send("set-user-context", { userId, deviceId });
  }

  async setDsk(dsk: CryptoKey): Promise<void> {
    await this.send("set-dsk", { dsk });
  }

  async setInitialized(): Promise<void> {
    await this.send("set-initialized", {});
  }

  async clearTransientKeys(): Promise<void> {
    await this.send("clear-transient-keys", {});
  }

  terminate(): void {
    this.terminated = true;
    for (const [id, pending] of this.pending) {
      pending.reject(new Error("Worker terminated"));
      this.pending.delete(id);
    }
    this.worker.terminate();
  }

  // ── Key import ────────────────────────────────────────

  async importIdentityKeys(params: {
    encryptedEcdhPrivate: Uint8Array;
    ecdhPrivateNonce: Uint8Array;
    encryptedSigningPrivate: Uint8Array;
    signingPrivateNonce: Uint8Array;
  }): Promise<PublicKeys> {
    return (await this.send(
      "import-identity-keys",
      params as unknown as Record<string, unknown>,
    )) as PublicKeys;
  }

  async importDeviceKeys(params: {
    ecdhPrivate: Uint8Array;
    signingPrivate: Uint8Array;
  }): Promise<{ ecdhPublic: Uint8Array; signingPublic: Uint8Array }> {
    return (await this.send(
      "import-device-keys",
      params as unknown as Record<string, unknown>,
    )) as {
      ecdhPublic: Uint8Array;
      signingPublic: Uint8Array;
    };
  }

  async importUmk(umk: Uint8Array): Promise<void> {
    await this.send("import-umk", { umk });
  }

  // ── Key generation ────────────────────────────────────

  async generateIdentityKeys(): Promise<{
    ecdhPublic: Uint8Array;
    signingPublic: Uint8Array;
  }> {
    return (await this.send("generate-identity-keys", {})) as {
      ecdhPublic: Uint8Array;
      signingPublic: Uint8Array;
    };
  }

  async generateDeviceKeys(): Promise<{
    ecdhPublic: Uint8Array;
    signingPublic: Uint8Array;
  }> {
    return (await this.send("generate-device-keys", {})) as {
      ecdhPublic: Uint8Array;
      signingPublic: Uint8Array;
    };
  }

  async generateUmk(): Promise<void> {
    await this.send("generate-umk", {});
  }

  async generateKek(workspaceId: string, keyVersion?: number): Promise<{ keyVersion: number }> {
    return (await this.send("generate-kek", { workspaceId, keyVersion })) as { keyVersion: number };
  }

  async generateDek(
    documentId: string,
    workspaceId: string,
    dekKeyVersion?: number,
    setActive?: boolean,
  ): Promise<{ encryptedDek: Uint8Array; nonce: Uint8Array; keyVersion: number }> {
    return (await this.send("generate-dek", {
      documentId,
      workspaceId,
      dekKeyVersion,
      setActive,
    })) as {
      encryptedDek: Uint8Array;
      nonce: Uint8Array;
      keyVersion: number;
    };
  }

  async generateClientNonce(): Promise<Uint8Array> {
    return (await this.send("generate-client-nonce", {})) as Uint8Array;
  }

  async generateRecoveryKey(): Promise<{
    mnemonic: string;
    encryptedUmk: Uint8Array;
    nonce: Uint8Array;
  }> {
    return (await this.send("generate-recovery-key", {})) as {
      mnemonic: string;
      encryptedUmk: Uint8Array;
      nonce: Uint8Array;
    };
  }

  // ── Password derivation ───────────────────────────────

  async deriveAuthKeys(params: {
    password: string;
    salt: Uint8Array;
    kdfParams: { memory: number; iterations: number; parallelism: number };
  }): Promise<{ authKey: Uint8Array }> {
    return (await this.sendWithRateLimitRetry(
      "derive-auth-keys",
      params as unknown as Record<string, unknown>,
    )) as { authKey: Uint8Array };
  }

  async validateMnemonic(mnemonic: string): Promise<boolean> {
    const result = (await this.send("validate-mnemonic", { mnemonic })) as { valid: boolean };
    return result.valid;
  }

  async deriveRuk(mnemonic: string): Promise<void> {
    await this.send("derive-ruk", { mnemonic });
  }

  // ── UMK wrapping ──────────────────────────────────────

  async wrapUmkForServer(userId: string): Promise<{ encrypted: Uint8Array; nonce: Uint8Array }> {
    return (await this.send("wrap-umk-for-server", { userId })) as {
      encrypted: Uint8Array;
      nonce: Uint8Array;
    };
  }

  async wrapUmkWithRuk(): Promise<{ encrypted: Uint8Array; nonce: Uint8Array }> {
    return (await this.send("wrap-umk-with-ruk", {})) as {
      encrypted: Uint8Array;
      nonce: Uint8Array;
    };
  }

  async unwrapUmkWithRuk(params: {
    encrypted: Uint8Array;
    nonce: Uint8Array;
    userId: string;
  }): Promise<void> {
    await this.send("unwrap-umk-with-ruk", params as unknown as Record<string, unknown>);
  }

  // ── Identity key wrapping ─────────────────────────────

  async wrapIdentityKeysForServer(userId: string): Promise<{
    encryptedEcdhPrivate: Uint8Array;
    ecdhPrivateNonce: Uint8Array;
    encryptedSigningPrivate: Uint8Array;
    signingPrivateNonce: Uint8Array;
  }> {
    return (await this.send("wrap-identity-keys-for-server", { userId })) as {
      encryptedEcdhPrivate: Uint8Array;
      ecdhPrivateNonce: Uint8Array;
      encryptedSigningPrivate: Uint8Array;
      signingPrivateNonce: Uint8Array;
    };
  }

  // ── DEK operations ────────────────────────────────────

  async wrapDek(params: {
    documentId: string;
    workspaceId: string;
  }): Promise<{ encryptedDek: Uint8Array; nonce: Uint8Array }> {
    return (await this.send("wrap-dek", params)) as {
      encryptedDek: Uint8Array;
      nonce: Uint8Array;
    };
  }

  async unwrapDek(params: {
    encryptedDek: Uint8Array;
    nonce: Uint8Array;
    documentId: string;
    workspaceId: string;
    keyVersion: number;
    isActive?: boolean;
    kekVersion?: number;
  }): Promise<void> {
    await this.send("unwrap-dek", params as unknown as Record<string, unknown>);
  }

  async encryptTitle(params: {
    title: string;
    documentId: string;
    keyVersion: number;
  }): Promise<{ encrypted: Uint8Array; nonce: Uint8Array }> {
    return (await this.send("encrypt-title", params)) as {
      encrypted: Uint8Array;
      nonce: Uint8Array;
    };
  }

  async decryptTitle(params: {
    encrypted: Uint8Array;
    nonce: Uint8Array;
    documentId: string;
    keyVersion: number;
  }): Promise<string> {
    const result = (await this.send(
      "decrypt-title",
      params as unknown as Record<string, unknown>,
    )) as {
      title: string;
    };
    return result.title;
  }

  async decryptTitleBatch(items: TitleDecryptItem[]): Promise<TitleDecryptResult[]> {
    return (await this.send("decrypt-title-batch", {
      items,
    })) as TitleDecryptResult[];
  }

  async encryptContent(params: {
    plaintext: Uint8Array;
    documentId: string;
    keyVersion: number;
  }): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }> {
    return (await this.send("encrypt-content", params as unknown as Record<string, unknown>)) as {
      ciphertext: Uint8Array;
      nonce: Uint8Array;
    };
  }

  async decryptContent(params: {
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    documentId: string;
    keyVersion: number;
  }): Promise<Uint8Array> {
    const result = (await this.send(
      "decrypt-content",
      params as unknown as Record<string, unknown>,
    )) as { plaintext: Uint8Array };
    return result.plaintext;
  }

  async encryptSnapshot(params: {
    plaintext: Uint8Array;
    documentId: string;
    keyVersion: number;
  }): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }> {
    return (await this.send("encrypt-snapshot", params as unknown as Record<string, unknown>)) as {
      ciphertext: Uint8Array;
      nonce: Uint8Array;
    };
  }

  async decryptSnapshot(params: {
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    documentId: string;
    keyVersion: number;
  }): Promise<Uint8Array> {
    const result = (await this.send(
      "decrypt-snapshot",
      params as unknown as Record<string, unknown>,
    )) as { plaintext: Uint8Array };
    return result.plaintext;
  }

  async hasDek(documentId: string, keyVersion?: number): Promise<boolean> {
    const result = (await this.send("has-dek", { documentId, keyVersion })) as { hasDek: boolean };
    return result.hasDek;
  }

  async cacheDek(params: {
    documentId: string;
    dek: Uint8Array;
    keyVersion: number;
  }): Promise<void> {
    await this.send("cache-dek", params as unknown as Record<string, unknown>);
  }

  async evictDek(documentId: string, keyVersion: number): Promise<void> {
    await this.send("evict-dek", { documentId, keyVersion });
  }

  // ── KEK operations ────────────────────────────────────

  async encryptKekForDevice(
    params: KekForDeviceParams,
  ): Promise<{ encrypted: Uint8Array; nonce: Uint8Array }> {
    return (await this.send(
      "encrypt-kek-for-device",
      params as unknown as Record<string, unknown>,
    )) as { encrypted: Uint8Array; nonce: Uint8Array };
  }

  async decryptKekFromDeviceEnvelope(params: KekFromDeviceEnvelopeParams): Promise<void> {
    await this.send(
      "decrypt-kek-from-device-envelope",
      params as unknown as Record<string, unknown>,
    );
  }

  async encryptKekForMember(
    params: KekForMemberParams,
  ): Promise<{ encrypted: Uint8Array; nonce: Uint8Array }> {
    return (await this.send(
      "encrypt-kek-for-member",
      params as unknown as Record<string, unknown>,
    )) as { encrypted: Uint8Array; nonce: Uint8Array };
  }

  async decryptKekFromMemberEnvelope(params: KekFromMemberEnvelopeParams): Promise<void> {
    await this.send(
      "decrypt-kek-from-member-envelope",
      params as unknown as Record<string, unknown>,
    );
  }

  async wrapKekWithUmk(
    params: KekBackupParams,
  ): Promise<{ encrypted: Uint8Array; nonce: Uint8Array }> {
    return (await this.send("wrap-kek-with-umk", params as unknown as Record<string, unknown>)) as {
      encrypted: Uint8Array;
      nonce: Uint8Array;
    };
  }

  async unwrapKekFromBackup(params: KekFromBackupParams): Promise<void> {
    await this.send("unwrap-kek-from-backup", params as unknown as Record<string, unknown>);
  }

  async encryptKekForInvitation(
    params: KekForInvitationParams,
  ): Promise<{ encrypted: Uint8Array; nonce: Uint8Array }> {
    return (await this.send(
      "encrypt-kek-for-invitation",
      params as unknown as Record<string, unknown>,
    )) as { encrypted: Uint8Array; nonce: Uint8Array };
  }

  async decryptKekFromInvitation(params: KekFromInvitationParams): Promise<void> {
    await this.send("decrypt-kek-from-invitation", params as unknown as Record<string, unknown>);
  }

  async setActiveKekVersion(workspaceId: string, keyVersion: number): Promise<void> {
    await this.send("set-active-kek-version", { workspaceId, keyVersion });
  }

  async resolveKek(
    workspaceId: string,
    keyVersion?: number,
  ): Promise<{ found: boolean; keyVersion?: number }> {
    return (await this.send("resolve-kek", { workspaceId, keyVersion })) as {
      found: boolean;
      keyVersion?: number;
    };
  }

  async cacheKek(params: {
    workspaceId: string;
    kek: Uint8Array;
    keyVersion: number;
  }): Promise<void> {
    await this.send("cache-kek", params as unknown as Record<string, unknown>);
  }

  // ── Signing ───────────────────────────────────────────

  async signPop(params: {
    challenge: string;
    deviceId: string;
  }): Promise<{ signature: Uint8Array }> {
    return (await this.send("sign-pop", params)) as { signature: Uint8Array };
  }

  async signWsEnvelope(params: {
    prefix: string;
    ciphertext: string;
    nonce: string;
    publicData: Record<string, unknown>;
  }): Promise<{ signature: Uint8Array }> {
    return (await this.send("sign-ws-envelope", params)) as {
      signature: Uint8Array;
    };
  }

  async signMessage(params: {
    action: string;
    payload: Record<string, unknown>;
  }): Promise<{ signature: Uint8Array }> {
    return (await this.send("sign-message", params)) as { signature: Uint8Array };
  }

  async signDeviceApproval(params: {
    deviceId: string;
    deviceSigningPublic: Uint8Array;
    deviceEcdhPublic: Uint8Array;
    clientNonce: Uint8Array;
  }): Promise<{ signature: Uint8Array }> {
    return (await this.send(
      "sign-device-approval",
      params as unknown as Record<string, unknown>,
    )) as {
      signature: Uint8Array;
    };
  }

  async signDeviceRegistration(params: {
    deviceSigningPublic: Uint8Array;
    deviceEcdhPublic: Uint8Array;
    clientNonce: Uint8Array;
  }): Promise<{ signature: Uint8Array }> {
    return (await this.send(
      "sign-device-registration",
      params as unknown as Record<string, unknown>,
    )) as { signature: Uint8Array };
  }

  async signRecoveryChallenge(message: Uint8Array): Promise<{ signature: Uint8Array }> {
    return (await this.send("sign-recovery-challenge", {
      message: message as unknown,
    })) as {
      signature: Uint8Array;
    };
  }

  async signSessionProof(params: {
    prefix: string;
    localSessionId: string;
    remoteSessionId: string;
  }): Promise<{ signature: Uint8Array }> {
    return (await this.send("sign-session-proof", params)) as {
      signature: Uint8Array;
    };
  }

  // ── Verification ──────────────────────────────────────

  async verifySessionProof(params: {
    prefix: string;
    localSessionId: string;
    remoteSessionId: string;
    signature: Uint8Array;
    signingPubKey: Uint8Array;
  }): Promise<boolean> {
    const result = (await this.send(
      "verify-session-proof",
      params as unknown as Record<string, unknown>,
    )) as { valid: boolean };
    return result.valid;
  }

  async verifyWsSignature(params: {
    prefix: string;
    ciphertext: string;
    nonce: string;
    publicData: Record<string, unknown>;
    signature: Uint8Array;
    signingPubKey: Uint8Array;
  }): Promise<boolean> {
    const result = (await this.send(
      "verify-ws-signature",
      params as unknown as Record<string, unknown>,
    )) as { valid: boolean };
    return result.valid;
  }

  async verifyEd25519(params: {
    message: Uint8Array;
    signature: Uint8Array;
    publicKey: Uint8Array;
  }): Promise<boolean> {
    const result = (await this.send(
      "verify-ed25519",
      params as unknown as Record<string, unknown>,
    )) as {
      valid: boolean;
    };
    return result.valid;
  }

  async verifyDeviceIdentitySignature(params: {
    deviceId: string;
    deviceSigningPublic: Uint8Array;
    deviceEcdhPublic: Uint8Array;
    clientNonce: Uint8Array;
    identitySignature: Uint8Array;
    identitySigningPublic: Uint8Array;
  }): Promise<boolean> {
    const result = (await this.send(
      "verify-device-identity-signature",
      params as unknown as Record<string, unknown>,
    )) as { valid: boolean };
    return result.valid;
  }

  // ── Hashing ───────────────────────────────────────────

  async computeUpdateHash(params: Record<string, unknown>): Promise<string> {
    const result = (await this.send("compute-update-hash", params)) as { hash: string };
    return result.hash;
  }

  async computeSnapshotProof(params: {
    ciphertextHash: string;
    parentProof: string;
    snapshotId: string;
  }): Promise<string> {
    const result = (await this.send("compute-snapshot-proof", params)) as { proof: string };
    return result.proof;
  }

  async blake3Hash(data: Uint8Array): Promise<Uint8Array> {
    return (await this.send("blake3-hash", { data: data as unknown })) as Uint8Array;
  }

  async computeSas(params: {
    identitySigningPublic: Uint8Array;
    deviceSigningPublic: Uint8Array;
    deviceEcdhPublic: Uint8Array;
    clientNonce: Uint8Array;
  }): Promise<SasResultData> {
    return (await this.send(
      "compute-sas",
      params as unknown as Record<string, unknown>,
    )) as SasResultData;
  }

  async calculateFingerprint(signingPublicKey: Uint8Array): Promise<string> {
    const result = (await this.send("calculate-fingerprint", {
      signingPublicKey: signingPublicKey as unknown,
    })) as {
      fingerprint: string;
    };
    return result.fingerprint;
  }

  // ── ECDH ──────────────────────────────────────────────

  async ecdhEncrypt(params: {
    theirPublic: Uint8Array;
    plaintext: Uint8Array;
    aad: Uint8Array;
    hkdfInfo: string;
  }): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }> {
    return (await this.send("ecdh-encrypt", params as unknown as Record<string, unknown>)) as {
      ciphertext: Uint8Array;
      nonce: Uint8Array;
    };
  }

  async ecdhDecrypt(params: {
    theirPublic: Uint8Array;
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    aad: Uint8Array;
    hkdfInfo: string;
  }): Promise<Uint8Array> {
    const result = (await this.send(
      "ecdh-decrypt",
      params as unknown as Record<string, unknown>,
    )) as {
      plaintext: Uint8Array;
    };
    return result.plaintext;
  }

  async ecdhEncryptUmkForDevice(params: {
    theirPublic: Uint8Array;
    senderDeviceId: string;
    targetDeviceId: string;
  }): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }> {
    return (await this.send("ecdh-encrypt-umk", params as unknown as Record<string, unknown>)) as {
      ciphertext: Uint8Array;
      nonce: Uint8Array;
    };
  }

  async ecdhDecryptUmkFromDevice(params: {
    theirPublic: Uint8Array;
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    senderDeviceId: string;
    targetDeviceId: string;
  }): Promise<void> {
    await this.send("ecdh-decrypt-umk", params as unknown as Record<string, unknown>);
  }

  // ── Trust transfer ────────────────────────────────────

  async encryptTrustState(params: {
    targetDeviceId: string;
    targetDeviceEcdhPublic: Uint8Array;
    transferNonce: Uint8Array;
  }): Promise<
    { empty: true } | { ciphertext: Uint8Array; nonce: Uint8Array; signature: Uint8Array }
  > {
    return (await this.send("encrypt-trust-state", params as unknown as Record<string, unknown>)) as
      | { empty: true }
      | { ciphertext: Uint8Array; nonce: Uint8Array; signature: Uint8Array };
  }

  async decryptTrustState(params: {
    senderDeviceEcdhPublic: Uint8Array;
    senderIdentitySigningPublic: Uint8Array;
    senderDeviceId: string;
    transferNonce: Uint8Array;
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    signature: Uint8Array;
  }): Promise<{ imported: number }> {
    return (await this.send(
      "decrypt-trust-state",
      params as unknown as Record<string, unknown>,
    )) as { imported: number };
  }

  // ── TOFU ──────────────────────────────────────────────

  async tofuVerify(params: {
    userId: string;
    deviceId: string;
    signingPublicKey: Uint8Array;
    ecdhPublicKey: Uint8Array;
  }): Promise<{ status: string }> {
    return (await this.send("tofu-verify", params as unknown as Record<string, unknown>)) as {
      status: string;
    };
  }

  async tofuVerifyAllDevices(params: {
    devices: Array<{
      userId: string;
      deviceId: string;
      signingPublicKey: Uint8Array;
      ecdhPublicKey: Uint8Array;
    }>;
  }): Promise<{ errors: string[] }> {
    return (await this.send(
      "tofu-verify-all-devices",
      params as unknown as Record<string, unknown>,
    )) as { errors: string[] };
  }

  async tofuTrustDevice(params: {
    userId: string;
    deviceId: string;
    signingPublicKey: Uint8Array;
    ecdhPublicKey: Uint8Array;
  }): Promise<void> {
    await this.send("tofu-trust-device", params as unknown as Record<string, unknown>);
  }

  async tofuUpdateLastSeen(params: { userId: string; deviceId: string }): Promise<void> {
    await this.send("tofu-update-last-seen", params);
  }

  async tofuHandleResult(result: {
    status: string;
    newEntry?: {
      userId: string;
      deviceId: string;
      signingPublicKey: Uint8Array;
      ecdhPublicKey: Uint8Array;
      firstSeenAt: number;
      lastSeenAt: number;
    };
  }): Promise<void> {
    await this.send("tofu-handle-result", { result } as unknown as Record<string, unknown>);
  }

  // ── DSK wrapping (for persistence) ────────────────────

  async wrapWithPdk(params: {
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
  }> {
    return (await this.send("wrap-with-pdk", params as unknown as Record<string, unknown>)) as {
      wrappedUmk: { ciphertext: string; nonce: string } | null;
      wrappedDeviceKeys: {
        ecdh: { ciphertext: string; nonce: string };
        signing: { ciphertext: string; nonce: string };
      } | null;
    };
  }

  async unwrapWithPdk(params: {
    userId: string;
    passwordParams: {
      password: string;
      salt: Uint8Array;
      kdfParams: { memory: number; iterations: number; parallelism: number };
    };
    wrappedUmk?: { ciphertext: string; nonce: string };
    wrappedDeviceEcdh?: { ciphertext: string; nonce: string };
    wrappedDeviceSigning?: { ciphertext: string; nonce: string };
  }): Promise<{ umkRestored: boolean; deviceKeysRestored: boolean }> {
    return (await this.send("unwrap-with-pdk", params as unknown as Record<string, unknown>)) as {
      umkRestored: boolean;
      deviceKeysRestored: boolean;
    };
  }

  async wrapUmkWithDsk(userId: string): Promise<{ ciphertext: ArrayBuffer; iv: ArrayBuffer }> {
    return (await this.send("wrap-umk-with-dsk", { userId })) as {
      ciphertext: ArrayBuffer;
      iv: ArrayBuffer;
    };
  }

  async wrapDeviceKeysWithDsk(userId: string): Promise<{
    wrappedEcdh: { ciphertext: ArrayBuffer; iv: ArrayBuffer };
    wrappedSigning: { ciphertext: ArrayBuffer; iv: ArrayBuffer };
  }> {
    return (await this.send("wrap-device-keys-with-dsk", { userId })) as {
      wrappedEcdh: { ciphertext: ArrayBuffer; iv: ArrayBuffer };
      wrappedSigning: { ciphertext: ArrayBuffer; iv: ArrayBuffer };
    };
  }

  // ── Internal ──────────────────────────────────────────

  private async sendWithRateLimitRetry(
    type: CryptoRequestType,
    payload: Record<string, unknown>,
    maxRetries = 2,
  ): Promise<unknown> {
    for (let attempt = 0; ; attempt++) {
      try {
        return await this.send(type, payload);
      } catch (err) {
        if (
          err instanceof CryptoWorkerError &&
          err.code === "rate_limited" &&
          attempt < maxRetries
        ) {
          await new Promise((r) => setTimeout(r, 10_000));
          continue;
        }
        throw err;
      }
    }
  }

  private send(type: CryptoRequestType, payload: Record<string, unknown>): Promise<unknown> {
    if (this.terminated) {
      return Promise.reject(new Error("Worker terminated"));
    }

    return new Promise((resolve, reject) => {
      const id = crypto.randomUUID();
      this.pending.set(id, { resolve, reject });

      const request: CryptoRequest = { id, type, payload };
      this.worker.postMessage(request);
    });
  }

  async generateDsk(): Promise<void> {
    await this.send("generate-dsk", {});
  }

  async tofuGetAllEntries(): Promise<
    Array<{
      userId: string;
      deviceId: string;
      signingPublicKey: Uint8Array;
      ecdhPublicKey: Uint8Array;
      firstSeenAt: number;
      lastSeenAt: number;
    }>
  > {
    const result = (await this.send("tofu-get-all-entries", {})) as {
      entries: Array<{
        userId: string;
        deviceId: string;
        signingPublicKey: Uint8Array;
        ecdhPublicKey: Uint8Array;
        firstSeenAt: number;
        lastSeenAt: number;
      }>;
    };
    return result.entries;
  }

  async tofuImportEntries(
    entries: Array<{
      userId: string;
      deviceId: string;
      signingPublicKey: Uint8Array;
      ecdhPublicKey: Uint8Array;
      firstSeenAt: number;
      lastSeenAt: number;
    }>,
  ): Promise<void> {
    await this.send("tofu-import-entries", { entries });
  }

  async generateInvitationToken(): Promise<{
    token: string;
    tokenHash: string;
    tokenPrefix: string;
  }> {
    return (await this.send("generate-invitation-token", {})) as {
      token: string;
      tokenHash: string;
      tokenPrefix: string;
    };
  }

  async sha256Hash(data: Uint8Array): Promise<string> {
    const result = (await this.send("sha256-hash", { data })) as { hash: string };
    return result.hash;
  }
}

// ── Singleton ─────────────────────────────────────────────

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
