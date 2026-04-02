import type { SasResultData } from "./types";
import type { CryptoWorkerClientMethodContext } from "./client-shared";

export interface SignWorkerClientMethods {
  signPop(params: { challenge: string; deviceId: string }): Promise<{ signature: Uint8Array }>;
  signWsEnvelope(params: {
    prefix: string;
    ciphertext: string;
    nonce: string;
    publicData: Record<string, unknown>;
  }): Promise<{ signature: Uint8Array }>;
  signMessage(params: {
    action: string;
    payload: Record<string, unknown>;
  }): Promise<{ signature: Uint8Array }>;
  signDeviceApproval(params: {
    deviceId: string;
    deviceSigningPublic: Uint8Array;
    deviceEcdhPublic: Uint8Array;
    clientNonce: Uint8Array;
  }): Promise<{ signature: Uint8Array }>;
  signDeviceRegistration(params: {
    deviceSigningPublic: Uint8Array;
    deviceEcdhPublic: Uint8Array;
    clientNonce: Uint8Array;
  }): Promise<{ signature: Uint8Array }>;
  signRecoveryChallenge(message: Uint8Array): Promise<{ signature: Uint8Array }>;
  signSessionProof(params: {
    prefix: string;
    localSessionId: string;
    remoteSessionId: string;
  }): Promise<{ signature: Uint8Array }>;
  verifySessionProof(params: {
    prefix: string;
    localSessionId: string;
    remoteSessionId: string;
    signature: Uint8Array;
    signingPubKey: Uint8Array;
  }): Promise<boolean>;
  verifyWsSignature(params: {
    prefix: string;
    ciphertext: string;
    nonce: string;
    publicData: Record<string, unknown>;
    signature: Uint8Array;
    signingPubKey: Uint8Array;
  }): Promise<boolean>;
  verifyEd25519(params: {
    message: Uint8Array;
    signature: Uint8Array;
    publicKey: Uint8Array;
  }): Promise<boolean>;
  verifyDeviceIdentitySignature(params: {
    deviceId: string;
    deviceSigningPublic: Uint8Array;
    deviceEcdhPublic: Uint8Array;
    clientNonce: Uint8Array;
    identitySignature: Uint8Array;
    identitySigningPublic: Uint8Array;
  }): Promise<boolean>;
  computeUpdateHash(params: Record<string, unknown>): Promise<string>;
  computeSnapshotProof(params: {
    ciphertextHash: string;
    parentProof: string;
    snapshotId: string;
  }): Promise<string>;
  blake3Hash(data: Uint8Array): Promise<Uint8Array>;
  computeSas(params: {
    identitySigningPublic: Uint8Array;
    deviceSigningPublic: Uint8Array;
    deviceEcdhPublic: Uint8Array;
    clientNonce: Uint8Array;
  }): Promise<SasResultData>;
  calculateFingerprint(signingPublicKey: Uint8Array): Promise<string>;
  ecdhEncrypt(params: {
    theirPublic: Uint8Array;
    plaintext: Uint8Array;
    aad: Uint8Array;
    hkdfInfo: string;
  }): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }>;
  ecdhDecrypt(params: {
    theirPublic: Uint8Array;
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    aad: Uint8Array;
    hkdfInfo: string;
  }): Promise<Uint8Array>;
  ecdhEncryptUmkForDevice(params: {
    theirPublic: Uint8Array;
    senderDeviceId: string;
    targetDeviceId: string;
  }): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array }>;
  ecdhDecryptUmkFromDevice(params: {
    theirPublic: Uint8Array;
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    senderDeviceId: string;
    targetDeviceId: string;
  }): Promise<void>;
  encryptTrustState(params: {
    targetDeviceId: string;
    targetDeviceEcdhPublic: Uint8Array;
    transferNonce: Uint8Array;
  }): Promise<
    { empty: true } | { ciphertext: Uint8Array; nonce: Uint8Array; signature: Uint8Array }
  >;
  decryptTrustState(params: {
    senderDeviceEcdhPublic: Uint8Array;
    senderIdentitySigningPublic: Uint8Array;
    senderDeviceId: string;
    transferNonce: Uint8Array;
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    signature: Uint8Array;
  }): Promise<{ imported: number }>;
}

export const signWorkerClientMethods: SignWorkerClientMethods &
  ThisType<CryptoWorkerClientMethodContext> = {
  async signPop(params) {
    return (await this.send("sign-pop", params)) as { signature: Uint8Array };
  },

  async signWsEnvelope(params) {
    return (await this.send("sign-ws-envelope", params)) as { signature: Uint8Array };
  },

  async signMessage(params) {
    return (await this.send("sign-message", params)) as { signature: Uint8Array };
  },

  async signDeviceApproval(params) {
    return (await this.send("sign-device-approval", params)) as {
      signature: Uint8Array;
    };
  },

  async signDeviceRegistration(params) {
    return (await this.send("sign-device-registration", params)) as {
      signature: Uint8Array;
    };
  },

  async signRecoveryChallenge(message) {
    return (await this.send("sign-recovery-challenge", { message })) as {
      signature: Uint8Array;
    };
  },

  async signSessionProof(params) {
    return (await this.send("sign-session-proof", params)) as {
      signature: Uint8Array;
    };
  },

  async verifySessionProof(params) {
    const result = (await this.send("verify-session-proof", params)) as { valid: boolean };
    return result.valid;
  },

  async verifyWsSignature(params) {
    const result = (await this.send("verify-ws-signature", params)) as { valid: boolean };
    return result.valid;
  },

  async verifyEd25519(params) {
    const result = (await this.send("verify-ed25519", params)) as { valid: boolean };
    return result.valid;
  },

  async verifyDeviceIdentitySignature(params) {
    const result = (await this.send("verify-device-identity-signature", params)) as {
      valid: boolean;
    };
    return result.valid;
  },

  async computeUpdateHash(params) {
    const result = (await this.send("compute-update-hash", params)) as { hash: string };
    return result.hash;
  },

  async computeSnapshotProof(params) {
    const result = (await this.send("compute-snapshot-proof", params)) as { proof: string };
    return result.proof;
  },

  async blake3Hash(data) {
    return (await this.send("blake3-hash", { data })) as Uint8Array;
  },

  async computeSas(params) {
    return (await this.send("compute-sas", params)) as SasResultData;
  },

  async calculateFingerprint(signingPublicKey) {
    const result = (await this.send("calculate-fingerprint", {
      signingPublicKey,
    })) as {
      fingerprint: string;
    };
    return result.fingerprint;
  },

  async ecdhEncrypt(params) {
    return (await this.send("ecdh-encrypt", params)) as {
      ciphertext: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async ecdhDecrypt(params) {
    const result = (await this.send("ecdh-decrypt", params)) as { plaintext: Uint8Array };
    return result.plaintext;
  },

  async ecdhEncryptUmkForDevice(params) {
    return (await this.send("ecdh-encrypt-umk", params)) as {
      ciphertext: Uint8Array;
      nonce: Uint8Array;
    };
  },

  async ecdhDecryptUmkFromDevice(params) {
    await this.send("ecdh-decrypt-umk", params);
  },

  async encryptTrustState(params) {
    return (await this.send("encrypt-trust-state", params)) as
      | { empty: true }
      | { ciphertext: Uint8Array; nonce: Uint8Array; signature: Uint8Array };
  },

  async decryptTrustState(params) {
    return (await this.send("decrypt-trust-state", params)) as { imported: number };
  },
};
