import { describe, expect, it } from "vite-plus/test";
import { buildRecoveryTargetDeviceRegistration } from "./recover";

describe("recover", () => {
  it("builds the target device payload embedded in the recovery session", () => {
    const request = buildRecoveryTargetDeviceRegistration({
      deviceId: "device-1",
      identitySigningKeyId: "identity-signing-key",
      publicKeys: {
        ecdhPublic: new Uint8Array([1, 2]),
        hybridEncryptionPublicKeyMaterial: {
          protocol: "refmd.hybrid-encryption-key-material",
          version: 1,
          suite_id:
            "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65",
          suite_rank: 1000,
          owner_kind: "device",
          owner_id: "device-1",
          x25519_public: "x25519",
          mlkem768_public: "mlkem",
          hybrid_public: "hybrid",
        },
        encryptionKeyId: "device-encryption-key",
        hybridSigningPublicKeyMaterial: {
          protocol: "refmd.hybrid-signing-key-material",
          version: 1,
          suite_id: "refmd-v2-hybrid-signature-ed25519-mldsa65",
          suite_rank: 1000,
          owner_kind: "device",
          owner_id: "device-1",
          ed25519_public: "ed25519",
          mldsa65_public: "mldsa",
        },
        signingKeyId: "device-signing-key",
      },
      clientNonce: new Uint8Array([3, 4]),
    });

    expect(request).toMatchObject({
      device_id: "device-1",
      identity_signing_key_id: "identity-signing-key",
    });
    expect(request).not.toHaveProperty("ake_responder_prekeys");
    expect(request).not.toHaveProperty("registration_challenge");
  });
});
