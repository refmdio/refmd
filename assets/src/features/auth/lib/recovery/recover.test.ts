import { describe, expect, it } from "vite-plus/test";
import { buildRecoveryDeviceRegistrationRequest } from "./recover";
import type { InitialAkeResponderPrekeyRecord } from "@/shared/lib/crypto/initial-ake";

describe("recover", () => {
  it("includes initial AKE responder prekeys when creating the pending recovered device", () => {
    const initialAkeResponderPrekeys = {
      umk_distribution: { id: "umk" } as unknown as InitialAkeResponderPrekeyRecord,
      trust_transfer: { id: "trust" } as unknown as InitialAkeResponderPrekeyRecord,
      device_approval_kek_initial: [
        {
          workspace_id: "workspace-1",
          prekey: { id: "workspace-1" } as unknown as InitialAkeResponderPrekeyRecord,
        },
      ],
    } as unknown as Parameters<
      typeof buildRecoveryDeviceRegistrationRequest
    >[0]["initialAkeResponderPrekeys"];

    const request = buildRecoveryDeviceRegistrationRequest({
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
      registrationChallenge: "challenge",
      initialAkeResponderPrekeys,
    });

    expect(request).toMatchObject({
      device_id: "device-1",
      identity_signing_key_id: "identity-signing-key",
      ake_responder_prekeys: initialAkeResponderPrekeys,
    });
  });
});
