import { describe, expect, it } from "vite-plus/test";
import { blake3Base64Url } from "./hash";
import { canonicalizeStrictBytes } from "./jcs";
import { buildRecoverableIdentitySecretRecord } from "./recoverable-identity-secret-record";

describe("recoverable identity secret record", () => {
  it("binds both encrypted branches to the exact epoch and immutable preimage", () => {
    const userId = crypto.randomUUID();
    const params = {
      id: crypto.randomUUID(),
      userId,
      identityKeyEpoch: 1,
      previousRecordHash: "GENESIS",
      encryptedSigningPrivateMaterial: new Uint8Array([1, 2, 3]),
      signingPrivateMaterialNonce: new Uint8Array(24).fill(4),
      encryptedEncryptionPrivateMaterial: new Uint8Array([5, 6, 7]),
      encryptionPrivateMaterialNonce: new Uint8Array(24).fill(8),
      signingKeyId: "F3Yv3dlppFOSXWVxesPuohMgtmtUNC_eFRKNbK8hIV8",
      encryptionKeyId: "EOXPPTyKT580aMjMWO6oSJKiL9rbwayyJBAZAETB1VM",
      isCurrent: true,
    };

    const first = buildRecoverableIdentitySecretRecord(params);
    const nextEpoch = buildRecoverableIdentitySecretRecord({ ...params, identityKeyEpoch: 2 });

    expect(Object.keys(first).sort()).toHaveLength(14);
    expect(first.identity_key_epoch).toBe(1);
    expect(first.previous_record_hash).toBe("GENESIS");
    expect(first.signing_material_aad_hash).not.toBe(nextEpoch.signing_material_aad_hash);
    expect(first.encryption_material_aad_hash).not.toBe(nextEpoch.encryption_material_aad_hash);
    expect(first.record_hash).not.toBe(nextEpoch.record_hash);
    expect(first.signing_material_aad_hash).toBe(
      blake3Base64Url(
        canonicalizeStrictBytes({
          protocol: "refmd.hybrid-signing-private-key-material-encryption",
          version: 1,
          purpose: "identity_hybrid_signing_private_key_material",
          owner_kind: "identity",
          owner_id: userId,
          signing_key_id: params.signingKeyId,
          suite_id: "refmd-v2-hybrid-signature-ed25519-mldsa65",
          suite_rank: 1000,
          storage_scope: {
            kind: "user_identity_key",
            user_id: userId,
            identity_key_epoch: 1,
          },
        }),
      ),
    );
    expect(first.encryption_material_aad_hash).toBe(
      blake3Base64Url(
        canonicalizeStrictBytes({
          protocol: "refmd.hybrid-encryption-private-key-material-encryption",
          version: 1,
          purpose: "identity_hybrid_encryption_private_key_material",
          owner_kind: "identity",
          owner_id: userId,
          encryption_key_id: params.encryptionKeyId,
          suite_id:
            "refmd-v2-draft-ietf-hpke-pq-04-mlkem768-x25519-hkdfsha256-chacha20poly1305-ed25519-mldsa65",
          suite_rank: 1000,
          storage_scope: {
            kind: "user_identity_key",
            user_id: userId,
            identity_key_epoch: 1,
          },
        }),
      ),
    );
  });
});
