import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { decodeBase64UrlStrict, encodeBase64Url } from "./encoding";
import { blake3Base64Url } from "./hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "./jcs";
import { CURRENT_PROTOCOL_VERSION, CURRENT_SUITE_RANK, SUITE_IDS } from "./suite";

export const HYBRID_ENCRYPTION_KEY_MATERIAL_PROTOCOL = "refmd.hybrid-encryption-key-material";

export const HYBRID_ENCRYPTION_LENGTHS = {
  X25519_PUBLIC: 32,
  X25519_PRIVATE: 32,
  MLKEM768_PUBLIC: 1184,
  MLKEM768_PRIVATE: 2400,
  HYBRID_PUBLIC: 1216,
} as const;

export type HybridEncryptionOwnerKind = "identity" | "device" | "share_participant_device";

export interface HybridEncryptionPublicKeyMaterial {
  protocol: typeof HYBRID_ENCRYPTION_KEY_MATERIAL_PROTOCOL;
  version: typeof CURRENT_PROTOCOL_VERSION;
  suite_id: typeof SUITE_IDS.SIGNED_PQ_HYBRID_WRAP;
  suite_rank: typeof CURRENT_SUITE_RANK;
  owner_kind: HybridEncryptionOwnerKind;
  owner_id: string;
  x25519_public: string;
  mlkem768_public: string;
  hybrid_public: string;
}

export type IdentityHybridEncryptionPublicKeyMaterial = HybridEncryptionPublicKeyMaterial & {
  owner_kind: "identity";
};

export type DeviceHybridEncryptionPublicKeyMaterial = HybridEncryptionPublicKeyMaterial & {
  owner_kind: "device";
};

export interface HybridEncryptionPrivateKeyMaterial extends HybridEncryptionPublicKeyMaterial {
  x25519_private: string;
  mlkem768_private: string;
}

export function generateHybridEncryptionPrivateKeyMaterial(
  ownerKind: HybridEncryptionOwnerKind,
  ownerId: string,
): HybridEncryptionPrivateKeyMaterial {
  const x25519Private = x25519.utils.randomSecretKey();
  const x25519Public = x25519.getPublicKey(x25519Private);
  const mlkem = ml_kem768.keygen();
  const hybridPublic = concatBytes(mlkem.publicKey, x25519Public);

  return {
    protocol: HYBRID_ENCRYPTION_KEY_MATERIAL_PROTOCOL,
    version: CURRENT_PROTOCOL_VERSION,
    suite_id: SUITE_IDS.SIGNED_PQ_HYBRID_WRAP,
    suite_rank: CURRENT_SUITE_RANK,
    owner_kind: ownerKind,
    owner_id: ownerId,
    x25519_private: encodeBase64Url(x25519Private),
    x25519_public: encodeBase64Url(x25519Public),
    mlkem768_private: encodeBase64Url(mlkem.secretKey),
    mlkem768_public: encodeBase64Url(mlkem.publicKey),
    hybrid_public: encodeBase64Url(hybridPublic),
  };
}

export function publicHybridEncryptionMaterialFromPrivate(
  material: HybridEncryptionPrivateKeyMaterial,
): HybridEncryptionPublicKeyMaterial {
  assertHybridEncryptionPrivateKeyMaterial(material);

  return {
    protocol: HYBRID_ENCRYPTION_KEY_MATERIAL_PROTOCOL,
    version: CURRENT_PROTOCOL_VERSION,
    suite_id: SUITE_IDS.SIGNED_PQ_HYBRID_WRAP,
    suite_rank: CURRENT_SUITE_RANK,
    owner_kind: material.owner_kind,
    owner_id: material.owner_id,
    x25519_public: material.x25519_public,
    mlkem768_public: material.mlkem768_public,
    hybrid_public: material.hybrid_public,
  };
}

export function computeHybridEncryptionKeyId(material: HybridEncryptionPublicKeyMaterial): string {
  assertHybridEncryptionPublicKeyMaterial(material);
  return blake3Base64Url(canonicalizeStrictBytes(material as unknown as StrictJsonValue));
}

export function assertHybridEncryptionPublicKeyMaterial(
  material: unknown,
): asserts material is HybridEncryptionPublicKeyMaterial {
  if (!material || typeof material !== "object") {
    throw new Error("hybrid_encryption_public_key_material_invalid");
  }

  const value = material as Record<string, unknown>;
  const expectedKeys = [
    "hybrid_public",
    "mlkem768_public",
    "owner_id",
    "owner_kind",
    "protocol",
    "suite_id",
    "suite_rank",
    "version",
    "x25519_public",
  ].sort();

  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(expectedKeys)) {
    throw new Error("hybrid_encryption_public_key_material_keys_invalid");
  }
  assertCommonPublicMaterial(value);
}

export function assertHybridEncryptionPrivateKeyMaterial(
  material: unknown,
): asserts material is HybridEncryptionPrivateKeyMaterial {
  if (!material || typeof material !== "object") {
    throw new Error("hybrid_encryption_private_key_material_invalid");
  }

  const value = material as Record<string, unknown>;
  const expectedKeys = [
    "hybrid_public",
    "mlkem768_private",
    "mlkem768_public",
    "owner_id",
    "owner_kind",
    "protocol",
    "suite_id",
    "suite_rank",
    "version",
    "x25519_private",
    "x25519_public",
  ].sort();

  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(expectedKeys)) {
    throw new Error("hybrid_encryption_private_key_material_keys_invalid");
  }
  assertCommonPublicMaterial(value);

  const x25519Private = decodeBase64UrlStrict(
    value.x25519_private as string,
    HYBRID_ENCRYPTION_LENGTHS.X25519_PRIVATE,
  );
  const mlkemPrivate = decodeBase64UrlStrict(
    value.mlkem768_private as string,
    HYBRID_ENCRYPTION_LENGTHS.MLKEM768_PRIVATE,
  );

  const expectedX25519Public = encodeBase64Url(x25519.getPublicKey(x25519Private));
  const expectedMlkemPublic = encodeBase64Url(ml_kem768.getPublicKey(mlkemPrivate));

  if (expectedX25519Public !== value.x25519_public) {
    throw new Error("hybrid_encryption_x25519_public_mismatch");
  }
  if (expectedMlkemPublic !== value.mlkem768_public) {
    throw new Error("hybrid_encryption_mlkem768_public_mismatch");
  }
}

function assertCommonPublicMaterial(value: Record<string, unknown>): void {
  if (value.protocol !== HYBRID_ENCRYPTION_KEY_MATERIAL_PROTOCOL) {
    throw new Error("hybrid_encryption_protocol_invalid");
  }
  if (value.version !== CURRENT_PROTOCOL_VERSION) {
    throw new Error("hybrid_encryption_version_invalid");
  }
  if (value.suite_id !== SUITE_IDS.SIGNED_PQ_HYBRID_WRAP) {
    throw new Error("hybrid_encryption_suite_invalid");
  }
  if (value.suite_rank !== CURRENT_SUITE_RANK) {
    throw new Error("hybrid_encryption_suite_rank_invalid");
  }
  if (!["identity", "device", "share_participant_device"].includes(value.owner_kind as string)) {
    throw new Error("hybrid_encryption_owner_kind_invalid");
  }
  if (typeof value.owner_id !== "string" || value.owner_id.length === 0) {
    throw new Error("hybrid_encryption_owner_id_invalid");
  }

  const x25519Public = decodeBase64UrlStrict(
    value.x25519_public as string,
    HYBRID_ENCRYPTION_LENGTHS.X25519_PUBLIC,
  );
  const mlkemPublic = decodeBase64UrlStrict(
    value.mlkem768_public as string,
    HYBRID_ENCRYPTION_LENGTHS.MLKEM768_PUBLIC,
  );
  const hybridPublic = decodeBase64UrlStrict(
    value.hybrid_public as string,
    HYBRID_ENCRYPTION_LENGTHS.HYBRID_PUBLIC,
  );

  if (encodeBase64Url(concatBytes(mlkemPublic, x25519Public)) !== encodeBase64Url(hybridPublic)) {
    throw new Error("hybrid_encryption_hybrid_public_mismatch");
  }
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
