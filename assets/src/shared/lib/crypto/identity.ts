import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { decodeBase64UrlStrict, randomBytes } from "./encoding";
import { buildIdentityHybridEncryptionPrivateKeyMaterialAad, buildIdentitySigningAad } from "./aad";
import {
  assertHybridSigningPrivateKeyMaterial,
  computeSigningKeyId,
  generateHybridSigningPrivateKeyMaterial,
  publicKeyMaterialFromPrivate,
  type HybridSigningPrivateKeyMaterial,
  type HybridSigningPublicKeyMaterial,
} from "./signature";
import { canonicalizeStrictBytes, parseJsonStrictBytes, type StrictJsonValue } from "./jcs";
import {
  assertHybridEncryptionPrivateKeyMaterial,
  computeHybridEncryptionKeyId,
  generateHybridEncryptionPrivateKeyMaterial,
  publicHybridEncryptionMaterialFromPrivate,
  type HybridEncryptionPrivateKeyMaterial,
  type HybridEncryptionPublicKeyMaterial,
} from "./hybrid-encryption";

export interface IdentityKeyPair {
  ecdhPrivate: Uint8Array;
  ecdhPublic: Uint8Array;
  hybridEncryptionPrivateKeyMaterial: HybridEncryptionPrivateKeyMaterial;
  hybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  encryptionKeyId: string;
  hybridSigningPrivateKeyMaterial: HybridSigningPrivateKeyMaterial;
  hybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
}

export interface EncryptedIdentityKeys {
  encryptedHybridEncryptionPrivateKeyMaterial: Uint8Array;
  hybridEncryptionPrivateKeyMaterialNonce: Uint8Array;
  encryptionKeyId: string;
  encryptedHybridSigningPrivateKeyMaterial: Uint8Array;
  hybridSigningPrivateKeyMaterialNonce: Uint8Array;
  signingKeyId: string;
}

export function generateIdentityKeyPair(userId: string): IdentityKeyPair {
  const hybridEncryptionPrivateKeyMaterial = generateHybridEncryptionPrivateKeyMaterial(
    "identity",
    userId,
  );
  const hybridEncryptionPublicKeyMaterial = publicHybridEncryptionMaterialFromPrivate(
    hybridEncryptionPrivateKeyMaterial,
  );
  const ecdhPrivate = decodeBase64UrlStrict(hybridEncryptionPrivateKeyMaterial.x25519_private, 32);
  const hybridSigningPrivateKeyMaterial = generateHybridSigningPrivateKeyMaterial(
    "identity",
    userId,
  );
  return {
    ecdhPrivate,
    ecdhPublic: x25519.getPublicKey(ecdhPrivate),
    hybridEncryptionPrivateKeyMaterial,
    hybridEncryptionPublicKeyMaterial,
    encryptionKeyId: computeHybridEncryptionKeyId(hybridEncryptionPublicKeyMaterial),
    hybridSigningPrivateKeyMaterial,
    hybridSigningPublicKeyMaterial: publicKeyMaterialFromPrivate(hybridSigningPrivateKeyMaterial),
  };
}

export function encryptIdentityKeys(
  keyPair: IdentityKeyPair,
  umk: Uint8Array,
  userId: string,
  identityKeyEpoch: number,
): EncryptedIdentityKeys {
  const encryptionNonce = randomBytes(24);
  const signingNonce = randomBytes(24);
  const encryptionKeyId = computeHybridEncryptionKeyId(keyPair.hybridEncryptionPublicKeyMaterial);
  const signingKeyId = computeSigningKeyId(keyPair.hybridSigningPublicKeyMaterial);
  const encryptionCipher = xchacha20poly1305(
    umk,
    encryptionNonce,
    buildIdentityHybridEncryptionPrivateKeyMaterialAad(userId, encryptionKeyId, identityKeyEpoch),
  );
  const signingCipher = xchacha20poly1305(
    umk,
    signingNonce,
    buildIdentitySigningAad(userId, signingKeyId, identityKeyEpoch),
  );
  return {
    encryptedHybridEncryptionPrivateKeyMaterial: encryptionCipher.encrypt(
      canonicalizeStrictBytes(
        keyPair.hybridEncryptionPrivateKeyMaterial as unknown as StrictJsonValue,
      ),
    ),
    hybridEncryptionPrivateKeyMaterialNonce: encryptionNonce,
    encryptionKeyId,
    encryptedHybridSigningPrivateKeyMaterial: signingCipher.encrypt(
      canonicalizeStrictBytes(
        keyPair.hybridSigningPrivateKeyMaterial as unknown as StrictJsonValue,
      ),
    ),
    hybridSigningPrivateKeyMaterialNonce: signingNonce,
    signingKeyId,
  };
}

export function decryptIdentityPrivateKeys(
  encrypted: EncryptedIdentityKeys,
  umk: Uint8Array,
  userId: string,
  identityKeyEpoch: number,
): IdentityKeyPair {
  const encryptionCipher = xchacha20poly1305(
    umk,
    encrypted.hybridEncryptionPrivateKeyMaterialNonce,
    buildIdentityHybridEncryptionPrivateKeyMaterialAad(
      userId,
      encrypted.encryptionKeyId,
      identityKeyEpoch,
    ),
  );
  const signingCipher = xchacha20poly1305(
    umk,
    encrypted.hybridSigningPrivateKeyMaterialNonce,
    buildIdentitySigningAad(userId, encrypted.signingKeyId, identityKeyEpoch),
  );
  const decodedEncryptionPrivateMaterial = parseJsonStrictBytes(
    encryptionCipher.decrypt(encrypted.encryptedHybridEncryptionPrivateKeyMaterial),
  );
  assertHybridEncryptionPrivateKeyMaterial(decodedEncryptionPrivateMaterial);
  if (
    decodedEncryptionPrivateMaterial.owner_kind !== "identity" ||
    decodedEncryptionPrivateMaterial.owner_id !== userId
  ) {
    throw new Error("identity_hybrid_encryption_private_key_material_owner_mismatch");
  }
  const hybridEncryptionPublicKeyMaterial = publicHybridEncryptionMaterialFromPrivate(
    decodedEncryptionPrivateMaterial,
  );
  if (
    computeHybridEncryptionKeyId(hybridEncryptionPublicKeyMaterial) !== encrypted.encryptionKeyId
  ) {
    throw new Error("identity_hybrid_encryption_private_key_material_key_id_mismatch");
  }
  const decodedPrivateMaterial = parseJsonStrictBytes(
    signingCipher.decrypt(encrypted.encryptedHybridSigningPrivateKeyMaterial),
  );
  assertHybridSigningPrivateKeyMaterial(decodedPrivateMaterial);
  if (
    decodedPrivateMaterial.owner_kind !== "identity" ||
    decodedPrivateMaterial.owner_id !== userId
  ) {
    throw new Error("identity_hybrid_signing_private_key_material_owner_mismatch");
  }
  if (
    computeSigningKeyId(publicKeyMaterialFromPrivate(decodedPrivateMaterial)) !==
    encrypted.signingKeyId
  ) {
    throw new Error("identity_hybrid_signing_private_key_material_key_id_mismatch");
  }
  const ecdhPrivate = decodeBase64UrlStrict(decodedEncryptionPrivateMaterial.x25519_private, 32);
  const x25519Public = x25519.getPublicKey(ecdhPrivate);
  return {
    ecdhPrivate,
    ecdhPublic: x25519Public,
    hybridEncryptionPrivateKeyMaterial: decodedEncryptionPrivateMaterial,
    hybridEncryptionPublicKeyMaterial,
    encryptionKeyId: computeHybridEncryptionKeyId(hybridEncryptionPublicKeyMaterial),
    hybridSigningPrivateKeyMaterial: decodedPrivateMaterial,
    hybridSigningPublicKeyMaterial: publicKeyMaterialFromPrivate(decodedPrivateMaterial),
  };
}
