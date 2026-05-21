import { x25519 } from "@noble/curves/ed25519.js";
import {
  computeSigningKeyId,
  generateHybridSigningPrivateKeyMaterial,
  publicKeyMaterialFromPrivate,
  type HybridSigningPrivateKeyMaterial,
  type HybridSigningPublicKeyMaterial,
} from "./signature";
import {
  computeHybridEncryptionKeyId,
  generateHybridEncryptionPrivateKeyMaterial,
  publicHybridEncryptionMaterialFromPrivate,
  type HybridEncryptionPrivateKeyMaterial,
  type HybridEncryptionPublicKeyMaterial,
} from "./hybrid-encryption";
import { decodeBase64UrlStrict, randomBytes } from "./encoding";

export interface DeviceKeyPair {
  ecdhPrivate: Uint8Array;
  ecdhPublic: Uint8Array;
  hybridEncryptionPrivateKeyMaterial: HybridEncryptionPrivateKeyMaterial;
  hybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  encryptionKeyId: string;
  hybridSigningPrivateKeyMaterial: HybridSigningPrivateKeyMaterial;
  hybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  signingKeyId: string;
}

export function generateDeviceKeyPair(
  deviceId: string,
  ownerKind: "device" | "share_participant_device" = "device",
): DeviceKeyPair {
  const hybridEncryptionPrivateKeyMaterial = generateHybridEncryptionPrivateKeyMaterial(
    ownerKind,
    deviceId,
  );
  const hybridEncryptionPublicKeyMaterial = publicHybridEncryptionMaterialFromPrivate(
    hybridEncryptionPrivateKeyMaterial,
  );
  const ecdhPrivate = decodeX25519Private(hybridEncryptionPrivateKeyMaterial);
  const hybridSigningPrivateKeyMaterial = generateHybridSigningPrivateKeyMaterial(
    ownerKind,
    deviceId,
  );
  const hybridSigningPublicKeyMaterial = publicKeyMaterialFromPrivate(
    hybridSigningPrivateKeyMaterial,
  );
  return {
    ecdhPrivate,
    ecdhPublic: x25519.getPublicKey(ecdhPrivate),
    hybridEncryptionPrivateKeyMaterial,
    hybridEncryptionPublicKeyMaterial,
    encryptionKeyId: computeHybridEncryptionKeyId(hybridEncryptionPublicKeyMaterial),
    hybridSigningPrivateKeyMaterial,
    hybridSigningPublicKeyMaterial,
    signingKeyId: computeSigningKeyId(hybridSigningPublicKeyMaterial),
  };
}

function decodeX25519Private(material: HybridEncryptionPrivateKeyMaterial): Uint8Array {
  return decodeBase64UrlStrict(material.x25519_private, 32);
}

export function generateClientNonce(): Uint8Array {
  return randomBytes(16);
}
