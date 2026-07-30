import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { generateMnemonic, mnemonicToSeed, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { encodeBase64Url, randomBytes } from "./encoding";
import { HKDF_ZERO_SALT } from "./constants";
import { buildRecoveryUmkWrapAad } from "./aad";
import {
  computeSigningKeyId,
  publicKeyMaterialFromPrivate,
  SIGNING_PRIVATE_KEY_MATERIAL_PROTOCOL,
  type HybridSigningPrivateKeyMaterial,
  type RecoveryAuthorizationHybridSigningPublicKeyMaterial,
} from "./signature";
import { CURRENT_PROTOCOL_VERSION, CURRENT_SUITE_RANK, SUITE_IDS } from "./suite";
interface RecoveryKeyData {
  mnemonic: string;
  ruk: Uint8Array;
  recoveryAuthorizationPublicKey: RecoveryAuthorizationHybridSigningPublicKeyMaterial;
  recoveryAuthorizationKeyId: string;
}
export async function generateRecoveryKey(userId: string): Promise<RecoveryKeyData> {
  const mnemonic = generateMnemonic(wordlist, 256);
  const ruk = await deriveRukFromMnemonic(mnemonic);
  const authorization = deriveRecoveryAuthorizationKey(ruk, userId);
  return {
    mnemonic,
    ruk,
    recoveryAuthorizationPublicKey: authorization.publicKeyMaterial,
    recoveryAuthorizationKeyId: authorization.keyId,
  };
}
export async function deriveRukFromMnemonic(mnemonic: string): Promise<Uint8Array> {
  if (!validateMnemonic(mnemonic, wordlist)) {
    throw new Error("Invalid BIP39 mnemonic");
  }
  const seed = await mnemonicToSeed(mnemonic, "");
  return hkdf(sha256, seed, HKDF_ZERO_SALT, new TextEncoder().encode("ruk"), 32);
}
export function wrapUmkWithRuk(
  umk: Uint8Array,
  ruk: Uint8Array,
  userId: string,
): {
  encryptedUmk: Uint8Array;
  nonce: Uint8Array;
} {
  const nonce = randomBytes(24);
  const aad = buildRecoveryUmkWrapAad(userId);
  const cipher = xchacha20poly1305(ruk, nonce, aad);
  return { encryptedUmk: cipher.encrypt(umk), nonce };
}
export function deriveRecoveryAuthorizationKey(
  ruk: Uint8Array,
  userId: string,
): {
  privateKeyMaterial: HybridSigningPrivateKeyMaterial;
  publicKeyMaterial: RecoveryAuthorizationHybridSigningPublicKeyMaterial;
  keyId: string;
} {
  const ed25519Private = hkdf(
    sha256,
    ruk,
    HKDF_ZERO_SALT,
    new TextEncoder().encode("recovery-authorization-ed25519"),
    32,
  );
  const mldsa65Seed = hkdf(
    sha256,
    ruk,
    HKDF_ZERO_SALT,
    new TextEncoder().encode("recovery-authorization-mldsa65"),
    32,
  );
  const ed25519Public = ed25519.getPublicKey(ed25519Private);
  const mldsa65Keys = ml_dsa65.keygen(mldsa65Seed);
  const privateKeyMaterial: HybridSigningPrivateKeyMaterial = {
    protocol: SIGNING_PRIVATE_KEY_MATERIAL_PROTOCOL,
    version: CURRENT_PROTOCOL_VERSION,
    owner_kind: "recovery_authorization",
    owner_id: userId,
    ed25519_private: encodeBase64Url(ed25519Private),
    ed25519_public: encodeBase64Url(ed25519Public),
    mldsa65_private: encodeBase64Url(mldsa65Keys.secretKey),
    mldsa65_public: encodeBase64Url(mldsa65Keys.publicKey),
    suite_id: SUITE_IDS.HYBRID_SIGNATURE,
    suite_rank: CURRENT_SUITE_RANK,
  };
  const publicKeyMaterial = publicKeyMaterialFromPrivate(
    privateKeyMaterial,
  ) as RecoveryAuthorizationHybridSigningPublicKeyMaterial;
  return {
    privateKeyMaterial,
    publicKeyMaterial,
    keyId: computeSigningKeyId(publicKeyMaterial),
  };
}

export function isValidMnemonic(mnemonic: string): boolean {
  return validateMnemonic(mnemonic, wordlist);
}
export function unwrapUmkWithRuk(
  encryptedUmk: Uint8Array,
  nonce: Uint8Array,
  ruk: Uint8Array,
  userId: string,
): Uint8Array {
  const aad = buildRecoveryUmkWrapAad(userId);
  const cipher = xchacha20poly1305(ruk, nonce, aad);
  return cipher.decrypt(encryptedUmk);
}
