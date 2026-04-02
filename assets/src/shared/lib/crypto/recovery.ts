import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { generateMnemonic, mnemonicToSeed, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { randomBytes } from "./encoding";
import { HKDF_ZERO_SALT } from "./constants";
import { buildRecoveryUmkWrapAad } from "./aad";
interface RecoveryKeyData {
  mnemonic: string;
  ruk: Uint8Array;
}
export async function generateRecoveryKey(): Promise<RecoveryKeyData> {
  const mnemonic = generateMnemonic(wordlist, 256);
  const ruk = await deriveRukFromMnemonic(mnemonic);
  return { mnemonic, ruk };
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
