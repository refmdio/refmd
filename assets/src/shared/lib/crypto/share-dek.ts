import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { buildShareDekWrapAad } from "./aad";
import { HKDF_ZERO_SALT } from "./constants";
import { randomBytes } from "./encoding";

export function deriveOpenShareDekEncryptionKey(shareAuthorizationSecret: Uint8Array): Uint8Array {
  return hkdf(
    sha256,
    shareAuthorizationSecret,
    HKDF_ZERO_SALT,
    new TextEncoder().encode("RefMD:v2:open-share-dek-encryption"),
    32,
  );
}

export function deriveOpenShareAdmissionKey(shareAuthorizationSecret: Uint8Array): Uint8Array {
  return hkdf(
    sha256,
    shareAuthorizationSecret,
    HKDF_ZERO_SALT,
    new TextEncoder().encode("RefMD:v2:open-share-admission"),
    32,
  );
}

export function derivePasswordShareDekEncryptionKey(
  passwordShareDekEncryptionKey: Uint8Array,
  shareCapabilitySecret: Uint8Array,
): Uint8Array {
  return hkdf(
    sha256,
    passwordShareDekEncryptionKey,
    shareCapabilitySecret,
    new TextEncoder().encode("RefMD:v2:password-share-dek-encryption"),
    32,
  );
}

export function derivePasswordShareAdmissionKey(
  passwordCapabilitySecret: Uint8Array,
  shareCapabilitySecret: Uint8Array,
): Uint8Array {
  return hkdf(
    sha256,
    passwordCapabilitySecret,
    shareCapabilitySecret,
    new TextEncoder().encode("RefMD:v2:password-share-admission"),
    32,
  );
}

export function unwrapShareDek(params: {
  encryptedDek: Uint8Array;
  nonce: Uint8Array;
  dekEncryptionKey: Uint8Array;
  shareId: string;
  documentId: string;
}): Uint8Array {
  const aad = buildShareDekWrapAad(params.shareId, params.documentId);
  const cipher = xchacha20poly1305(params.dekEncryptionKey, params.nonce, aad);
  return cipher.decrypt(params.encryptedDek);
}

export function wrapShareDek(params: {
  dek: Uint8Array;
  dekEncryptionKey: Uint8Array;
  shareId: string;
  documentId: string;
}): { encryptedDek: Uint8Array; nonce: Uint8Array } {
  const nonce = randomBytes(24);
  const aad = buildShareDekWrapAad(params.shareId, params.documentId);
  const cipher = xchacha20poly1305(params.dekEncryptionKey, nonce, aad);
  return { encryptedDek: cipher.encrypt(params.dek), nonce };
}
