import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "./encoding";
import { buildDeviceKekDistributionAad, buildUmkKekBackupAad, buildMemberEnvelopeKekAad } from "./aad";
import { ecdhEncrypt, ecdhDecrypt } from "./ecdh-cipher";

export function generateKek(): Uint8Array {
  return randomBytes(32);
}

export function encryptKekForDevice(
  kek: Uint8Array,
  senderEcdhPrivate: Uint8Array,
  targetEcdhPublic: Uint8Array,
  workspaceId: string,
  userId: string,
  senderDeviceId: string,
  targetDeviceId: string,
  keyVersion: number,
): { ciphertext: Uint8Array; nonce: Uint8Array } {
  const aad = buildDeviceKekDistributionAad(workspaceId, userId, senderDeviceId, targetDeviceId, keyVersion);
  return ecdhEncrypt(kek, senderEcdhPrivate, targetEcdhPublic, "kek_wrap", aad);
}

export function unwrapKekFromBackup(
  encryptedKek: Uint8Array,
  nonce: Uint8Array,
  umk: Uint8Array,
  workspaceId: string,
  userId: string,
  keyVersion: number,
): Uint8Array {
  const aad = buildUmkKekBackupAad(workspaceId, userId, keyVersion);
  const cipher = xchacha20poly1305(umk, nonce, aad);
  return cipher.decrypt(encryptedKek);
}

export function encryptKekForMember(
  kek: Uint8Array,
  senderEcdhPrivate: Uint8Array,
  targetIdentityEcdhPublic: Uint8Array,
  workspaceId: string,
  targetUserId: string,
  senderDeviceId: string,
  keyVersion: number,
): { ciphertext: Uint8Array; nonce: Uint8Array } {
  const aad = buildMemberEnvelopeKekAad(workspaceId, targetUserId, keyVersion, senderDeviceId);
  return ecdhEncrypt(kek, senderEcdhPrivate, targetIdentityEcdhPublic, "kek_wrap", aad);
}

export function decryptKekFromMemberEnvelope(
  encryptedKek: Uint8Array,
  nonce: Uint8Array,
  identityEcdhPrivate: Uint8Array,
  senderEcdhPublic: Uint8Array,
  workspaceId: string,
  targetUserId: string,
  keyVersion: number,
  senderDeviceId: string,
): Uint8Array {
  const aad = buildMemberEnvelopeKekAad(workspaceId, targetUserId, keyVersion, senderDeviceId);
  return ecdhDecrypt(encryptedKek, nonce, identityEcdhPrivate, senderEcdhPublic, "kek_wrap", aad);
}

export function decryptKekFromDeviceEnvelope(
  encryptedKek: Uint8Array,
  nonce: Uint8Array,
  receiverEcdhPrivate: Uint8Array,
  senderEcdhPublic: Uint8Array,
  workspaceId: string,
  userId: string,
  senderDeviceId: string,
  receiverDeviceId: string,
  keyVersion: number,
): Uint8Array {
  const aad = buildDeviceKekDistributionAad(workspaceId, userId, senderDeviceId, receiverDeviceId, keyVersion);
  return ecdhDecrypt(encryptedKek, nonce, receiverEcdhPrivate, senderEcdhPublic, "kek_wrap", aad);
}

export function wrapKekWithUmk(
  kek: Uint8Array,
  umk: Uint8Array,
  workspaceId: string,
  userId: string,
  keyVersion: number,
): { encryptedKek: Uint8Array; nonce: Uint8Array } {
  const nonce = randomBytes(24);
  const aad = buildUmkKekBackupAad(workspaceId, userId, keyVersion);
  const cipher = xchacha20poly1305(umk, nonce, aad);
  return { encryptedKek: cipher.encrypt(kek), nonce };
}
