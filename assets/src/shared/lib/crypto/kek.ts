import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "./encoding";
import { HKDF_ZERO_SALT } from "./constants";
import {
  buildDeviceKekDistributionAad,
  buildUmkKekBackupAad,
  buildMemberEnvelopeKekAad,
  buildInvitationKekWrapAad,
} from "./aad";
import { ecdhEncrypt, ecdhDecrypt } from "./ecdh-cipher";
const INVITATION_KEK_WRAP_INFO = new TextEncoder().encode("invitation_kek_wrap");

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
  const aad = buildDeviceKekDistributionAad(
    workspaceId,
    userId,
    senderDeviceId,
    targetDeviceId,
    keyVersion,
  );
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
  const aad = buildDeviceKekDistributionAad(
    workspaceId,
    userId,
    senderDeviceId,
    receiverDeviceId,
    keyVersion,
  );
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

export function encryptKekForInvitation(
  kek: Uint8Array,
  tokenBytes: Uint8Array,
  workspaceId: string,
  invitationId: string,
  keyVersion: number,
): { encryptedKek: Uint8Array; nonce: Uint8Array } {
  const tokenKey = hkdf(sha256, tokenBytes, HKDF_ZERO_SALT, INVITATION_KEK_WRAP_INFO, 32);
  const nonce = randomBytes(24);
  const aad = buildInvitationKekWrapAad(workspaceId, invitationId, keyVersion);
  const cipher = xchacha20poly1305(tokenKey, nonce, aad);
  return { encryptedKek: cipher.encrypt(kek), nonce };
}

export function decryptKekFromInvitation(
  encryptedKek: Uint8Array,
  nonce: Uint8Array,
  tokenBytes: Uint8Array,
  workspaceId: string,
  invitationId: string,
  keyVersion: number,
): Uint8Array {
  const tokenKey = hkdf(sha256, tokenBytes, HKDF_ZERO_SALT, INVITATION_KEK_WRAP_INFO, 32);
  const aad = buildInvitationKekWrapAad(workspaceId, invitationId, keyVersion);
  const cipher = xchacha20poly1305(tokenKey, nonce, aad);
  return cipher.decrypt(encryptedKek);
}
