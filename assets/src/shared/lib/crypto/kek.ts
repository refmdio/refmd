import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "./encoding";
import { buildDeviceKekDistributionAad, buildUmkKekBackupAad } from "./aad";
import { ecdhEncrypt } from "./ecdh-cipher";

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
