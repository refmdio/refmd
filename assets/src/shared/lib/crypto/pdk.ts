import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "./encoding";
import { buildPdkUmkWrapAad, buildPdkDeviceEcdhAad, buildPdkDeviceSigningAad } from "./aad";

const PDK_UMK_KEY = "refmd-pdk-umk";
const PDK_DEVICE_ECDH_KEY = "refmd-pdk-device-ecdh";
const PDK_DEVICE_SIGNING_KEY = "refmd-pdk-device-signing";

interface PdkWrapped {
  ciphertext: string;
  nonce: string;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function pdkWrap(pdk: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): PdkWrapped {
  const nonce = randomBytes(24);
  const cipher = xchacha20poly1305(pdk, nonce, aad);
  const ciphertext = cipher.encrypt(plaintext);
  return { ciphertext: toHex(ciphertext), nonce: toHex(nonce) };
}

function pdkUnwrap(pdk: Uint8Array, wrapped: PdkWrapped, aad: Uint8Array): Uint8Array {
  const nonce = fromHex(wrapped.nonce);
  const ciphertext = fromHex(wrapped.ciphertext);
  const cipher = xchacha20poly1305(pdk, nonce, aad);
  return cipher.decrypt(ciphertext);
}

export function storePdkWrappedUmk(pdk: Uint8Array, umk: Uint8Array, userId: string): void {
  const aad = buildPdkUmkWrapAad(userId);
  const wrapped = pdkWrap(pdk, umk, aad);
  localStorage.setItem(PDK_UMK_KEY, JSON.stringify(wrapped));
}

export function loadPdkWrappedUmk(pdk: Uint8Array, userId: string): Uint8Array | null {
  try {
    const raw = localStorage.getItem(PDK_UMK_KEY);
    if (!raw) return null;
    const wrapped: PdkWrapped = JSON.parse(raw);
    const aad = buildPdkUmkWrapAad(userId);
    return pdkUnwrap(pdk, wrapped, aad);
  } catch {
    return null;
  }
}

export function storePdkWrappedDeviceKeys(
  pdk: Uint8Array,
  ecdhPrivate: Uint8Array,
  signingPrivate: Uint8Array,
  userId: string,
): void {
  const ecdhAad = buildPdkDeviceEcdhAad(userId);
  const signingAad = buildPdkDeviceSigningAad(userId);
  const wrappedEcdh = pdkWrap(pdk, ecdhPrivate, ecdhAad);
  const wrappedSigning = pdkWrap(pdk, signingPrivate, signingAad);
  localStorage.setItem(PDK_DEVICE_ECDH_KEY, JSON.stringify(wrappedEcdh));
  localStorage.setItem(PDK_DEVICE_SIGNING_KEY, JSON.stringify(wrappedSigning));
}

export function loadPdkWrappedDeviceKeys(
  pdk: Uint8Array,
  userId: string,
): { ecdhPrivate: Uint8Array; signingPrivate: Uint8Array } | null {
  try {
    const ecdhRaw = localStorage.getItem(PDK_DEVICE_ECDH_KEY);
    const signingRaw = localStorage.getItem(PDK_DEVICE_SIGNING_KEY);
    if (!ecdhRaw || !signingRaw) return null;
    const ecdhAad = buildPdkDeviceEcdhAad(userId);
    const signingAad = buildPdkDeviceSigningAad(userId);
    const ecdhPrivate = pdkUnwrap(pdk, JSON.parse(ecdhRaw), ecdhAad);
    const signingPrivate = pdkUnwrap(pdk, JSON.parse(signingRaw), signingAad);
    return { ecdhPrivate, signingPrivate };
  } catch {
    return null;
  }
}

export function clearPdkWrappedUmk(): void {
  localStorage.removeItem(PDK_UMK_KEY);
}

export function clearPdkWrappedKeys(): void {
  localStorage.removeItem(PDK_UMK_KEY);
  localStorage.removeItem(PDK_DEVICE_ECDH_KEY);
  localStorage.removeItem(PDK_DEVICE_SIGNING_KEY);
}
