import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import { randomBytes, base64UrlEncode } from "./encoding";
import { sign, verify } from "./identity";
import { buildSignatureMessage, SIGNATURE_ACTION } from "./signature";
interface DeviceKeyPair {
  ecdhPrivate: Uint8Array;
  ecdhPublic: Uint8Array;
  signingPrivate: Uint8Array;
  signingPublic: Uint8Array;
}
export function generateDeviceKeyPair(): DeviceKeyPair {
  const ecdhPrivate = x25519.utils.randomSecretKey();
  const signingPrivate = ed25519.utils.randomSecretKey();
  return {
    ecdhPrivate,
    ecdhPublic: x25519.getPublicKey(ecdhPrivate),
    signingPrivate,
    signingPublic: ed25519.getPublicKey(signingPrivate),
  };
}
export function generateClientNonce(): Uint8Array {
  return randomBytes(16);
}
export function signDeviceApproval(
  deviceSigningPublicKey: Uint8Array,
  deviceEcdhPublicKey: Uint8Array,
  clientNonce: Uint8Array,
  identitySigningPrivate: Uint8Array,
): Uint8Array {
  const message = buildSignatureMessage(SIGNATURE_ACTION.DEVICE_APPROVAL, {
    device_signing_public_key: base64UrlEncode(deviceSigningPublicKey),
    device_ecdh_public_key: base64UrlEncode(deviceEcdhPublicKey),
    client_nonce: base64UrlEncode(clientNonce),
  });
  return sign(message, identitySigningPrivate);
}
export function signDeviceRegistration(
  deviceSigningPublicKey: Uint8Array,
  deviceEcdhPublicKey: Uint8Array,
  clientNonce: Uint8Array,
  identitySigningPrivate: Uint8Array,
): Uint8Array {
  const message = buildSignatureMessage(SIGNATURE_ACTION.DEVICE_REGISTRATION, {
    device_signing_public_key: base64UrlEncode(deviceSigningPublicKey),
    device_ecdh_public_key: base64UrlEncode(deviceEcdhPublicKey),
    client_nonce: base64UrlEncode(clientNonce),
  });
  return sign(message, identitySigningPrivate);
}
export function verifyDeviceIdentitySignature(
  deviceSigningPublicKey: Uint8Array,
  deviceEcdhPublicKey: Uint8Array,
  clientNonce: Uint8Array,
  identitySignature: Uint8Array,
  identitySigningPublic: Uint8Array,
): boolean {
  for (const action of [SIGNATURE_ACTION.DEVICE_APPROVAL, SIGNATURE_ACTION.DEVICE_REGISTRATION]) {
    const message = buildSignatureMessage(action, {
      device_signing_public_key: base64UrlEncode(deviceSigningPublicKey),
      device_ecdh_public_key: base64UrlEncode(deviceEcdhPublicKey),
      client_nonce: base64UrlEncode(clientNonce),
    });
    try {
      if (verify(message, identitySignature, identitySigningPublic)) return true;
    } catch {
      // continue
    }
  }
  return false;
}
