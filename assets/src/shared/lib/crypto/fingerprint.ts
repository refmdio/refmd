import { blake3 } from "@noble/hashes/blake3.js";
import { base64UrlEncode } from "./encoding";

export function calculateFingerprint(signingPublicKey: Uint8Array): string {
  if (signingPublicKey.length !== 32) {
    throw new Error("Signing public key must be 32 bytes");
  }
  const hash = blake3(signingPublicKey, { dkLen: 16 });
  return base64UrlEncode(hash);
}

export function formatFingerprint(fingerprint: string): string {
  const groups: string[] = [];
  for (let i = 0; i < fingerprint.length; i += 4) {
    groups.push(fingerprint.slice(i, i + 4));
  }
  return groups.join(" ");
}
