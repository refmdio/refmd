import { blake3 } from "@noble/hashes/blake3.js";
import { decodeBase64UrlStrict, encodeBase64Url } from "./encoding";

export type HashSentinelPolicy = "none" | ReadonlySet<string>;

const BLAKE3_B64URL_RE = /^[A-Za-z0-9_-]{43}$/;

export function blake3Base64Url(bytes: Uint8Array): string {
  return encodeBase64Url(blake3(bytes));
}

export function assertBlake3Base64Url(
  value: string,
  sentinelPolicy: HashSentinelPolicy = "none",
): void {
  if (sentinelPolicy !== "none" && sentinelPolicy.has(value)) {
    return;
  }
  if (!BLAKE3_B64URL_RE.test(value)) {
    throw new Error("invalid_blake3_base64url");
  }
  decodeBase64UrlStrict(value, 32);
  if (/^[0-9a-f]{64}$/i.test(value)) {
    throw new Error("invalid_blake3_hex");
  }
}
