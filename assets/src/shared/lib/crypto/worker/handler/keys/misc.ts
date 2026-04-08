import { base64UrlEncode, randomBytes } from "../../../encoding";
import type { HandlerPayload } from "../utils";

export async function handleGenerateInvitationToken(): Promise<unknown> {
  const tokenBytes = randomBytes(32);
  const tokenBase64 = base64UrlEncode(tokenBytes);
  const hashBuffer = await crypto.subtle.digest("SHA-256", tokenBytes.buffer as ArrayBuffer);
  const tokenHash = base64UrlEncode(new Uint8Array(hashBuffer));
  const tokenPrefix = tokenBase64.slice(0, 4);
  return { token: tokenBase64, tokenHash, tokenPrefix };
}

export async function handleSha256Hash(payload: HandlerPayload): Promise<unknown> {
  const data = payload.data as Uint8Array;
  const hashBuffer = await crypto.subtle.digest("SHA-256", data.buffer as ArrayBuffer);
  return { hash: base64UrlEncode(new Uint8Array(hashBuffer)) };
}
