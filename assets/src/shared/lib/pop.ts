import { authApi } from "@/shared/api";
import {
  base64UrlEncode,
  sign,
  buildSignatureMessage,
  SIGNATURE_ACTION,
} from "@/shared/lib/crypto";
import { deviceState } from "@/shared/lib/auth-state";

export interface PopHeaders {
  "X-PoP-Device-Id": string;
  "X-PoP-Challenge": string;
  "X-PoP-Signature": string;
}

export async function getPopHeaders(): Promise<PopHeaders> {
  const device = deviceState();
  if (!device?.deviceId || !device.deviceSigningPrivate) {
    throw new Error("Device not available for PoP");
  }

  const { challenge } = await authApi.popChallenge(device.deviceId);

  const message = buildSignatureMessage(SIGNATURE_ACTION.POP_CHALLENGE, {
    challenge: challenge,
    device_id: device.deviceId,
  });

  const signature = sign(message, device.deviceSigningPrivate);

  return {
    "X-PoP-Device-Id": device.deviceId,
    "X-PoP-Challenge": challenge,
    "X-PoP-Signature": base64UrlEncode(signature),
  };
}

export async function fetchWithPop(
  url: string,
  options: RequestInit = {},
): Promise<Response> {
  const popHeaders = await getPopHeaders();
  const headers = new Headers(options.headers);
  headers.set("X-PoP-Device-Id", popHeaders["X-PoP-Device-Id"]);
  headers.set("X-PoP-Challenge", popHeaders["X-PoP-Challenge"]);
  headers.set("X-PoP-Signature", popHeaders["X-PoP-Signature"]);
  headers.set("Content-Type", "application/json");

  return fetch(url, {
    ...options,
    headers,
    credentials: "include",
  });
}
