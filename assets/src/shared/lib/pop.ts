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

export interface ExplicitDeviceKeys {
  deviceId: string;
  deviceSigningPrivate: Uint8Array;
}

export async function getPopHeaders(explicitDevice?: ExplicitDeviceKeys): Promise<PopHeaders> {
  const deviceId = explicitDevice?.deviceId ?? deviceState()?.deviceId;
  const signingPrivate =
    explicitDevice?.deviceSigningPrivate ?? deviceState()?.deviceSigningPrivate;

  if (!deviceId || !signingPrivate) {
    throw new Error("Device not available for PoP");
  }

  const { challenge } = await authApi.popChallenge(deviceId);

  const message = buildSignatureMessage(SIGNATURE_ACTION.POP_CHALLENGE, {
    challenge: challenge,
    device_id: deviceId,
  });

  const signature = sign(message, signingPrivate);

  return {
    "X-PoP-Device-Id": deviceId,
    "X-PoP-Challenge": challenge,
    "X-PoP-Signature": base64UrlEncode(signature),
  };
}
