import { authApi } from "@/shared/api";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { ensureDskInWorker, persistCurrentDeviceKeys } from "./device-crypto-setup";
import type { DeviceRegistrationPublicKeys } from "../model/types";

type NormalRegistrationDecision =
  | {
      kind: "needs_password";
      dskUnavailableOAuth: false;
    }
  | {
      kind: "ready";
      dskUnavailableOAuth: boolean;
    };

interface NormalRegistrationPreparation {
  identitySigningPublic: Uint8Array;
  publicKeys: DeviceRegistrationPublicKeys;
  decision: NormalRegistrationDecision;
}

export function decideNormalRegistrationNextStep(input: {
  hasDsk: boolean;
  deviceKeysPersisted: boolean;
  authType: string | null | undefined;
}): NormalRegistrationDecision {
  if (input.hasDsk) {
    if (!input.deviceKeysPersisted) {
      return { kind: "needs_password", dskUnavailableOAuth: false };
    }
    return { kind: "ready", dskUnavailableOAuth: false };
  }

  if (input.authType === "password") {
    return { kind: "needs_password", dskUnavailableOAuth: false };
  }

  return { kind: "ready", dskUnavailableOAuth: true };
}

export async function prepareNormalRegistration(
  userId: string,
): Promise<NormalRegistrationPreparation> {
  const me = await authApi.me();
  if (!me.identity_signing_public_key) {
    throw new Error("Identity key not available");
  }

  const worker = getCryptoWorker();
  await worker.setUserContext(userId);

  const hasDsk = await ensureDskInWorker();
  const publicKeys = await worker.generateDeviceKeys();
  const deviceKeysPersisted = hasDsk ? await persistCurrentDeviceKeys(userId) : false;

  return {
    identitySigningPublic: base64UrlDecode(me.identity_signing_public_key),
    publicKeys,
    decision: decideNormalRegistrationNextStep({
      hasDsk,
      deviceKeysPersisted,
      authType: me.auth_type,
    }),
  };
}
