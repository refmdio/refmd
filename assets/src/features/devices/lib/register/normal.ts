import { authApi } from "@/shared/api";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { ensureDskInWorker, persistCurrentDeviceKeys } from "./session-keys";
import type { DeviceRegistrationPublicKeys } from "../../model/register/types";

type NormalRegistrationDecision =
  | {
      kind: "needs_password";
      dskUnavailableOAuth: false;
    }
  | {
      kind: "ready";
      dskUnavailableOAuth: boolean;
    };

type NormalRegistrationPreparation = {
  identityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  publicKeys: DeviceRegistrationPublicKeys;
  decision: NormalRegistrationDecision;
};

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
  const identityHybridSigningPublicKeyMaterial =
    typeof me.identity_hybrid_signing_public_key_material?.ed25519_public === "string"
      ? (me.identity_hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial)
      : null;
  if (!identityHybridSigningPublicKeyMaterial) {
    throw new Error("account_genesis_required");
  }

  const worker = getCryptoWorker();
  const deviceId = crypto.randomUUID();
  await worker.setUserContext(userId, deviceId);

  const hasDsk = await ensureDskInWorker();
  const publicKeys = await worker.generateDeviceKeys({ deviceId });
  const deviceKeysPersisted = hasDsk ? await persistCurrentDeviceKeys(userId) : false;

  return {
    identityHybridSigningPublicKeyMaterial,
    publicKeys: {
      deviceId,
      ...publicKeys,
    },
    decision: decideNormalRegistrationNextStep({
      hasDsk,
      deviceKeysPersisted,
      authType: me.auth_type,
    }),
  };
}
