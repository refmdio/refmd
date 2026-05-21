import { authApi, encryptionApi } from "@/shared/api";
import { getKeyDirectoryPin } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
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

interface NormalRegistrationPreparation {
  identityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
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
  const identityHybridSigningPublicKeyMaterial =
    typeof me.identity_hybrid_signing_public_key_material?.ed25519_public === "string"
      ? (me.identity_hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial)
      : null;
  if (!identityHybridSigningPublicKeyMaterial) {
    throw new Error("Identity key not available");
  }

  const worker = getCryptoWorker();
  const deviceId = crypto.randomUUID();
  await worker.setUserContext(userId, deviceId);

  const hasDsk = await ensureDskInWorker();
  const publicKeys = await worker.generateDeviceKeys({ deviceId });
  const { workspace_ids: workspaceIds } = await encryptionApi.getWorkspaceIds();
  const userKeyDirectoryPin = await getKeyDirectoryPin("user", userId);
  const issuedAtEventSequence =
    typeof me.candidate_user_event_head_sequence === "number"
      ? me.candidate_user_event_head_sequence
      : (userKeyDirectoryPin?.eventHeadSequence ?? 1);
  const expiresEventSequence = issuedAtEventSequence + 1;
  const umkDistribution = await worker.generateInitialAkeResponderPrekey({
    operationId: deviceId,
    userId,
    deviceId,
    purpose: "umk_distribution",
    issuedAtEventSequence,
    expiresEventSequence,
  });
  const trustTransfer = await worker.generateInitialAkeResponderPrekey({
    operationId: crypto.randomUUID(),
    userId,
    deviceId,
    purpose: "trust_transfer",
    issuedAtEventSequence,
    expiresEventSequence,
  });
  const deviceApprovalKekInitial: NonNullable<
    DeviceRegistrationPublicKeys["initialAkeResponderPrekeys"]
  >["device_approval_kek_initial"] = [];
  for (const workspaceId of workspaceIds) {
    deviceApprovalKekInitial.push({
      workspace_id: workspaceId,
      prekey: await worker.generateInitialAkeResponderPrekey({
        operationId: deviceId,
        userId,
        deviceId,
        purpose: "device_approval_kek_initial",
        issuedAtEventSequence,
        expiresEventSequence,
      }),
    });
  }
  const initialAkeResponderPrekeys = {
    umk_distribution: umkDistribution,
    trust_transfer: trustTransfer,
    device_approval_kek_initial: deviceApprovalKekInitial,
  };
  const deviceKeysPersisted = hasDsk ? await persistCurrentDeviceKeys(userId) : false;

  return {
    identityHybridSigningPublicKeyMaterial,
    publicKeys: {
      deviceId,
      ...publicKeys,
      initialAkeResponderPrekeys,
    },
    decision: decideNormalRegistrationNextStep({
      hasDsk,
      deviceKeysPersisted,
      authType: me.auth_type,
    }),
  };
}
