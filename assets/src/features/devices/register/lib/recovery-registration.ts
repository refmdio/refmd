import { authApi, devicesApi } from "@/shared/api";
import type { AuthState } from "@/entities/session";
import { setCryptoWorkerReady, setFullSession } from "@/entities/session";
import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { persistDeviceId, persistWrappedUmk } from "@/shared/lib/auth-key-persistence";
import { getDeviceName, getDeviceType } from "@/shared/lib/device-metadata";
import { ensureDskInWorker, persistCurrentDeviceKeys } from "./device-crypto-setup";
import { restoreWorkspaceKeks } from "./workspace-kek-recovery";
import type { DeviceRegistrationPublicKeys } from "../model/types";

type RecoveryRegistrationResult =
  | {
      kind: "navigate";
      path: string;
    }
  | {
      kind: "needs_password";
      publicKeys: DeviceRegistrationPublicKeys;
    }
  | {
      kind: "done";
      statusMessage: string;
      redirectPath: string;
      dskUnavailableOAuth: boolean;
    };

export async function registerRecoveredDevice(params: {
  auth: AuthState;
  completionRedirectPath: string;
  onStatusMessage?: (message: string) => void;
}): Promise<RecoveryRegistrationResult> {
  const { auth, completionRedirectPath, onStatusMessage } = params;
  const worker = getCryptoWorker();
  const publicIdentityKeys = await worker.getPublicKeys();
  if (!publicIdentityKeys.identitySigningPublic) {
    return {
      kind: "navigate",
      path: "/auth/recovery",
    };
  }

  await worker.setUserContext(auth.user.id);

  const hasDsk = await ensureDskInWorker();
  const publicKeys = await worker.generateDeviceKeys();

  if (hasDsk) {
    const persisted = await persistCurrentDeviceKeys(auth.user.id);
    if (!persisted) {
      console.warn(
        "[recovery-registration] Device key persistence failed; session may not survive restart",
      );
    }
  }

  const nonce = await worker.generateClientNonce();
  const { signature: deviceSignature } = await worker.signDeviceRegistration({
    deviceSigningPublic: publicKeys.signingPublic,
    deviceEcdhPublic: publicKeys.ecdhPublic,
    clientNonce: nonce,
  });

  const identitySigningPublicKey = auth.identitySigningPublic;
  if (!identitySigningPublicKey) throw new Error("Identity signing public key not available");

  const pendingRegistration = await devicesApi.createRegistration({
    name: getDeviceName(),
    device_type: getDeviceType(),
    device_ecdh_public_key: base64UrlEncode(publicKeys.ecdhPublic),
    device_signing_public_key: base64UrlEncode(publicKeys.signingPublic),
    client_nonce: base64UrlEncode(nonce),
    identity_signing_public_key: base64UrlEncode(identitySigningPublicKey),
  });

  const approval = await devicesApi.approve(pendingRegistration.device_id, {
    identity_signature: base64UrlEncode(deviceSignature),
  });
  const deviceId = approval.device.id;

  await worker.setUserContext(auth.user.id, deviceId);
  await worker.setInitialized();
  setCryptoWorkerReady(true);

  if (hasDsk) {
    const wrappedUmk = await worker.wrapUmkWithDsk(auth.user.id);
    await persistWrappedUmk({
      wrappedUmk,
      kmsi: false,
      userId: auth.user.id,
    });
  }

  setFullSession(
    {
      user: auth.user,
      sessionId: auth.sessionId,
      identitySigningPublic: auth.identitySigningPublic,
      identityEcdhPublic: auth.identityEcdhPublic,
      expiresAt: auth.expiresAt,
    },
    {
      deviceId,
      deviceSigningPublic: publicKeys.signingPublic,
      deviceEcdhPublic: publicKeys.ecdhPublic,
    },
  );

  persistDeviceId(deviceId, auth.user.id);
  onStatusMessage?.("Restoring workspace keys...");
  const kekResults = await restoreWorkspaceKeks(auth.user.id, deviceId);
  if (kekResults.backupDecryptFailed) {
    throw new Error(
      "KEK backup decryption failed. This may indicate data corruption. Some workspaces may require key distribution from an existing device.",
    );
  }

  if (!hasDsk) {
    const me = await authApi.me();
    if (me.auth_type === "password") {
      return {
        kind: "needs_password",
        publicKeys,
      };
    }
  }

  await worker.clearTransientKeys();

  return {
    kind: "done",
    statusMessage: formatRecoveryCompletionMessage(kekResults.needsDistribution.length),
    redirectPath: completionRedirectPath,
    dskUnavailableOAuth: !hasDsk,
  };
}

function formatRecoveryCompletionMessage(needsDistributionCount: number): string {
  if (needsDistributionCount > 0) {
    return `Recovery complete. ${needsDistributionCount} workspace(s) require key distribution from an existing device.`;
  }

  return "Recovery complete!";
}
