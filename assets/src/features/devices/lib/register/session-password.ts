import { authApi } from "@/shared/api";
import type { AuthState } from "@/entities/session";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { loadPersistedDskIntoWorker, persistCurrentDeviceKeys } from "./session-keys";
import type { DeviceRegistrationPublicKeys } from "../../model/register/types";

interface CompletePasswordReentryOptions {
  auth: AuthState;
  password: string;
  pendingKeysGenerated: boolean;
  devicePublicKeys: DeviceRegistrationPublicKeys | null;
  postApprovalPersistence: boolean;
  completionRedirectPath: string;
}

type PasswordReentryOutcome =
  | {
      kind: "resume_registration";
      publicKeys: DeviceRegistrationPublicKeys;
    }
  | {
      kind: "complete";
      redirectPath: string;
    };

export async function completePasswordReentry(
  options: CompletePasswordReentryOptions,
): Promise<PasswordReentryOutcome> {
  await verifyCurrentUserPassword(options.auth.user.email, options.password);
  const worker = getCryptoWorker();

  if (!options.pendingKeysGenerated) throw new Error("No pending keys");

  if (!(await loadPersistedDskIntoWorker())) {
    throw new Error("Persistent key storage is required to save device keys");
  }

  const persisted = await persistCurrentDeviceKeys(options.auth.user.id);
  if (!persisted) {
    throw new Error("Could not persist device keys");
  }

  await worker.clearTransientKeys();

  if (options.postApprovalPersistence) {
    return {
      kind: "complete",
      redirectPath: options.completionRedirectPath,
    };
  }

  if (!options.devicePublicKeys) throw new Error("No device public keys");

  return {
    kind: "resume_registration",
    publicKeys: options.devicePublicKeys,
  };
}

export async function verifyRegistrationReauth(
  auth: AuthState,
  password: string,
  publicKeys: DeviceRegistrationPublicKeys | null,
): Promise<DeviceRegistrationPublicKeys> {
  await verifyCurrentUserPassword(auth.user.email, password);
  if (!publicKeys) throw new Error("No pending keys");
  return publicKeys;
}

export async function clearTransientKeysBestEffort(): Promise<void> {
  await getCryptoWorker()
    .clearTransientKeys()
    .catch(() => {
      // Best-effort cleanup before retrying the registration flow.
    });
}

async function verifyCurrentUserPassword(
  email: string,
  password: string,
): Promise<Awaited<ReturnType<typeof authApi.getSalt>>> {
  const saltResponse = await authApi.getSalt(email);
  const worker = getCryptoWorker();
  const { authKey } = await worker.deriveAuthKeys({
    password,
    salt: base64UrlDecode(saltResponse.salt),
    kdfParams: saltResponse.kdf_params,
  });
  await authApi.verifyKey(base64UrlEncode(authKey));
  await worker.clearTransientKeys();
  return saltResponse;
}
