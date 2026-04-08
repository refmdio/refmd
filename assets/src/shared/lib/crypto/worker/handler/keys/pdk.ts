import type { WorkerKeyState } from "../../state";
import { CryptoOperationError } from "../../operation-error";
import { base64UrlEncode } from "../../../encoding";
import { deriveAuthKeys } from "../../../kdf";
import { pdkUnwrapDeviceKeys, pdkUnwrapUmk, pdkWrapDeviceKeys, pdkWrapUmk } from "../../../pdk";
import { requireUserId, setDeviceFromPrivateKeys } from "../utils";
import type { HandlerPayload } from "../utils";

interface PasswordParams {
  password: string;
  salt: Uint8Array;
  kdfParams: {
    memory: number;
    iterations: number;
    parallelism: number;
  };
}

async function derivePdk(params: PasswordParams): Promise<{ pdk: Uint8Array; puk: Uint8Array }> {
  const saltBase64 = base64UrlEncode(params.salt);
  const derived = await deriveAuthKeys(params.password, saltBase64, {
    algorithm: "argon2id",
    memory: params.kdfParams.memory,
    iterations: params.kdfParams.iterations,
    parallelism: params.kdfParams.parallelism,
    hash_length: 32,
  });

  return { pdk: derived.pdk, puk: derived.puk };
}

export async function handleWrapWithPdk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const userId = requireUserId(state);
  const passwordParams = payload.passwordParams as PasswordParams | undefined;

  if (!passwordParams) {
    throw new CryptoOperationError("internal_error", "passwordParams required for PDK wrapping");
  }

  const { pdk, puk } = await derivePdk(passwordParams);
  puk.fill(0);

  let wrappedUmk: { ciphertext: string; nonce: string } | null = null;
  if (state.umk) {
    wrappedUmk = pdkWrapUmk(pdk, state.umk, userId);
  }

  let wrappedDeviceKeys: {
    ecdh: { ciphertext: string; nonce: string };
    signing: { ciphertext: string; nonce: string };
  } | null = null;
  if (state.deviceEcdhPrivate && state.deviceSigningPrivate) {
    wrappedDeviceKeys = pdkWrapDeviceKeys(
      pdk,
      state.deviceEcdhPrivate,
      state.deviceSigningPrivate,
      userId,
    );
  }

  pdk.fill(0);
  return { wrappedUmk, wrappedDeviceKeys };
}

export async function handleUnwrapWithPdk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const userId = (payload.userId as string) ?? requireUserId(state);
  const passwordParams = payload.passwordParams as PasswordParams | undefined;

  if (!passwordParams) {
    throw new CryptoOperationError("internal_error", "passwordParams required for PDK unwrapping");
  }

  const { pdk, puk } = await derivePdk(passwordParams);
  puk.fill(0);

  let umkRestored = false;
  let deviceKeysRestored = false;

  if (payload.wrappedUmk) {
    const wrappedUmk = payload.wrappedUmk as { ciphertext: string; nonce: string };
    state.umk = pdkUnwrapUmk(pdk, wrappedUmk, userId);
    umkRestored = true;
  }

  if (payload.wrappedDeviceEcdh && payload.wrappedDeviceSigning) {
    const deviceKeys = pdkUnwrapDeviceKeys(
      pdk,
      payload.wrappedDeviceEcdh as { ciphertext: string; nonce: string },
      payload.wrappedDeviceSigning as { ciphertext: string; nonce: string },
      userId,
    );
    setDeviceFromPrivateKeys(state, deviceKeys.ecdhPrivate, deviceKeys.signingPrivate);
    deviceKeysRestored = true;
  }

  pdk.fill(0);
  return { umkRestored, deviceKeysRestored };
}
