import type { WorkerKeyState } from "../../state";
import { base64UrlDecode, base64UrlEncode } from "../../../encoding";
import { deriveAuthKeys } from "../../../kdf";
import {
  deriveRukFromMnemonic,
  generateRecoveryKey,
  isValidMnemonic,
  unwrapUmkWithRuk,
  wrapUmkWithRuk,
} from "../../../recovery";
import {
  clearTransientPuk,
  setTransientPuk,
  setTransientRuk,
  takeTransientRuk,
} from "../transient";
import { requireUmk, requireUserId } from "../utils";
import { CryptoOperationError } from "../../operation-error";
import type { HandlerPayload } from "../utils";

export async function handleGenerateRecoveryKey(state: WorkerKeyState): Promise<unknown> {
  const umk = requireUmk(state);
  const userId = requireUserId(state);

  const { mnemonic, ruk } = await generateRecoveryKey();
  const { encryptedUmk, nonce } = wrapUmkWithRuk(umk, ruk, userId);
  ruk.fill(0);

  return { mnemonic, encryptedUmk, nonce };
}

export async function handleDeriveAuthKeys(payload: HandlerPayload): Promise<unknown> {
  const password = payload.password as string;
  const salt = payload.salt as Uint8Array;
  const kdfParams = payload.kdfParams as {
    memory: number;
    iterations: number;
    parallelism: number;
  };

  const saltBase64 = base64UrlEncode(salt);
  const derived = await deriveAuthKeys(password, saltBase64, {
    algorithm: "argon2id",
    memory: kdfParams.memory,
    iterations: kdfParams.iterations,
    parallelism: kdfParams.parallelism,
    hash_length: 32,
  });

  clearTransientPuk();
  setTransientPuk(derived.puk);
  derived.pdk.fill(0);

  return { authKey: base64UrlDecode(derived.authKeyBase64) };
}

export function handleValidateMnemonic(payload: HandlerPayload): unknown {
  return { valid: isValidMnemonic(payload.mnemonic as string) };
}

export async function handleDeriveRuk(payload: HandlerPayload): Promise<unknown> {
  const mnemonic = payload.mnemonic as string;
  const ruk = await deriveRukFromMnemonic(mnemonic);
  setTransientRuk(ruk);
  return { status: "ok" };
}

export function handleWrapUmkWithRuk(state: WorkerKeyState): unknown {
  const umk = requireUmk(state);
  const userId = requireUserId(state);
  const ruk = takeTransientRuk();

  if (!ruk) {
    throw new CryptoOperationError("not_initialized", "RUK not available - derive RUK first");
  }

  const { encryptedUmk, nonce } = wrapUmkWithRuk(umk, ruk, userId);
  ruk.fill(0);
  return { encrypted: encryptedUmk, nonce };
}

export function handleUnwrapUmkWithRuk(state: WorkerKeyState, payload: HandlerPayload): unknown {
  const encrypted = payload.encrypted as Uint8Array;
  const nonce = payload.nonce as Uint8Array;
  const userId = payload.userId as string;
  const ruk = takeTransientRuk();

  if (!ruk) {
    throw new CryptoOperationError("not_initialized", "RUK not available - derive RUK first");
  }

  state.umk = unwrapUmkWithRuk(encrypted, nonce, ruk, userId);
  state.userId = userId;
  ruk.fill(0);

  return { status: "ok" };
}
