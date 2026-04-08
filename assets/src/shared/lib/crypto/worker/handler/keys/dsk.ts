import type { WorkerKeyState } from "../../state";
import { CryptoOperationError } from "../../operation-error";
import { buildDskDeviceEcdhAad, buildDskDeviceSigningAad, buildDskUmkCacheAad } from "../../../aad";
import { storeDsk } from "../../../dsk";
import { dskDecrypt, dskEncrypt, requireDsk, requireUmk, setDeviceFromPrivateKeys } from "../utils";
import type { HandlerPayload } from "../utils";

export async function handleWrapWithDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const plaintext = payload.plaintext as Uint8Array;
  const aad = payload.aad as Uint8Array;
  return dskEncrypt(dsk, plaintext, aad);
}

export async function handleUnwrapWithDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const ciphertext = payload.ciphertext as ArrayBuffer;
  const iv = payload.iv as ArrayBuffer;
  const aad = payload.aad as Uint8Array;
  return { plaintext: await dskDecrypt(dsk, ciphertext, iv, aad) };
}

export async function handleWrapUmkWithDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const umk = requireUmk(state);
  const userId = payload.userId as string;
  return dskEncrypt(dsk, umk, buildDskUmkCacheAad(userId));
}

export async function handleUnwrapUmkFromDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const ciphertext = payload.ciphertext as ArrayBuffer;
  const iv = payload.iv as ArrayBuffer;
  const userId = payload.userId as string;
  state.umk = await dskDecrypt(dsk, ciphertext, iv, buildDskUmkCacheAad(userId));
  return { status: "ok" };
}

export async function handleWrapDeviceKeysWithDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const userId = payload.userId as string;

  if (!state.deviceEcdhPrivate || !state.deviceSigningPrivate) {
    throw new CryptoOperationError("not_initialized", "Device keys not available");
  }

  const wrappedEcdh = await dskEncrypt(dsk, state.deviceEcdhPrivate, buildDskDeviceEcdhAad(userId));
  const wrappedSigning = await dskEncrypt(
    dsk,
    state.deviceSigningPrivate,
    buildDskDeviceSigningAad(userId),
  );

  return { wrappedEcdh, wrappedSigning };
}

export async function handleUnwrapDeviceKeysFromDsk(
  state: WorkerKeyState,
  payload: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const wrappedEcdh = payload.wrappedEcdh as { ciphertext: ArrayBuffer; iv: ArrayBuffer };
  const wrappedSigning = payload.wrappedSigning as { ciphertext: ArrayBuffer; iv: ArrayBuffer };
  const userId = payload.userId as string;

  const ecdhPrivate = await dskDecrypt(
    dsk,
    wrappedEcdh.ciphertext,
    wrappedEcdh.iv,
    buildDskDeviceEcdhAad(userId),
  );
  const signingPrivate = await dskDecrypt(
    dsk,
    wrappedSigning.ciphertext,
    wrappedSigning.iv,
    buildDskDeviceSigningAad(userId),
  );
  setDeviceFromPrivateKeys(state, ecdhPrivate, signingPrivate);

  return { status: "ok" };
}

export async function handleGenerateDskKey(state: WorkerKeyState): Promise<unknown> {
  const dsk = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
  state.dsk = dsk;
  await storeDsk(dsk);
  return { status: "ok" };
}
