import type { WorkerKeyState } from "./state";
import { buildDeviceUmkDistributionAad } from "../aad";
import { ecdhDecrypt, ecdhEncrypt } from "../ecdh-cipher";
import {
  type HandlerPayload,
  requireDeviceEcdhPrivate,
  requireUmk,
  requireUserId,
} from "./handler-utils";

export function handleEcdhEncrypt(state: WorkerKeyState, p: HandlerPayload): unknown {
  const theirPublic = p.theirPublic as Uint8Array;
  const plaintext = p.plaintext as Uint8Array;
  const aad = p.aad as Uint8Array;
  const hkdfInfo = p.hkdfInfo as string;
  const deviceEcdhPrivate = requireDeviceEcdhPrivate(state);

  const result = ecdhEncrypt(plaintext, deviceEcdhPrivate, theirPublic, hkdfInfo, aad);
  return { ciphertext: result.ciphertext, nonce: result.nonce };
}

export function handleEcdhDecrypt(state: WorkerKeyState, p: HandlerPayload): unknown {
  const theirPublic = p.theirPublic as Uint8Array;
  const ciphertext = p.ciphertext as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const aad = p.aad as Uint8Array;
  const hkdfInfo = p.hkdfInfo as string;
  const deviceEcdhPrivate = requireDeviceEcdhPrivate(state);

  const plaintext = ecdhDecrypt(ciphertext, nonce, deviceEcdhPrivate, theirPublic, hkdfInfo, aad);
  return { plaintext };
}

export function handleEcdhEncryptUmk(state: WorkerKeyState, p: HandlerPayload): unknown {
  const theirPublic = p.theirPublic as Uint8Array;
  const senderDeviceId = p.senderDeviceId as string;
  const targetDeviceId = p.targetDeviceId as string;
  const userId = requireUserId(state);
  const aad = buildDeviceUmkDistributionAad(userId, senderDeviceId, targetDeviceId);
  const deviceEcdhPrivate = requireDeviceEcdhPrivate(state);
  const umk = requireUmk(state);

  const result = ecdhEncrypt(umk, deviceEcdhPrivate, theirPublic, "device_umk_wrap", aad);
  return { ciphertext: result.ciphertext, nonce: result.nonce };
}

export function handleEcdhDecryptUmk(state: WorkerKeyState, p: HandlerPayload): unknown {
  const theirPublic = p.theirPublic as Uint8Array;
  const ciphertext = p.ciphertext as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const senderDeviceId = p.senderDeviceId as string;
  const targetDeviceId = p.targetDeviceId as string;
  const userId = requireUserId(state);
  const aad = buildDeviceUmkDistributionAad(userId, senderDeviceId, targetDeviceId);
  const deviceEcdhPrivate = requireDeviceEcdhPrivate(state);

  const umk = ecdhDecrypt(
    ciphertext,
    nonce,
    deviceEcdhPrivate,
    theirPublic,
    "device_umk_wrap",
    aad,
  );
  state.umk = umk;
  return { status: "ok" };
}
