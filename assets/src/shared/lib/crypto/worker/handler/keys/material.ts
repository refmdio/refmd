import type { WorkerKeyState } from "../../state";
import { decryptIdentityPrivateKeys, generateIdentityKeyPair } from "../../../identity";
import { generateUmk } from "../../../umk";
import { generateClientNonce, generateDeviceKeyPair } from "../../../device";
import {
  requireUmk,
  requireUserId,
  setDeviceFromPrivateKeys,
  setIdentityFromDecrypted,
} from "../utils";
import type { HandlerPayload } from "../utils";

export function handleImportIdentityKeys(state: WorkerKeyState, payload: HandlerPayload): unknown {
  const umk = requireUmk(state);
  const userId = requireUserId(state);

  const identity = decryptIdentityPrivateKeys(
    {
      encryptedEcdhPrivate: payload.encryptedEcdhPrivate as Uint8Array,
      ecdhPrivateNonce: payload.ecdhPrivateNonce as Uint8Array,
      encryptedSigningPrivate: payload.encryptedSigningPrivate as Uint8Array,
      signingPrivateNonce: payload.signingPrivateNonce as Uint8Array,
    },
    umk,
    userId,
  );
  setIdentityFromDecrypted(state, identity);

  return {
    deviceSigningPublic: state.deviceSigningPublic,
    deviceEcdhPublic: state.deviceEcdhPublic,
    identitySigningPublic: identity.signingPublic,
    identityEcdhPublic: identity.ecdhPublic,
  };
}

export function handleImportDeviceKeys(state: WorkerKeyState, payload: HandlerPayload): unknown {
  setDeviceFromPrivateKeys(
    state,
    payload.ecdhPrivate as Uint8Array,
    payload.signingPrivate as Uint8Array,
  );
  return {
    ecdhPublic: state.deviceEcdhPublic,
    signingPublic: state.deviceSigningPublic,
  };
}

export function handleImportUmk(state: WorkerKeyState, payload: HandlerPayload): unknown {
  state.umk = payload.umk as Uint8Array;
  return { status: "ok" };
}

export function handleGenerateIdentityKeys(state: WorkerKeyState): unknown {
  const keyPair = generateIdentityKeyPair();
  setIdentityFromDecrypted(state, keyPair);
  return { ecdhPublic: keyPair.ecdhPublic, signingPublic: keyPair.signingPublic };
}

export function handleGenerateDeviceKeys(state: WorkerKeyState): unknown {
  const keyPair = generateDeviceKeyPair();
  state.deviceEcdhPrivate = keyPair.ecdhPrivate;
  state.deviceEcdhPublic = keyPair.ecdhPublic;
  state.deviceSigningPrivate = keyPair.signingPrivate;
  state.deviceSigningPublic = keyPair.signingPublic;
  return { ecdhPublic: keyPair.ecdhPublic, signingPublic: keyPair.signingPublic };
}

export function handleGenerateUmk(state: WorkerKeyState): unknown {
  state.umk = generateUmk();
  return { status: "ok" };
}

export function handleGenerateClientNonce(): Uint8Array {
  return generateClientNonce();
}
