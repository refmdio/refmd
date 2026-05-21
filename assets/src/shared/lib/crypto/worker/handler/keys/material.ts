import type { WorkerKeyState } from "../../state";
import { decryptIdentityPrivateKeys, generateIdentityKeyPair } from "../../../identity";
import { generateUmk } from "../../../umk";
import { generateClientNonce, generateDeviceKeyPair } from "../../../device";
import {
  requireUmk,
  currentDeviceHybridSigningState,
  requireDeviceId,
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
      encryptedHybridEncryptionPrivateKeyMaterial:
        payload.encryptedHybridEncryptionPrivateKeyMaterial as Uint8Array,
      hybridEncryptionPrivateKeyMaterialNonce:
        payload.hybridEncryptionPrivateKeyMaterialNonce as Uint8Array,
      encryptionKeyId: payload.encryptionKeyId as string,
      encryptedHybridSigningPrivateKeyMaterial:
        payload.encryptedHybridSigningPrivateKeyMaterial as Uint8Array,
      hybridSigningPrivateKeyMaterialNonce:
        payload.hybridSigningPrivateKeyMaterialNonce as Uint8Array,
      signingKeyId: payload.signingKeyId as string,
    },
    umk,
    userId,
  );
  setIdentityFromDecrypted(state, identity);
  const deviceHybridSigningPublicKeyMaterialKeyMaterial =
    currentDeviceHybridSigningState(state)?.publicKeyMaterial;

  return {
    deviceHybridSigningPublicKeyMaterial: deviceHybridSigningPublicKeyMaterialKeyMaterial,
    deviceEcdhPublic: state.deviceEcdhPublic,
    identityHybridSigningPublicKeyMaterial: identity.hybridSigningPublicKeyMaterial,
    identityEcdhPublic: identity.ecdhPublic,
    identityHybridEncryptionPublicKeyMaterial: identity.hybridEncryptionPublicKeyMaterial,
    identityEncryptionKeyId: identity.encryptionKeyId,
  };
}

export function handleImportUmk(state: WorkerKeyState, payload: HandlerPayload): unknown {
  state.umk = payload.umk as Uint8Array;
  return { status: "ok" };
}

export function handleGenerateIdentityKeys(state: WorkerKeyState): unknown {
  const userId = requireUserId(state);
  const keyPair = generateIdentityKeyPair(userId);
  setIdentityFromDecrypted(state, keyPair);
  return {
    ecdhPublic: keyPair.ecdhPublic,
    hybridEncryptionPublicKeyMaterial: keyPair.hybridEncryptionPublicKeyMaterial,
    encryptionKeyId: keyPair.encryptionKeyId,
    hybridSigningPublicKeyMaterial: keyPair.hybridSigningPublicKeyMaterial,
  };
}

export function handleGenerateDeviceKeys(state: WorkerKeyState, payload: HandlerPayload): unknown {
  const deviceId = (payload.deviceId as string | undefined) ?? requireDeviceId(state);
  const ownerKind =
    payload.ownerKind === "share_participant_device" ? "share_participant_device" : "device";
  const keyPair = generateDeviceKeyPair(deviceId, ownerKind);
  setDeviceFromPrivateKeys(
    state,
    keyPair.ecdhPrivate,
    keyPair.hybridEncryptionPrivateKeyMaterial,
    keyPair.hybridSigningPrivateKeyMaterial,
    ownerKind,
    deviceId,
  );
  state.deviceId = deviceId;
  return {
    ecdhPublic: keyPair.ecdhPublic,
    hybridEncryptionPublicKeyMaterial: keyPair.hybridEncryptionPublicKeyMaterial,
    encryptionKeyId: keyPair.encryptionKeyId,
    hybridSigningPublicKeyMaterial: keyPair.hybridSigningPublicKeyMaterial,
    signingKeyId: keyPair.signingKeyId,
  };
}

export function handleGenerateUmk(state: WorkerKeyState): unknown {
  state.umk = generateUmk();
  return { status: "ok" };
}

export function handleGenerateClientNonce(): Uint8Array {
  return generateClientNonce();
}
