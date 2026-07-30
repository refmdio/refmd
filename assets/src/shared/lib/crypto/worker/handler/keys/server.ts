import type { WorkerKeyState } from "../../state";
import { wrapUmk } from "../../../umk";
import { encryptIdentityKeys } from "../../../identity";
import { takeTransientPuk } from "../transient";
import {
  requireIdentityEcdhPrivate,
  requireIdentityHybridEncryptionPrivateKeyMaterial,
  requireIdentityHybridSigningPrivateKeyMaterial,
  requireUmk,
} from "../utils";
import { CryptoOperationError } from "../../operation-error";
import type { HandlerPayload } from "../utils";

export function handleWrapUmkForServer(state: WorkerKeyState, payload: HandlerPayload): unknown {
  const umk = requireUmk(state);
  const userId = payload.userId as string;
  const puk = takeTransientPuk();

  if (!puk) {
    throw new CryptoOperationError("not_initialized", "PUK not available - derive auth keys first");
  }

  const { encryptedUmk, nonce } = wrapUmk(umk, puk, userId);
  puk.fill(0);
  return { encrypted: encryptedUmk, nonce };
}

export function handleWrapIdentityKeysForServer(
  state: WorkerKeyState,
  payload: HandlerPayload,
): unknown {
  const umk = requireUmk(state);
  const userId = payload.userId as string;
  const ecdhPrivate = requireIdentityEcdhPrivate(state);
  const hybridEncryptionPrivateKeyMaterial =
    requireIdentityHybridEncryptionPrivateKeyMaterial(state);
  const hybridSigningPrivateKeyMaterial = requireIdentityHybridSigningPrivateKeyMaterial(state);

  if (
    !state.identityEcdhPrivate ||
    !state.identityEcdhPublic ||
    !state.identityHybridEncryptionPrivateKeyMaterial ||
    !state.identityHybridEncryptionPublicKeyMaterial ||
    !state.identityHybridSigningState
  ) {
    throw new CryptoOperationError("not_initialized", "Identity keys not available");
  }

  const encrypted = encryptIdentityKeys(
    {
      ecdhPrivate,
      ecdhPublic: state.identityEcdhPublic,
      hybridEncryptionPrivateKeyMaterial,
      hybridEncryptionPublicKeyMaterial: state.identityHybridEncryptionPublicKeyMaterial,
      encryptionKeyId: "",
      hybridSigningPrivateKeyMaterial,
      hybridSigningPublicKeyMaterial: state.identityHybridSigningState.publicKeyMaterial,
    },
    umk,
    userId,
    payload.identityKeyEpoch as number,
  );

  return {
    encryptedHybridEncryptionPrivateKeyMaterial:
      encrypted.encryptedHybridEncryptionPrivateKeyMaterial,
    hybridEncryptionPrivateKeyMaterialNonce: encrypted.hybridEncryptionPrivateKeyMaterialNonce,
    encryptionKeyId: encrypted.encryptionKeyId,
    encryptedHybridSigningPrivateKeyMaterial: encrypted.encryptedHybridSigningPrivateKeyMaterial,
    hybridSigningPrivateKeyMaterialNonce: encrypted.hybridSigningPrivateKeyMaterialNonce,
    signingKeyId: encrypted.signingKeyId,
  };
}

export function handleWrapIdentitySuccessorForServer(
  state: WorkerKeyState,
  payload: HandlerPayload,
): unknown {
  const umk = requireUmk(state);
  const successor = state.pendingIdentitySuccessor;
  if (!successor) {
    throw new CryptoOperationError("not_initialized", "Identity successor not available");
  }
  return encryptIdentityKeys(
    successor,
    umk,
    payload.userId as string,
    payload.identityKeyEpoch as number,
  );
}
