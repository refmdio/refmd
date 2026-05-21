import type { WorkerKeyState } from "../../state";
import { wrapUmk } from "../../../umk";
import { encryptIdentityKeys } from "../../../identity";
import { takeTransientPuk } from "../transient";
import { requireUmk } from "../utils";
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
      ecdhPrivate: state.identityEcdhPrivate,
      ecdhPublic: state.identityEcdhPublic,
      hybridEncryptionPrivateKeyMaterial: state.identityHybridEncryptionPrivateKeyMaterial,
      hybridEncryptionPublicKeyMaterial: state.identityHybridEncryptionPublicKeyMaterial,
      encryptionKeyId: "",
      hybridSigningPrivateKeyMaterial: state.identityHybridSigningState.privateKeyMaterial,
      hybridSigningPublicKeyMaterial: state.identityHybridSigningState.publicKeyMaterial,
    },
    umk,
    userId,
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
