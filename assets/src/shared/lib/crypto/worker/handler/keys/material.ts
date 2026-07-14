import type { WorkerKeyState } from "../../state";
import { decryptIdentityPrivateKeys, generateIdentityKeyPair } from "../../../identity";
import {
  computeHybridEncryptionKeyId,
  destroyHybridEncryptionPrivateKeyMaterial,
} from "../../../hybrid-encryption";
import { computeSigningKeyId, destroyHybridSigningPrivateKeyMaterial } from "../../../signature";
import { generateUmk } from "../../../umk";
import { generateClientNonce, generateDeviceKeyPair } from "../../../device";
import { canonicalizeStrict, canonicalizeStrictBytes, type StrictJsonValue } from "../../../jcs";
import { blake3Base64Url } from "../../../hash";
import {
  requireUmk,
  currentDeviceHybridSigningState,
  requireDeviceId,
  requireUserId,
  setDeviceFromPrivateKeys,
  setIdentityFromDecrypted,
} from "../utils";
import type { HandlerPayload } from "../utils";
import { zeroOut } from "../../state";

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
  handleSetIdentityRotationDeadline(state, payload);
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
  state.identityRotationDueAtMs = null;
  return {
    ecdhPublic: keyPair.ecdhPublic,
    hybridEncryptionPublicKeyMaterial: keyPair.hybridEncryptionPublicKeyMaterial,
    encryptionKeyId: keyPair.encryptionKeyId,
    hybridSigningPublicKeyMaterial: keyPair.hybridSigningPublicKeyMaterial,
  };
}

export function handleGenerateIdentitySuccessor(state: WorkerKeyState): unknown {
  const userId = requireUserId(state);
  if (state.pendingIdentitySuccessor) throw new Error("identity_successor_already_pending");
  state.identityRotationActivation = null;
  state.identityRotationFinalization = null;
  const keyPair = generateIdentityKeyPair(userId);
  state.pendingIdentitySuccessor = keyPair;
  return {
    ecdhPublic: keyPair.ecdhPublic,
    hybridEncryptionPublicKeyMaterial: keyPair.hybridEncryptionPublicKeyMaterial,
    encryptionKeyId: keyPair.encryptionKeyId,
    hybridSigningPublicKeyMaterial: keyPair.hybridSigningPublicKeyMaterial,
  };
}

export function handleImportIdentitySuccessor(
  state: WorkerKeyState,
  payload: HandlerPayload,
): unknown {
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
    requireUmk(state),
    requireUserId(state),
  );
  const activeEncryptionKeyId = state.identityHybridEncryptionPublicKeyMaterial
    ? computeHybridEncryptionKeyId(state.identityHybridEncryptionPublicKeyMaterial)
    : null;
  const activeSigningKeyId = state.identityHybridSigningState?.signingKeyId ?? null;
  if (
    state.identityRotationActivation?.successorEncryptionKeyId === identity.encryptionKeyId &&
    state.identityRotationActivation.successorSigningKeyId ===
      computeSigningKeyId(identity.hybridSigningPublicKeyMaterial) &&
    activeEncryptionKeyId === identity.encryptionKeyId &&
    activeSigningKeyId === state.identityRotationActivation.successorSigningKeyId
  ) {
    destroyIdentityKeyPair(identity);
    return {
      ecdhPublic: state.identityEcdhPublic,
      encryptionKeyId: activeEncryptionKeyId,
      hybridEncryptionPublicKeyMaterial: state.identityHybridEncryptionPublicKeyMaterial,
      hybridSigningPublicKeyMaterial: state.identityHybridSigningState!.publicKeyMaterial,
    };
  }
  if (state.pendingIdentitySuccessor) destroyIdentityKeyPair(state.pendingIdentitySuccessor);
  state.pendingIdentitySuccessor = identity;
  return {
    ecdhPublic: identity.ecdhPublic,
    encryptionKeyId: identity.encryptionKeyId,
    hybridEncryptionPublicKeyMaterial: identity.hybridEncryptionPublicKeyMaterial,
    hybridSigningPublicKeyMaterial: identity.hybridSigningPublicKeyMaterial,
  };
}

export function handleRestoreActivatedIdentitySuccessor(
  state: WorkerKeyState,
  payload: HandlerPayload,
): unknown {
  const successor = decryptIdentityPrivateKeys(
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
    requireUmk(state),
    requireUserId(state),
  );
  const successorSigningKeyId = computeSigningKeyId(successor.hybridSigningPublicKeyMaterial);
  const previousEncryptionKeyId = payload.previousEncryptionKeyId as string;
  const previousSigningKeyId = payload.previousSigningKeyId as string;
  const activeEncryptionKeyId = state.identityHybridEncryptionPublicKeyMaterial
    ? computeHybridEncryptionKeyId(state.identityHybridEncryptionPublicKeyMaterial)
    : null;
  const activeSigningKeyId = state.identityHybridSigningState?.signingKeyId ?? null;

  if (
    activeEncryptionKeyId === successor.encryptionKeyId &&
    activeSigningKeyId === successorSigningKeyId
  ) {
    destroyIdentityKeyPair(successor);
    if (state.pendingIdentitySuccessor) destroyIdentityKeyPair(state.pendingIdentitySuccessor);
    state.pendingIdentitySuccessor = null;
    state.identityRotationFinalization = null;
    state.identityRotationActivation = {
      previousEncryptionKeyId,
      previousSigningKeyId,
      successorEncryptionKeyId: activeEncryptionKeyId,
      successorSigningKeyId: activeSigningKeyId,
    };
    return {
      ecdhPublic: state.identityEcdhPublic,
      encryptionKeyId: activeEncryptionKeyId,
      hybridEncryptionPublicKeyMaterial: state.identityHybridEncryptionPublicKeyMaterial,
      hybridSigningPublicKeyMaterial: state.identityHybridSigningState!.publicKeyMaterial,
    };
  }

  if (
    activeEncryptionKeyId !== previousEncryptionKeyId ||
    activeSigningKeyId !== previousSigningKeyId
  ) {
    destroyIdentityKeyPair(successor);
    throw new Error("identity_successor_activation_restore_mismatch");
  }

  if (state.pendingIdentitySuccessor) destroyIdentityKeyPair(state.pendingIdentitySuccessor);
  state.pendingIdentitySuccessor = successor;
  state.identityRotationActivation = null;
  state.identityRotationFinalization = {
    previousEncryptionKeyId,
    previousSigningKeyId,
    successorEncryptionKeyId: successor.encryptionKeyId,
    successorSigningKeyId,
  };
  return {
    ecdhPublic: successor.ecdhPublic,
    encryptionKeyId: successor.encryptionKeyId,
    hybridEncryptionPublicKeyMaterial: successor.hybridEncryptionPublicKeyMaterial,
    hybridSigningPublicKeyMaterial: successor.hybridSigningPublicKeyMaterial,
  };
}

export function handleActivateIdentitySuccessor(state: WorkerKeyState): unknown {
  const successor = state.pendingIdentitySuccessor;
  if (!successor) {
    if (state.identityRotationActivation) {
      return { ...state.identityRotationActivation, oldPrivateKeyDeleted: true };
    }
    throw new Error("identity_successor_unavailable");
  }
  const finalization = state.identityRotationFinalization;
  if (!finalization) throw new Error("identity_successor_finalization_not_started");
  const previousSigningKeyId = state.identityHybridSigningState?.signingKeyId ?? null;
  const previousEncryptionKeyId = state.identityHybridEncryptionPublicKeyMaterial
    ? computeHybridEncryptionKeyId(state.identityHybridEncryptionPublicKeyMaterial)
    : null;
  if (!previousEncryptionKeyId || !previousSigningKeyId) {
    throw new Error("identity_rotation_previous_key_missing");
  }
  const successorSigningKeyId = computeSigningKeyId(successor.hybridSigningPublicKeyMaterial);
  if (
    finalization.previousEncryptionKeyId !== previousEncryptionKeyId ||
    finalization.previousSigningKeyId !== previousSigningKeyId ||
    finalization.successorEncryptionKeyId !== successor.encryptionKeyId ||
    finalization.successorSigningKeyId !== successorSigningKeyId
  ) {
    throw new Error("identity_successor_finalization_mismatch");
  }
  const previousEcdhPrivate = state.identityEcdhPrivate;
  const previousEncryptionPrivate = state.identityHybridEncryptionPrivateKeyMaterial;
  const previousSigningPrivate = state.identityHybridSigningState?.privateKeyMaterial ?? null;
  setIdentityFromDecrypted(state, successor);
  state.pendingIdentitySuccessor = null;
  zeroOut(previousEcdhPrivate);
  if (previousEncryptionPrivate) {
    destroyHybridEncryptionPrivateKeyMaterial(previousEncryptionPrivate);
  }
  if (previousSigningPrivate) destroyHybridSigningPrivateKeyMaterial(previousSigningPrivate);
  const activation = {
    previousEncryptionKeyId,
    previousSigningKeyId,
    successorEncryptionKeyId: successor.encryptionKeyId,
    successorSigningKeyId,
  };
  state.identityRotationActivation = activation;
  state.identityRotationFinalization = null;
  state.identityRotationDueAtMs = null;
  return {
    ...activation,
    oldPrivateKeyDeleted: true,
  };
}

export function handleBeginIdentitySuccessorFinalization(state: WorkerKeyState): unknown {
  if (state.identityRotationActivation) {
    return { ...state.identityRotationActivation, oldPrivateKeyUseBlocked: true };
  }
  const successor = state.pendingIdentitySuccessor;
  const previousSigningKeyId = state.identityHybridSigningState?.signingKeyId ?? null;
  const previousEncryptionKeyId = state.identityHybridEncryptionPublicKeyMaterial
    ? computeHybridEncryptionKeyId(state.identityHybridEncryptionPublicKeyMaterial)
    : null;
  if (!successor || !previousEncryptionKeyId || !previousSigningKeyId) {
    throw new Error("identity_successor_unavailable");
  }
  const finalization = {
    previousEncryptionKeyId,
    previousSigningKeyId,
    successorEncryptionKeyId: successor.encryptionKeyId,
    successorSigningKeyId: computeSigningKeyId(successor.hybridSigningPublicKeyMaterial),
  };
  if (
    state.identityRotationFinalization &&
    canonicalizeStrict(state.identityRotationFinalization as unknown as StrictJsonValue) !==
      canonicalizeStrict(finalization as unknown as StrictJsonValue)
  ) {
    throw new Error("identity_successor_finalization_mismatch");
  }
  state.identityRotationFinalization = finalization;
  return { ...finalization, oldPrivateKeyUseBlocked: true };
}

export function handleDiscardIdentitySuccessor(state: WorkerKeyState): unknown {
  if (state.pendingIdentitySuccessor) destroyIdentityKeyPair(state.pendingIdentitySuccessor);
  state.pendingIdentitySuccessor = null;
  state.identityRotationFinalization = null;
  return { status: "ok" };
}

export function handleSetIdentityRotationDeadline(
  state: WorkerKeyState,
  payload: HandlerPayload,
): unknown {
  const dueAt = payload.rotationDueAt;
  if (dueAt === null) {
    state.identityRotationDueAtMs = null;
    return { status: "ok" };
  }
  if (typeof dueAt !== "string" || !Number.isFinite(Date.parse(dueAt))) {
    throw new Error("identity_rotation_deadline_invalid");
  }
  state.identityRotationDueAtMs = Date.parse(dueAt);
  return { status: "ok" };
}

export function handleTrustIdentityRotationCheckpoint(
  state: WorkerKeyState,
  payload: HandlerPayload,
): unknown {
  trustIdentityRotationCheckpoint(
    state,
    payload.checkpointPayload,
    true,
    payload.checkpointAncestryPayloads,
  );
  return { status: "ok" };
}

export function trustIdentityRotationCheckpoint(
  state: WorkerKeyState,
  checkpointPayload: unknown,
  allowOverdue: boolean,
  checkpointAncestryPayloads: unknown = [],
): void {
  if (
    !allowOverdue &&
    state.identityRotationDueAtMs !== null &&
    state.identityRotationDueAtMs <= Date.now()
  ) {
    throw new Error("identity_rotation_checkpoint_trust_overdue");
  }
  if (
    !checkpointPayload ||
    typeof checkpointPayload !== "object" ||
    Array.isArray(checkpointPayload) ||
    !state.userId ||
    !state.identityHybridSigningState ||
    !state.identityHybridEncryptionPublicKeyMaterial
  ) {
    throw new Error("identity_rotation_checkpoint_trust_invalid");
  }
  const checkpoint = checkpointPayload as Record<string, unknown>;
  const identityKeys = Array.isArray(checkpoint.identity_keys)
    ? checkpoint.identity_keys.filter(
        (entry): entry is Record<string, unknown> =>
          !!entry && typeof entry === "object" && !Array.isArray(entry),
      )
    : [];
  const currentEncryptionKeyId = computeHybridEncryptionKeyId(
    state.identityHybridEncryptionPublicKeyMaterial,
  );
  const currentSigningKeyId = state.identityHybridSigningState.signingKeyId;
  const revoked = Array.isArray(checkpoint.revoked_key_ids) ? checkpoint.revoked_key_ids : [];
  if (
    checkpoint.scope_kind !== "user" ||
    checkpoint.scope_id !== state.userId ||
    !identityKeys.some((entry) => entry.key_id === currentEncryptionKeyId) ||
    !identityKeys.some((entry) => entry.key_id === currentSigningKeyId) ||
    revoked.includes(currentEncryptionKeyId) ||
    revoked.includes(currentSigningKeyId)
  ) {
    throw new Error("identity_rotation_checkpoint_trust_invalid");
  }
  if (allowOverdue && state.identityRotationTrustedCheckpointPayload) {
    assertIdentityRotationCheckpointAdvance(
      state.identityRotationTrustedCheckpointPayload,
      checkpoint,
      checkpointAncestryPayloads,
    );
  }
  state.identityRotationTrustedCheckpointPayload = structuredClone(checkpoint);
}

function assertIdentityRotationCheckpointAdvance(
  existing: Record<string, unknown>,
  candidate: Record<string, unknown>,
  ancestryPayloads: unknown,
): void {
  const existingCanonical = canonicalizeStrict(existing as StrictJsonValue);
  const candidateCanonical = canonicalizeStrict(candidate as StrictJsonValue);
  if (existingCanonical === candidateCanonical) return;
  if (!Array.isArray(ancestryPayloads)) {
    throw new Error("identity_rotation_checkpoint_trust_replacement");
  }

  const payloads = ancestryPayloads.filter(
    (entry): entry is Record<string, unknown> =>
      !!entry && typeof entry === "object" && !Array.isArray(entry),
  );
  const path = [...payloads, candidate]
    .filter(
      (entry, index, entries) =>
        entries.findIndex(
          (other) =>
            canonicalizeStrict(other as StrictJsonValue) ===
            canonicalizeStrict(entry as StrictJsonValue),
        ) === index,
    )
    .sort((left, right) => checkpointSequence(left) - checkpointSequence(right));
  const anchorIndex = path.findIndex(
    (entry) => canonicalizeStrict(entry as StrictJsonValue) === existingCanonical,
  );
  const candidateIndex = path.findIndex(
    (entry) => canonicalizeStrict(entry as StrictJsonValue) === candidateCanonical,
  );
  if (anchorIndex < 0 || candidateIndex <= anchorIndex || candidateIndex !== path.length - 1) {
    throw new Error("identity_rotation_checkpoint_trust_replacement");
  }

  for (let index = anchorIndex + 1; index <= candidateIndex; index += 1) {
    const previous = path[index - 1]!;
    const next = path[index]!;
    if (
      checkpointSequence(next) !== checkpointSequence(previous) + 1 ||
      next.previous_checkpoint_hash !== checkpointPayloadHash(previous)
    ) {
      throw new Error("identity_rotation_checkpoint_trust_replacement");
    }
  }
}

function checkpointSequence(payload: Record<string, unknown>): number {
  const sequence = payload.sequence;
  if (!Number.isSafeInteger(sequence) || (sequence as number) < 1) {
    throw new Error("identity_rotation_checkpoint_trust_invalid");
  }
  return sequence as number;
}

function checkpointPayloadHash(payload: Record<string, unknown>): string {
  return blake3Base64Url(canonicalizeStrictBytes(payload as StrictJsonValue));
}

function destroyIdentityKeyPair(identity: import("../../../identity").IdentityKeyPair): void {
  zeroOut(identity.ecdhPrivate);
  destroyHybridEncryptionPrivateKeyMaterial(identity.hybridEncryptionPrivateKeyMaterial);
  destroyHybridSigningPrivateKeyMaterial(identity.hybridSigningPrivateKeyMaterial);
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
