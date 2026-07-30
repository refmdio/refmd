import { describe, expect, it } from "vite-plus/test";
import { createInitialState } from "../../state";
import {
  handleActivateIdentitySuccessor,
  handleBeginIdentitySuccessorFinalization,
  handleDiscardIdentitySuccessor,
  handleGenerateIdentityKeys,
  handleGenerateIdentitySuccessor,
  handleImportIdentityKeys,
  handleImportIdentitySuccessor,
  handleRestoreActivatedIdentitySuccessor,
  handleTrustIdentityRotationCheckpoint,
  trustIdentityRotationCheckpoint,
} from "./material";
import { handleWrapIdentityKeysForServer, handleWrapIdentitySuccessorForServer } from "./server";
import {
  requireIdentityEcdhPrivate,
  requireIdentityHybridEncryptionPrivateKeyMaterial,
  requireIdentityHybridSigningPrivateKeyMaterial,
} from "../utils";
import {
  handleSignIdentityKeyDirectoryCheckpoint,
  handleSignIdentityKeyDirectoryEvent,
} from "../sign";
import { resolveIdentityApprovalPublicMaterial } from "../tofu";
import {
  actorWithCheckpointAuthority,
  eventHead,
  eventRef,
  identityActor,
  keyDirectoryCheckpoint,
  keyDirectoryEvent,
  keyEntry,
} from "../../../key-directory/primitives";
import { blake3Base64Url } from "../../../hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "../../../jcs";
import { computeSigningKeyId } from "../../../signature";
import { computeHybridEncryptionKeyId } from "../../../hybrid-encryption";

describe("identity successor lifecycle", () => {
  it("keeps the current identity active until activation and destroys all old private material", () => {
    const state = createInitialState();
    state.userId = crypto.randomUUID();
    state.umk = crypto.getRandomValues(new Uint8Array(32));
    handleGenerateIdentityKeys(state);
    const previousPrivate = state.identityEcdhPrivate!;
    const previousEncryptionPrivate = state.identityHybridEncryptionPrivateKeyMaterial!;
    const previousSigningPrivate = state.identityHybridSigningState!.privateKeyMaterial;
    const previousSigningKeyId = state.identityHybridSigningState!.signingKeyId;

    const successor = handleGenerateIdentitySuccessor(state) as {
      encryptionKeyId: string;
    };
    const trustedCheckpoint = { scope_kind: "user", scope_id: state.userId, sequence: 1 };
    state.identityRotationTrustedCheckpointPayload = trustedCheckpoint;

    expect(state.identityHybridSigningState!.signingKeyId).toBe(previousSigningKeyId);
    const wrapped = handleWrapIdentitySuccessorForServer(state, {
      userId: state.userId,
      identityKeyEpoch: 2,
    }) as { encryptionKeyId: string };
    expect(wrapped.encryptionKeyId).toBe(successor.encryptionKeyId);
    const finalization = handleBeginIdentitySuccessorFinalization(state) as {
      oldPrivateKeyUseBlocked: boolean;
    };
    expect(finalization.oldPrivateKeyUseBlocked).toBe(true);
    expect(() => requireIdentityHybridSigningPrivateKeyMaterial(state)).toThrow(
      "Identity private key is blocked during rotation finalization",
    );
    expect(() => requireIdentityHybridEncryptionPrivateKeyMaterial(state)).toThrow(
      "Identity private key is blocked during rotation finalization",
    );
    expect(() => requireIdentityEcdhPrivate(state)).toThrow(
      "Identity private key is blocked during rotation finalization",
    );
    expect(() =>
      handleWrapIdentityKeysForServer(state, { userId: state.userId, identityKeyEpoch: 1 }),
    ).toThrow("Identity private key is blocked during rotation finalization");

    const result = handleActivateIdentitySuccessor(state) as {
      previousSigningKeyId: string;
      successorEncryptionKeyId: string;
      oldPrivateKeyDeleted: boolean;
    };
    expect(result.previousSigningKeyId).toBe(previousSigningKeyId);
    expect(result.successorEncryptionKeyId).toBe(successor.encryptionKeyId);
    expect(result.oldPrivateKeyDeleted).toBe(true);
    expect([...previousPrivate]).toEqual(Array.from({ length: 32 }, () => 0));
    expect(previousEncryptionPrivate.x25519_private).toBe("");
    expect(previousEncryptionPrivate.mlkem768_x25519_private).toBe("");
    expect(previousSigningPrivate.ed25519_private).toBe("");
    expect(previousSigningPrivate.mldsa65_private).toBe("");
    expect(state.pendingIdentitySuccessor).toBeNull();
    expect(state.identityRotationTrustedCheckpointPayload).toEqual(trustedCheckpoint);
  });

  it("keeps activation idempotent after importing the server-pending successor again", () => {
    const state = createInitialState();
    state.userId = crypto.randomUUID();
    state.umk = crypto.getRandomValues(new Uint8Array(32));
    handleGenerateIdentityKeys(state);
    handleGenerateIdentitySuccessor(state);
    const encrypted = {
      ...(handleWrapIdentitySuccessorForServer(state, {
        userId: state.userId,
        identityKeyEpoch: 2,
      }) as Parameters<typeof handleImportIdentitySuccessor>[1]),
      identityKeyEpoch: 2,
    };

    handleBeginIdentitySuccessorFinalization(state);
    const first = handleActivateIdentitySuccessor(state);
    const restored = handleImportIdentitySuccessor(state, encrypted) as { encryptionKeyId: string };
    const second = handleActivateIdentitySuccessor(state);
    const repeatedAuthorization = handleBeginIdentitySuccessorFinalization(state);

    expect(restored.encryptionKeyId).toBe(
      (first as { successorEncryptionKeyId: string }).successorEncryptionKeyId,
    );
    expect(second).toEqual(first);
    expect(repeatedAuthorization).toEqual(
      expect.objectContaining({
        previousSigningKeyId: (first as { previousSigningKeyId: string }).previousSigningKeyId,
        successorEncryptionKeyId: (first as { successorEncryptionKeyId: string })
          .successorEncryptionKeyId,
        oldPrivateKeyUseBlocked: true,
      }),
    );
    expect(state.pendingIdentitySuccessor).toBeNull();
  });

  it("reconstructs activated finalization in a fresh worker without the predecessor secret", () => {
    const source = createInitialState();
    source.userId = crypto.randomUUID();
    source.umk = crypto.getRandomValues(new Uint8Array(32));
    handleGenerateIdentityKeys(source);
    const previousEncryptionKeyId = computeHybridEncryptionKeyId(
      source.identityHybridEncryptionPublicKeyMaterial!,
    );
    const previousSigningKeyId = source.identityHybridSigningState!.signingKeyId;
    handleGenerateIdentitySuccessor(source);
    const encrypted = {
      ...(handleWrapIdentitySuccessorForServer(source, {
        userId: source.userId,
        identityKeyEpoch: 2,
      }) as Parameters<typeof handleImportIdentityKeys>[1]),
      identityKeyEpoch: 2,
    };

    const restored = createInitialState();
    restored.userId = source.userId;
    restored.umk = source.umk;
    handleImportIdentityKeys(restored, { ...encrypted, rotationDueAt: null });

    const successor = handleRestoreActivatedIdentitySuccessor(restored, {
      ...encrypted,
      previousEncryptionKeyId,
      previousSigningKeyId,
    }) as { encryptionKeyId: string };
    const authorization = handleBeginIdentitySuccessorFinalization(restored);
    const activation = handleActivateIdentitySuccessor(restored);

    expect(successor.encryptionKeyId).not.toBe(previousEncryptionKeyId);
    expect(restored.pendingIdentitySuccessor).toBeNull();
    expect(authorization).toEqual(
      expect.objectContaining({ previousEncryptionKeyId, previousSigningKeyId }),
    );
    expect(activation).toEqual(
      expect.objectContaining({ previousEncryptionKeyId, oldPrivateKeyDeleted: true }),
    );
  });

  it("resolves retired identity signing keys only from the trusted checkpoint", () => {
    const state = createInitialState();
    state.userId = crypto.randomUUID();
    handleGenerateIdentityKeys(state);
    const retiredSigningKeyId = state.identityHybridSigningState!.signingKeyId;
    const retiredPublicMaterial = state.identityHybridSigningState!.publicKeyMaterial;
    handleGenerateIdentitySuccessor(state);
    handleBeginIdentitySuccessorFinalization(state);
    handleActivateIdentitySuccessor(state);
    const currentSigningKeyId = state.identityHybridSigningState!.signingKeyId;
    const validFrom = { scope_kind: "user", scope_id: state.userId, event_sequence: 1 };
    state.identityRotationTrustedCheckpointPayload = keyDirectoryCheckpoint({
      scopeKind: "user",
      scopeId: state.userId,
      sequence: 3,
      issuedAt: new Date().toISOString(),
      coveredEventHead: { head_sequence: 3, head_hash: blake3Base64Url(new Uint8Array([3])) },
      identityKeys: [
        keyEntry(retiredSigningKeyId, retiredPublicMaterial, validFrom),
        keyEntry(
          currentSigningKeyId,
          state.identityHybridSigningState!.publicKeyMaterial,
          validFrom,
        ),
      ],
      deviceKeys: [],
      shareParticipantKeys: [],
      revokedKeyIds: [retiredSigningKeyId],
    });

    expect(resolveIdentityApprovalPublicMaterial(state, retiredSigningKeyId)).toEqual(
      retiredPublicMaterial,
    );
    expect(resolveIdentityApprovalPublicMaterial(state, currentSigningKeyId)).toEqual(
      state.identityHybridSigningState!.publicKeyMaterial,
    );
    expect(resolveIdentityApprovalPublicMaterial(state, "unknown-key")).toBeNull();

    const identityKeys = state.identityRotationTrustedCheckpointPayload.identity_keys as Record<
      string,
      unknown
    >[];
    identityKeys[0] = {
      ...identityKeys[0],
      key_material: { ...retiredPublicMaterial, owner_id: "x" },
    };
    expect(resolveIdentityApprovalPublicMaterial(state, retiredSigningKeyId)).toBeNull();
  });

  it("rejects overdue identity signing while allowing the rotation transition", () => {
    const state = createInitialState();
    state.userId = crypto.randomUUID();
    handleGenerateIdentityKeys(state);
    state.identityRotationDueAtMs = Date.now() - 1;

    expect(() =>
      handleSignIdentityKeyDirectoryCheckpoint(state, {
        variant: "identity_active",
        checkpointPayload: {},
      }),
    ).toThrow("Identity signing key rotation is overdue");
    expect(() => requireIdentityHybridSigningPrivateKeyMaterial(state)).toThrow(
      "Identity signing key rotation is overdue",
    );
    expect(requireIdentityHybridSigningPrivateKeyMaterial(state, { allowOverdue: true })).toBe(
      state.identityHybridSigningState!.privateKeyMaterial,
    );

    const successor = handleGenerateIdentitySuccessor(state) as {
      encryptionKeyId: string;
      hybridEncryptionPublicKeyMaterial: Record<string, unknown>;
      hybridSigningPublicKeyMaterial: Parameters<typeof computeSigningKeyId>[0];
    };
    expect(() =>
      handleSignIdentityKeyDirectoryCheckpoint(state, {
        variant: "identity_rotation",
        checkpointPayload: {},
      }),
    ).toThrow("Identity signing key rotation is overdue");
    expect(() =>
      handleSignIdentityKeyDirectoryEvent(state, {
        eventType: "identity_key_added",
        eventPayload: {},
      }),
    ).toThrow("Identity signing key rotation is overdue");

    const currentValidFrom = {
      scope_kind: "user",
      scope_id: state.userId,
      event_sequence: 1,
      event_hash: blake3Base64Url(new Uint8Array([1])),
    };
    const previous = keyDirectoryCheckpoint({
      scopeKind: "user",
      scopeId: state.userId,
      sequence: 1,
      issuedAt: new Date().toISOString(),
      coveredEventHead: { head_sequence: 1, head_hash: blake3Base64Url(new Uint8Array([1])) },
      identityKeys: [
        keyEntry(
          computeHybridEncryptionKeyId(state.identityHybridEncryptionPublicKeyMaterial!),
          state.identityHybridEncryptionPublicKeyMaterial!,
          currentValidFrom,
        ),
        keyEntry(
          state.identityHybridSigningState!.signingKeyId,
          state.identityHybridSigningState!.publicKeyMaterial,
          currentValidFrom,
        ),
      ],
      deviceKeys: [],
      shareParticipantKeys: [],
      revokedKeyIds: [],
    });
    expect(() =>
      handleTrustIdentityRotationCheckpoint(state, { checkpointPayload: previous }),
    ).not.toThrow();
    const successorSigningKeyId = computeSigningKeyId(successor.hybridSigningPublicKeyMaterial);
    const startedEvent = keyDirectoryEvent({
      scopeKind: "user",
      scopeId: state.userId,
      sequence: 2,
      eventType: "rotation_started",
      actor: actorWithCheckpointAuthority(
        identityActor(state.userId, state.identityHybridSigningState!.signingKeyId),
        "user",
        state.userId,
        previous,
      ),
      previousEventHash: (previous.covered_event_head as Record<string, string>).head_hash,
      body: {
        event_type: "rotation_started",
        rotation_kind: "identity",
        scope_kind: "user",
        scope_id: state.userId,
        old_identity_signing_key_id: state.identityHybridSigningState!.signingKeyId,
        old_identity_encryption_key_id: computeHybridEncryptionKeyId(
          state.identityHybridEncryptionPublicKeyMaterial!,
        ),
        new_identity_signing_key_id: successorSigningKeyId,
        new_identity_encryption_key_id: successor.encryptionKeyId,
        old_user_checkpoint_sequence: previous.sequence,
        old_user_checkpoint_hash: blake3Base64Url(
          canonicalizeStrictBytes(previous as StrictJsonValue),
        ),
        new_key_material_hash: blake3Base64Url(
          canonicalizeStrictBytes({
            hybrid_encryption_public_key_material:
              successor.hybridEncryptionPublicKeyMaterial as unknown as StrictJsonValue,
            hybrid_signing_public_key_material:
              successor.hybridSigningPublicKeyMaterial as unknown as StrictJsonValue,
          }),
        ),
        not_before_event_sequence: 2,
        reason: "scheduled",
      },
    });
    const event = keyDirectoryEvent({
      scopeKind: "user",
      scopeId: state.userId,
      sequence: 3,
      eventType: "identity_key_added",
      actor: actorWithCheckpointAuthority(
        identityActor(state.userId, state.identityHybridSigningState!.signingKeyId),
        "user",
        state.userId,
        previous,
      ),
      previousEventHash: eventHead(startedEvent).head_hash as string,
      body: {
        key_id: successorSigningKeyId,
        key_material_hash: blake3Base64Url(
          canonicalizeStrictBytes(
            successor.hybridSigningPublicKeyMaterial as unknown as StrictJsonValue,
          ),
        ),
      },
    });
    const validFrom = eventRef("user", state.userId, event);
    const checkpoint = keyDirectoryCheckpoint({
      scopeKind: "user",
      scopeId: state.userId,
      sequence: 2,
      issuedAt: new Date().toISOString(),
      previousCheckpointHash: blake3Base64Url(canonicalizeStrictBytes(previous as StrictJsonValue)),
      coveredEventHead: eventHead(event),
      identityKeys: [
        ...((previous.identity_keys as Record<string, unknown>[]) ?? []),
        keyEntry(successor.encryptionKeyId, successor.hybridEncryptionPublicKeyMaterial, validFrom),
        keyEntry(successorSigningKeyId, successor.hybridSigningPublicKeyMaterial, validFrom),
      ],
      deviceKeys: [],
      shareParticipantKeys: [],
      revokedKeyIds: [],
    });

    expect(() =>
      handleSignIdentityKeyDirectoryEvent(state, {
        eventType: "rotation_started",
        eventPayload: startedEvent,
        rotationPreviousCheckpointPayload: previous,
      }),
    ).not.toThrow();
    expect(() =>
      handleSignIdentityKeyDirectoryEvent(state, {
        eventType: "identity_key_added",
        eventPayload: event,
        rotationPreviousCheckpointPayload: previous,
        rotationStartedEventPayload: startedEvent,
      }),
    ).not.toThrow();
    expect(() =>
      handleSignIdentityKeyDirectoryCheckpoint(state, {
        variant: "identity_rotation",
        checkpointPayload: checkpoint,
        rotationPreviousCheckpointPayload: previous,
        rotationStartedEventPayload: startedEvent,
        rotationEventPayload: event,
      }),
    ).not.toThrow();

    expect(() =>
      handleSignIdentityKeyDirectoryEvent(state, {
        eventType: "identity_key_added",
        eventPayload: { ...event, unauthorized: true },
        rotationPreviousCheckpointPayload: previous,
        rotationStartedEventPayload: startedEvent,
      }),
    ).toThrow("Identity signing key rotation is overdue");
    expect(() =>
      handleSignIdentityKeyDirectoryCheckpoint(state, {
        variant: "identity_rotation",
        checkpointPayload: { ...checkpoint, unauthorized: true },
        rotationPreviousCheckpointPayload: previous,
        rotationStartedEventPayload: startedEvent,
        rotationEventPayload: event,
      }),
    ).toThrow("Identity signing key rotation is overdue");

    const fabricatedPrevious: Record<string, unknown> = {
      ...previous,
      device_keys: [{ key_id: "attacker-controlled" }],
    };
    expect(() => trustIdentityRotationCheckpoint(state, fabricatedPrevious, true)).toThrow(
      "identity_rotation_checkpoint_trust_replacement",
    );
    const approvedDeviceCheckpoint = keyDirectoryCheckpoint({
      scopeKind: "user",
      scopeId: state.userId,
      sequence: 2,
      issuedAt: new Date().toISOString(),
      previousCheckpointHash: blake3Base64Url(canonicalizeStrictBytes(previous as StrictJsonValue)),
      coveredEventHead: eventHead(event),
      identityKeys: previous.identity_keys as Record<string, unknown>[],
      deviceKeys: [{ key_id: "approved-device" }],
      shareParticipantKeys: [],
      revokedKeyIds: [],
    });
    expect(() =>
      trustIdentityRotationCheckpoint(state, approvedDeviceCheckpoint, true, [previous]),
    ).not.toThrow();
    expect(state.identityRotationTrustedCheckpointPayload).toEqual(approvedDeviceCheckpoint);
    const fabricatedEvent = keyDirectoryEvent({
      scopeKind: "user",
      scopeId: state.userId,
      sequence: 2,
      eventType: "identity_key_added",
      actor: actorWithCheckpointAuthority(
        identityActor(state.userId, state.identityHybridSigningState!.signingKeyId),
        "user",
        state.userId,
        fabricatedPrevious,
      ),
      previousEventHash: (fabricatedPrevious.covered_event_head as Record<string, string>)
        .head_hash,
      body: event.body as Record<string, unknown>,
    });
    expect(() =>
      handleSignIdentityKeyDirectoryEvent(state, {
        eventType: "identity_key_added",
        eventPayload: fabricatedEvent,
        rotationPreviousCheckpointPayload: fabricatedPrevious,
        rotationStartedEventPayload: startedEvent,
      }),
    ).toThrow("Identity signing key rotation is overdue");
  });

  it("discards a pending successor without changing the current identity", () => {
    const state = createInitialState();
    state.userId = crypto.randomUUID();
    handleGenerateIdentityKeys(state);
    const currentSigningKeyId = state.identityHybridSigningState!.signingKeyId;

    handleGenerateIdentitySuccessor(state);
    handleDiscardIdentitySuccessor(state);

    expect(state.pendingIdentitySuccessor).toBeNull();
    expect(state.identityHybridSigningState!.signingKeyId).toBe(currentSigningKeyId);
  });

  it("restores a durably wrapped pending successor without replacing the current identity", () => {
    const source = createInitialState();
    source.userId = crypto.randomUUID();
    source.umk = crypto.getRandomValues(new Uint8Array(32));
    handleGenerateIdentityKeys(source);
    const generated = handleGenerateIdentitySuccessor(source) as { encryptionKeyId: string };
    const encrypted = handleWrapIdentitySuccessorForServer(source, {
      userId: source.userId,
      identityKeyEpoch: 2,
    }) as Parameters<typeof handleImportIdentitySuccessor>[1];
    encrypted.identityKeyEpoch = 2;

    const restored = createInitialState();
    restored.userId = source.userId;
    restored.umk = source.umk;
    handleGenerateIdentityKeys(restored);
    const currentSigningKeyId = restored.identityHybridSigningState!.signingKeyId;

    const result = handleImportIdentitySuccessor(restored, encrypted) as {
      encryptionKeyId: string;
    };

    expect(result.encryptionKeyId).toBe(generated.encryptionKeyId);
    expect(restored.pendingIdentitySuccessor?.encryptionKeyId).toBe(generated.encryptionKeyId);
    expect(restored.identityHybridSigningState!.signingKeyId).toBe(currentSigningKeyId);
  });
});
