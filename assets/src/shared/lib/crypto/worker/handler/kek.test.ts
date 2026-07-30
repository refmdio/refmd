import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const dskStoreMocks = vi.hoisted(() => ({
  deleteValue: vi.fn(),
  loadValue: vi.fn(),
  storeValue: vi.fn(),
}));
const operationProofMocks = vi.hoisted(() => ({ verify: vi.fn() }));
const admissionMocks = vi.hoisted(() => ({
  verify: vi.fn(),
  require: vi.fn(),
  token: { verified: true },
}));

vi.mock("./dsk-idb", () => ({
  deleteDskStoreValueInWorker: dskStoreMocks.deleteValue,
  loadDskStoreValueInWorker: dskStoreMocks.loadValue,
  loadDskStoreValueStrictInWorker: dskStoreMocks.loadValue,
  storeDskStoreValueInWorker: dskStoreMocks.storeValue,
}));
vi.mock("@/shared/lib/anti-rollback/key-directory-pin/wrap-operation-proof", () => ({
  verifyWorkspaceSignedPqWrapOperation: operationProofMocks.verify,
}));
vi.mock("@/shared/lib/anti-rollback/key-directory-pin/recipient-delivery-admission", () => ({
  verifyRecipientDeliveryAdmission: admissionMocks.verify,
  recipientDeliveryOperationProof: admissionMocks.require,
}));

import { base64UrlEncode, randomBytes } from "../../encoding";
import { blake3Base64Url } from "../../hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "../../jcs";
import { createInitialState, setActiveKekVersion, setCachedKek } from "../state";
import {
  handleCreateSignedPqGuestInvitationShareKeyWrap,
  handleCommitGuestInvitationShareKey,
  handleDeleteKekVersion,
  handleFinalizeSignedPqWrapOperationCheckpoint,
  handleGenerateInitialAkeResponderPrekey,
  handleGenerateKek,
  handleOpenSignedPqGuestInvitationShareKeyWrap,
  handleOpenSignedPqDeviceKekWrap,
  handleOpenRecipientBoundInvitationDeviceKekWrap,
  handleRewrapInvitationBootstrapForKekRotation,
  handleUnwrapKekFromInvitationBootstrap,
  handleWrapKekForInvitationBootstrap,
} from "./kek";
import { handleGenerateInvitationRedeemAuthority } from "./sign";
import { handleGenerateDeviceKeys } from "./keys/material";
import type { HybridEncryptionPublicKeyMaterial } from "../../hybrid-encryption";
import {
  signedPqWrapEventBody,
  signedPqWrapRecordFromEnvelope,
  type SignedPqWrapRecord,
} from "../../signed-pq-wrap";

const workspaceId = "workspace-1";
const guestInvitationId = "guest-invitation-1";

beforeEach(() => {
  vi.clearAllMocks();
  dskStoreMocks.loadValue.mockResolvedValue(null);
  dskStoreMocks.deleteValue.mockResolvedValue(undefined);
  dskStoreMocks.storeValue.mockResolvedValue(undefined);
  operationProofMocks.verify.mockImplementation(async (_workspaceId, operationProof) =>
    verifiedOperationFor(signedPqWrapRecordFromEnvelope(operationProof)),
  );
  admissionMocks.verify.mockResolvedValue(admissionMocks.token);
  admissionMocks.require.mockImplementation((admission, operationProof) => {
    if (admission !== admissionMocks.token)
      throw new Error("recipient_delivery_admission_required");
    return operationProof;
  });
});

describe("KEK deletion boundary", () => {
  it("keeps existing same-version KEK material stable across generation retries", () => {
    const state = createInitialState();
    const pendingKek = new Uint8Array([5, 6, 7, 8]);
    setCachedKek(state, workspaceId, pendingKek, 2);
    setActiveKekVersion(state, workspaceId, 1);

    expect(handleGenerateKek(state, { workspaceId, keyVersion: 2 })).toEqual({ keyVersion: 2 });

    expect(state.kekCache.get(workspaceId)?.get(2)?.kek).toBe(pendingKek);
    expect(state.activeKekVersions.get(workspaceId)).toBe(2);
  });

  it("zeroizes the old cached version and deletes matching offline persistence", async () => {
    const state = createInitialState();
    const oldKek = new Uint8Array([1, 2, 3, 4]);
    setCachedKek(state, workspaceId, oldKek, 1);
    setCachedKek(state, workspaceId, new Uint8Array([5, 6, 7, 8]), 2);
    setActiveKekVersion(state, workspaceId, 2);
    dskStoreMocks.loadValue
      .mockResolvedValueOnce({
        keyVersion: 1,
        ciphertext: new ArrayBuffer(1),
        iv: new ArrayBuffer(1),
      })
      .mockResolvedValueOnce(null);

    await expect(handleDeleteKekVersion(state, { workspaceId, keyVersion: 1 })).resolves.toEqual({
      memoryDeleted: true,
      offlineDeleted: true,
      keyVersion: 1,
    });

    expect([...oldKek]).toEqual([0, 0, 0, 0]);
    expect(state.kekCache.get(workspaceId)?.has(1)).toBe(false);
    expect(state.kekCache.get(workspaceId)?.has(2)).toBe(true);
    expect(dskStoreMocks.deleteValue).toHaveBeenCalledWith("refmd-offline-key:kek:workspace-1");
  });

  it("refuses to delete the active KEK version", async () => {
    const state = createInitialState();
    const activeKek = new Uint8Array([1, 2, 3, 4]);
    setCachedKek(state, workspaceId, activeKek, 1);
    setActiveKekVersion(state, workspaceId, 1);

    await expect(handleDeleteKekVersion(state, { workspaceId, keyVersion: 1 })).rejects.toThrow(
      "active_kek_version_deletion_forbidden",
    );
    expect([...activeKek]).toEqual([1, 2, 3, 4]);
    expect(dskStoreMocks.deleteValue).not.toHaveBeenCalled();
  });
});

describe("Initial AKE responder prekey boundary", () => {
  it.each([undefined, "legacy_distribution"])(
    "rejects an unlisted purpose without defaulting it (%s)",
    (purpose) => {
      const state = createInitialState();
      const deviceId = crypto.randomUUID();
      handleGenerateDeviceKeys(state, { deviceId });

      expect(() =>
        handleGenerateInitialAkeResponderPrekey(state, {
          purpose,
          operationId: crypto.randomUUID(),
          userId: crypto.randomUUID(),
          deviceId,
          serverChallenge: base64UrlEncode(randomBytes(32)),
          issuedAtMs: 1_700_000_000_000,
          expiresAtMs: 1_700_000_300_000,
        }),
      ).toThrow("responder_prekey_purpose_invalid");
      expect(state.initialAkeResponderPrekeys.size).toBe(0);
    },
  );

  it("rejects a challenge that is not exactly 32 bytes", () => {
    const state = createInitialState();
    const deviceId = crypto.randomUUID();
    handleGenerateDeviceKeys(state, { deviceId });

    expect(() =>
      handleGenerateInitialAkeResponderPrekey(state, {
        purpose: "umk_distribution",
        operationId: crypto.randomUUID(),
        userId: crypto.randomUUID(),
        deviceId,
        serverChallenge: base64UrlEncode(randomBytes(31)),
        issuedAtMs: 1_700_000_000_000,
        expiresAtMs: 1_700_000_300_000,
      }),
    ).toThrow("invalid_base64url_decoded_length");
    expect(state.initialAkeResponderPrekeys.size).toBe(0);
  });
});

function scopedGuestAad() {
  return {
    protocol: "refmd.guest-invitation-bootstrap",
    version: 1,
    suite_id: "refmd-v2-invitation-bootstrap-xchacha20poly1305",
    workspace_id: workspaceId,
    guest_invitation_id: guestInvitationId,
    scope_kind: "document",
    scope_id: "document-1",
    permission: "view",
    delivery_mode: "unknown_fragment",
    recipient_user_id: "NOT_APPLICABLE",
    recipient_device_ids: [],
    key_version_context: {
      workspace_kek_version: "NOT_APPLICABLE",
      share_key_version: 1,
      dek_version: 1,
    },
    token_hash: "token-hash",
  };
}

function scopedGuestPlaintext() {
  return {
    protocol: "refmd.guest-invitation-bootstrap",
    version: 1,
    workspace_id: workspaceId,
    guest_invitation_id: guestInvitationId,
    scope_kind: "document",
    scope_id: "document-1",
    permission: "view",
    key_version_context: {
      workspace_kek_version: "NOT_APPLICABLE",
      share_key_version: 1,
      dek_version: 1,
    },
    workspace_key_directory_checkpoint: { payload: { checkpoint: true }, signatures: [] },
    workspace_pin_bootstrap_hash: "pin-hash",
    workspace_pin_bootstrap: { payload: { pin: true }, signatures: [] },
  };
}

describe("invitation bootstrap package boundary", () => {
  it("rewraps a workspace-scoped guest package from the old KEK to the new KEK", () => {
    const issuerState = createInitialState();
    const oldKek = randomBytes(32);
    const newKek = randomBytes(32);
    setCachedKek(issuerState, workspaceId, oldKek, 1);
    setCachedKek(issuerState, workspaceId, newKek, 2);
    setActiveKekVersion(issuerState, workspaceId, 2);
    handleGenerateInvitationRedeemAuthority(issuerState, { invitationId: guestInvitationId });
    const bootstrapSecret = base64UrlEncode(randomBytes(32));
    const keyVersionContext = {
      workspace_kek_version: 1,
      share_key_version: "NOT_APPLICABLE",
      dek_version: "NOT_APPLICABLE",
    };
    const aad = {
      ...scopedGuestAad(),
      scope_kind: "workspace",
      scope_id: "none",
      key_version_context: keyVersionContext,
    };
    const plaintext = {
      ...scopedGuestPlaintext(),
      scope_kind: "workspace",
      scope_id: "none",
      key_version_context: keyVersionContext,
    };
    const bootstrap = handleWrapKekForInvitationBootstrap(issuerState, {
      protocol: "refmd.guest-invitation-bootstrap",
      workspaceId,
      keyVersion: 1,
      bootstrapSecret,
      aad,
      plaintext,
      redeemAuthorityInvitationId: guestInvitationId,
    }) as Record<string, unknown>;

    const updated = handleRewrapInvitationBootstrapForKekRotation(issuerState, {
      bootstrap,
      workspaceId,
      oldKeyVersion: 1,
      newKeyVersion: 2,
    }) as Record<string, unknown>;
    expect(updated.key_version).toBe(2);
    expect(updated).toMatchObject({
      aad: { key_version_context: { workspace_kek_version: 2 } },
      package_key_maintenance_wrap: { key_version: 2 },
    });

    const recipientState = createInitialState();
    handleUnwrapKekFromInvitationBootstrap(recipientState, {
      bootstrap: updated,
      bootstrapSecret,
    });
    expect(recipientState.activeKekVersions.get(workspaceId)).toBe(2);
    expect(recipientState.kekCache.get(workspaceId)?.get(2)?.kek).toEqual(newKek);
  });

  it("creates scoped capability packages and commits the share key only after guest binding", async () => {
    const issuerState = createInitialState();
    const shareKey = randomBytes(32);
    issuerState.shareSecrets.set("scoped-share", { dekEncryptionKey: shareKey });
    handleGenerateInvitationRedeemAuthority(issuerState, { invitationId: guestInvitationId });
    const bootstrapSecret = base64UrlEncode(randomBytes(32));
    const bootstrap = handleWrapKekForInvitationBootstrap(issuerState, {
      protocol: "refmd.guest-invitation-bootstrap",
      workspaceId,
      keyVersion: 1,
      bootstrapSecret,
      aad: scopedGuestAad(),
      plaintext: scopedGuestPlaintext(),
      redeemAuthorityInvitationId: guestInvitationId,
      maintenanceShareSlug: "scoped-share",
    }) as Record<string, unknown>;

    const recipientState = createInitialState();
    handleUnwrapKekFromInvitationBootstrap(recipientState, {
      bootstrap,
      bootstrapSecret,
    });
    expect(recipientState.kekCache.has(workspaceId)).toBe(false);
    expect(recipientState.activeKekVersions.has(workspaceId)).toBe(false);
    expect(recipientState.pendingGuestInvitationShareKeys.get(guestInvitationId)).toEqual(shareKey);

    recipientState.userId = "33333333-3333-4333-8333-333333333333";
    recipientState.deviceId = "44444444-4444-4444-8444-444444444444";
    recipientState.dsk = await crypto.subtle.importKey(
      "raw",
      randomBytes(32).buffer as ArrayBuffer,
      "HKDF",
      false,
      ["deriveKey"],
    );
    await handleCommitGuestInvitationShareKey(recipientState, {
      invitationId: guestInvitationId,
      shareId: "55555555-5555-4555-8555-555555555555",
      scopeKind: "document",
      scopeId: "document-1",
      permission: "view",
      shareKeyVersion: 1,
      dekVersion: 1,
    });
    expect(recipientState.pendingGuestInvitationShareKeys.has(guestInvitationId)).toBe(false);
    expect(recipientState.guestShareKeys.get("55555555-5555-4555-8555-555555555555")?.key).toEqual(
      shareKey,
    );
    expect(dskStoreMocks.storeValue).toHaveBeenCalledOnce();
  });

  it("rejects scoped guest package creation without a scoped maintenance key", () => {
    const issuerState = createInitialState();
    handleGenerateInvitationRedeemAuthority(issuerState, { invitationId: guestInvitationId });
    expect(() =>
      handleWrapKekForInvitationBootstrap(issuerState, {
        protocol: "refmd.guest-invitation-bootstrap",
        workspaceId,
        keyVersion: 1,
        bootstrapSecret: base64UrlEncode(randomBytes(32)),
        aad: scopedGuestAad(),
        plaintext: scopedGuestPlaintext(),
        redeemAuthorityInvitationId: guestInvitationId,
      }),
    ).toThrow("invitation_bootstrap_maintenance_share_required");
  });

  it("rejects invitation bootstrap packages with extra envelope keys", () => {
    const issuerState = createInitialState();
    issuerState.shareSecrets.set("scoped-share", { dekEncryptionKey: randomBytes(32) });
    handleGenerateInvitationRedeemAuthority(issuerState, { invitationId: guestInvitationId });
    const bootstrapSecret = base64UrlEncode(randomBytes(32));
    const bootstrap = handleWrapKekForInvitationBootstrap(issuerState, {
      protocol: "refmd.guest-invitation-bootstrap",
      workspaceId,
      keyVersion: 1,
      bootstrapSecret,
      aad: scopedGuestAad(),
      plaintext: scopedGuestPlaintext(),
      redeemAuthorityInvitationId: guestInvitationId,
      maintenanceShareSlug: "scoped-share",
    }) as Record<string, unknown>;

    expect(() =>
      handleUnwrapKekFromInvitationBootstrap(createInitialState(), {
        bootstrap: { ...bootstrap, compatibility_hash: "not-allowed" },
        bootstrapSecret,
      }),
    ).toThrow("invitation_bootstrap_package_invalid");
  });

  it("does not pre-deliver workspace KEK material for known guest recipients", () => {
    const issuerUserId = "11111111-1111-4111-8111-111111111111";
    const issuerDeviceId = "22222222-2222-4222-8222-222222222222";
    const recipientUserId = "33333333-3333-4333-8333-333333333333";
    const recipientDeviceId = "44444444-4444-4444-8444-444444444444";
    const issuerState = createInitialState();
    issuerState.userId = issuerUserId;
    handleGenerateDeviceKeys(issuerState, { deviceId: issuerDeviceId });
    handleGenerateInvitationRedeemAuthority(issuerState, { invitationId: guestInvitationId });
    setCachedKek(issuerState, workspaceId, randomBytes(32), 1);
    setActiveKekVersion(issuerState, workspaceId, 1);

    const recipientState = createInitialState();
    recipientState.userId = recipientUserId;
    const recipientKeys = handleGenerateDeviceKeys(recipientState, {
      deviceId: recipientDeviceId,
    }) as {
      encryptionKeyId: string;
      hybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
    };
    const checkpointHash = base64UrlEncode(randomBytes(32));
    const coveredHeadHash = base64UrlEncode(randomBytes(32));
    const aad = {
      ...scopedGuestAad(),
      scope_kind: "workspace",
      scope_id: "none",
      permission: "edit",
      delivery_mode: "known_recipient",
      recipient_user_id: recipientUserId,
      recipient_device_ids: [recipientDeviceId],
      key_version_context: {
        workspace_kek_version: 1,
        share_key_version: "NOT_APPLICABLE",
        dek_version: "NOT_APPLICABLE",
      },
    };
    const bootstrap = handleWrapKekForInvitationBootstrap(issuerState, {
      protocol: "refmd.guest-invitation-bootstrap",
      workspaceId,
      keyVersion: 1,
      recipientDelivery: {
        recipientUserId,
        senderUserId: issuerUserId,
        senderDeviceId: issuerDeviceId,
        operationCheckpoint: {
          sequence: 1,
          checkpointHash,
          coveredHeadSequence: 1,
          coveredHeadHash,
        },
        devices: [
          {
            deviceId: recipientDeviceId,
            encryptionKeyId: recipientKeys.encryptionKeyId,
            hybridEncryptionPublicKeyMaterial: recipientKeys.hybridEncryptionPublicKeyMaterial,
            keyCheckpointSequence: 1,
            keyCheckpointHash: checkpointHash,
          },
        ],
      },
      aad,
      plaintext: {
        ...scopedGuestPlaintext(),
        scope_kind: "workspace",
        scope_id: "none",
        permission: "edit",
        key_version_context: {
          workspace_kek_version: 1,
          share_key_version: "NOT_APPLICABLE",
          dek_version: "NOT_APPLICABLE",
        },
      },
      redeemAuthorityInvitationId: guestInvitationId,
      includeWorkspaceKek: false,
    }) as Record<string, unknown>;

    expect(bootstrap.package_key_recipient_wrap).toMatchObject({
      delivery_mode: "known_recipient",
      recipient_user_id: recipientUserId,
      wraps: [],
    });
    expect(() =>
      handleUnwrapKekFromInvitationBootstrap(recipientState, {
        bootstrap,
      }),
    ).toThrow("invitation_recipient_bound_delivery_required");
  });
});

describe("guest invitation share key delivery", () => {
  it("moves the worker-owned share key into recipient guest storage with exact metadata", async () => {
    const issuerUserId = "11111111-1111-4111-8111-111111111111";
    const issuerDeviceId = "22222222-2222-4222-8222-222222222222";
    const guestUserId = "33333333-3333-4333-8333-333333333333";
    const guestDeviceId = "44444444-4444-4444-8444-444444444444";
    const shareId = "55555555-5555-4555-8555-555555555555";
    const shareKey = randomBytes(32);
    const checkpointHash = base64UrlEncode(randomBytes(32));
    const eventHash = base64UrlEncode(randomBytes(32));

    const issuerState = createInitialState();
    issuerState.userId = issuerUserId;
    handleGenerateDeviceKeys(issuerState, { deviceId: issuerDeviceId });
    issuerState.shareSecrets.set("share-slug", { dekEncryptionKey: shareKey });

    const recipientState = createInitialState();
    recipientState.userId = guestUserId;
    recipientState.deviceId = guestDeviceId;
    recipientState.dsk = await crypto.subtle.importKey(
      "raw",
      randomBytes(32).buffer as ArrayBuffer,
      "HKDF",
      false,
      ["deriveKey"],
    );
    const recipientKeys = handleGenerateDeviceKeys(recipientState, {
      deviceId: guestDeviceId,
    }) as {
      encryptionKeyId: string;
      hybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
    };
    const resource = {
      workspace_id: workspaceId,
      guest_invitation_id: guestInvitationId,
      guest_user_id: guestUserId,
      guest_device_id: guestDeviceId,
      recipient_encryption_key_id: recipientKeys.encryptionKeyId,
      share_id: shareId,
      scope_kind: "document",
      scope_id: "66666666-6666-4666-8666-666666666666",
      permission: "view",
      document_scope_hash: base64UrlEncode(randomBytes(32)),
      share_key_version: 3,
      dek_version: 3,
      guest_invitation_redeemed_event_hash: eventHash,
    };
    const issuedRecord = handleCreateSignedPqGuestInvitationShareKeyWrap(issuerState, {
      shareSlug: "share-slug",
      recipientPublicKeyMaterial: recipientKeys.hybridEncryptionPublicKeyMaterial,
      senderUserId: issuerUserId,
      senderDeviceId: issuerDeviceId,
      resource,
      eventScope: { scope_kind: "workspace", scope_id: workspaceId },
      operationCheckpoint: {
        sequence: 4,
        checkpointHash,
        coveredHeadSequence: 9,
        coveredHeadHash: eventHash,
      },
      eventPrevious: { sequence: 9, hash: eventHash },
      recipientKeyCheckpoint: {
        scopeKind: "workspace",
        scopeId: workspaceId,
        sequence: 5,
        checkpointHash,
      },
    }) as { event: { wrap_event_sequence: number; wrap_event_hash: string } };
    const finalCheckpointHash = base64UrlEncode(randomBytes(32));
    const record = handleFinalizeSignedPqWrapOperationCheckpoint(issuerState, {
      record: issuedRecord,
      operationCheckpoint: {
        sequence: 5,
        checkpointHash: finalCheckpointHash,
        coveredHeadSequence: issuedRecord.event.wrap_event_sequence,
        coveredHeadHash: issuedRecord.event.wrap_event_hash,
      },
    });
    const verifiedOperation = verifiedOperationFor(record as SignedPqWrapRecord);
    const recipientDeliveryAdmissionProof = {
      attempt: {
        context_id: guestInvitationId,
        context_kind: "guest_invitation" as const,
        context_snapshot: {},
        live_redeem_challenge_hash: base64UrlEncode(randomBytes(32)),
        recipient_nonce_state_hash: base64UrlEncode(randomBytes(32)),
        recipient_redeem_nonce: base64UrlEncode(randomBytes(32)),
        redeem_attempt_id: "attempt-1",
        resource_hash: base64UrlEncode(randomBytes(32)),
        target_device_id: guestDeviceId,
        target_encryption_key_id: recipientKeys.encryptionKeyId,
        target_user_id: guestUserId,
        workspace_id: workspaceId,
      },
      authorization: {},
      freshnessProof: {},
      baseCheckpoint: {},
      currentCheckpoint: {},
      authorityEventAncestry: [],
      acceptedEventAncestry: [],
    };

    await expect(
      handleOpenSignedPqGuestInvitationShareKeyWrap(recipientState, {
        operationProof: record,
        senderSigningPublicKeyMaterial: issuerState.deviceHybridSigningState!.publicKeyMaterial,
      }),
    ).rejects.toThrow("recipient_delivery_admission_required");
    expect(admissionMocks.verify).not.toHaveBeenCalled();

    await expect(
      handleOpenRecipientBoundInvitationDeviceKekWrap(recipientState, {
        operationProof: record,
        senderSigningPublicKeyMaterial: issuerState.deviceHybridSigningState!.publicKeyMaterial,
      }),
    ).rejects.toThrow("recipient_delivery_admission_required");
    expect(admissionMocks.verify).not.toHaveBeenCalled();

    await expect(
      handleOpenSignedPqGuestInvitationShareKeyWrap(recipientState, {
        record,
        recipientDeliveryAdmissionProof,
        senderSigningPublicKeyMaterial: issuerState.deviceHybridSigningState!.publicKeyMaterial,
        verifiedOperation,
      }),
    ).rejects.toThrow("signed_pq_wrap_operation_proof_invalid");
    expect(operationProofMocks.verify).not.toHaveBeenCalled();

    operationProofMocks.verify.mockRejectedValueOnce(
      new Error("signed_pq_wrap_operation_checkpoint_fork"),
    );
    await expect(
      handleOpenSignedPqGuestInvitationShareKeyWrap(recipientState, {
        operationProof: record,
        recipientDeliveryAdmissionProof,
        senderSigningPublicKeyMaterial: issuerState.deviceHybridSigningState!.publicKeyMaterial,
      }),
    ).rejects.toThrow("signed_pq_wrap_operation_checkpoint_fork");
    expect(recipientState.guestShareKeys.has(shareId)).toBe(false);

    admissionMocks.verify.mockRejectedValueOnce(
      new Error("recipient_delivery_admission_not_in_pinned_chain"),
    );
    await expect(
      handleOpenSignedPqGuestInvitationShareKeyWrap(recipientState, {
        operationProof: record,
        recipientDeliveryAdmissionProof,
        senderSigningPublicKeyMaterial: issuerState.deviceHybridSigningState!.publicKeyMaterial,
      }),
    ).rejects.toThrow("recipient_delivery_admission_not_in_pinned_chain");
    expect(recipientState.guestShareKeys.has(shareId)).toBe(false);

    await handleOpenSignedPqGuestInvitationShareKeyWrap(recipientState, {
      operationProof: record,
      recipientDeliveryAdmissionProof,
      senderSigningPublicKeyMaterial: issuerState.deviceHybridSigningState!.publicKeyMaterial,
    });

    expect(operationProofMocks.verify).toHaveBeenLastCalledWith(workspaceId, record);
    expect(admissionMocks.verify).toHaveBeenCalledWith(recipientDeliveryAdmissionProof);
    expect(admissionMocks.require).toHaveBeenCalledWith(admissionMocks.token, record);

    await expect(
      handleOpenSignedPqDeviceKekWrap(recipientState, {
        operationProof: record,
        senderSigningPublicKeyMaterial: issuerState.deviceHybridSigningState!.publicKeyMaterial,
      }),
    ).rejects.toThrow("recipient_delivery_admission_required");

    expect(recipientState.guestShareKeys.get(shareId)).toMatchObject({
      scopeKind: "document",
      scopeId: resource.scope_id,
      permission: "view",
      shareKeyVersion: 3,
      dekVersion: 3,
    });
    expect(recipientState.guestShareKeys.get(shareId)?.key).toEqual(shareKey);
    expect(dskStoreMocks.storeValue).toHaveBeenCalledOnce();
  });
});

function verifiedOperationFor(record: SignedPqWrapRecord) {
  const eventBody = signedPqWrapEventBody(record) as Record<string, StrictJsonValue>;
  return {
    protocol: "refmd.verified-signed-pq-wrap-operation",
    version: 1,
    sequence: record.operation_checkpoint.checkpoint_sequence,
    checkpointHash: record.operation_checkpoint.checkpoint_hash,
    coveredHeadSequence: record.operation_checkpoint.covered_event_head_sequence,
    coveredHeadHash: record.operation_checkpoint.covered_event_head_hash,
    wrapEventSequence: record.event.wrap_event_sequence,
    wrapEventHash: record.event.wrap_event_hash,
    wrapEventBodyHash: record.event.wrap_event_body_hash,
    wrapBodyHash: eventBody.wrap_body_hash as string,
    transcriptHash: record.transcript_hash,
    recordCommitmentHash: blake3Base64Url(
      canonicalizeStrictBytes(record as unknown as StrictJsonValue),
    ),
  } as const;
}
