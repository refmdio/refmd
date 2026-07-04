import { beforeEach, describe, expect, it, vi } from "vitest";
import type {
  KeyDirectoryPin,
  SignedKeyDirectoryEnvelope,
} from "@/shared/lib/anti-rollback/key-directory-pin/types";
import { checkpointHash, eventHash } from "@/shared/lib/anti-rollback/key-directory-pin/primitives";
import type { DocumentOperationAdmission } from "@/shared/lib/ws/document-payloads";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { currentSuitePolicy } from "@/shared/lib/crypto/suite";
import {
  installVerifiedTransferredKeyDirectoryCheckpoint,
  rememberVerifiedKeyDirectoryLineage,
} from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import {
  pinFromCheckpoint,
  verifyCheckpointAncestry,
  verifyEventAncestry,
} from "@/shared/lib/anti-rollback/key-directory-pin/verification";
import {
  assertWriteSessionNotInvalidatedByEvents,
  expandDocumentAdmissionCheckpointAncestry,
  resolveDocumentWriteSessionSigningKeyFromAdmission,
  verifyDocumentOperationAdmission,
  verifyDocumentOperationAdmissionAncestry,
  verifyDocumentWriteSessionAdmission,
  verifyDocumentWriteSessionNotInvalidated,
} from "./document-operation-admission";

const pinStore = vi.hoisted(() => new Map<string, KeyDirectoryPin>());

vi.mock("@/shared/lib/storage/idb", () => ({
  openIdb: vi.fn(async () => ({})),
  idbGet: vi.fn(async (_db: unknown, _storeName: string, key: string) => pinStore.get(key)),
  idbConditionalPut: vi.fn(
    async (
      _db: unknown,
      _storeName: string,
      key: string,
      value: KeyDirectoryPin,
      predicate: (existing: KeyDirectoryPin | undefined) => boolean,
    ) => {
      const existing = pinStore.get(key);
      if (!predicate(existing)) return false;
      pinStore.set(key, value);
      return true;
    },
  ),
}));

vi.mock("@/shared/lib/anti-rollback/key-directory-pin/verification", async () => {
  const actual = await vi.importActual<
    typeof import("@/shared/lib/anti-rollback/key-directory-pin/verification")
  >("@/shared/lib/anti-rollback/key-directory-pin/verification");

  return {
    ...actual,
    verifyCheckpointAncestry: vi.fn(async () => {}),
    verifyEventAncestry: vi.fn(async () => {}),
  };
});

beforeEach(() => {
  vi.clearAllMocks();
  pinStore.clear();
});

function event(
  eventType: string,
  body: Record<string, unknown>,
  sequence: number,
): SignedKeyDirectoryEnvelope {
  return {
    payload: {
      scope_kind: "workspace",
      scope_id: "workspace-1",
      sequence,
      event_type: eventType,
      previous_event_hash: `previous-${sequence}`,
      actor: {
        signer_kind: "device",
        user_id: "admin-user",
        device_id: "admin-device",
        signing_key_id: "admin-key",
      },
      body,
    },
    signatures: [],
  } as unknown as SignedKeyDirectoryEnvelope;
}

function sessionEvent(
  owner: "device" | "share_participant_device" = "device",
): SignedKeyDirectoryEnvelope {
  return {
    payload: {
      scope_kind: "workspace",
      scope_id: "workspace-1",
      sequence: 10,
      event_type: "document_write_session_admitted",
      previous_event_hash: "previous-session",
      actor:
        owner === "device"
          ? {
              signer_kind: "device",
              user_id: "writer-user",
              device_id: "writer-device",
              signing_key_id: "writer-key",
            }
          : {
              signer_kind: "share_participant_device",
              share_id: "share-1",
              share_participant_principal_id: "principal-1",
              share_participant_device_id: "share-device-1",
              signing_key_id: "writer-key",
            },
      body: {},
    },
    signatures: [],
  } as unknown as SignedKeyDirectoryEnvelope;
}

function publicData(ownerKind: "device" | "share_participant_device" = "device") {
  return {
    authorityKind: ownerKind === "device" ? "workspace_device" : "share_participant_device",
    authorityScopeId: ownerKind === "device" ? "workspace-1" : "share-1",
    ownerKind,
    signingKeyId: "writer-key",
  };
}

function signed(payload: Record<string, unknown>): SignedKeyDirectoryEnvelope {
  return {
    payload,
    signatures: [{ signer: { signer_kind: "device" }, signature: { test: true } }],
  } as unknown as SignedKeyDirectoryEnvelope;
}

function keyDirectoryEvent(
  sequence: number,
  workspaceId = "workspace-1",
): SignedKeyDirectoryEnvelope {
  return signed({
    protocol: "refmd.key-directory-event",
    version: 1,
    scope_kind: "workspace",
    scope_id: workspaceId,
    sequence,
    event_type: "suite_policy_changed",
    ...(sequence > 1 ? { previous_event_hash: `event-${sequence - 1}` } : {}),
    actor: {
      signer_kind: "device",
      user_id: "admin-user",
      device_id: "admin-device",
      signing_key_id: "admin-key",
    },
    body: {
      suite_policy_version: currentSuitePolicy().suite_policy_version,
      min_suite_rank: currentSuitePolicy().min_suite_rank,
      allowed_suite_ids: currentSuitePolicy().allowed_suite_ids,
    },
  });
}

function keyDirectoryCheckpoint(
  sequence: number,
  eventEnvelope: SignedKeyDirectoryEnvelope,
  previousCheckpoint?: SignedKeyDirectoryEnvelope,
  workspaceId = "workspace-1",
): SignedKeyDirectoryEnvelope {
  const policy = currentSuitePolicy();
  return signed({
    protocol: "refmd.key-directory-checkpoint",
    version: 1,
    scope_kind: "workspace",
    scope_id: workspaceId,
    sequence,
    ...(previousCheckpoint ? { previous_checkpoint_hash: checkpointHash(previousCheckpoint) } : {}),
    covered_event_head: {
      head_sequence: sequence,
      head_hash: eventHash(eventEnvelope),
    },
    suite_policy_version: policy.suite_policy_version,
    min_suite_rank: policy.min_suite_rank,
    allowed_suite_ids: policy.allowed_suite_ids,
    identity_keys: [],
    device_keys: [],
    share_participant_keys: [],
    revoked_key_ids: [],
  });
}

describe("expandDocumentAdmissionCheckpointAncestry", () => {
  it("expands compressed checkpoint state from the admission candidate anchor", () => {
    const identityKeys = [{ key_id: "identity-1", key_material: { test: "identity" } }];
    const deviceKeys = [{ key_id: "device-1", key_material: { test: "device" } }];
    const shareParticipantKeys = [{ key_id: "share-1", key_material: { test: "share" } }];
    const revokedKeyIds = ["revoked-1"];
    const candidate = signed({
      sequence: 1,
      covered_event_head: { head_sequence: 1, head_hash: "event-1" },
      identity_keys: identityKeys,
      device_keys: deviceKeys,
      share_participant_keys: shareParticipantKeys,
      revoked_key_ids: revokedKeyIds,
    });
    const compressed = {
      payload: {
        sequence: 2,
        previous_checkpoint_hash: "checkpoint-1",
        covered_event_head: { head_sequence: 2, head_hash: "event-2" },
      },
      payloadStateCompression: "inherit_checkpoint_state_v1",
      signatures: candidate.signatures,
    };
    const admission = {
      workspaceKeyDirectoryEvents: [],
      workspaceKeyDirectoryCheckpoint: candidate as unknown as Record<string, unknown>,
      workspaceKeyDirectoryCheckpointAncestry: [compressed],
    } satisfies DocumentOperationAdmission;

    const [expanded] = expandDocumentAdmissionCheckpointAncestry(admission);

    expect(expanded?.payload.identity_keys).toEqual(identityKeys);
    expect(expanded?.payload.device_keys).toEqual(deviceKeys);
    expect(expanded?.payload.share_participant_keys).toEqual(shareParticipantKeys);
    expect(expanded?.payload.revoked_key_ids).toEqual(revokedKeyIds);
    expect("identity_keys" in compressed.payload).toBe(false);
  });

  it("rejects compressed checkpoint state without an expansion anchor", () => {
    const candidate = signed({
      sequence: 2,
      covered_event_head: { head_sequence: 2, head_hash: "event-2" },
    });
    const admission = {
      workspaceKeyDirectoryEvents: [],
      workspaceKeyDirectoryCheckpoint: candidate as unknown as Record<string, unknown>,
      workspaceKeyDirectoryCheckpointAncestry: [
        {
          payload: {
            sequence: 1,
            covered_event_head: { head_sequence: 1, head_hash: "event-1" },
          },
          payloadStateCompression: "inherit_checkpoint_state_v1",
          signatures: candidate.signatures,
        },
      ],
    } satisfies DocumentOperationAdmission;

    expect(() => expandDocumentAdmissionCheckpointAncestry(admission)).toThrow(
      "key_directory_checkpoint_compression_anchor_missing",
    );
  });
});

describe("verifyDocumentOperationAdmissionAncestry", () => {
  it("accepts an older candidate when the admission carries bounded membership proof to current", async () => {
    const events = [1, 2, 3, 4].map((sequence) => keyDirectoryEvent(sequence));
    const checkpoints: SignedKeyDirectoryEnvelope[] = [];
    for (let index = 0; index < events.length; index += 1) {
      checkpoints.push(keyDirectoryCheckpoint(index + 1, events[index]!, checkpoints[index - 1]));
    }
    await installVerifiedTransferredKeyDirectoryCheckpoint({
      scopeKind: "workspace",
      scopeId: "workspace-1",
      checkpointEnvelope: checkpoints[3]!,
    });

    const admission = {
      workspaceKeyDirectoryEvents: [events[1] as unknown as Record<string, unknown>],
      workspaceKeyDirectoryCheckpoint: checkpoints[1] as unknown as Record<string, unknown>,
      workspaceKeyDirectoryCheckpointAncestry: [
        checkpoints[0],
        checkpoints[2],
        checkpoints[3],
      ] as unknown as Record<string, unknown>[],
      workspaceKeyDirectoryEventAncestry: [events[2], events[3]] as unknown as Record<
        string,
        unknown
      >[],
    } satisfies DocumentOperationAdmission;

    await expect(
      verifyDocumentOperationAdmissionAncestry({
        admission,
        workspaceId: "workspace-1",
      }),
    ).resolves.toBeUndefined();
  });

  it("refreshes candidate-to-current lineage when bounded old admission lacks current proof", async () => {
    const events = [1, 2, 3, 4].map((sequence) => keyDirectoryEvent(sequence));
    const checkpoints: SignedKeyDirectoryEnvelope[] = [];
    for (let index = 0; index < events.length; index += 1) {
      checkpoints.push(keyDirectoryCheckpoint(index + 1, events[index]!, checkpoints[index - 1]));
    }
    await installVerifiedTransferredKeyDirectoryCheckpoint({
      scopeKind: "workspace",
      scopeId: "workspace-1",
      checkpointEnvelope: checkpoints[3]!,
    });

    const refreshKeyDirectory = vi.fn(
      async (params?: { trustedCheckpointEnvelope?: SignedKeyDirectoryEnvelope }) => {
        expect(params?.trustedCheckpointEnvelope).toEqual(checkpoints[1]);
        rememberVerifiedKeyDirectoryLineage({
          scopeKind: "workspace",
          scopeId: "workspace-1",
          checkpointEnvelope: checkpoints[3]!,
          checkpointAncestry: [checkpoints[1]!, checkpoints[2]!],
          eventAncestry: [events[2]!, events[3]!],
        });
      },
    );
    vi.mocked(verifyCheckpointAncestry).mockRejectedValueOnce(
      new Error("document_admission_current_checkpoint_missing"),
    );

    const admission = {
      workspaceKeyDirectoryEvents: [],
      workspaceKeyDirectoryCheckpoint: checkpoints[1] as unknown as Record<string, unknown>,
      workspaceKeyDirectoryCheckpointAncestry: [checkpoints[0]] as unknown as Record<
        string,
        unknown
      >[],
      workspaceKeyDirectoryEventAncestry: [events[1]] as unknown as Record<string, unknown>[],
    } satisfies DocumentOperationAdmission;

    await expect(
      verifyDocumentOperationAdmissionAncestry({
        admission,
        workspaceId: "workspace-1",
        refreshKeyDirectory,
      }),
    ).resolves.toBeUndefined();
    expect(refreshKeyDirectory).toHaveBeenCalledTimes(1);
    expect(verifyCheckpointAncestry).toHaveBeenLastCalledWith(
      "workspace",
      "workspace-1",
      expect.objectContaining({
        checkpointSequence: 2,
        eventHeadSequence: 2,
      }),
      [checkpoints[1], checkpoints[2]],
      checkpoints[3],
      [events[2], events[3]],
      [events[1]],
    );
  });

  it("refreshes candidate-to-current lineage when compact checkpoint proof has a gap", async () => {
    const events = [1, 2, 3, 4].map((sequence) => keyDirectoryEvent(sequence));
    const checkpoints: SignedKeyDirectoryEnvelope[] = [];
    for (let index = 0; index < events.length; index += 1) {
      checkpoints.push(keyDirectoryCheckpoint(index + 1, events[index]!, checkpoints[index - 1]));
    }
    await installVerifiedTransferredKeyDirectoryCheckpoint({
      scopeKind: "workspace",
      scopeId: "workspace-1",
      checkpointEnvelope: checkpoints[3]!,
    });

    const refreshKeyDirectory = vi.fn(
      async (params?: { trustedCheckpointEnvelope?: SignedKeyDirectoryEnvelope }) => {
        expect(params?.trustedCheckpointEnvelope).toEqual(checkpoints[1]);
        rememberVerifiedKeyDirectoryLineage({
          scopeKind: "workspace",
          scopeId: "workspace-1",
          checkpointEnvelope: checkpoints[3]!,
          checkpointAncestry: [checkpoints[1]!, checkpoints[2]!],
          eventAncestry: [events[1]!, events[2]!, events[3]!],
        });
      },
    );
    vi.mocked(verifyCheckpointAncestry).mockRejectedValueOnce(
      new Error("key_directory_checkpoint_sequence_gap"),
    );

    const admission = {
      workspaceKeyDirectoryEvents: [],
      workspaceKeyDirectoryCheckpoint: checkpoints[1] as unknown as Record<string, unknown>,
      workspaceKeyDirectoryCheckpointAncestry: [checkpoints[0]] as unknown as Record<
        string,
        unknown
      >[],
      workspaceKeyDirectoryEventAncestry: [events[1]] as unknown as Record<string, unknown>[],
    } satisfies DocumentOperationAdmission;

    await expect(
      verifyDocumentOperationAdmissionAncestry({
        admission,
        workspaceId: "workspace-1",
        refreshKeyDirectory,
      }),
    ).resolves.toBeUndefined();
    expect(refreshKeyDirectory).toHaveBeenCalledTimes(1);
  });
});

describe("verifyDocumentWriteSessionNotInvalidated", () => {
  it("uses verified cached current checkpoint when an old admission does not carry it", async () => {
    const workspaceId = "workspace-cached-current-checkpoint";
    const event1 = keyDirectoryEvent(1, workspaceId);
    const sessionEvent = signed({
      protocol: "refmd.key-directory-event",
      version: 1,
      scope_kind: "workspace",
      scope_id: workspaceId,
      sequence: 2,
      event_type: "document_write_session_admitted",
      previous_event_hash: eventHash(event1),
      actor: {
        signer_kind: "device",
        user_id: "writer-user",
        device_id: "writer-device",
        signing_key_id: "writer-key",
      },
      body: {},
    });
    const event3 = keyDirectoryEvent(3, workspaceId);
    const event4 = keyDirectoryEvent(4, workspaceId);
    const checkpoint1 = keyDirectoryCheckpoint(1, event1, undefined, workspaceId);
    const sessionCheckpoint = keyDirectoryCheckpoint(2, sessionEvent, checkpoint1, workspaceId);
    const checkpoint3 = keyDirectoryCheckpoint(3, event3, sessionCheckpoint, workspaceId);
    const currentCheckpoint = keyDirectoryCheckpoint(4, event4, checkpoint3, workspaceId);
    await installVerifiedTransferredKeyDirectoryCheckpoint({
      scopeKind: "workspace",
      scopeId: workspaceId,
      checkpointEnvelope: currentCheckpoint,
    });
    rememberVerifiedKeyDirectoryLineage({
      scopeKind: "workspace",
      scopeId: workspaceId,
      checkpointEnvelope: currentCheckpoint,
      checkpointAncestry: [checkpoint3],
      eventAncestry: [event3, event4],
    });
    const admission = {
      workspaceKeyDirectoryEvents: [sessionEvent as unknown as Record<string, unknown>],
      workspaceKeyDirectoryCheckpoint: sessionCheckpoint as unknown as Record<string, unknown>,
      workspaceKeyDirectoryCheckpointAncestry: [],
      workspaceKeyDirectoryEventAncestry: [event3, event4] as unknown as Record<string, unknown>[],
    } satisfies DocumentOperationAdmission;

    await expect(
      verifyDocumentWriteSessionNotInvalidated({
        admission,
        publicData: {
          ownerKind: "device",
          signingKeyId: "writer-key",
        },
        workspaceId,
        documentId: "doc-1",
        keyVersion: 1,
      }),
    ).resolves.toBeUndefined();
  });

  it("uses retained current checkpoint body when compact current lineage is unavailable", async () => {
    const workspaceId = "workspace-retained-checkpoint";
    const event1 = keyDirectoryEvent(1, workspaceId);
    const sessionEvent = signed({
      protocol: "refmd.key-directory-event",
      version: 1,
      scope_kind: "workspace",
      scope_id: workspaceId,
      sequence: 2,
      event_type: "document_write_session_admitted",
      previous_event_hash: eventHash(event1),
      actor: {
        signer_kind: "device",
        user_id: "writer-user",
        device_id: "writer-device",
        signing_key_id: "writer-key",
      },
      body: {},
    });
    const event3 = keyDirectoryEvent(3, workspaceId);
    const event4 = keyDirectoryEvent(4, workspaceId);
    const checkpoint1 = keyDirectoryCheckpoint(1, event1, undefined, workspaceId);
    const sessionCheckpoint = keyDirectoryCheckpoint(2, sessionEvent, checkpoint1, workspaceId);
    const checkpoint3 = keyDirectoryCheckpoint(3, event3, sessionCheckpoint, workspaceId);
    const currentCheckpoint = keyDirectoryCheckpoint(4, event4, checkpoint3, workspaceId);
    pinStore.set(
      `workspace:${workspaceId}`,
      pinFromCheckpoint("workspace", workspaceId, currentCheckpoint),
    );
    rememberVerifiedKeyDirectoryLineage({
      scopeKind: "workspace",
      scopeId: workspaceId,
      checkpointEnvelope: checkpoint3,
      checkpointAncestry: [currentCheckpoint],
      eventAncestry: [event3, event4],
    });
    const admission = {
      workspaceKeyDirectoryEvents: [sessionEvent as unknown as Record<string, unknown>],
      workspaceKeyDirectoryCheckpoint: sessionCheckpoint as unknown as Record<string, unknown>,
      workspaceKeyDirectoryCheckpointAncestry: [],
      workspaceKeyDirectoryEventAncestry: [event3, event4] as unknown as Record<string, unknown>[],
    } satisfies DocumentOperationAdmission;

    await expect(
      verifyDocumentWriteSessionNotInvalidated({
        admission,
        publicData: {
          ownerKind: "device",
          signingKeyId: "writer-key",
        },
        workspaceId,
        documentId: "doc-1",
        keyVersion: 1,
      }),
    ).resolves.toBeUndefined();

    expect(vi.mocked(verifyEventAncestry)).toHaveBeenCalledWith(
      "workspace",
      workspaceId,
      expect.objectContaining({
        checkpointSequence: 2,
        checkpointHash: checkpointHash(sessionCheckpoint),
      }),
      [event3, event4],
      currentCheckpoint,
      sessionCheckpoint.payload,
    );
  });
});

function writeSessionAdmission(bodyOverrides: Record<string, unknown> = {}) {
  const actor = {
    signer_kind: "device",
    user_id: "writer-user",
    device_id: "writer-device",
    signing_key_id: "writer-key",
  };
  const session = signed({
    scope_kind: "workspace",
    scope_id: "workspace-1",
    sequence: 10,
    event_type: "document_write_session_admitted",
    previous_event_hash: "previous-session",
    actor,
    body: {
      actor_hash: "actor-hash",
      authority_kind: "workspace_device",
      authority_scope_id: "workspace-1",
      document_id: "doc-1",
      document_permission_proof_hash: "permission-proof",
      event_type: "document_write_session_admitted",
      expires_at_ms: 1_030_000,
      issued_at_ms: 1_000_000,
      max_ciphertext_bytes: 1024,
      max_update_count: 8,
      min_dek_version: 2,
      previous_workspace_event_hash: "previous-session",
      previous_workspace_event_sequence: 9,
      session_id: "session-1",
      session_nonce: "nonce-1",
      workspace_id: "workspace-1",
      ...bodyOverrides,
    },
  });
  const checkpoint = signed({
    sequence: 6,
    previous_checkpoint_hash: "checkpoint-5",
    covered_event_head: {
      head_sequence: 10,
      head_hash: eventHash(session),
    },
  });

  const admission = {
    workspaceKeyDirectoryEvents: [session as unknown as Record<string, unknown>],
    workspaceKeyDirectoryCheckpoint: checkpoint as unknown as Record<string, unknown>,
  } satisfies DocumentOperationAdmission;

  return {
    admission,
    publicData: {
      ...publicData(),
      keyCheckpointHash: "checkpoint-5",
      keyCheckpointSequence: 5,
      keyVersion: 2,
      minDekVersion: 2,
      writeSessionCounter: 1,
      writeSessionEventHash: eventHash(session),
      writeSessionId: "session-1",
    },
  };
}

function operationPermissionProofHash(
  publicData: Record<string, unknown>,
  workspaceId: string,
  documentId: string,
): string {
  return blake3Base64Url(
    canonicalizeStrictBytes({
      protocol: "refmd.document-permission-proof",
      version: 1,
      workspace_id: workspaceId,
      document_id: documentId,
      authority_kind: publicData.authorityKind,
      authority_id: publicData.authorityId,
      authority_context_key: publicData.authorityContextKey,
      authority_scope_id: publicData.authorityScopeId,
      authority_permission_version: publicData.authorityPermissionVersion,
      permission: "edit",
    } as StrictJsonValue),
  );
}

function snapshotAdmission() {
  const actor = {
    signer_kind: "device",
    user_id: "writer-user",
    device_id: "writer-device",
    signing_key_id: "writer-key",
  };
  const signature = { test: "signature" };
  const publicData = {
    authorityKind: "workspace_device",
    authorityId: "workspace-1",
    authorityContextKey: "writer-key",
    authorityScopeId: "workspace-1",
    authorityPermissionVersion: 1,
    ownerKind: "device",
    ownerId: "writer-device",
    signingKeyId: "writer-key",
    keyCheckpointHash: "checkpoint-5",
    keyCheckpointSequence: 5,
    keyVersion: 2,
  };
  const operationHash = "snapshot-operation";
  const snapshot = signed({
    scope_kind: "workspace",
    scope_id: "workspace-1",
    sequence: 10,
    event_type: "document_snapshot_accepted",
    previous_event_hash: "previous-snapshot",
    actor,
    body: {
      actor_hash: blake3Base64Url(canonicalizeStrictBytes(actor as StrictJsonValue)),
      admission_nonce: "nonce-1",
      dek_version: 2,
      document_id: "doc-1",
      document_permission_proof_hash: operationPermissionProofHash(
        publicData,
        "workspace-1",
        "doc-1",
      ),
      event_type: "document_snapshot_accepted",
      min_dek_version: 2,
      operation_hash: operationHash,
      operation_signature_hash: blake3Base64Url(
        canonicalizeStrictBytes(signature as StrictJsonValue),
      ),
      previous_workspace_event_hash: "previous-snapshot",
      previous_workspace_event_sequence: 9,
      workspace_id: "workspace-1",
    },
  });
  const checkpoint = signed({
    sequence: 6,
    previous_checkpoint_hash: "checkpoint-5",
    covered_event_head: {
      head_sequence: 10,
      head_hash: eventHash(snapshot),
    },
  });

  const admission = {
    workspaceKeyDirectoryEvents: [snapshot as unknown as Record<string, unknown>],
    workspaceKeyDirectoryCheckpoint: checkpoint as unknown as Record<string, unknown>,
  } satisfies DocumentOperationAdmission;

  return { admission, operationHash, publicData, signature };
}

describe("assertWriteSessionNotInvalidatedByEvents", () => {
  it("rejects workspace actor removal, write downgrade, and signing key revocation", () => {
    expect(() =>
      assertWriteSessionNotInvalidatedByEvents({
        sessionEvent: sessionEvent(),
        publicData: publicData(),
        documentId: "doc-1",
        keyVersion: 2,
        events: [
          event("member_removed", { workspace_id: "workspace-1", user_id: "writer-user" }, 11),
        ],
      }),
    ).toThrow("document_write_session_actor_removed");

    expect(() =>
      assertWriteSessionNotInvalidatedByEvents({
        sessionEvent: sessionEvent(),
        publicData: publicData(),
        documentId: "doc-1",
        keyVersion: 2,
        events: [
          event(
            "member_role_changed",
            { workspace_id: "workspace-1", user_id: "writer-user", base_role: "viewer" },
            11,
          ),
        ],
      }),
    ).toThrow("document_write_session_actor_write_denied");

    expect(() =>
      assertWriteSessionNotInvalidatedByEvents({
        sessionEvent: sessionEvent(),
        publicData: publicData(),
        documentId: "doc-1",
        keyVersion: 2,
        events: [event("signing_key_revoked", { key_id: "writer-key" }, 11)],
      }),
    ).toThrow("document_write_session_signing_key_revoked");
  });

  it("rejects share revocation, matching share scope removal, and DEK floor increases", () => {
    expect(() =>
      assertWriteSessionNotInvalidatedByEvents({
        sessionEvent: sessionEvent("share_participant_device"),
        publicData: publicData("share_participant_device"),
        documentId: "doc-1",
        keyVersion: 2,
        events: [event("share_revoked", { workspace_id: "workspace-1", share_id: "share-1" }, 11)],
      }),
    ).toThrow("document_write_session_share_revoked");

    expect(() =>
      assertWriteSessionNotInvalidatedByEvents({
        sessionEvent: sessionEvent("share_participant_device"),
        publicData: publicData("share_participant_device"),
        documentId: "doc-1",
        keyVersion: 2,
        events: [
          event(
            "share_key_scope_removed",
            {
              workspace_id: "workspace-1",
              share_id: "share-1",
              scope_kind: "document",
              scope_id: "doc-1",
            },
            11,
          ),
        ],
      }),
    ).toThrow("document_write_session_share_scope_removed");

    expect(() =>
      assertWriteSessionNotInvalidatedByEvents({
        sessionEvent: sessionEvent("share_participant_device"),
        publicData: publicData("share_participant_device"),
        documentId: "doc-1",
        documentAncestorIds: ["ancestor-folder"],
        keyVersion: 2,
        events: [
          event(
            "share_key_scope_removed",
            {
              workspace_id: "workspace-1",
              share_id: "share-1",
              scope_kind: "folder",
              scope_id: "unrelated-folder",
            },
            11,
          ),
        ],
      }),
    ).not.toThrow();

    expect(() =>
      assertWriteSessionNotInvalidatedByEvents({
        sessionEvent: sessionEvent("share_participant_device"),
        publicData: publicData("share_participant_device"),
        documentId: "doc-1",
        keyVersion: 2,
        events: [
          event(
            "share_key_scope_removed",
            {
              workspace_id: "workspace-1",
              share_id: "share-1",
              scope_kind: "folder",
              scope_id: "folder-1",
            },
            11,
          ),
        ],
      }),
    ).toThrow("document_write_session_share_scope_evidence_missing");

    expect(() =>
      assertWriteSessionNotInvalidatedByEvents({
        sessionEvent: sessionEvent("share_participant_device"),
        publicData: publicData("share_participant_device"),
        documentId: "doc-1",
        documentAncestorIds: ["folder-1"],
        keyVersion: 2,
        events: [
          event(
            "share_key_scope_removed",
            {
              workspace_id: "workspace-1",
              share_id: "share-1",
              scope_kind: "folder",
              scope_id: "folder-1",
            },
            11,
          ),
        ],
      }),
    ).toThrow("document_write_session_share_scope_removed");

    expect(() =>
      assertWriteSessionNotInvalidatedByEvents({
        sessionEvent: sessionEvent("share_participant_device"),
        publicData: publicData("share_participant_device"),
        documentId: "doc-1",
        keyVersion: 2,
        events: [
          event(
            "share_key_scope_removed",
            {
              workspace_id: "workspace-1",
              share_id: "other-share",
              scope_kind: "folder",
              scope_id: "folder-1",
            },
            11,
          ),
        ],
      }),
    ).not.toThrow();

    expect(() =>
      assertWriteSessionNotInvalidatedByEvents({
        sessionEvent: sessionEvent(),
        publicData: publicData(),
        documentId: "doc-1",
        keyVersion: 2,
        events: [
          event(
            "rotation_completed",
            {
              rotation_kind: "dek",
              scope_kind: "document",
              scope_id: "doc-1",
              new_key_version: 3,
            },
            11,
          ),
        ],
      }),
    ).toThrow("document_write_session_dek_floor_invalidated");
  });

  it("rejects matching guest grant and guest device revocations for share participant sessions", () => {
    expect(() =>
      assertWriteSessionNotInvalidatedByEvents({
        sessionEvent: sessionEvent("share_participant_device"),
        publicData: publicData("share_participant_device"),
        documentId: "doc-1",
        documentAncestorIds: ["folder-1"],
        keyVersion: 2,
        events: [
          event(
            "guest_grant_revoked",
            {
              workspace_id: "workspace-1",
              guest_grant_id: "grant-1",
              guest_user_id: "principal-1",
              scope_kind: "folder",
              scope_id: "folder-1",
              revoked_at_event_sequence: 11,
              reason: "manual",
            },
            11,
          ),
        ],
      }),
    ).toThrow("document_write_session_guest_grant_revoked");

    expect(() =>
      assertWriteSessionNotInvalidatedByEvents({
        sessionEvent: sessionEvent("share_participant_device"),
        publicData: publicData("share_participant_device"),
        documentId: "doc-1",
        keyVersion: 2,
        events: [
          event(
            "guest_device_revoked",
            {
              workspace_id: "workspace-1",
              guest_user_id: "principal-1",
              guest_device_id: "share-device-1",
              guest_signing_key_id: "writer-key",
              guest_encryption_key_id: "guest-encryption-key",
              revoked_at_event_sequence: 11,
              reason: "manual",
            },
            11,
          ),
        ],
      }),
    ).toThrow("document_write_session_guest_device_revoked");

    expect(() =>
      assertWriteSessionNotInvalidatedByEvents({
        sessionEvent: sessionEvent("share_participant_device"),
        publicData: publicData("share_participant_device"),
        documentId: "doc-1",
        documentAncestorIds: ["folder-1"],
        keyVersion: 2,
        events: [
          event(
            "guest_grant_revoked",
            {
              workspace_id: "workspace-1",
              guest_grant_id: "grant-2",
              guest_user_id: "other-principal",
              scope_kind: "folder",
              scope_id: "folder-1",
              revoked_at_event_sequence: 11,
              reason: "manual",
            },
            11,
          ),
          event(
            "guest_device_revoked",
            {
              workspace_id: "workspace-1",
              guest_user_id: "principal-1",
              guest_device_id: "other-device",
              guest_signing_key_id: "other-key",
              guest_encryption_key_id: "guest-encryption-key",
              revoked_at_event_sequence: 12,
              reason: "manual",
            },
            12,
          ),
        ],
      }),
    ).not.toThrow();
  });

  it("rejects archive and read-only document state invalidation", () => {
    for (const invalidatingEvent of [
      event(
        "document_write_state_changed",
        { workspace_id: "workspace-1", document_id: "doc-1", write_state: "archived" },
        11,
      ),
      event(
        "document_write_state_changed",
        { workspace_id: "workspace-1", document_id: "doc-1", write_state: "read_only" },
        12,
      ),
      event(
        "document_write_state_changed",
        { workspace_id: "workspace-1", document_id: "doc-1", write_state: "write_disabled" },
        13,
      ),
    ]) {
      expect(() =>
        assertWriteSessionNotInvalidatedByEvents({
          sessionEvent: sessionEvent(),
          publicData: publicData(),
          documentId: "doc-1",
          keyVersion: 2,
          events: [invalidatingEvent],
        }),
      ).toThrow("document_write_session_document_state_invalidated");
    }
  });

  it("allows unrelated workspace movement and still-writable role changes", () => {
    expect(() =>
      assertWriteSessionNotInvalidatedByEvents({
        sessionEvent: sessionEvent(),
        publicData: publicData(),
        documentId: "doc-1",
        keyVersion: 2,
        events: [
          event(
            "member_role_changed",
            { workspace_id: "workspace-1", user_id: "other-user", base_role: "viewer" },
            11,
          ),
          event(
            "member_role_changed",
            { workspace_id: "workspace-1", user_id: "writer-user", base_role: "editor" },
            12,
          ),
          event(
            "share_key_scope_removed",
            {
              workspace_id: "workspace-1",
              share_id: "share-2",
              scope_kind: "document",
              scope_id: "doc-2",
            },
            13,
          ),
          event(
            "rotation_completed",
            {
              rotation_kind: "kek",
              scope_kind: "workspace",
              scope_id: "workspace-1",
              new_key_version: 9,
            },
            14,
          ),
          event(
            "document_write_state_changed",
            { workspace_id: "workspace-1", document_id: "doc-2", write_state: "archived" },
            15,
          ),
          event(
            "document_write_state_changed",
            { workspace_id: "workspace-1", document_id: "doc-1", write_state: "writable" },
            16,
          ),
        ],
      }),
    ).not.toThrow();
  });
});

describe("resolveDocumentWriteSessionSigningKeyFromAdmission", () => {
  it("resolves an edit share participant signing key from the admission checkpoint", () => {
    const session = signed({
      scope_kind: "workspace",
      scope_id: "workspace-1",
      sequence: 10,
      event_type: "document_write_session_admitted",
      previous_event_hash: "previous-session",
      actor: {
        signer_kind: "share_participant_device",
        share_id: "share-1",
        share_participant_principal_id: "principal-1",
        share_participant_device_id: "share-device-1",
        signing_key_id: "writer-key",
      },
      body: {},
    });
    const signingKeyMaterial = {
      protocol: "refmd.hybrid-signing-key-material",
      owner_kind: "share_participant_device",
      owner_id: "share-device-1",
    };
    const checkpoint = signed({
      sequence: 6,
      previous_checkpoint_hash: "checkpoint-5",
      covered_event_head: {
        head_sequence: 10,
        head_hash: eventHash(session),
      },
      share_participant_keys: [
        {
          key_id: "writer-key",
          key_material: signingKeyMaterial,
        },
      ],
    });
    const admission = {
      workspaceKeyDirectoryEvents: [session as unknown as Record<string, unknown>],
      workspaceKeyDirectoryCheckpoint: checkpoint as unknown as Record<string, unknown>,
    } satisfies DocumentOperationAdmission;

    expect(
      resolveDocumentWriteSessionSigningKeyFromAdmission({
        admission,
        publicData: {
          ownerKind: "share_participant_device",
          ownerId: "share-device-1",
          signingKeyId: "writer-key",
          authorityContextKey: "share-1:principal-1",
        },
      }),
    ).toEqual({
      key: signingKeyMaterial,
      actorUserId: "principal-1",
    });
  });
});

describe("verifyDocumentOperationAdmission", () => {
  it("accepts snapshot admission body shape before signature verification", async () => {
    const { admission, operationHash, publicData, signature } = snapshotAdmission();

    await expect(
      verifyDocumentOperationAdmission({
        admission,
        actorUserId: "writer-user",
        documentId: "doc-1",
        eventType: "document_snapshot_accepted",
        operationHash,
        publicData,
        signature,
        workspaceId: "workspace-1",
      }),
    ).rejects.not.toThrow("document_admission_body_keys_invalid");
  });
});

describe("verifyDocumentWriteSessionAdmission", () => {
  it("rejects malformed write-session body keys", async () => {
    const { admission, publicData } = writeSessionAdmission();
    const event = admission.workspaceKeyDirectoryEvents[0] as unknown as SignedKeyDirectoryEnvelope;
    const body = event.payload.body as Record<string, unknown>;
    delete body.session_nonce;

    await expect(
      verifyDocumentWriteSessionAdmission({
        admission,
        actorUserId: "writer-user",
        documentId: "doc-1",
        publicData,
        workspaceId: "workspace-1",
      }),
    ).rejects.toThrow("document_admission_body_keys_invalid");
  });

  it("rejects mismatched write-session authority binding", async () => {
    const { admission, publicData } = writeSessionAdmission({
      authority_scope_id: "workspace-2",
    });

    await expect(
      verifyDocumentWriteSessionAdmission({
        admission,
        actorUserId: "writer-user",
        documentId: "doc-1",
        publicData,
        workspaceId: "workspace-1",
      }),
    ).rejects.toThrow("document_admission_authority_scope_mismatch");
  });
});
