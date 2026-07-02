import { describe, expect, it } from "vitest";
import type { SignedKeyDirectoryEnvelope } from "@/shared/lib/anti-rollback/key-directory-pin/types";
import { eventHash } from "@/shared/lib/anti-rollback/key-directory-pin/primitives";
import type { DocumentOperationAdmission } from "@/shared/lib/ws/document-payloads";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import {
  assertWriteSessionNotInvalidatedByEvents,
  resolveDocumentWriteSessionSigningKeyFromAdmission,
  verifyDocumentOperationAdmission,
  verifyDocumentWriteSessionAdmission,
} from "./document-operation-admission";

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
