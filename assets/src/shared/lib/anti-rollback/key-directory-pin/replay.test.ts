import { describe, expect, it } from "vite-plus/test";
import type { SignedKeyDirectoryEnvelope } from "./types";
import {
  assertAndApplyRotationReplayState,
  rotationReplayStateFromAuthorityEvents,
  verifyEventSemantics,
} from "./replay";

const USER_ID = "11111111-1111-4111-8111-111111111111";
const OLD_SIGNING_KEY_ID = "old-signing-key";
const NEW_SIGNING_KEY_ID = "new-signing-key";

describe("rotation replay authority state", () => {
  it("reconstructs a completed identity rotation from signed authority history", () => {
    const completion = rotationEvent("rotation_completed", 8);
    const authorityState = rotationReplayStateFromAuthorityEvents(
      [rotationEvent("rotation_started", 4)],
      [completion],
    );
    const state = assertAndApplyRotationReplayState(authorityState, completion);

    expect(Object.values(state)).toEqual([
      expect.objectContaining({
        status: "completed",
        newIdentitySigningKeyId: NEW_SIGNING_KEY_ID,
      }),
    ]);
  });

  it("rejects a completion without its rotation start authority", () => {
    const completion = rotationEvent("rotation_completed", 8);
    const state = rotationReplayStateFromAuthorityEvents([], [completion]);

    expect(() => assertAndApplyRotationReplayState(state, completion)).toThrow(
      "rotation_started_event_missing",
    );
  });

  it("accepts document DEK rotation events in a workspace directory", () => {
    const event = documentRotationEvent("dek");

    expect(() => verifyEventSemantics(event, {})).not.toThrow();
  });

  it("rejects document scope for non-DEK workspace rotations", () => {
    const event = documentRotationEvent("kek");

    expect(() => verifyEventSemantics(event, {})).toThrow("rotation_event_scope_mismatch");
  });
});

describe("member role change replay semantics", () => {
  it("accepts the exact canonical permission transition body", () => {
    expect(() => verifyEventSemantics(memberRoleChangeEvent(), {})).not.toThrow();
  });

  it("rejects old, extra, duplicate, unsorted, and unknown permission bodies", () => {
    const valid = memberRoleChangeEvent();
    const body = valid.payload.body as Record<string, unknown>;
    for (const invalidBody of [
      { workspace_id: valid.payload.scope_id, user_id: "member-1", base_role: "viewer" },
      { ...body, legacy_role: "viewer" },
      { ...body, effective_permissions: ["document:read", "document:read"] },
      { ...body, effective_permissions: ["member:list", "document:read"] },
      { ...body, effective_permissions: ["unknown:permission"] },
    ]) {
      const event = { ...valid, payload: { ...valid.payload, body: invalidBody } };
      expect(() => verifyEventSemantics(event, {})).toThrow();
    }
  });
});

function memberRoleChangeEvent(): SignedKeyDirectoryEnvelope {
  return {
    payload: {
      protocol: "refmd.key-directory-event",
      version: 1,
      scope_kind: "workspace",
      scope_id: "22222222-2222-4222-8222-222222222222",
      sequence: 13,
      event_type: "member_role_changed",
      body: {
        workspace_id: "22222222-2222-4222-8222-222222222222",
        user_id: "11111111-1111-4111-8111-111111111111",
        previous_role_id: "33333333-3333-4333-8333-333333333333",
        previous_base_role: "editor",
        previous_effective_permissions: ["document:read", "document:write", "member:list"],
        role_id: "44444444-4444-4444-8444-444444444444",
        base_role: "viewer",
        effective_permissions: ["document:read", "member:list"],
        permission_version: 2,
        changed_at_event_sequence: 13,
      },
    },
    signatures: [],
  } as unknown as SignedKeyDirectoryEnvelope;
}

function documentRotationEvent(rotationKind: "dek" | "kek"): SignedKeyDirectoryEnvelope {
  return {
    payload: {
      protocol: "refmd.key-directory-event",
      version: 1,
      scope_kind: "workspace",
      scope_id: "22222222-2222-4222-8222-222222222222",
      sequence: 13,
      event_type: "rotation_started",
      body: {
        event_type: "rotation_started",
        rotation_kind: rotationKind,
        scope_kind: "document",
        scope_id: "33333333-3333-4333-8333-333333333333",
        old_key_version: 1,
        new_key_version: 2,
        not_before_event_sequence: 13,
        reason: "time_based",
      },
    },
    signatures: [],
  } as unknown as SignedKeyDirectoryEnvelope;
}

function rotationEvent(
  eventType: "rotation_started" | "rotation_completed",
  sequence: number,
): SignedKeyDirectoryEnvelope {
  return {
    payload: {
      protocol: "refmd.key-directory-event",
      version: 1,
      scope_kind: "user",
      scope_id: USER_ID,
      sequence,
      event_type: eventType,
      body: {
        event_type: eventType,
        rotation_kind: "identity",
        scope_kind: "user",
        scope_id: USER_ID,
        old_identity_signing_key_id: OLD_SIGNING_KEY_ID,
        new_identity_signing_key_id: NEW_SIGNING_KEY_ID,
      },
    },
    signatures: [],
  } as unknown as SignedKeyDirectoryEnvelope;
}
