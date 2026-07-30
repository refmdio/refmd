import { describe, expect, it, vi } from "vite-plus/test";

vi.mock("./primitives", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./primitives")>();
  return {
    ...actual,
    signEvent: vi.fn(async (_ownerKind: string, payload: Record<string, unknown>) => ({
      payload,
      signatures: [],
    })),
    signCheckpoint: vi.fn(
      async (_ownerKind: string, _variant: string, payload: Record<string, unknown>) => ({
        payload,
        signatures: [],
      }),
    ),
  };
});

import { eventHash } from "./primitives";
import {
  buildWorkspaceMemberRemovalKeyDirectoryAppend,
  buildWorkspaceMemberRoleChangesKeyDirectoryAppend,
} from "./membership-events";

describe("workspace member removal key directory append", () => {
  it("revokes encryption keys before signing keys so the actor signature remains valid", async () => {
    const checkpointEnvelope = {
      payload: {
        scope_kind: "workspace",
        scope_id: "workspace-1",
        sequence: 4,
        covered_event_head: {
          head_sequence: 10,
          head_hash: "previous-head",
        },
        identity_keys: [],
        device_keys: [
          {
            key_id: "signing-key-1",
            key_material: {
              protocol: "refmd.hybrid-signing-key-material",
              owner_kind: "device",
              owner_id: "device-1",
            },
          },
          {
            key_id: "encryption-key-1",
            key_material: {
              protocol: "refmd.hybrid-encryption-key-material",
              owner_kind: "device",
              owner_id: "device-1",
            },
          },
        ],
        share_participant_keys: [],
        revoked_key_ids: [],
      },
      signatures: [],
    } as unknown as Parameters<
      typeof buildWorkspaceMemberRemovalKeyDirectoryAppend
    >[0]["checkpointEnvelope"];

    const append = await buildWorkspaceMemberRemovalKeyDirectoryAppend({
      workspaceId: "workspace-1",
      actorUserId: "member-1",
      actorDeviceId: "device-1",
      removedUserId: "member-1",
      currentKekVersion: 3,
      documents: [
        { id: "document-2", minDekVersion: 4 },
        { id: "document-1", minDekVersion: 2 },
      ],
      checkpointEnvelope,
    });

    const payloads = append.events.map((event) => event.payload as Record<string, unknown>);
    const checkpointPayload = append.checkpoint.payload as Record<string, unknown>;
    expect(payloads.map((payload) => payload.event_type)).toEqual([
      "member_removed",
      "rotation_started",
      "rotation_started",
      "rotation_started",
    ]);
    expect(payloads.map((payload) => payload.sequence)).toEqual([11, 12, 13, 14]);
    expect(
      payloads.slice(1).map((payload) => (payload.body as Record<string, unknown>).scope_id),
    ).toEqual(["workspace-1", "document-1", "document-2"]);
    expect(checkpointPayload.covered_event_head).toEqual({
      head_sequence: 14,
      head_hash: eventHash(payloads[3] ?? {}),
    });
  });
});

describe("workspace member role change key directory append", () => {
  it("chains one canonical event per affected member into one checkpoint", async () => {
    const checkpointEnvelope = {
      payload: {
        scope_kind: "workspace",
        scope_id: "workspace-1",
        sequence: 4,
        covered_event_head: { head_sequence: 10, head_hash: "previous-head" },
        identity_keys: [],
        device_keys: [
          {
            key_id: "signing-key-1",
            key_material: {
              protocol: "refmd.hybrid-signing-key-material",
              owner_kind: "device",
              owner_id: "device-1",
            },
          },
        ],
        share_participant_keys: [],
        revoked_key_ids: [],
      },
      signatures: [],
    } as unknown as Parameters<
      typeof buildWorkspaceMemberRoleChangesKeyDirectoryAppend
    >[0]["checkpointEnvelope"];

    const append = await buildWorkspaceMemberRoleChangesKeyDirectoryAppend({
      workspaceId: "workspace-1",
      actorUserId: "owner-1",
      actorDeviceId: "device-1",
      checkpointEnvelope,
      changes: [
        {
          targetUserId: "member-1",
          previousRoleId: "role-1",
          previousBaseRole: "editor",
          roleId: "role-2",
          baseRole: "viewer",
        },
        {
          targetUserId: "member-2",
          previousRoleId: "role-1",
          previousBaseRole: "editor",
          roleId: "role-1",
          baseRole: "editor",
        },
      ],
    });

    const payloads = append.events.map((event) => event.payload as Record<string, unknown>);
    const firstBody = payloads[0]?.body as Record<string, unknown>;
    const checkpointPayload = append.checkpoint.payload as Record<string, unknown>;
    expect(payloads.map((payload) => payload.sequence)).toEqual([11, 12]);
    expect(payloads[1]?.previous_event_hash).toBe(eventHash(payloads[0] ?? {}));
    expect(Object.keys(firstBody).sort()).toEqual([
      "changed_at_event_sequence",
      "new_base_role",
      "new_role_id",
      "previous_base_role",
      "previous_role_id",
      "user_id",
      "workspace_id",
    ]);
    expect(checkpointPayload.covered_event_head).toEqual({
      head_sequence: 12,
      head_hash: eventHash(payloads[1] ?? {}),
    });
  });
});
