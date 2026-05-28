import { describe, expect, it, vi } from "vitest";

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
import { buildWorkspaceMemberRemovalKeyDirectoryAppend } from "./membership-events";

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
      removedDeviceKeys: [
        {
          signingKeyId: "signing-key-1",
          encryptionKeyId: "encryption-key-1",
        },
      ],
      checkpointEnvelope,
    });

    const payloads = append.events.map((event) => event.payload as Record<string, unknown>);
    const checkpointPayload = append.checkpoint.payload as Record<string, unknown>;
    expect(payloads.map((payload) => payload.event_type)).toEqual([
      "member_removed",
      "encryption_key_revoked",
      "signing_key_revoked",
    ]);
    expect(payloads.map((payload) => payload.sequence)).toEqual([11, 12, 13]);
    expect(payloads[2]?.previous_event_hash).toBe(eventHash(payloads[1] ?? {}));
    expect(checkpointPayload.covered_event_head).toEqual({
      head_sequence: 13,
      head_hash: eventHash(payloads[2] ?? {}),
    });
  });
});
