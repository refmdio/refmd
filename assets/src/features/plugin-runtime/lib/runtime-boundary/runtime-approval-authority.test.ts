import { beforeEach, describe, expect, it, vi } from "vitest";
import { eventHash } from "@/shared/lib/anti-rollback/key-directory-pin/primitives";
import type { SignedKeyDirectoryEnvelope } from "@/shared/lib/anti-rollback/key-directory-pin/types";
import type { StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { verifyPluginRuntimeApprovalAuthorityFromKeyDirectory } from "./runtime-approval-authority";

const mocks = vi.hoisted(() => ({
  deviceState: vi.fn(),
  fetchVerifiedKeyDirectory: vi.fn(),
  getKeyDirectoryPin: vi.fn(),
  lookupVerifiedKeyDirectoryCheckpointBodies: vi.fn(),
  lookupVerifiedKeyDirectoryEventBodies: vi.fn(),
  lookupVerifiedKeyDirectoryLineage: vi.fn(),
  verifyInitialReplay: vi.fn(),
}));

vi.mock("@/entities/session", () => ({
  deviceState: mocks.deviceState,
}));

vi.mock("@/shared/lib/key-directory/fetch", () => ({
  fetchVerifiedKeyDirectory: mocks.fetchVerifiedKeyDirectory,
}));

vi.mock("@/shared/lib/anti-rollback/key-directory-pin/pins", () => ({
  getKeyDirectoryPin: mocks.getKeyDirectoryPin,
  lookupVerifiedKeyDirectoryCheckpointBodies: mocks.lookupVerifiedKeyDirectoryCheckpointBodies,
  lookupVerifiedKeyDirectoryEventBodies: mocks.lookupVerifiedKeyDirectoryEventBodies,
  lookupVerifiedKeyDirectoryLineage: mocks.lookupVerifiedKeyDirectoryLineage,
}));

vi.mock("@/shared/lib/anti-rollback/key-directory-pin/verification", () => ({
  verifyInitialReplay: mocks.verifyInitialReplay,
}));

describe("plugin runtime approval authority verification", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    mocks.deviceState.mockReturnValue({ deviceId: "device-one" });
    mocks.fetchVerifiedKeyDirectory.mockReset();
    mocks.getKeyDirectoryPin.mockReset();
    mocks.lookupVerifiedKeyDirectoryCheckpointBodies.mockReset();
    mocks.lookupVerifiedKeyDirectoryEventBodies.mockReset();
    mocks.lookupVerifiedKeyDirectoryLineage.mockReset();
    mocks.verifyInitialReplay.mockReset();
    mocks.verifyInitialReplay.mockResolvedValue(undefined);
    mocks.lookupVerifiedKeyDirectoryCheckpointBodies.mockReturnValue([]);
    mocks.lookupVerifiedKeyDirectoryEventBodies.mockReturnValue([]);
  });

  it("verifies approval authority from runtime proof evidence without refetching latest lineage", async () => {
    const workspaceId = "11111111-1111-4111-8111-111111111111";
    const userId = "22222222-2222-4222-8222-222222222222";
    const deviceId = "33333333-3333-4333-8333-333333333333";
    const signingKeyId = "signing-key-one";
    const memberEvent = keyDirectoryEnvelope({
      protocol: "refmd.key-directory-event",
      version: 1,
      scope_kind: "workspace",
      scope_id: workspaceId,
      sequence: 1,
      event_type: "member_added",
      actor: {
        signer_kind: "device",
        user_id: userId,
        device_id: deviceId,
        signing_key_id: signingKeyId,
      },
      body: {
        workspace_id: workspaceId,
        user_id: userId,
        base_role: "admin",
      },
    });
    const checkpoint = keyDirectoryEnvelope({
      protocol: "refmd.key-directory-checkpoint",
      version: 1,
      scope_kind: "workspace",
      scope_id: workspaceId,
      sequence: 1,
      covered_event_head: {
        head_sequence: 1,
        head_hash: eventHash(memberEvent),
      },
      identity_keys: [],
      device_keys: [
        {
          key_id: signingKeyId,
          key_material: {
            protocol: "refmd.hybrid-signing-key-material",
            version: 1,
            owner_kind: "device",
            owner_id: deviceId,
            ed25519_public: "ed25519-public",
            mldsa65_public: "mldsa65-public",
          },
          valid_from: {
            scope_kind: "workspace",
            scope_id: workspaceId,
            event_sequence: 1,
            event_hash: eventHash(memberEvent),
          },
        },
      ],
      share_participant_keys: [],
      revoked_key_ids: [],
    });
    const authority = {
      kind: "key_directory_membership",
      scope_kind: "workspace",
      workspace_id: workspaceId,
      user_id: userId,
      device_id: deviceId,
      signing_key_id: signingKeyId,
      event_head_sequence: 1,
      event_head_hash: eventHash(memberEvent),
      checkpoint_sequence: 1,
      checkpoint_hash: eventHash(checkpoint),
    };

    await expect(
      verifyPluginRuntimeApprovalAuthorityFromKeyDirectory({
        descriptor: {} as never,
        approvalSubject: {
          owner_scope_kind: "workspace",
          owner_workspace_id: workspaceId,
        },
        authority,
        proof: {
          event_hash: "approval-event-hash",
          subject: {},
          actor: {},
          hybrid_signature: {} as never,
          signing_key_id: signingKeyId,
          approval_authority: authority,
          approval_authority_checkpoint: checkpoint as unknown as StrictJsonValue,
          approval_authority_event_ancestry: [memberEvent as unknown as StrictJsonValue],
        },
      }),
    ).resolves.toBeUndefined();

    expect(mocks.verifyInitialReplay).toHaveBeenCalledWith(
      "workspace",
      workspaceId,
      [memberEvent],
      checkpoint,
    );
    expect(mocks.fetchVerifiedKeyDirectory).not.toHaveBeenCalled();
  });

  it("verifies fetched approval authority from retained compact-lineage bodies", async () => {
    const workspaceId = "11111111-1111-4111-8111-111111111111";
    const userId = "22222222-2222-4222-8222-222222222222";
    const deviceId = "33333333-3333-4333-8333-333333333333";
    const signingKeyId = "signing-key-one";
    const memberEvent = keyDirectoryEnvelope({
      protocol: "refmd.key-directory-event",
      version: 1,
      scope_kind: "workspace",
      scope_id: workspaceId,
      sequence: 1,
      event_type: "member_added",
      actor: {
        signer_kind: "device",
        user_id: userId,
        device_id: deviceId,
        signing_key_id: signingKeyId,
      },
      body: {
        workspace_id: workspaceId,
        user_id: userId,
        base_role: "admin",
      },
    });
    const checkpoint = keyDirectoryEnvelope({
      protocol: "refmd.key-directory-checkpoint",
      version: 1,
      scope_kind: "workspace",
      scope_id: workspaceId,
      sequence: 1,
      covered_event_head: {
        head_sequence: 1,
        head_hash: eventHash(memberEvent),
      },
      identity_keys: [],
      device_keys: [
        {
          key_id: signingKeyId,
          key_material: {
            protocol: "refmd.hybrid-signing-key-material",
            version: 1,
            owner_kind: "device",
            owner_id: deviceId,
            ed25519_public: "ed25519-public",
            mldsa65_public: "mldsa65-public",
          },
          valid_from: {
            scope_kind: "workspace",
            scope_id: workspaceId,
            event_sequence: 1,
            event_hash: eventHash(memberEvent),
          },
        },
      ],
      share_participant_keys: [],
      revoked_key_ids: [],
    });
    const authority = {
      kind: "key_directory_membership",
      scope_kind: "workspace",
      workspace_id: workspaceId,
      user_id: userId,
      device_id: deviceId,
      signing_key_id: signingKeyId,
      event_head_sequence: 1,
      event_head_hash: eventHash(memberEvent),
      checkpoint_sequence: 1,
      checkpoint_hash: eventHash(checkpoint),
    };

    mocks.fetchVerifiedKeyDirectory.mockResolvedValue({ checkpoint });
    mocks.getKeyDirectoryPin.mockResolvedValue({
      pinKey: `workspace:${workspaceId}`,
      scopeKind: "workspace",
      scopeId: workspaceId,
      checkpointSequence: 1,
      checkpointHash: eventHash(checkpoint),
      eventHeadSequence: 1,
      eventHeadHash: eventHash(memberEvent),
      suitePolicyVersion: 1,
      minSuiteRank: 1,
      allowedSuiteIdsHash: "suite-hash",
      observedAt: 1,
    });
    mocks.lookupVerifiedKeyDirectoryLineage.mockReturnValue({
      checkpoints: [],
      events: [],
    });
    mocks.lookupVerifiedKeyDirectoryCheckpointBodies.mockReturnValue([checkpoint]);
    mocks.lookupVerifiedKeyDirectoryEventBodies.mockReturnValue([memberEvent]);

    await expect(
      verifyPluginRuntimeApprovalAuthorityFromKeyDirectory({
        descriptor: {} as never,
        approvalSubject: {
          owner_scope_kind: "workspace",
          owner_workspace_id: workspaceId,
        },
        authority,
        proof: {
          event_hash: "approval-event-hash",
          subject: {},
          actor: {},
          hybrid_signature: {} as never,
          signing_key_id: signingKeyId,
          approval_authority: authority,
        },
      }),
    ).resolves.toBeUndefined();

    expect(mocks.fetchVerifiedKeyDirectory).toHaveBeenCalledWith({
      scopeKind: "workspace",
      scopeId: workspaceId,
      popDeviceId: "device-one",
    });
  });
});

function keyDirectoryEnvelope(payload: Record<string, unknown>): SignedKeyDirectoryEnvelope {
  return {
    payload,
    signatures: [
      {
        signer: { signer_kind: "device", signing_key_id: "signing-key-one" },
        signature: {} as never,
      },
    ],
  };
}
