import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  advanceKeyDirectoryPinWithProof: vi.fn(),
  getKeyDirectoryPin: vi.fn(),
  getPopHeaders: vi.fn(),
  getPreferredSessionScope: vi.fn(),
  hashKeyDirectoryCheckpointEnvelope: vi.fn(),
  lookupVerifiedKeyDirectoryLineage: vi.fn(),
}));

vi.mock("@/shared/lib/anti-rollback/key-directory-pin/pins", () => ({
  advanceKeyDirectoryPinWithProof: mocks.advanceKeyDirectoryPinWithProof,
  getKeyDirectoryPin: mocks.getKeyDirectoryPin,
  hashKeyDirectoryCheckpointEnvelope: mocks.hashKeyDirectoryCheckpointEnvelope,
  lookupVerifiedKeyDirectoryLineage: mocks.lookupVerifiedKeyDirectoryLineage,
}));

vi.mock("@/shared/lib/auth/pop", () => ({
  getPopHeaders: mocks.getPopHeaders,
}));

vi.mock("@/shared/lib/auth/session-scope", () => ({
  getPreferredSessionScope: mocks.getPreferredSessionScope,
  SHARE_SESSION_SCOPE_HEADER: "X-Refmd-Share-Session",
}));

import { fetchVerifiedKeyDirectory } from "./fetch";

describe("fetchVerifiedKeyDirectory", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    mocks.advanceKeyDirectoryPinWithProof.mockReset();
    mocks.getKeyDirectoryPin.mockReset();
    mocks.getPopHeaders.mockReset();
    mocks.getPreferredSessionScope.mockReset();
    mocks.hashKeyDirectoryCheckpointEnvelope.mockReset();
    mocks.lookupVerifiedKeyDirectoryLineage.mockReset();

    mocks.getPopHeaders.mockResolvedValue({ "X-Refmd-PoP": "proof" });
    mocks.getPreferredSessionScope.mockReturnValue("user");
  });

  it("hydrates verified lineage when the server returns the already pinned checkpoint", async () => {
    const scopeId = "11111111-1111-4111-8111-111111111111";
    const pin = {
      pinKey: `workspace:${scopeId}`,
      checkpointSequence: 4,
      checkpointHash: "checkpoint-hash",
      eventHeadSequence: 7,
      eventHeadHash: "event-head-hash",
      suitePolicyVersion: 1,
      minSuiteRank: 1,
    };
    const checkpoint = { payload: { sequence: 4 }, signatures: [] };
    const cachedEvent = { payload: { sequence: 6 }, signatures: [] };
    const responseEvent = { payload: { sequence: 7 }, signatures: [] };

    mocks.getKeyDirectoryPin.mockResolvedValue(pin);
    mocks.hashKeyDirectoryCheckpointEnvelope.mockReturnValue(pin.checkpointHash);
    mocks.lookupVerifiedKeyDirectoryLineage.mockReturnValue({
      checkpoints: [],
      events: [cachedEvent],
    });

    const fetchMock = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            checkpoint,
            checkpoint_ancestry: [],
            event_ancestry: [responseEvent],
            rotation_deletion_evidences: [],
            pin: {
              checkpoint_sequence: pin.checkpointSequence,
              checkpoint_hash: pin.checkpointHash,
              event_head_sequence: pin.eventHeadSequence,
              event_head_hash: pin.eventHeadHash,
            },
          }),
          {
            headers: { "Content-Type": "application/json" },
            status: 200,
          },
        ),
    );
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      fetchVerifiedKeyDirectory({
        scopeKind: "workspace",
        scopeId,
        popDeviceId: "22222222-2222-4222-8222-222222222222",
      }),
    ).resolves.toEqual({ checkpoint });

    expect(mocks.advanceKeyDirectoryPinWithProof).toHaveBeenCalledWith({
      scopeKind: "workspace",
      scopeId,
      checkpointEnvelope: checkpoint,
      checkpointAncestry: [],
      eventAncestry: [responseEvent],
      authorityEventAncestry: [cachedEvent, responseEvent],
      rotationDeletionEvidences: [],
    });
  });
});
