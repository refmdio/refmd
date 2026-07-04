import { beforeEach, describe, expect, it, vi } from "vitest";
import type { KeyDirectoryEnvelope } from "@/shared/lib/crypto/key-directory/types";

const mocks = vi.hoisted(() => ({
  advanceKeyDirectoryPinWithProof: vi.fn(),
  getKeyDirectoryPin: vi.fn(),
  getPopHeaders: vi.fn(),
  getPreferredSessionScope: vi.fn(),
  hashKeyDirectoryCheckpointEnvelope: vi.fn(),
  lookupVerifiedKeyDirectoryEventBodies: vi.fn(),
  verifyAndRememberKeyDirectoryLineageFromTrustedAnchor: vi.fn(),
}));

vi.mock("@/shared/lib/anti-rollback/key-directory-pin/pins", () => ({
  advanceKeyDirectoryPinWithProof: mocks.advanceKeyDirectoryPinWithProof,
  getKeyDirectoryPin: mocks.getKeyDirectoryPin,
  hashKeyDirectoryCheckpointEnvelope: mocks.hashKeyDirectoryCheckpointEnvelope,
  lookupVerifiedKeyDirectoryEventBodies: mocks.lookupVerifiedKeyDirectoryEventBodies,
  verifyAndRememberKeyDirectoryLineageFromTrustedAnchor:
    mocks.verifyAndRememberKeyDirectoryLineageFromTrustedAnchor,
}));

vi.mock("@/shared/lib/auth/pop", () => ({
  getPopHeaders: mocks.getPopHeaders,
}));

vi.mock("@/shared/lib/auth/session-scope", () => ({
  getPreferredSessionScope: mocks.getPreferredSessionScope,
  SHARE_SESSION_SCOPE_HEADER: "X-Refmd-Share-Session",
}));

import { fetchVerifiedKeyDirectory, fetchVerifiedKeyDirectoryFromTrustedCheckpoint } from "./fetch";

describe("fetchVerifiedKeyDirectory", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    mocks.advanceKeyDirectoryPinWithProof.mockReset();
    mocks.getKeyDirectoryPin.mockReset();
    mocks.getPopHeaders.mockReset();
    mocks.getPreferredSessionScope.mockReset();
    mocks.hashKeyDirectoryCheckpointEnvelope.mockReset();
    mocks.lookupVerifiedKeyDirectoryEventBodies.mockReset();
    mocks.verifyAndRememberKeyDirectoryLineageFromTrustedAnchor.mockReset();

    mocks.getPopHeaders.mockResolvedValue({ "X-Refmd-PoP": "proof" });
    mocks.getPreferredSessionScope.mockReturnValue("user");
    mocks.lookupVerifiedKeyDirectoryEventBodies.mockReturnValue([]);
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
    mocks.lookupVerifiedKeyDirectoryEventBodies.mockReturnValue([cachedEvent]);

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

  it("fetches and remembers current lineage from a trusted older checkpoint", async () => {
    const scopeId = "11111111-1111-4111-8111-111111111111";
    const currentPin = {
      pinKey: `workspace:${scopeId}`,
      checkpointSequence: 4,
      checkpointHash: "checkpoint-4",
      eventHeadSequence: 7,
      eventHeadHash: "event-7",
      suitePolicyVersion: 1,
      minSuiteRank: 1,
    };
    const trustedCheckpoint = {
      payload: {
        sequence: 2,
        covered_event_head: {
          head_sequence: 5,
          head_hash: "event-5",
        },
      },
      signatures: [],
    } as unknown as KeyDirectoryEnvelope;
    const currentCheckpoint = {
      payload: {
        sequence: 4,
        covered_event_head: {
          head_sequence: 7,
          head_hash: "event-7",
        },
      },
      signatures: [],
    } as unknown as KeyDirectoryEnvelope;
    const checkpointAncestry = [
      trustedCheckpoint,
      { payload: { sequence: 3 }, signatures: [] },
    ] as unknown as Record<string, unknown>[];
    const eventAncestry = [{ payload: { sequence: 6 }, signatures: [] }];

    mocks.getKeyDirectoryPin.mockResolvedValue(currentPin);
    mocks.hashKeyDirectoryCheckpointEnvelope.mockImplementation(
      (checkpoint: { payload: unknown }) => {
        const payload = checkpoint.payload as { sequence?: number };
        return `checkpoint-${payload.sequence}`;
      },
    );

    const fetchMock = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            checkpoint: currentCheckpoint,
            checkpoint_ancestry: checkpointAncestry,
            event_ancestry: eventAncestry,
            rotation_deletion_evidences: [],
            pin: {
              checkpoint_sequence: currentPin.checkpointSequence,
              checkpoint_hash: currentPin.checkpointHash,
              event_head_sequence: currentPin.eventHeadSequence,
              event_head_hash: currentPin.eventHeadHash,
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
      fetchVerifiedKeyDirectoryFromTrustedCheckpoint({
        scopeKind: "workspace",
        scopeId,
        popDeviceId: "22222222-2222-4222-8222-222222222222",
        trustedCheckpointEnvelope: trustedCheckpoint,
      }),
    ).resolves.toEqual({ checkpoint: currentCheckpoint });

    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("checkpoint_sequence=2"),
      expect.any(Object),
    );
    expect(mocks.verifyAndRememberKeyDirectoryLineageFromTrustedAnchor).toHaveBeenCalledWith({
      scopeKind: "workspace",
      scopeId,
      trustedCheckpointEnvelope: trustedCheckpoint,
      checkpointEnvelope: currentCheckpoint,
      checkpointAncestry,
      eventAncestry,
      authorityEventAncestry: eventAncestry,
      rotationDeletionEvidences: [],
    });
  });

  it("advances a stale local pin from a trusted older checkpoint response", async () => {
    const scopeId = "11111111-1111-4111-8111-111111111111";
    const localPin = {
      pinKey: `workspace:${scopeId}`,
      checkpointSequence: 3,
      checkpointHash: "checkpoint-3",
      eventHeadSequence: 6,
      eventHeadHash: "event-6",
      suitePolicyVersion: 1,
      minSuiteRank: 1,
    };
    const advancedPin = {
      ...localPin,
      checkpointSequence: 4,
      checkpointHash: "checkpoint-4",
      eventHeadSequence: 8,
      eventHeadHash: "event-8",
    };
    const trustedCheckpoint = {
      payload: {
        sequence: 2,
        covered_event_head: {
          head_sequence: 5,
          head_hash: "event-5",
        },
      },
      signatures: [],
    } as unknown as KeyDirectoryEnvelope;
    const localCheckpoint = {
      payload: {
        sequence: 3,
        covered_event_head: {
          head_sequence: 6,
          head_hash: "event-6",
        },
      },
      signatures: [],
    } as unknown as Record<string, unknown>;
    const latestCheckpoint = {
      payload: {
        sequence: 4,
        covered_event_head: {
          head_sequence: 8,
          head_hash: "event-8",
        },
      },
      signatures: [],
    } as unknown as KeyDirectoryEnvelope;
    const event6 = { payload: { sequence: 6 }, signatures: [] };
    const event7 = { payload: { sequence: 7 }, signatures: [] };
    const event8 = { payload: { sequence: 8 }, signatures: [] };
    const checkpointAncestry = [trustedCheckpoint, localCheckpoint];
    const eventAncestry = [event6, event7, event8];

    mocks.getKeyDirectoryPin.mockResolvedValueOnce(localPin).mockResolvedValueOnce(advancedPin);
    mocks.hashKeyDirectoryCheckpointEnvelope.mockImplementation(
      (checkpoint: { payload: unknown }) => {
        const payload = checkpoint.payload as { sequence?: number };
        return `checkpoint-${payload.sequence}`;
      },
    );

    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              checkpoint: latestCheckpoint,
              checkpoint_ancestry: checkpointAncestry,
              event_ancestry: eventAncestry,
              rotation_deletion_evidences: [],
              pin: {
                checkpoint_sequence: advancedPin.checkpointSequence,
                checkpoint_hash: advancedPin.checkpointHash,
                event_head_sequence: advancedPin.eventHeadSequence,
                event_head_hash: advancedPin.eventHeadHash,
              },
            }),
            {
              headers: { "Content-Type": "application/json" },
              status: 200,
            },
          ),
      ),
    );

    await expect(
      fetchVerifiedKeyDirectoryFromTrustedCheckpoint({
        scopeKind: "workspace",
        scopeId,
        popDeviceId: "22222222-2222-4222-8222-222222222222",
        trustedCheckpointEnvelope: trustedCheckpoint,
      }),
    ).resolves.toEqual({ checkpoint: latestCheckpoint });

    expect(mocks.verifyAndRememberKeyDirectoryLineageFromTrustedAnchor).toHaveBeenCalledWith({
      scopeKind: "workspace",
      scopeId,
      trustedCheckpointEnvelope: trustedCheckpoint,
      checkpointEnvelope: latestCheckpoint,
      checkpointAncestry,
      eventAncestry,
      authorityEventAncestry: eventAncestry,
      rotationDeletionEvidences: [],
    });
    expect(mocks.advanceKeyDirectoryPinWithProof).toHaveBeenCalledWith({
      scopeKind: "workspace",
      scopeId,
      checkpointEnvelope: latestCheckpoint,
      checkpointAncestry: [localCheckpoint],
      eventAncestry: [event7, event8],
      authorityEventAncestry: eventAncestry,
      rotationDeletionEvidences: [],
    });
  });

  it("falls back to local-pin anchored refresh when the local pin is older than the trusted checkpoint", async () => {
    const scopeId = "11111111-1111-4111-8111-111111111111";
    const localPin = {
      pinKey: `workspace:${scopeId}`,
      checkpointSequence: 1,
      checkpointHash: "checkpoint-1",
      eventHeadSequence: 1,
      eventHeadHash: "event-1",
      suitePolicyVersion: 1,
      minSuiteRank: 1,
    };
    const advancedPin = {
      ...localPin,
      checkpointSequence: 4,
      checkpointHash: "checkpoint-4",
      eventHeadSequence: 4,
      eventHeadHash: "event-4",
    };
    const localCheckpoint = {
      payload: {
        sequence: 1,
        covered_event_head: {
          head_sequence: 1,
          head_hash: "event-1",
        },
      },
      signatures: [],
    } as unknown as Record<string, unknown>;
    const trustedCheckpoint = {
      payload: {
        sequence: 2,
        covered_event_head: {
          head_sequence: 2,
          head_hash: "event-2",
        },
      },
      signatures: [],
    } as unknown as KeyDirectoryEnvelope;
    const latestCheckpoint = {
      payload: {
        sequence: 4,
        covered_event_head: {
          head_sequence: 4,
          head_hash: "event-4",
        },
      },
      signatures: [],
    } as unknown as KeyDirectoryEnvelope;
    const checkpoint3 = {
      payload: {
        sequence: 3,
        covered_event_head: {
          head_sequence: 3,
          head_hash: "event-3",
        },
      },
      signatures: [],
    } as unknown as Record<string, unknown>;
    const event2 = { payload: { sequence: 2 }, signatures: [] };
    const event3 = { payload: { sequence: 3 }, signatures: [] };
    const event4 = { payload: { sequence: 4 }, signatures: [] };

    mocks.getKeyDirectoryPin
      .mockResolvedValueOnce(localPin)
      .mockResolvedValueOnce(localPin)
      .mockResolvedValueOnce(advancedPin);
    mocks.hashKeyDirectoryCheckpointEnvelope.mockImplementation(
      (checkpoint: { payload: unknown }) => {
        const payload = checkpoint.payload as { sequence?: number };
        return `checkpoint-${payload.sequence}`;
      },
    );

    const fetchMock = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            checkpoint: latestCheckpoint,
            checkpoint_ancestry: [localCheckpoint, trustedCheckpoint, checkpoint3],
            event_ancestry: [event2, event3, event4],
            rotation_deletion_evidences: [],
            pin: {
              checkpoint_sequence: advancedPin.checkpointSequence,
              checkpoint_hash: advancedPin.checkpointHash,
              event_head_sequence: advancedPin.eventHeadSequence,
              event_head_hash: advancedPin.eventHeadHash,
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
      fetchVerifiedKeyDirectoryFromTrustedCheckpoint({
        scopeKind: "workspace",
        scopeId,
        popDeviceId: "22222222-2222-4222-8222-222222222222",
        trustedCheckpointEnvelope: trustedCheckpoint,
      }),
    ).resolves.toEqual({ checkpoint: latestCheckpoint });

    expect(fetchMock).toHaveBeenCalledWith(
      expect.stringContaining("checkpoint_sequence=1"),
      expect.any(Object),
    );
    expect(mocks.verifyAndRememberKeyDirectoryLineageFromTrustedAnchor).not.toHaveBeenCalled();
    expect(mocks.advanceKeyDirectoryPinWithProof).toHaveBeenCalledWith({
      scopeKind: "workspace",
      scopeId,
      checkpointEnvelope: latestCheckpoint,
      checkpointAncestry: [localCheckpoint, trustedCheckpoint, checkpoint3],
      eventAncestry: [event2, event3, event4],
      authorityEventAncestry: [event2, event3, event4],
      rotationDeletionEvidences: [],
    });
  });

  it("stops trusted checkpoint refresh retries after persistent pin-race failures", async () => {
    const scopeId = "11111111-1111-4111-8111-111111111111";
    const currentPin = {
      pinKey: `workspace:${scopeId}`,
      checkpointSequence: 4,
      checkpointHash: "checkpoint-4",
      eventHeadSequence: 7,
      eventHeadHash: "event-7",
      suitePolicyVersion: 1,
      minSuiteRank: 1,
    };
    const trustedCheckpoint = {
      payload: {
        sequence: 2,
        covered_event_head: {
          head_sequence: 5,
          head_hash: "event-5",
        },
      },
      signatures: [],
    } as unknown as KeyDirectoryEnvelope;
    const currentCheckpoint = {
      payload: {
        sequence: 4,
        covered_event_head: {
          head_sequence: 7,
          head_hash: "event-7",
        },
      },
      signatures: [],
    } as unknown as KeyDirectoryEnvelope;

    mocks.getKeyDirectoryPin.mockResolvedValue(currentPin);
    mocks.hashKeyDirectoryCheckpointEnvelope.mockImplementation(
      (checkpoint: { payload: unknown }) => {
        const payload = checkpoint.payload as { sequence?: number };
        return `checkpoint-${payload.sequence}`;
      },
    );
    mocks.verifyAndRememberKeyDirectoryLineageFromTrustedAnchor.mockRejectedValue(
      new Error("key_directory_checkpoint_anchor_mismatch"),
    );

    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              checkpoint: currentCheckpoint,
              checkpoint_ancestry: [trustedCheckpoint],
              event_ancestry: [],
              rotation_deletion_evidences: [],
              pin: {
                checkpoint_sequence: currentPin.checkpointSequence,
                checkpoint_hash: currentPin.checkpointHash,
                event_head_sequence: currentPin.eventHeadSequence,
                event_head_hash: currentPin.eventHeadHash,
              },
            }),
            {
              headers: { "Content-Type": "application/json" },
              status: 200,
            },
          ),
      ),
    );

    await expect(
      fetchVerifiedKeyDirectoryFromTrustedCheckpoint({
        scopeKind: "workspace",
        scopeId,
        popDeviceId: "22222222-2222-4222-8222-222222222222",
        trustedCheckpointEnvelope: trustedCheckpoint,
      }),
    ).rejects.toThrow("key_directory_checkpoint_anchor_mismatch");

    expect(mocks.verifyAndRememberKeyDirectoryLineageFromTrustedAnchor).toHaveBeenCalledTimes(4);
  });
});
