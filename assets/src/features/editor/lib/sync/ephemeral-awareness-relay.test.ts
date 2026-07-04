import { Awareness } from "y-protocols/awareness";
import * as Y from "yjs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { DocumentState } from "../../model/document-state/types";
import { setupAwarenessRelay } from "./ephemeral-awareness-relay";
import { sendEphemeralEnvelope } from "./ephemeral-send";

vi.mock("@/shared/lib/ws/phoenix-channel", () => ({
  getChannelState: () => "joined",
}));

vi.mock("./share-access", () => ({
  getDocumentDekCacheKey: () => "document-dek-cache-key",
}));

vi.mock("./ephemeral-send", () => ({
  sendEphemeralEnvelope: vi.fn(() => Promise.resolve()),
}));

function emitAwarenessUpdateKeepalive(awareness: Awareness): void {
  (
    awareness as unknown as {
      emit: (
        event: "update",
        args: [{ added: number[]; updated: number[]; removed: number[] }, origin: unknown],
      ) => void;
    }
  ).emit("update", [
    {
      added: [],
      updated: [awareness.clientID],
      removed: [],
    },
    "local-keepalive",
  ]);
}

function createRelayState(): DocumentState {
  const yDoc = new Y.Doc();
  const awareness = new Awareness(yDoc);

  return {
    awareness,
    awarenessRelayCleanup: null,
    channel: {},
    ephemeralSession: {
      sessionId: new Uint8Array(24),
      sessionCounter: 0,
      trustedPeers: new Map([["trusted-peer-session", { lastCounter: 0, signingKeyId: "peer" }]]),
      pendingInitializes: new Map(),
      initializeSent: true,
    },
    keyVersion: 1,
    stateKey: "document-state",
    workspaceId: "workspace-id",
  } as unknown as DocumentState;
}

describe("setupAwarenessRelay", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.mocked(sendEphemeralEnvelope).mockClear();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("does not send signed ephemeral frames for Awareness keepalive update events", async () => {
    const state = createRelayState();
    setupAwarenessRelay(state, "document-id", "local-signing-key");

    emitAwarenessUpdateKeepalive(state.awareness);
    await vi.advanceTimersByTimeAsync(150);

    expect(sendEphemeralEnvelope).not.toHaveBeenCalled();
    state.awarenessRelayCleanup?.();
  });

  it("sends signed ephemeral frames for semantic local Awareness changes", async () => {
    const state = createRelayState();
    setupAwarenessRelay(state, "document-id", "local-signing-key");

    state.awareness.setLocalStateField("user", {
      userId: "user-id",
      name: "User",
      color: "#5b8def",
      signingKeyId: "local-signing-key",
    });
    await vi.advanceTimersByTimeAsync(150);

    expect(sendEphemeralEnvelope).toHaveBeenCalledTimes(1);
    expect(sendEphemeralEnvelope).toHaveBeenCalledWith(
      expect.any(Uint8Array),
      "document-id",
      state,
      "local-signing-key",
      "document-state",
      "document-dek-cache-key",
    );
    state.awarenessRelayCleanup?.();
  });
});
