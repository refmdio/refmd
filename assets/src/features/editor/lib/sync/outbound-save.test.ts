import { describe, expect, it } from "vitest";
import type { UpdateSaveFailedPayload } from "@/shared/lib/ws/document-payloads";
import type { DocumentState } from "../../model/document-state/types";
import { handleUpdateSaveFailed } from "./outbound-save";

function documentState(overrides: Partial<DocumentState> = {}): DocumentState {
  return {
    localClock: 5,
    preSendLocalClock: 4,
    pendingUpdateBytes: new Uint8Array([1, 2, 3]),
    pendingUpdateEnvelope: { publicData: {} },
    pendingSnapshot: null,
    pendingSnapshotEnvelope: null,
    pendingSaveTimeout: null,
    _pendingSaveWatchdogKind: null,
    _pendingSaveWatchdogStartedAt: null,
    sending: true,
    writeSession: null,
    writeSessionPromise: null,
    writeSessionReadyAt: null,
    writeSessionError: null,
    snapshotUpdatesCount: 0,
    _admissionDirectoryRefreshRequired: false,
    _forceCompleteReconnect: false,
    _recentSaveEvents: [],
    ...overrides,
  } as unknown as DocumentState;
}

describe("handleUpdateSaveFailed", () => {
  it("forces snapshot fallback instead of reconnect retry for oversized updates", () => {
    const state = documentState();
    const payload = {
      reason: "document_update_payload_too_large",
      requiresNewSnapshot: false,
    } as UpdateSaveFailedPayload;

    const recovery = handleUpdateSaveFailed(payload, state);

    expect(recovery).toBe("none");
    expect(state.snapshotUpdatesCount).toBe(Infinity);
    expect(state._admissionDirectoryRefreshRequired).toBe(true);
    expect(state._forceCompleteReconnect).toBe(false);
    expect(state.pendingUpdateBytes).toBeNull();
    expect(state.pendingUpdateEnvelope).toBeNull();
    expect(state.sending).toBe(false);
    expect(state.localClock).toBe(4);
  });
});
