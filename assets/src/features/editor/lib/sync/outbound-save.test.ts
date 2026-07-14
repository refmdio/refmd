import * as Y from "yjs";
import { describe, expect, it, vi } from "vite-plus/test";
import {
  canonicalMarkdownText,
  encodeCanonicalDiffAsUpdate,
  encodeCanonicalStateAsUpdateV2,
} from "@/shared/lib/yjs/canonical-document";
import type {
  SnapshotSavedPayload,
  UpdateSaveFailedPayload,
} from "@/shared/lib/ws/document-payloads";
import type { DocumentState } from "../../model/document-state/types";
import { handleSnapshotSaved, handleUpdateSaveFailed } from "./outbound-save";

const mocks = vi.hoisted(() => ({
  cacheDocumentState: vi.fn(async () => {}),
  completeDekRotationAfterSnapshot: vi.fn(async () => {}),
  deletePendingChanges: vi.fn(async () => {}),
}));

vi.mock("./bootstrap-key-rotation", () => ({
  completeDekRotationAfterSnapshot: mocks.completeDekRotationAfterSnapshot,
}));

vi.mock("@/shared/lib/anti-rollback/document-state-pins", () => ({
  buildDocumentStatePinKey: vi.fn(() => "pin"),
  getDocumentStatePin: vi.fn(async () => null),
  putDocumentStatePin: vi.fn(async () => {}),
  updatePinFromState: vi.fn(() => ({})),
}));

vi.mock("@/shared/lib/offline/cache/manager/write", () => ({
  cacheDocumentState: mocks.cacheDocumentState,
}));

vi.mock("@/shared/lib/offline/storage/store", () => ({
  deletePendingChanges: mocks.deletePendingChanges,
}));

vi.mock("./outbound-publication", () => ({
  queuePublicationSaveSync: vi.fn(),
}));

function documentState(overrides: Partial<DocumentState> = {}): DocumentState {
  return {
    stateKey: "state",
    access: { kind: "workspace" },
    yDoc: new Y.Doc(),
    localClock: 5,
    preSendLocalClock: 4,
    activeSnapshotId: null,
    snapshotProofHash: "",
    snapshotCiphertextHash: "",
    knownClocks: {},
    confirmedClocks: {},
    writeSessionCounters: {},
    snapshotBaseClocks: {},
    lastSavedState: null,
    latestVersion: 0,
    keyVersion: 1,
    workspaceId: "workspace",
    pendingRotationKeyVersion: null,
    pendingRotationSnapshot: false,
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
    autoSync: null,
    _admissionDirectoryRefreshRequired: false,
    _forceCompleteReconnect: false,
    _recentSaveEvents: [],
    ...overrides,
  } as unknown as DocumentState;
}

function snapshotAck(snapshotId = "snapshot-1"): SnapshotSavedPayload {
  return {
    snapshotId,
    latestVersion: 2,
    proofChainHash: "proof",
    ciphertextHash: "ciphertext",
    snapshotAdmissionEventHash: "admission",
  };
}

function installPendingSnapshot(state: DocumentState, text: string): void {
  const yText = state.yDoc.getText("content");
  yText.insert(0, text);
  const snapshotYjsState = encodeCanonicalStateAsUpdateV2(state.yDoc);
  state.pendingSnapshot = {
    snapshotId: "snapshot-1",
    parentSnapshotId: "GENESIS",
    ciphertextHash: "ciphertext",
    parentProofHash: "GENESIS",
    snapshotYjsState,
    knownClocksAtSend: { "device:key": 1 },
  };
  state.pendingSnapshotEnvelope = {};
}

function applyUpdateToSavedBaseline(saved: Uint8Array, update: Uint8Array): string {
  const doc = new Y.Doc();
  try {
    Y.applyUpdate(doc, saved, "remote");
    Y.applyUpdate(doc, update, "local");
    return canonicalMarkdownText(doc);
  } finally {
    doc.destroy();
  }
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

describe("handleSnapshotSaved", () => {
  it("resumes DEK completion after reload from the current key version", async () => {
    vi.clearAllMocks();
    const state = documentState({
      keyVersion: 2,
      pendingRotationKeyVersion: null,
      pendingRotationSnapshot: true,
    });
    installPendingSnapshot(state, "rotation snapshot\n");

    await handleSnapshotSaved(snapshotAck(), state, "document-1");

    expect(mocks.completeDekRotationAfterSnapshot).toHaveBeenCalledWith({
      documentId: "document-1",
      workspaceId: "workspace",
      state,
      oldKeyVersion: 1,
      newKeyVersion: 2,
    });
    expect(mocks.cacheDocumentState).toHaveBeenCalledOnce();
    expect(mocks.completeDekRotationAfterSnapshot.mock.invocationCallOrder[0]).toBeLessThan(
      mocks.cacheDocumentState.mock.invocationCallOrder[0]!,
    );
    expect(state.pendingRotationSnapshot).toBe(false);
  });

  it("rebases the live document onto the accepted snapshot before the next edit", async () => {
    const state = documentState({
      autoSync: {
        dispose: vi.fn(),
        drain: vi.fn(async () => {}),
        notifyLocalEdit: vi.fn(),
        prepareWriteSession: vi.fn(async () => true),
        flush: vi.fn(),
        flushNow: vi.fn(async () => {}),
      },
    });
    installPendingSnapshot(state, "snapshot text\n");

    await handleSnapshotSaved(snapshotAck(), state);
    state.yDoc.getText("content").insert(canonicalMarkdownText(state.yDoc).length, "after ack\n");

    const update = encodeCanonicalDiffAsUpdate(state.yDoc, state.lastSavedState);

    expect(state.snapshotBaseClocks).toEqual({ "device:key": 1 });
    expect(state.knownClocks).toEqual({});
    expect(state.confirmedClocks).toEqual({});
    expect(state.localClock).toBe(0);
    expect(update).not.toBeNull();
    expect(update!.length).toBeGreaterThan(2);
    expect(applyUpdateToSavedBaseline(state.lastSavedState!, update!)).toBe(
      "snapshot text\nafter ack\n",
    );
  });

  it("preserves text typed while the accepted snapshot was in flight", async () => {
    const notifyLocalEdit = vi.fn();
    const state = documentState({
      autoSync: {
        dispose: vi.fn(),
        drain: vi.fn(async () => {}),
        notifyLocalEdit,
        prepareWriteSession: vi.fn(async () => true),
        flush: vi.fn(),
        flushNow: vi.fn(async () => {}),
      },
    });
    installPendingSnapshot(state, "snapshot text\n");
    state.yDoc.getText("content").insert(canonicalMarkdownText(state.yDoc).length, "in flight\n");

    await handleSnapshotSaved(snapshotAck(), state);
    const update = encodeCanonicalDiffAsUpdate(state.yDoc, state.lastSavedState);

    expect(canonicalMarkdownText(state.yDoc)).toBe("snapshot text\nin flight\n");
    expect(update).not.toBeNull();
    expect(applyUpdateToSavedBaseline(state.lastSavedState!, update!)).toBe(
      "snapshot text\nin flight\n",
    );
    expect(notifyLocalEdit).toHaveBeenCalled();
  });
});
