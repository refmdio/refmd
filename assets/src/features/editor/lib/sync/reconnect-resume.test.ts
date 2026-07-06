import { beforeEach, describe, expect, test, vi } from "vitest";
import * as Y from "yjs";
import {
  canonicalMarkdownText,
  replaceDocWithCanonicalText,
} from "@/shared/lib/yjs/canonical-document";
import type { DocumentPayload } from "@/shared/lib/ws/document-payloads";
import type { DocumentState } from "../../model/document-state/types";
import { createSyncGapError } from "./inbound-verify-decrypt";

const handleDocumentMessageMock = vi.hoisted(() => vi.fn());
const pushSnapshotMock = vi.hoisted(() => vi.fn(() => true));

vi.mock("./inbound-document", () => ({
  handleDocumentMessage: handleDocumentMessageMock,
  handleRemoteSnapshot: vi.fn(),
  handleRemoteUpdate: vi.fn(),
  handleRemoteWriteSession: vi.fn(),
}));

vi.mock("./inbound-signing-keys", () => ({
  applyDeviceKeyCache: vi.fn(),
  buildDocumentSigningKeyCaches: vi.fn(async () => ({ status: "ok" })),
}));

vi.mock("@/shared/lib/ws/phoenix-channel", () => ({
  getChannelState: vi.fn(() => "joined"),
  pushSnapshot: pushSnapshotMock,
  pushUpdate: vi.fn(() => true),
}));

import {
  captureNoBaselineReconnectRollback,
  resumeReconnectDocument,
  rollbackNoBaselineReconnectState,
} from "./reconnect-resume";

function stateWithText(text: string): DocumentState {
  const yDoc = new Y.Doc();
  if (text.length > 0) yDoc.getText("content").insert(0, text);
  return {
    stateKey: "doc-1",
    documentId: "doc-1",
    workspaceId: "workspace-1",
    access: { kind: "workspace" },
    yDoc,
    activeSnapshotId: "local-snapshot",
    localClock: 4,
    knownClocks: { "device:local": 3 },
    confirmedClocks: { "device:local": 2 },
    writeSessionCounters: { "event:local": 2 },
    snapshotBaseClocks: { "device:base": 1 },
    lastSavedState: null,
    snapshotUpdatesCount: 7,
    snapshotProofHash: "local-proof",
    snapshotCiphertextHash: "local-ciphertext",
    latestVersion: 11,
    keyVersion: 5,
    awareness: {
      clientID: 1,
      getStates: () => new Map([[1, {}]]),
    },
    awarenessClientOwners: new Map(),
    pendingUpdateEnvelope: null,
    pendingUpdateBytes: null,
    pendingSnapshot: null,
    pendingSnapshotEnvelope: null,
    sending: false,
    readOnly: false,
    autoSync: null,
    _pendingRemoteEvents: [],
    _pendingOutOfOrderUpdates: [],
  } as unknown as DocumentState;
}

function snapshotState(text: string): Uint8Array {
  const doc = new Y.Doc();
  try {
    if (text.length > 0) doc.getText("content").insert(0, text);
    return Y.encodeStateAsUpdateV2(doc);
  } finally {
    doc.destroy();
  }
}

function pendingGenesisSnapshot(text: string, parentSnapshotId = "GENESIS") {
  return {
    snapshotId: "pending-genesis",
    parentSnapshotId,
    ciphertextHash: "pending-ciphertext",
    parentProofHash: "GENESIS",
    snapshotYjsState: snapshotState(text),
    knownClocksAtSend: {},
  };
}

describe("reconnect resume", () => {
  beforeEach(() => {
    handleDocumentMessageMock.mockReset();
    pushSnapshotMock.mockClear();
  });

  test("rolls back no-baseline reconnect state before failing contained-line conflicts", () => {
    const state = stateWithText("same\n");
    try {
      const rollback = captureNoBaselineReconnectRollback(state, "same\n");

      replaceDocWithCanonicalText(state.yDoc, "server\nsame\n", "remote");
      state.activeSnapshotId = "server-snapshot";
      state.localClock = 9;
      state.knownClocks = { "device:server": 8 };
      state.confirmedClocks = { "device:server": 8 };
      state.writeSessionCounters = { "event:server": 1 };
      state.snapshotBaseClocks = { "device:server-base": 7 };
      state.lastSavedState = new Uint8Array([1, 2, 3]);
      state.snapshotUpdatesCount = 0;
      state.snapshotProofHash = "server-proof";
      state.snapshotCiphertextHash = "server-ciphertext";
      state.latestVersion = 20;
      state.keyVersion = 6;

      rollbackNoBaselineReconnectState(state, rollback);

      expect(canonicalMarkdownText(state.yDoc)).toBe("same\n");
      expect(state.activeSnapshotId).toBe("local-snapshot");
      expect(state.localClock).toBe(4);
      expect(state.knownClocks).toEqual({ "device:local": 3 });
      expect(state.confirmedClocks).toEqual({ "device:local": 2 });
      expect(state.writeSessionCounters).toEqual({ "event:local": 2 });
      expect(state.snapshotBaseClocks).toEqual({ "device:base": 1 });
      expect(state.lastSavedState).toBeNull();
      expect(state.snapshotUpdatesCount).toBe(7);
      expect(state.snapshotProofHash).toBe("local-proof");
      expect(state.snapshotCiphertextHash).toBe("local-ciphertext");
      expect(state.latestVersion).toBe(11);
      expect(state.keyVersion).toBe(5);
    } finally {
      state.yDoc.destroy();
    }
  });

  test("fail-closes and rolls back when inbound no-baseline structural merge throws", async () => {
    const state = stateWithText("same\n");
    const failClosed = vi.fn();
    handleDocumentMessageMock.mockImplementation(async () => {
      replaceDocWithCanonicalText(state.yDoc, "server\nsame\n", "remote");
      state.activeSnapshotId = "server-snapshot";
      state.localClock = 9;
      state.knownClocks = { "device:server": 8 };
      state.confirmedClocks = { "device:server": 8 };
      state.writeSessionCounters = { "event:server": 1 };
      state.snapshotBaseClocks = { "device:server-base": 7 };
      state.lastSavedState = new Uint8Array([1, 2, 3]);
      throw createSyncGapError("canonical_structural_merge_unavailable");
    });

    try {
      await expect(
        resumeReconnectDocument({} as DocumentPayload, state, "doc-1", undefined, failClosed),
      ).resolves.toBeUndefined();

      expect(failClosed).toHaveBeenCalledTimes(1);
      expect(failClosed.mock.calls[0]?.[0]).toBe("reconnect_failed");
      expect(pushSnapshotMock).not.toHaveBeenCalled();
      expect(canonicalMarkdownText(state.yDoc)).toBe("same\n");
      expect(state.activeSnapshotId).toBe("local-snapshot");
      expect(state.localClock).toBe(4);
      expect(state.knownClocks).toEqual({ "device:local": 3 });
      expect(state.confirmedClocks).toEqual({ "device:local": 2 });
      expect(state.writeSessionCounters).toEqual({ "event:local": 2 });
      expect(state.snapshotBaseClocks).toEqual({ "device:base": 1 });
      expect(state.lastSavedState).toBeNull();
    } finally {
      state.yDoc.destroy();
    }
  });

  test("replays pending no-baseline snapshot instead of failing on empty reconnect payload", async () => {
    const state = stateWithText("# aue");
    const failClosed = vi.fn();
    const pendingSnapshot = pendingGenesisSnapshot("# aue");
    const pendingEnvelope = { ciphertext: "ciphertext" };

    state.activeSnapshotId = null;
    state.snapshotProofHash = "";
    state.snapshotCiphertextHash = "";
    state.latestVersion = 0;
    state.pendingSnapshot = pendingSnapshot;
    state.pendingSnapshotEnvelope = pendingEnvelope;
    state.sending = false;
    state.initialized = false;
    state.channel = {} as DocumentState["channel"];

    handleDocumentMessageMock.mockImplementation(async () => {
      replaceDocWithCanonicalText(state.yDoc, "", "remote");
      state.activeSnapshotId = null;
      state.initialized = true;
    });

    try {
      await expect(
        resumeReconnectDocument({} as DocumentPayload, state, "doc-1", undefined, failClosed),
      ).resolves.toBeUndefined();

      expect(failClosed).not.toHaveBeenCalled();
      expect(canonicalMarkdownText(state.yDoc)).toBe("# aue");
      expect(state.pendingSnapshot).toBe(pendingSnapshot);
      expect(state.pendingSnapshotEnvelope).toBe(pendingEnvelope);
      expect(state.sending).toBe(true);
      expect(state.initialized).toBe(true);
      expect(pushSnapshotMock).toHaveBeenCalledTimes(1);
      const pushCall = pushSnapshotMock.mock.calls[0] as unknown[] | undefined;
      expect(pushCall?.[0]).toBe("doc-1");
      expect(pushCall?.[1]).toBe(pendingEnvelope);
    } finally {
      state.yDoc.destroy();
    }
  });

  test("replays pending no-baseline snapshot when inbound structural merge throws before replay", async () => {
    const state = stateWithText("# aue");
    const failClosed = vi.fn();
    const pendingSnapshot = pendingGenesisSnapshot("# aue");
    const pendingEnvelope = { ciphertext: "ciphertext" };

    state.activeSnapshotId = null;
    state.snapshotProofHash = "";
    state.snapshotCiphertextHash = "";
    state.latestVersion = 0;
    state.pendingSnapshot = pendingSnapshot;
    state.pendingSnapshotEnvelope = pendingEnvelope;
    state.sending = false;
    state.initialized = false;
    state.channel = {} as DocumentState["channel"];

    handleDocumentMessageMock.mockImplementation(async () => {
      replaceDocWithCanonicalText(state.yDoc, "", "remote");
      state.activeSnapshotId = null;
      throw createSyncGapError("canonical_structural_merge_unavailable");
    });

    try {
      await expect(
        resumeReconnectDocument({} as DocumentPayload, state, "doc-1", undefined, failClosed),
      ).resolves.toBeUndefined();

      expect(failClosed).not.toHaveBeenCalled();
      expect(canonicalMarkdownText(state.yDoc)).toBe("# aue");
      expect(state.pendingSnapshot).toBe(pendingSnapshot);
      expect(state.pendingSnapshotEnvelope).toBe(pendingEnvelope);
      expect(state.sending).toBe(true);
      expect(state.initialized).toBe(true);
      expect(pushSnapshotMock).toHaveBeenCalledTimes(1);
      const pushCall = pushSnapshotMock.mock.calls[0] as unknown[] | undefined;
      expect(pushCall?.[0]).toBe("doc-1");
      expect(pushCall?.[1]).toBe(pendingEnvelope);
    } finally {
      state.yDoc.destroy();
    }
  });

  test("fail-closes thrown no-baseline conflicts when the server snapshot changed", async () => {
    const state = stateWithText("# aue");
    const failClosed = vi.fn();
    const pendingSnapshot = pendingGenesisSnapshot("# aue");
    const pendingEnvelope = { ciphertext: "ciphertext" };

    state.activeSnapshotId = null;
    state.snapshotProofHash = "";
    state.snapshotCiphertextHash = "";
    state.latestVersion = 0;
    state.pendingSnapshot = pendingSnapshot;
    state.pendingSnapshotEnvelope = pendingEnvelope;
    state.sending = false;
    state.channel = {} as DocumentState["channel"];

    handleDocumentMessageMock.mockImplementation(async () => {
      replaceDocWithCanonicalText(state.yDoc, "server\n", "remote");
      state.activeSnapshotId = "server-snapshot";
      throw createSyncGapError("canonical_structural_merge_unavailable");
    });

    try {
      await expect(
        resumeReconnectDocument({} as DocumentPayload, state, "doc-1", undefined, failClosed),
      ).resolves.toBeUndefined();

      expect(failClosed).toHaveBeenCalledTimes(1);
      expect(failClosed.mock.calls[0]?.[0]).toBe("reconnect_failed");
      expect(pushSnapshotMock).not.toHaveBeenCalled();
      expect(canonicalMarkdownText(state.yDoc)).toBe("# aue");
      expect(state.activeSnapshotId).toBeNull();
    } finally {
      state.yDoc.destroy();
    }
  });

  test("fail-closes pending no-baseline replay when pending snapshot text is stale", async () => {
    const state = stateWithText("# aue");
    const failClosed = vi.fn();
    const pendingSnapshot = pendingGenesisSnapshot("# stale");
    const pendingEnvelope = { ciphertext: "ciphertext" };

    state.activeSnapshotId = null;
    state.snapshotProofHash = "";
    state.snapshotCiphertextHash = "";
    state.latestVersion = 0;
    state.pendingSnapshot = pendingSnapshot;
    state.pendingSnapshotEnvelope = pendingEnvelope;
    state.sending = false;
    state.channel = {} as DocumentState["channel"];

    handleDocumentMessageMock.mockImplementation(async () => {
      replaceDocWithCanonicalText(state.yDoc, "", "remote");
      state.activeSnapshotId = null;
      state.initialized = true;
    });

    try {
      await expect(
        resumeReconnectDocument({} as DocumentPayload, state, "doc-1", undefined, failClosed),
      ).resolves.toBeUndefined();

      expect(failClosed).toHaveBeenCalledTimes(1);
      expect(failClosed.mock.calls[0]?.[0]).toBe("reconnect_failed");
      expect(pushSnapshotMock).not.toHaveBeenCalled();
      expect(canonicalMarkdownText(state.yDoc)).toBe("# aue");
      expect(state.pendingSnapshot).toBeNull();
      expect(state.pendingSnapshotEnvelope).toBeNull();
    } finally {
      state.yDoc.destroy();
    }
  });

  test("fail-closes pending no-baseline replay when pending snapshot is not genesis", async () => {
    const state = stateWithText("# aue");
    const failClosed = vi.fn();
    const pendingSnapshot = pendingGenesisSnapshot("# aue", "existing-snapshot");
    const pendingEnvelope = { ciphertext: "ciphertext" };

    state.activeSnapshotId = null;
    state.snapshotProofHash = "";
    state.snapshotCiphertextHash = "";
    state.latestVersion = 0;
    state.pendingSnapshot = pendingSnapshot;
    state.pendingSnapshotEnvelope = pendingEnvelope;
    state.sending = false;
    state.channel = {} as DocumentState["channel"];

    handleDocumentMessageMock.mockImplementation(async () => {
      replaceDocWithCanonicalText(state.yDoc, "", "remote");
      state.activeSnapshotId = null;
      state.initialized = true;
    });

    try {
      await expect(
        resumeReconnectDocument({} as DocumentPayload, state, "doc-1", undefined, failClosed),
      ).resolves.toBeUndefined();

      expect(failClosed).toHaveBeenCalledTimes(1);
      expect(failClosed.mock.calls[0]?.[0]).toBe("reconnect_failed");
      expect(pushSnapshotMock).not.toHaveBeenCalled();
      expect(canonicalMarkdownText(state.yDoc)).toBe("# aue");
      expect(state.pendingSnapshot).toBeNull();
      expect(state.pendingSnapshotEnvelope).toBeNull();
    } finally {
      state.yDoc.destroy();
    }
  });
});
