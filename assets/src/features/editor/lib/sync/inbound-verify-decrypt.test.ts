import { describe, expect, it, vi } from "vite-plus/test";
import type { DocumentState } from "../../model/document-state/types";
import type { UpdatePayload } from "@/shared/lib/ws/document-payloads";
import {
  checkRotationSnapshot,
  commitWriteSessionCounter,
  resetWriteSessionCountersForSnapshotBaseline,
} from "./inbound-verify-decrypt";

const mocks = vi.hoisted(() => ({
  documentsGet: vi.fn(),
}));

vi.mock("@/shared/api/documents", () => ({
  documentsApi: {
    get: mocks.documentsGet,
  },
}));

function update(
  counter: number,
  overrides: Partial<UpdatePayload["publicData"]> = {},
): UpdatePayload {
  return {
    ciphertext: "",
    nonce: "",
    signature: {} as UpdatePayload["signature"],
    admission: {} as UpdatePayload["admission"],
    version: 1,
    publicData: {
      docId: "doc-1",
      signingKeyId: "signing-key-1",
      ownerKind: "device",
      ownerId: "device-1",
      authorityKind: "workspace_device",
      authorityId: "workspace-1",
      authorityContextKey: "signing-key-1",
      authorityScopeId: "workspace-1",
      authorityPermissionVersion: 1,
      keyCheckpointSequence: 1,
      keyCheckpointHash: "checkpoint",
      keyVersion: 1,
      refSnapshotId: "snapshot-1",
      clock: counter - 1,
      timestamp: 1_700_000_000_000 + counter,
      updateHash: `update-${counter}`,
      minDekVersion: 1,
      writeSessionEventHash: "write-session-event-1",
      writeSessionId: "write-session-1",
      writeSessionCounter: counter,
      ...overrides,
    },
  };
}

function state(): DocumentState {
  return {
    writeSessionCounters: {},
  } as DocumentState;
}

describe("commitWriteSessionCounter", () => {
  it("accepts strictly increasing counters for the same write session and signing key", () => {
    const documentState = state();

    commitWriteSessionCounter(update(1), documentState);
    commitWriteSessionCounter(update(2), documentState);

    expect(documentState.writeSessionCounters["write-session-event-1:signing-key-1"]).toBe(2);
  });

  it("rejects duplicate or lower counters for the same write session and signing key", () => {
    const documentState = state();

    commitWriteSessionCounter(update(3), documentState);

    expect(() => commitWriteSessionCounter(update(3), documentState)).toThrow(
      "Write session counter replay detected",
    );
    expect(() => commitWriteSessionCounter(update(2), documentState)).toThrow(
      "Write session counter replay detected",
    );
    expect(documentState.writeSessionCounters["write-session-event-1:signing-key-1"]).toBe(3);
  });

  it("tracks independent write sessions separately", () => {
    const documentState = state();

    commitWriteSessionCounter(update(2), documentState);
    commitWriteSessionCounter(
      update(1, { writeSessionEventHash: "write-session-event-2" }),
      documentState,
    );
    commitWriteSessionCounter(update(1, { signingKeyId: "signing-key-2" }), documentState);

    expect(documentState.writeSessionCounters).toEqual({
      "write-session-event-1:signing-key-1": 2,
      "write-session-event-2:signing-key-1": 1,
      "write-session-event-1:signing-key-2": 1,
    });
  });

  it("resets counters when a snapshot becomes the new verification baseline", () => {
    const documentState = state();

    commitWriteSessionCounter(update(3), documentState);
    resetWriteSessionCountersForSnapshotBaseline(documentState);

    expect(documentState.writeSessionCounters).toEqual({});
    expect(() => commitWriteSessionCounter(update(1), documentState)).not.toThrow();
    expect(documentState.writeSessionCounters["write-session-event-1:signing-key-1"]).toBe(1);
  });
});

describe("checkRotationSnapshot", () => {
  it("does not enable a pending snapshot when strict title recovery fails", async () => {
    mocks.documentsGet.mockResolvedValueOnce({
      needs_dek_rotation: false,
      needs_rotation_snapshot: true,
    });
    const retry = vi.fn().mockRejectedValueOnce(new Error("title_update_failed"));
    const notifyLocalEdit = vi.fn();
    const documentState = {
      access: { kind: "workspace" },
      pendingRotationSnapshot: false,
      _retryDekRotation: retry,
      autoSync: { notifyLocalEdit },
    } as unknown as DocumentState;

    checkRotationSnapshot("doc-1", documentState);

    await vi.waitFor(() => expect(retry).toHaveBeenCalledOnce());
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(documentState.pendingRotationSnapshot).toBe(false);
    expect(notifyLocalEdit).not.toHaveBeenCalled();
  });

  it("delegates pending snapshot recovery to the strict rotation callback", async () => {
    mocks.documentsGet.mockResolvedValueOnce({
      needs_dek_rotation: false,
      needs_rotation_snapshot: true,
    });
    const notifyLocalEdit = vi.fn();
    const documentState = {
      access: { kind: "workspace" },
      pendingRotationSnapshot: false,
      autoSync: { notifyLocalEdit },
    } as unknown as DocumentState;
    const retry = vi.fn(async () => {
      documentState.pendingRotationSnapshot = true;
      notifyLocalEdit();
    });
    documentState._retryDekRotation = retry;

    checkRotationSnapshot("doc-1", documentState);

    await vi.waitFor(() => expect(retry).toHaveBeenCalledOnce());
    expect(documentState.pendingRotationSnapshot).toBe(true);
    expect(notifyLocalEdit).toHaveBeenCalledOnce();
  });
});
