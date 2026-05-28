import { describe, expect, it } from "vitest";
import type { DocumentState } from "../../model/document-state/types";
import type { UpdatePayload } from "@/shared/lib/ws/document-payloads";
import { commitWriteSessionCounter } from "./inbound-verify-decrypt";

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
});
