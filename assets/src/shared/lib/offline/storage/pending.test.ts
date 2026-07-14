import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import type { PendingChangesEntry } from "./pending";
import { putPendingChanges, replacePendingChangesIfUnchanged } from "./pending";

const mocks = vi.hoisted(() => ({
  existing: undefined as Record<string, unknown> | undefined,
  idbConditionalPut: vi.fn(),
}));

vi.mock("@/shared/lib/offline/storage/db", () => ({
  openOfflineDb: vi.fn(async () => ({})),
  STORE_PENDING_CHANGES: "pending_changes",
}));

vi.mock("@/shared/lib/storage/idb", () => ({
  idbConditionalPut: mocks.idbConditionalPut,
  idbGet: vi.fn(),
  toArrayBuffer: (bytes: Uint8Array) =>
    bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
}));

function pending(keyVersion: number, writeId: string): PendingChangesEntry {
  return {
    documentId: "doc-1",
    encryptedDiff: new Uint8Array([keyVersion]),
    diffNonce: new Uint8Array([1]),
    keyVersion,
    writeId,
    createdAt: 10,
    updatedAt: 20,
  };
}

describe("pending change storage ordering", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.existing = undefined;
    mocks.idbConditionalPut.mockImplementation(
      async (
        _db: unknown,
        _store: string,
        _key: string,
        _value: unknown,
        shouldWrite: (existing: Record<string, unknown> | undefined) => boolean,
      ) => shouldWrite(mocks.existing),
    );
  });

  it("does not let a delayed old-DEK writer replace a newer-key record", async () => {
    mocks.existing = {
      keyVersion: 2,
      writeId: "rotation-write",
      updatedAt: 20,
    };

    await expect(putPendingChanges(pending(1, "stale-write"))).resolves.toBe(false);
  });

  it("uses record identity rather than timestamp for re-encryption CAS", async () => {
    mocks.existing = {
      keyVersion: 1,
      writeId: "newer-write",
      updatedAt: 20,
    };

    await expect(
      replacePendingChangesIfUnchanged(
        { keyVersion: 1, writeId: "older-write" },
        pending(2, "rotation-write"),
      ),
    ).resolves.toBe(false);
  });
});
