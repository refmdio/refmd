import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import type { PendingChangesEntry } from "@/shared/lib/offline/storage/store";
import { reencryptPendingChangesForLatestDek } from "./pending-reencrypt";

const mocks = vi.hoisted(() => ({
  getPendingChanges: vi.fn<() => Promise<PendingChangesEntry | null>>(),
  replacePendingChangesIfUnchanged:
    vi.fn<
      (
        expected: Pick<PendingChangesEntry, "keyVersion" | "writeId">,
        replacement: PendingChangesEntry,
      ) => Promise<boolean>
    >(),
}));

vi.mock("@/shared/lib/offline/storage/store", () => mocks);

describe("pending change DEK re-encryption", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.replacePendingChangesIfUnchanged.mockResolvedValue(true);
  });

  it("re-encrypts an old pending record with the latest DEK", async () => {
    const plaintext = new Uint8Array([1, 2, 3]);
    mocks.getPendingChanges.mockResolvedValue({
      documentId: "doc-1",
      encryptedDiff: new Uint8Array([4]),
      diffNonce: new Uint8Array([5]),
      keyVersion: 1,
      writeId: "write-1",
      createdAt: 10,
      updatedAt: 20,
    });
    const worker = {
      decryptOfflinePending: vi.fn(async () => plaintext),
      encryptOfflinePending: vi.fn(async () => ({
        ciphertext: new Uint8Array([6]),
        nonce: new Uint8Array([7]),
      })),
    };

    await expect(
      reencryptPendingChangesForLatestDek({
        documentId: "doc-1",
        latestKeyVersion: 2,
        worker: worker as never,
      }),
    ).resolves.toBe(true);

    expect(mocks.replacePendingChangesIfUnchanged).toHaveBeenCalledWith(
      { keyVersion: 1, writeId: "write-1" },
      expect.objectContaining({ keyVersion: 2, encryptedDiff: new Uint8Array([6]) }),
    );
    expect(plaintext).toEqual(new Uint8Array([0, 0, 0]));
  });

  it("retries against the newer pending record when the atomic replacement loses a race", async () => {
    const firstPlaintext = new Uint8Array([1]);
    const secondPlaintext = new Uint8Array([2]);
    mocks.getPendingChanges
      .mockResolvedValueOnce({
        documentId: "doc-1",
        encryptedDiff: new Uint8Array([3]),
        diffNonce: new Uint8Array([4]),
        keyVersion: 1,
        writeId: "write-1",
        createdAt: 10,
        updatedAt: 20,
      })
      .mockResolvedValueOnce({
        documentId: "doc-1",
        encryptedDiff: new Uint8Array([5]),
        diffNonce: new Uint8Array([6]),
        keyVersion: 1,
        writeId: "write-2",
        createdAt: 10,
        updatedAt: 30,
      });
    mocks.replacePendingChangesIfUnchanged.mockResolvedValueOnce(false).mockResolvedValueOnce(true);
    const worker = {
      decryptOfflinePending: vi
        .fn()
        .mockResolvedValueOnce(firstPlaintext)
        .mockResolvedValueOnce(secondPlaintext),
      encryptOfflinePending: vi.fn(async ({ plaintext }: { plaintext: Uint8Array }) => ({
        ciphertext: new Uint8Array(plaintext),
        nonce: new Uint8Array([7]),
      })),
    };

    await expect(
      reencryptPendingChangesForLatestDek({
        documentId: "doc-1",
        latestKeyVersion: 2,
        worker: worker as never,
      }),
    ).resolves.toBe(true);

    expect(mocks.replacePendingChangesIfUnchanged).toHaveBeenNthCalledWith(
      2,
      { keyVersion: 1, writeId: "write-2" },
      expect.objectContaining({ encryptedDiff: new Uint8Array([2]), keyVersion: 2 }),
    );
    expect(firstPlaintext).toEqual(new Uint8Array([0]));
    expect(secondPlaintext).toEqual(new Uint8Array([0]));
  });

  it("leaves a latest-version pending record unchanged", async () => {
    mocks.getPendingChanges.mockResolvedValue({
      documentId: "doc-1",
      encryptedDiff: new Uint8Array([4]),
      diffNonce: new Uint8Array([5]),
      keyVersion: 2,
      writeId: "write-3",
      createdAt: 10,
      updatedAt: 20,
    });

    await expect(
      reencryptPendingChangesForLatestDek({
        documentId: "doc-1",
        latestKeyVersion: 2,
        worker: {} as never,
      }),
    ).resolves.toBe(false);
    expect(mocks.replacePendingChangesIfUnchanged).not.toHaveBeenCalled();
  });
});
