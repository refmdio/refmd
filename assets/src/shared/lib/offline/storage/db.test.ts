import { beforeEach, describe, expect, it, vi } from "vite-plus/test";
import { openOfflineDb } from "./db";

const mocks = vi.hoisted(() => ({
  openIdb: vi.fn(),
}));

vi.mock("@/shared/lib/storage/idb", () => ({
  openIdb: mocks.openIdb,
}));

describe("offline storage schema", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("creates only the latest schema without legacy store cleanup", async () => {
    const createdStores: string[] = [];
    const createdIndexes: string[] = [];
    const deleteObjectStore = vi.fn();
    const db = {
      createObjectStore: vi.fn((name: string) => {
        createdStores.push(name);
        return {
          createIndex: vi.fn((indexName: string) => createdIndexes.push(indexName)),
        };
      }),
      deleteObjectStore,
    } as unknown as IDBDatabase;

    mocks.openIdb.mockImplementation(
      async (_name: string, _version: number, upgrade: (db: IDBDatabase, old: number) => void) => {
        upgrade(db, 0);
        return db;
      },
    );

    await openOfflineDb();

    expect(mocks.openIdb).toHaveBeenCalledWith("refmd-offline", 1, expect.any(Function));
    expect(createdStores).toEqual([
      "document-cache",
      "pending-changes",
      "offline-documents",
      "offline-created",
      "offline-workspaces",
      "offline-document-index",
    ]);
    expect(createdIndexes).toEqual(["by-lastAccessedAt", "by-workspaceId"]);
    expect(deleteObjectStore).not.toHaveBeenCalled();
  });
});
