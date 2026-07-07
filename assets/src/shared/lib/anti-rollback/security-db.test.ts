import { describe, expect, it, vi } from "vite-plus/test";
import { openIdb } from "@/shared/lib/storage/idb";
import {
  DOCUMENT_STATE_PIN_STORE_NAME,
  KEY_DIRECTORY_PIN_STORE_NAME,
  KEY_DIRECTORY_VERIFIED_LINEAGE_STORE_NAME,
  openSecurityDb,
} from "./security-db";

vi.mock("@/shared/lib/storage/idb", () => ({
  openIdb: vi.fn(async () => ({ close: vi.fn() })),
}));

describe("openSecurityDb", () => {
  it("owns refmd-security as version 1 initial schema", async () => {
    await openSecurityDb();

    expect(openIdb).toHaveBeenCalledWith("refmd-security", 1, expect.any(Function));
  });

  it("creates every required store in the version 1 initial schema", async () => {
    await openSecurityDb();

    const upgrade = vi.mocked(openIdb).mock.calls.at(-1)?.[2];
    expect(upgrade).toBeTypeOf("function");

    const stores = new Set<string>();
    const db = {
      objectStoreNames: {
        contains: (name: string) => stores.has(name),
      },
      createObjectStore: vi.fn((name: string) => {
        stores.add(name);
        return {};
      }),
    } as unknown as IDBDatabase;

    upgrade!(db, 0);

    expect(db.createObjectStore).toHaveBeenCalledWith(DOCUMENT_STATE_PIN_STORE_NAME, {
      keyPath: "documentId",
    });
    expect(db.createObjectStore).toHaveBeenCalledWith(KEY_DIRECTORY_PIN_STORE_NAME, {
      keyPath: "pinKey",
    });
    expect(db.createObjectStore).toHaveBeenCalledWith(KEY_DIRECTORY_VERIFIED_LINEAGE_STORE_NAME, {
      keyPath: "key",
    });
  });
});
