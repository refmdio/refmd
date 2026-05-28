import { afterEach, describe, expect, it, vi } from "vitest";
import { openIdb } from "./idb";

describe("openIdb", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("closes open connections when a database delete or upgrade needs versionchange", async () => {
    const close = vi.fn();
    const db = {
      close,
      onversionchange: null,
    } as unknown as IDBDatabase;
    let request: IDBOpenDBRequest | null = null;

    vi.stubGlobal("indexedDB", {
      open: vi.fn(() => {
        request = {
          error: null,
          result: db,
          onblocked: null,
          onerror: null,
          onsuccess: null,
          onupgradeneeded: null,
        } as unknown as IDBOpenDBRequest;
        queueMicrotask(() => request?.onsuccess?.({} as Event));
        return request;
      }),
    } as unknown as IDBFactory);

    await expect(openIdb("refmd-trust", 3, vi.fn())).resolves.toBe(db);

    const onVersionChange = (
      db as unknown as {
        onversionchange: ((event: IDBVersionChangeEvent) => void) | null;
      }
    ).onversionchange;
    expect(onVersionChange).toBeTypeOf("function");

    onVersionChange?.({} as IDBVersionChangeEvent);

    expect(close).toHaveBeenCalledTimes(1);
  });
});
