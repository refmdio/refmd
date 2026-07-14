import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";
import { clearAllPersistedKeys } from "./key-persistence";

describe("key persistence secure cleanup", () => {
  const openedDbs: string[] = [];
  const deletedDbs: string[] = [];
  const deletedCaches: string[] = [];

  beforeEach(() => {
    openedDbs.length = 0;
    deletedDbs.length = 0;
    deletedCaches.length = 0;
    vi.stubGlobal("localStorage", createStorage());
    vi.stubGlobal("sessionStorage", createStorage());
    localStorage.clear();
    sessionStorage.clear();

    vi.stubGlobal("indexedDB", {
      open(name: string) {
        openedDbs.push(name);
        const request = {
          result: {
            objectStoreNames: [],
            close: vi.fn(),
          },
          onsuccess: null as (() => void) | null,
          onerror: null as (() => void) | null,
          onblocked: null as (() => void) | null,
        };
        queueMicrotask(() => request.onsuccess?.());
        return request;
      },
      deleteDatabase(name: string) {
        deletedDbs.push(name);
        const request = {
          onsuccess: null as (() => void) | null,
          onerror: null as (() => void) | null,
          onblocked: null as (() => void) | null,
        };
        queueMicrotask(() => request.onsuccess?.());
        return request;
      },
    } as unknown as IDBFactory);

    vi.stubGlobal("caches", {
      async keys() {
        return ["refmd-app-cache", "third-party-cache"];
      },
      async delete(name: string) {
        deletedCaches.push(name);
        return true;
      },
    } as unknown as CacheStorage);
  });

  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it("deletes persisted key stores, local state, and cache storage", async () => {
    localStorage.setItem("refmd-device-id:user", "device-id");
    localStorage.setItem("recent-docs:workspace", "document-id");
    localStorage.setItem("editor-mode:document", "markdown");
    localStorage.setItem("unrelated", "keep");
    sessionStorage.setItem("refmd-session", "session");

    await clearAllPersistedKeys();

    expect(sessionStorage.length).toBe(0);
    expect(localStorage.getItem("refmd-device-id:user")).toBeNull();
    expect(localStorage.getItem("recent-docs:workspace")).toBeNull();
    expect(localStorage.getItem("editor-mode:document")).toBeNull();
    expect(localStorage.getItem("unrelated")).toBe("keep");
    expect(openedDbs).toEqual(["refmd-keys", "refmd-trust", "refmd-offline"]);
    expect(deletedDbs.sort()).toEqual(
      ["refmd-keys", "refmd-trust", "refmd-offline", "refmd-security"].sort(),
    );
    expect(deletedCaches.sort()).toEqual(["refmd-app-cache", "third-party-cache"].sort());
  });
});

function createStorage(): Storage {
  const values = new Map<string, string>();
  const storage = {
    get length() {
      return values.size;
    },
    clear() {
      for (const key of values.keys()) {
        delete (storage as Record<string, unknown>)[key];
      }
      values.clear();
    },
    getItem(key: string) {
      return values.get(key) ?? null;
    },
    key(index: number) {
      return Array.from(values.keys())[index] ?? null;
    },
    removeItem(key: string) {
      values.delete(key);
      delete (storage as Record<string, unknown>)[key];
    },
    setItem(key: string, value: string) {
      const stringValue = String(value);
      values.set(key, stringValue);
      (storage as unknown as Record<string, string>)[key] = stringValue;
    },
  };
  return storage as Storage;
}
