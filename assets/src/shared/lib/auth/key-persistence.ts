import { clearAuthBootstrap } from "@/shared/lib/crypto/dsk";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { PERSISTED_DATABASE_NAMES } from "@/shared/lib/storage/persistence-registry";

const DEVICE_ID_KEY_PREFIX = "refmd-device-id:";
export function persistDeviceId(deviceId: string, userId: string): void {
  localStorage.setItem(`${DEVICE_ID_KEY_PREFIX}${userId}`, deviceId);
}

export function getPersistedDeviceId(userId?: string): string | null {
  if (!userId) return null;
  return localStorage.getItem(`${DEVICE_ID_KEY_PREFIX}${userId}`);
}

export async function persistCurrentKeysWithDsk(
  userId: string,
  options?: { persistUmk?: boolean },
): Promise<void> {
  await getCryptoWorker().persistCurrentKeysWithDsk(userId, options);
}

export async function clearSessionData(
  options: { preserveAuthBootstrap?: boolean } = {},
): Promise<void> {
  sessionStorage.clear();
  if (!options.preserveAuthBootstrap) {
    await clearAuthBootstrap().catch(() => {});
  }
}

export async function clearAllPersistedKeys(): Promise<void> {
  sessionStorage.clear();
  for (const key of Object.keys(localStorage)) {
    if (
      key.startsWith("refmd") ||
      key.startsWith("recent-docs:") ||
      key.startsWith("editor-mode:")
    ) {
      localStorage.removeItem(key);
    }
  }
  const dbNames = PERSISTED_DATABASE_NAMES;
  const existingDbNames = await persistedDatabaseNames(dbNames);
  const existingDbNameSet = new Set(existingDbNames);
  if (existingDbNameSet.has("refmd-keys")) {
    await overwriteDbEntries("refmd-keys", [
      "dsk",
      "device-keys",
      "wrapped-umk",
      "wrapped-device-ecdh",
      "wrapped-device-mlkem768-material",
      "wrapped-device-hybrid-signing",
      "auth-bootstrap",
    ]);
  }
  if (existingDbNameSet.has("refmd-trust")) {
    await overwriteDbEntries("refmd-trust", []);
  }
  if (existingDbNameSet.has("refmd-offline")) {
    await overwriteDbEntries("refmd-offline", []);
  }
  const dbResults = await Promise.all(dbNames.map((name) => deleteDbWithRetry(name)));
  const failedDbs = dbResults.filter((result) => !result.deleted);
  if (failedDbs.length > 0) {
    throw new Error(
      `Secure logout incomplete: failed to delete ${failedDbs.map((result) => result.name).join(", ")}`,
    );
  }

  await clearCacheStorage();
}

async function persistedDatabaseNames(names: readonly string[]): Promise<readonly string[]> {
  if (typeof indexedDB.databases !== "function") return names;
  try {
    const existing = new Set(
      (await indexedDB.databases())
        .map((database) => database.name)
        .filter((name): name is string => typeof name === "string" && name.length > 0),
    );
    return names.filter((name) => existing.has(name));
  } catch {
    return names;
  }
}

function deleteDbWithRetry(
  name: string,
  retries = 20,
): Promise<{
  name: string;
  deleted: boolean;
}> {
  return new Promise((resolve) => {
    const retry = (remaining: number) => {
      if (remaining <= 0) {
        resolve({ name, deleted: false });
        return;
      }
      setTimeout(() => attempt(remaining - 1), 250);
    };
    const finishIfAbsent = (remaining: number) => {
      verifyDatabaseAbsent(name)
        .then((absent) => {
          if (absent) {
            resolve({ name, deleted: true });
            return;
          }
          retry(remaining);
        })
        .catch(() => retry(remaining));
    };
    const attempt = (remaining: number) => {
      try {
        const req = indexedDB.deleteDatabase(name);
        req.onsuccess = () => finishIfAbsent(remaining);
        req.onerror = () => retry(remaining);
        req.onblocked = () => retry(remaining);
      } catch {
        retry(remaining);
      }
    };
    attempt(retries);
  });
}

async function verifyDatabaseAbsent(name: string): Promise<boolean> {
  if (typeof indexedDB.databases !== "function") return true;
  const existing = await persistedDatabaseNames([name]);
  return existing.length === 0;
}

async function clearCacheStorage(): Promise<void> {
  if (typeof caches === "undefined") return;

  const cacheNames = await caches.keys();
  const failedCaches: string[] = [];

  for (const name of cacheNames) {
    try {
      const deleted = await caches.delete(name);
      if (!deleted) {
        failedCaches.push(name);
      }
    } catch {
      failedCaches.push(name);
    }
  }

  if (failedCaches.length > 0) {
    throw new Error(
      `Secure logout incomplete: failed to delete cache storage ${failedCaches.join(", ")}`,
    );
  }
}

function overwriteDbEntries(dbName: string, knownKeys: string[]): Promise<void> {
  return new Promise((resolve) => {
    try {
      const req = indexedDB.open(dbName);
      req.onsuccess = () => {
        const db = req.result;
        const storeNames = Array.from(db.objectStoreNames);
        let index = 0;
        const closeAndResolve = () => {
          db.close();
          resolve();
        };
        const processNextStore = () => {
          if (index >= storeNames.length) {
            closeAndResolve();
            return;
          }
          const storeName = storeNames[index++];
          try {
            const tx = db.transaction(storeName, "readwrite");
            const store = tx.objectStore(storeName);
            for (const key of knownKeys) {
              try {
                store.put(null, key);
              } catch {
                // Key may not exist.
              }
            }
            try {
              store.clear();
            } catch {
              // Store may be inaccessible.
            }
            tx.oncomplete = processNextStore;
            tx.onerror = processNextStore;
            tx.onabort = processNextStore;
          } catch {
            processNextStore();
          }
        };
        processNextStore();
      };
      req.onerror = () => resolve();
      req.onblocked = () => resolve();
    } catch {
      resolve();
    }
  });
}
