import { clearAuthBootstrap } from "@/shared/lib/crypto/dsk";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

const DEVICE_ID_KEY_PREFIX = "refmd-device-id:";
const OBSOLETE_CRYPTO_CACHE_PREFIXES = [
  "refmd-pdk",
  "refmd-pdk:",
  "refmd-umk-cache",
  "refmd-device-key-cache",
];

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
  clearLegacyCryptoCaches();
  await getCryptoWorker().persistCurrentKeysWithDsk(userId, options);
}

export async function clearSessionData(
  options: { preserveAuthBootstrap?: boolean } = {},
): Promise<void> {
  sessionStorage.clear();
  clearLegacyCryptoCaches();
  if (!options.preserveAuthBootstrap) {
    await clearAuthBootstrap().catch(() => {});
  }
}

function clearLegacyCryptoCaches(): void {
  for (const key of Object.keys(localStorage)) {
    if (OBSOLETE_CRYPTO_CACHE_PREFIXES.some((prefix) => key.startsWith(prefix))) {
      localStorage.removeItem(key);
    }
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
  await overwriteDbEntries("refmd-keys", [
    "dsk",
    "device-keys",
    "wrapped-umk",
    "wrapped-device-ecdh",
    "wrapped-device-mlkem768-material",
    "wrapped-device-hybrid-signing",
    "auth-bootstrap",
  ]);
  await overwriteDbEntries("refmd-trust", []);
  await overwriteDbEntries("refmd-offline", []);
  const deleteDb = (
    name: string,
    retries = 2,
  ): Promise<{
    name: string;
    deleted: boolean;
  }> =>
    new Promise((resolve) => {
      try {
        const req = indexedDB.deleteDatabase(name);
        req.onsuccess = () => resolve({ name, deleted: true });
        req.onerror = () => resolve({ name, deleted: false });
        req.onblocked = () => {
          if (retries > 0) {
            setTimeout(() => deleteDb(name, retries - 1).then(resolve), 200);
          } else {
            resolve({ name, deleted: false });
          }
        };
      } catch {
        resolve({ name, deleted: false });
      }
    });
  const dbNames = [
    "refmd-keys",
    "refmd-trust",
    "refmd-offline",
    "refmd-security",
    "refmd-share-sessions",
  ];
  const dbResults = await Promise.all(dbNames.map((name) => deleteDb(name)));
  const failedDbs = dbResults.filter((result) => !result.deleted);
  if (failedDbs.length > 0) {
    throw new Error(
      `Secure logout incomplete: failed to delete ${failedDbs.map((result) => result.name).join(", ")}`,
    );
  }

  await clearCacheStorage();
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
