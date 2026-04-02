import {
  storeWrappedUmkRaw,
  storeWrappedDeviceKeysRaw,
  clearWrappedUmk,
} from "@/shared/lib/crypto/dsk";
const DEVICE_ID_KEY_PREFIX = "refmd-device-id:";
const LEGACY_DEVICE_ID_KEY = "refmd-device-id";
export function persistDeviceId(deviceId: string, userId: string): void {
  localStorage.setItem(`${DEVICE_ID_KEY_PREFIX}${userId}`, deviceId);
  localStorage.setItem(LEGACY_DEVICE_ID_KEY, deviceId);
}
export function getPersistedDeviceId(userId?: string): string | null {
  if (userId) {
    return localStorage.getItem(`${DEVICE_ID_KEY_PREFIX}${userId}`);
  }
  return localStorage.getItem(LEGACY_DEVICE_ID_KEY);
}
const PDK_UMK_KEY = "refmd-pdk-umk";
const PDK_ECDH_KEY = "refmd-pdk-device-ecdh";
const PDK_SIGNING_KEY = "refmd-pdk-device-signing";
export function hasPdkData(): boolean {
  return (
    localStorage.getItem(PDK_UMK_KEY) !== null &&
    localStorage.getItem(PDK_ECDH_KEY) !== null &&
    localStorage.getItem(PDK_SIGNING_KEY) !== null
  );
}
interface PdkWrappedBlobs {
  ciphertext: string;
  nonce: string;
}
interface PdkWrappedKeySet {
  wrappedUmk?: PdkWrappedBlobs | null;
  wrappedDeviceKeys?: {
    ecdh: PdkWrappedBlobs;
    signing: PdkWrappedBlobs;
  } | null;
}
export function readPdkBlobs(): {
  pdkWrappedUmk: PdkWrappedBlobs | null;
  pdkWrappedDeviceEcdh: PdkWrappedBlobs | null;
  pdkWrappedDeviceSigning: PdkWrappedBlobs | null;
} {
  const parse = (raw: string | null): PdkWrappedBlobs | null => {
    if (!raw) return null;
    try {
      const parsed: unknown = JSON.parse(raw);
      if (
        typeof parsed === "object" &&
        parsed !== null &&
        "ciphertext" in parsed &&
        "nonce" in parsed
      ) {
        return parsed as PdkWrappedBlobs;
      }
    } catch {
      // Corrupted data
    }
    return null;
  };
  const umk = parse(localStorage.getItem(PDK_UMK_KEY));
  const ecdh = parse(localStorage.getItem(PDK_ECDH_KEY));
  const signing = parse(localStorage.getItem(PDK_SIGNING_KEY));
  if (!umk || !ecdh || !signing) {
    return { pdkWrappedUmk: null, pdkWrappedDeviceEcdh: null, pdkWrappedDeviceSigning: null };
  }
  return { pdkWrappedUmk: umk, pdkWrappedDeviceEcdh: ecdh, pdkWrappedDeviceSigning: signing };
}
export function persistPdkWrappedKeys(keys: PdkWrappedKeySet): void {
  if (keys.wrappedUmk) {
    localStorage.setItem(PDK_UMK_KEY, JSON.stringify(keys.wrappedUmk));
  }
  if (keys.wrappedDeviceKeys) {
    localStorage.setItem(PDK_ECDH_KEY, JSON.stringify(keys.wrappedDeviceKeys.ecdh));
    localStorage.setItem(PDK_SIGNING_KEY, JSON.stringify(keys.wrappedDeviceKeys.signing));
  }
}
export async function persistWrappedDeviceKeys(wrapped: {
  wrappedEcdh: {
    ciphertext: ArrayBuffer;
    iv: ArrayBuffer;
  };
  wrappedSigning: {
    ciphertext: ArrayBuffer;
    iv: ArrayBuffer;
  };
}): Promise<void> {
  await storeWrappedDeviceKeysRaw(wrapped.wrappedEcdh, wrapped.wrappedSigning);
}
export async function persistWrappedUmk(params: {
  wrappedUmk: {
    ciphertext: ArrayBuffer;
    iv: ArrayBuffer;
  };
  pdk?: Uint8Array;
  kmsi: boolean;
  userId: string;
}): Promise<void> {
  const { wrappedUmk, kmsi } = params;
  if (kmsi) {
    await storeWrappedUmkRaw(wrappedUmk);
  } else {
    sessionStorage.setItem(
      "refmd-session-umk-wrapped",
      JSON.stringify({
        ciphertext: Array.from(new Uint8Array(wrappedUmk.ciphertext)),
        iv: Array.from(new Uint8Array(wrappedUmk.iv)),
      }),
    );
    await clearWrappedUmk();
  }
}
export async function clearSessionData(): Promise<void> {
  sessionStorage.clear();
  const { clearAuthBootstrap } = await import("@/shared/lib/crypto/dsk");
  await clearAuthBootstrap().catch(() => {});
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
    "wrapped-device-signing",
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
  const dbNames = ["refmd-keys", "refmd-trust", "refmd-offline", "refmd-security"];
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
            // Transaction or store access error.
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
