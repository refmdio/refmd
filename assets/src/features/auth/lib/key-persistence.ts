import {
  storeWrappedUmkRaw,
  storeWrappedDeviceKeysRaw,
  clearWrappedUmk,
} from "@/shared/lib/crypto/dsk";

const DEVICE_ID_KEY = "refmd-device-id";

// PDK is kept in-memory only (disposable, never persisted).
let inMemoryPdk: Uint8Array | null = null;

// ── Device ID persistence ─────────────────────

export function persistDeviceId(deviceId: string): void {
  localStorage.setItem(DEVICE_ID_KEY, deviceId);
}

export function getPersistedDeviceId(): string | null {
  return localStorage.getItem(DEVICE_ID_KEY);
}

// ── Key restoration ───────────────────────────

export function hasPdkData(): boolean {
  return (
    localStorage.getItem("refmd-pdk-umk") !== null &&
    localStorage.getItem("refmd-pdk-device-ecdh") !== null &&
    localStorage.getItem("refmd-pdk-device-signing") !== null
  );
}

export function persistSessionPdk(pdk: Uint8Array): void {
  inMemoryPdk = pdk;
}

export function restoreSessionPdk(): Uint8Array | null {
  return inMemoryPdk;
}

export async function persistWrappedDeviceKeys(wrapped: {
  wrappedEcdh: { ciphertext: ArrayBuffer; iv: ArrayBuffer };
  wrappedSigning: { ciphertext: ArrayBuffer; iv: ArrayBuffer };
}): Promise<void> {
  await storeWrappedDeviceKeysRaw(wrapped.wrappedEcdh, wrapped.wrappedSigning);
}

export async function persistWrappedUmk(params: {
  wrappedUmk: { ciphertext: ArrayBuffer; iv: ArrayBuffer };
  pdk?: Uint8Array;
  kmsi: boolean;
  userId: string;
}): Promise<void> {
  const { wrappedUmk, kmsi } = params;

  if (kmsi) {
    await storeWrappedUmkRaw(wrappedUmk);
  } else {
    // Non-KMSI: sessionStorage (tab-scoped, lost on browser close)
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

export function clearSessionData(): void {
  sessionStorage.clear();
  inMemoryPdk = null;
}

export async function clearAllPersistedKeys(): Promise<void> {
  sessionStorage.clear();
  inMemoryPdk = null;

  for (const key of Object.keys(localStorage)) {
    if (
      key.startsWith("refmd") ||
      key.startsWith("recent-docs:") ||
      key.startsWith("editor-mode:")
    ) {
      localStorage.removeItem(key);
    }
  }

  // Overwrite sensitive entries before deletion (defense-in-depth: if
  // deleteDatabase fails, the sensitive content is already zeroed)
  await overwriteDbEntries("refmd-keys", [
    "dsk",
    "device-keys",
    "wrapped-umk",
    "wrapped-device-ecdh",
    "wrapped-device-signing",
  ]);
  await overwriteDbEntries("refmd-trust", []);
  await overwriteDbEntries("refmd-offline", []);

  const deleteDb = (name: string, retries = 2): Promise<{ name: string; deleted: boolean }> =>
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

  const dbNames = ["refmd-keys", "refmd-trust", "refmd-offline"];
  const dbResults = await Promise.all(dbNames.map((name) => deleteDb(name)));
  const failedDbs = dbResults.filter((r) => !r.deleted);
  if (failedDbs.length > 0) {
    throw new Error(
      `Secure logout incomplete: failed to delete ${failedDbs.map((r) => r.name).join(", ")}`,
    );
  }

  try {
    const cacheNames = await caches.keys();
    for (const name of cacheNames) {
      await caches.delete(name);
    }
  } catch {
    // Best effort (Cache API may not be available)
  }
}

function overwriteDbEntries(dbName: string, knownKeys: string[]): Promise<void> {
  return new Promise((resolve) => {
    try {
      const req = indexedDB.open(dbName);
      req.onsuccess = () => {
        const db = req.result;
        try {
          for (const storeName of db.objectStoreNames) {
            const tx = db.transaction(storeName, "readwrite");
            const store = tx.objectStore(storeName);
            // Overwrite known keys with null
            for (const key of knownKeys) {
              try {
                store.put(null, key);
              } catch {
                // Key may not exist
              }
            }
            // Clear entire store as fallback
            try {
              store.clear();
            } catch {
              // Store may be inaccessible
            }
          }
        } catch {
          // Transaction or store access error
        }
        db.close();
        resolve();
      };
      req.onerror = () => resolve();
      req.onblocked = () => resolve();
    } catch {
      resolve();
    }
  });
}
