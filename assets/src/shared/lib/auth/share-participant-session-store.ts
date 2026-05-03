import { idbGet, idbPut, openIdb } from "@/shared/lib/storage/idb";

const LEGACY_STORAGE_KEY = "refmd-share-participant-session";
const DB_NAME = "refmd-share-sessions";
const DB_VERSION = 1;
const STORE_NAME = "share-participant-sessions";

export interface WrappedBlob {
  ciphertext: ArrayBuffer;
  iv: ArrayBuffer;
}

export interface StoredShareParticipantSession {
  shareSlug: string;
  principalId: string;
  deviceId: string;
  displayName: string;
  signingPublicKey: string;
  encryptionPublicKey: string;
  wrappedDeviceEcdh: WrappedBlob;
  wrappedDeviceSigning: WrappedBlob;
}

export function clearLegacyShareParticipantSession(): void {
  localStorage.removeItem(LEGACY_STORAGE_KEY);
}

function openShareSessionDb(): Promise<IDBDatabase> {
  return openIdb(DB_NAME, DB_VERSION, (db) => {
    if (!db.objectStoreNames.contains(STORE_NAME)) {
      db.createObjectStore(STORE_NAME, { keyPath: "shareSlug" });
    }
  });
}

export async function readStoredShareParticipantSession(
  shareSlug: string,
): Promise<StoredShareParticipantSession | null> {
  clearLegacyShareParticipantSession();
  try {
    const db = await openShareSessionDb();
    return (await idbGet<StoredShareParticipantSession>(db, STORE_NAME, shareSlug)) ?? null;
  } catch {
    return null;
  }
}

export async function writeStoredShareParticipantSession(
  session: StoredShareParticipantSession,
): Promise<void> {
  clearLegacyShareParticipantSession();
  try {
    const db = await openShareSessionDb();
    await idbPut(db, STORE_NAME, session);
  } catch {
    // Best effort: canonical share access can continue with in-memory state.
  }
}

export async function deleteStoredShareParticipantSession(shareSlug: string): Promise<void> {
  try {
    const db = await openShareSessionDb();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      const request = store.delete(shareSlug);
      request.onerror = () => reject(request.error);
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.onerror = () => reject(tx.error);
    });
  } catch {
    // Best effort
  }
}

export async function clearStoredShareParticipantSessions(): Promise<void> {
  clearLegacyShareParticipantSession();

  try {
    const db = await openShareSessionDb();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      const request = store.clear();
      request.onerror = () => reject(request.error);
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.onerror = () => reject(tx.error);
    });
  } catch {
    // Best effort
  }
}

export async function deleteStoredShareParticipantSessionsForDevice(
  deviceId: string,
): Promise<void> {
  clearLegacyShareParticipantSession();

  try {
    const db = await openShareSessionDb();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      const request = store.openCursor();

      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const cursor = request.result;
        if (!cursor) return;

        const value = cursor.value as StoredShareParticipantSession;
        if (value.deviceId === deviceId) {
          cursor.delete();
        }

        cursor.continue();
      };

      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.onerror = () => reject(tx.error);
    });
  } catch {
    // Best effort
  }
}
