import { idbGet, idbPut, openIdb, toArrayBuffer } from "@/shared/lib/storage/idb";

const DB_NAME = "refmd-trust";
const DB_VERSION = 1;
const STORE_NAME = "tofu-entries";

export interface TofuEntry {
  userId: string;
  deviceId: string;
  signingPublicKey: Uint8Array;
  ecdhPublicKey: Uint8Array;
  firstSeenAt: number;
  lastSeenAt: number;
}

interface SerializedTofuEntry {
  userId: string;
  deviceId: string;
  signingPublicKey: ArrayBuffer;
  ecdhPublicKey: ArrayBuffer;
  firstSeenAt: number;
  lastSeenAt: number;
}

function openDb(): Promise<IDBDatabase> {
  return openIdb(DB_NAME, DB_VERSION, (db) => {
    if (!db.objectStoreNames.contains(STORE_NAME)) {
      const store = db.createObjectStore(STORE_NAME, {
        keyPath: ["userId", "deviceId"],
      });
      store.createIndex("by-user", "userId", { unique: false });
    }
  });
}

function compositeKey(userId: string, deviceId: string): [string, string] {
  return [userId, deviceId];
}

function serialize(entry: TofuEntry): SerializedTofuEntry {
  return {
    userId: entry.userId,
    deviceId: entry.deviceId,
    signingPublicKey: toArrayBuffer(entry.signingPublicKey),
    ecdhPublicKey: toArrayBuffer(entry.ecdhPublicKey),
    firstSeenAt: entry.firstSeenAt,
    lastSeenAt: entry.lastSeenAt,
  };
}

function deserialize(serialized: SerializedTofuEntry): TofuEntry {
  return {
    userId: serialized.userId,
    deviceId: serialized.deviceId,
    signingPublicKey: new Uint8Array(serialized.signingPublicKey),
    ecdhPublicKey: new Uint8Array(serialized.ecdhPublicKey),
    firstSeenAt: serialized.firstSeenAt,
    lastSeenAt: serialized.lastSeenAt,
  };
}

export async function saveTofuEntry(entry: TofuEntry): Promise<void> {
  const db = await openDb();
  await idbPut(db, STORE_NAME, serialize(entry));
}

export async function getTofuEntry(userId: string, deviceId: string): Promise<TofuEntry | null> {
  const db = await openDb();
  const result = await idbGet<SerializedTofuEntry>(db, STORE_NAME, compositeKey(userId, deviceId));
  return result ? deserialize(result) : null;
}

export async function updateLastSeen(userId: string, deviceId: string): Promise<boolean> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    const getRequest = store.get(compositeKey(userId, deviceId));
    let updated = false;

    getRequest.onerror = () => reject(getRequest.error);
    getRequest.onsuccess = () => {
      const result = getRequest.result as SerializedTofuEntry | undefined;
      if (!result) {
        return;
      }
      updated = true;
      result.lastSeenAt = Date.now();
      const putRequest = store.put(result);
      putRequest.onerror = () => reject(putRequest.error);
    };

    tx.oncomplete = () => {
      db.close();
      resolve(updated);
    };
    tx.onerror = () => reject(tx.error);
  });
}

export async function getAllTofuEntries(): Promise<TofuEntry[]> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const store = tx.objectStore(STORE_NAME);
    const request = store.getAll();
    let results: TofuEntry[] = [];

    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      results = (request.result as SerializedTofuEntry[]).map(deserialize);
    };

    tx.oncomplete = () => {
      db.close();
      resolve(results);
    };
    tx.onerror = () => reject(tx.error);
  });
}

export async function importTofuEntries(entries: TofuEntry[]): Promise<void> {
  if (entries.length === 0) return;

  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);

    for (const entry of entries) {
      const request = store.put(serialize(entry));
      request.onerror = () => reject(request.error);
    }

    tx.oncomplete = () => {
      db.close();
      resolve();
    };
    tx.onerror = () => reject(tx.error);
  });
}
