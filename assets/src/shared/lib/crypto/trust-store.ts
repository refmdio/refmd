import { idbGet, idbPut, openIdb, toArrayBuffer } from "@/shared/lib/storage/idb";

const DB_NAME = "refmd-trust";
const DB_VERSION = 1;
const STORE_NAME = "tofu-entries";
const TOFU_NAMESPACE_SEPARATOR = "\u0000";
export const DEFAULT_TOFU_NAMESPACE = "default";

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

function qualifyUserId(namespace: string, userId: string): string {
  if (namespace === DEFAULT_TOFU_NAMESPACE) {
    return userId;
  }

  return `${namespace}${TOFU_NAMESPACE_SEPARATOR}${userId}`;
}

function parseQualifiedUserId(qualifiedUserId: string): {
  namespace: string;
  userId: string;
} {
  const separatorIndex = qualifiedUserId.indexOf(TOFU_NAMESPACE_SEPARATOR);
  if (separatorIndex < 0) {
    return {
      namespace: DEFAULT_TOFU_NAMESPACE,
      userId: qualifiedUserId,
    };
  }

  return {
    namespace: qualifiedUserId.slice(0, separatorIndex),
    userId: qualifiedUserId.slice(separatorIndex + TOFU_NAMESPACE_SEPARATOR.length),
  };
}

function compositeKey(userId: string, deviceId: string): [string, string] {
  return [userId, deviceId];
}

function serialize(entry: TofuEntry, namespace: string): SerializedTofuEntry {
  return {
    userId: qualifyUserId(namespace, entry.userId),
    deviceId: entry.deviceId,
    signingPublicKey: toArrayBuffer(entry.signingPublicKey),
    ecdhPublicKey: toArrayBuffer(entry.ecdhPublicKey),
    firstSeenAt: entry.firstSeenAt,
    lastSeenAt: entry.lastSeenAt,
  };
}

function deserialize(serialized: SerializedTofuEntry): TofuEntry {
  const { userId } = parseQualifiedUserId(serialized.userId);
  return {
    userId,
    deviceId: serialized.deviceId,
    signingPublicKey: new Uint8Array(serialized.signingPublicKey),
    ecdhPublicKey: new Uint8Array(serialized.ecdhPublicKey),
    firstSeenAt: serialized.firstSeenAt,
    lastSeenAt: serialized.lastSeenAt,
  };
}

export async function saveTofuEntry(
  entry: TofuEntry,
  namespace = DEFAULT_TOFU_NAMESPACE,
): Promise<void> {
  const db = await openDb();
  await idbPut(db, STORE_NAME, serialize(entry, namespace));
}

export async function getTofuEntry(
  userId: string,
  deviceId: string,
  namespace = DEFAULT_TOFU_NAMESPACE,
): Promise<TofuEntry | null> {
  const db = await openDb();
  const result = await idbGet<SerializedTofuEntry>(
    db,
    STORE_NAME,
    compositeKey(qualifyUserId(namespace, userId), deviceId),
  );
  return result ? deserialize(result) : null;
}

export async function updateLastSeen(
  userId: string,
  deviceId: string,
  namespace = DEFAULT_TOFU_NAMESPACE,
): Promise<boolean> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    const getRequest = store.get(compositeKey(qualifyUserId(namespace, userId), deviceId));
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

export async function getAllTofuEntries(namespace = DEFAULT_TOFU_NAMESPACE): Promise<TofuEntry[]> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const store = tx.objectStore(STORE_NAME);
    const request = store.getAll();
    let results: TofuEntry[] = [];

    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      results = (request.result as SerializedTofuEntry[])
        .filter((entry) => parseQualifiedUserId(entry.userId).namespace === namespace)
        .map(deserialize);
    };

    tx.oncomplete = () => {
      db.close();
      resolve(results);
    };
    tx.onerror = () => reject(tx.error);
  });
}

export async function importTofuEntries(
  entries: TofuEntry[],
  namespace = DEFAULT_TOFU_NAMESPACE,
): Promise<void> {
  if (entries.length === 0) return;

  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);

    for (const entry of entries) {
      const request = store.put(serialize(entry, namespace));
      request.onerror = () => reject(request.error);
    }

    tx.oncomplete = () => {
      db.close();
      resolve();
    };
    tx.onerror = () => reject(tx.error);
  });
}
