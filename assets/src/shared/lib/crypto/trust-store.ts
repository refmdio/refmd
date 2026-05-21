import { idbConditionalPut, idbGet, openIdb, toArrayBuffer } from "@/shared/lib/storage/idb";
import { canonicalizeStrict, type StrictJsonValue } from "./jcs";
import type { HybridSigningPublicKeyMaterial } from "./signature-types";

const DB_NAME = "refmd-trust";
const DB_VERSION = 1;
const STORE_NAME = "tofu-entries";
const TOFU_NAMESPACE_SEPARATOR = "\u0000";
export const DEFAULT_TOFU_NAMESPACE = "default";

export interface TofuEntry {
  userId: string;
  deviceId: string;
  hybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  ecdhPublicKey: Uint8Array;
  firstSeenAt: number;
  lastSeenAt: number;
}

interface SerializedTofuEntry {
  userId: string;
  deviceId: string;
  hybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
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
    hybridSigningPublicKeyMaterial: entry.hybridSigningPublicKeyMaterial,
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
    hybridSigningPublicKeyMaterial: serialized.hybridSigningPublicKeyMaterial,
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
  const serialized = serialize(entry, namespace);
  const wrote = await idbConditionalPut<SerializedTofuEntry>(
    db,
    STORE_NAME,
    compositeKey(serialized.userId, serialized.deviceId),
    serialized,
    (existing) => !existing || sameTofuKeys(existing, serialized),
  );
  if (!wrote) throw new Error("tofu_entry_conflict");
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
  assertNoConflictingImportEntries(entries, namespace);

  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    let failed = false;

    for (const entry of entries) {
      const serialized = serialize(entry, namespace);
      const getRequest = store.get(compositeKey(serialized.userId, serialized.deviceId));
      getRequest.onerror = () => reject(getRequest.error);
      getRequest.onsuccess = () => {
        if (failed) return;
        const existing = getRequest.result as SerializedTofuEntry | undefined;
        if (existing && !sameTofuKeys(existing, serialized)) {
          failed = true;
          tx.abort();
          reject(new Error("tofu_entry_conflict"));
          return;
        }
        const request = store.put(serialized);
        request.onerror = () => reject(request.error);
      };
    }

    tx.oncomplete = () => {
      db.close();
      resolve();
    };
    tx.onerror = () => {
      db.close();
      if (!failed) reject(tx.error);
    };
    tx.onabort = () => {
      db.close();
      if (!failed) reject(tx.error);
    };
  });
}

function assertNoConflictingImportEntries(entries: TofuEntry[], namespace: string): void {
  const seen = new Map<string, SerializedTofuEntry>();
  for (const entry of entries) {
    const serialized = serialize(entry, namespace);
    const key = `${serialized.userId}${TOFU_NAMESPACE_SEPARATOR}${serialized.deviceId}`;
    const existing = seen.get(key);
    if (existing && !sameTofuKeys(existing, serialized)) {
      throw new Error("tofu_entry_conflict");
    }
    seen.set(key, serialized);
  }
}

function sameTofuKeys(left: SerializedTofuEntry, right: SerializedTofuEntry): boolean {
  return (
    canonicalizeStrict(left.hybridSigningPublicKeyMaterial as unknown as StrictJsonValue) ===
      canonicalizeStrict(right.hybridSigningPublicKeyMaterial as unknown as StrictJsonValue) &&
    sameArrayBuffer(left.ecdhPublicKey, right.ecdhPublicKey)
  );
}

function sameArrayBuffer(left: ArrayBuffer, right: ArrayBuffer): boolean {
  if (left.byteLength !== right.byteLength) return false;
  const leftBytes = new Uint8Array(left);
  const rightBytes = new Uint8Array(right);
  return leftBytes.every((byte, index) => byte === rightBytes[index]);
}
