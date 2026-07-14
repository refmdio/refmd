import { openIdb } from "@/shared/lib/storage/idb";

const DB_NAME = "refmd-keys";
const DB_VERSION = 1;
const STORE_NAME = "keystore";
const DSK_KEY = "dsk";
const WRAPPED_UMK_KEY = "wrapped-umk";
const WRAPPED_DEVICE_ECDH_KEY = "wrapped-device-ecdh";
const WRAPPED_DEVICE_MLKEM_KEY = "wrapped-device-mlkem768-material";
const WRAPPED_DEVICE_SIGNING_KEY = "wrapped-device-hybrid-signing";
export const SHARE_PARTICIPANT_DEVICE_KEY_PREFIX = "wrapped-share-participant-device";

interface WrappedBlob {
  ciphertext: ArrayBuffer;
  iv: ArrayBuffer;
}

export interface StoredDskInitData {
  dsk: CryptoKey;
  wrappedUmk: WrappedBlob | null;
  wrappedDeviceEcdh: WrappedBlob | null;
  wrappedDeviceMlkem: WrappedBlob | null;
  wrappedDeviceSigning: (WrappedBlob & { signingKeyId: string }) | null;
}

function openDskDb(timeoutMs = 5000): Promise<IDBDatabase> {
  return openIdb(
    DB_NAME,
    DB_VERSION,
    (db) => {
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    },
    timeoutMs,
  );
}

function idbGet<T>(db: IDBDatabase, key: string): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const store = tx.objectStore(STORE_NAME);
    const request = store.get(key);
    request.onerror = () => reject(request.error);
    tx.oncomplete = () => resolve(request.result as T | undefined);
    tx.onerror = () => reject(tx.error);
  });
}

function idbPut(db: IDBDatabase, key: string, value: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    const request = store.put(value, key);
    request.onerror = () => reject(request.error);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function idbDelete(db: IDBDatabase, key: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    const request = store.delete(key);
    request.onerror = () => reject(request.error);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

function idbDeleteByPrefix(db: IDBDatabase, prefix: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    const request = store.openKeyCursor();
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const cursor = request.result;
      if (!cursor) return;
      if (typeof cursor.key === "string" && cursor.key.startsWith(prefix)) {
        store.delete(cursor.key);
      }
      cursor.continue();
    };
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function storeDskInWorker(dsk: CryptoKey): Promise<void> {
  const db = await openDskDb();
  try {
    await idbPut(db, DSK_KEY, dsk);
  } finally {
    db.close();
  }
}

export async function hasStoredDskInWorker(): Promise<boolean> {
  try {
    const db = await openDskDb();
    try {
      return Boolean(await idbGet<CryptoKey>(db, DSK_KEY));
    } finally {
      db.close();
    }
  } catch {
    return false;
  }
}

export async function hasStoredDeviceKeysInWorker(): Promise<boolean> {
  try {
    const db = await openDskDb();
    try {
      const dsk = await idbGet<CryptoKey>(db, DSK_KEY);
      const wrappedDeviceEcdh = await idbGet<WrappedBlob>(db, WRAPPED_DEVICE_ECDH_KEY);
      const wrappedDeviceMlkem = await idbGet<WrappedBlob>(db, WRAPPED_DEVICE_MLKEM_KEY);
      const wrappedDeviceSigning = await idbGet<WrappedBlob & { signingKeyId: string }>(
        db,
        WRAPPED_DEVICE_SIGNING_KEY,
      );
      return Boolean(dsk && wrappedDeviceEcdh && wrappedDeviceMlkem && wrappedDeviceSigning);
    } finally {
      db.close();
    }
  } catch {
    return false;
  }
}

export async function loadStoredDskInitDataInWorker(): Promise<StoredDskInitData | null> {
  try {
    const db = await openDskDb();
    try {
      const dsk = await idbGet<CryptoKey>(db, DSK_KEY);
      if (!dsk) return null;
      const wrappedUmk = (await idbGet<WrappedBlob>(db, WRAPPED_UMK_KEY)) ?? null;
      const wrappedDeviceEcdh = (await idbGet<WrappedBlob>(db, WRAPPED_DEVICE_ECDH_KEY)) ?? null;
      const wrappedDeviceMlkem = (await idbGet<WrappedBlob>(db, WRAPPED_DEVICE_MLKEM_KEY)) ?? null;
      const wrappedDeviceSigning =
        (await idbGet<WrappedBlob & { signingKeyId: string }>(db, WRAPPED_DEVICE_SIGNING_KEY)) ??
        null;
      return { dsk, wrappedUmk, wrappedDeviceEcdh, wrappedDeviceMlkem, wrappedDeviceSigning };
    } finally {
      db.close();
    }
  } catch {
    return null;
  }
}

export async function loadDskStoreValueInWorker<T>(key: string): Promise<T | null> {
  try {
    const db = await openDskDb();
    try {
      return (await idbGet<T>(db, key)) ?? null;
    } finally {
      db.close();
    }
  } catch {
    return null;
  }
}

export async function loadDskStoreValueStrictInWorker<T>(key: string): Promise<T | null> {
  const db = await openDskDb();
  try {
    return (await idbGet<T>(db, key)) ?? null;
  } finally {
    db.close();
  }
}

export async function storeDskStoreValueInWorker(key: string, value: unknown): Promise<void> {
  const db = await openDskDb();
  try {
    await idbPut(db, key, value);
  } finally {
    db.close();
  }
}

export async function deleteDskStoreValueInWorker(key: string): Promise<void> {
  const db = await openDskDb();
  try {
    await idbDelete(db, key);
  } finally {
    db.close();
  }
}

export async function deleteDskStoreValuesByPrefixInWorker(prefix: string): Promise<void> {
  const db = await openDskDb();
  try {
    await idbDeleteByPrefix(db, prefix);
  } finally {
    db.close();
  }
}

function shareParticipantDeviceKey(
  shareId: string,
  shareParticipantDeviceId: string,
  kind: "ecdh" | "mlkem768" | "hybrid-signing",
): string {
  return [SHARE_PARTICIPANT_DEVICE_KEY_PREFIX, shareId, shareParticipantDeviceId, kind].join(":");
}

export async function storeShareParticipantDeviceKeysInWorker(
  shareId: string,
  shareParticipantDeviceId: string,
  wrapped: {
    wrappedEcdh: unknown;
    wrappedMlkem: unknown;
    wrappedSigning: unknown;
  },
): Promise<void> {
  const db = await openDskDb();
  try {
    await idbPut(
      db,
      shareParticipantDeviceKey(shareId, shareParticipantDeviceId, "ecdh"),
      wrapped.wrappedEcdh,
    );
    await idbPut(
      db,
      shareParticipantDeviceKey(shareId, shareParticipantDeviceId, "mlkem768"),
      wrapped.wrappedMlkem,
    );
    await idbPut(
      db,
      shareParticipantDeviceKey(shareId, shareParticipantDeviceId, "hybrid-signing"),
      wrapped.wrappedSigning,
    );
  } finally {
    db.close();
  }
}

export async function loadShareParticipantDeviceKeysInWorker(
  shareId: string,
  shareParticipantDeviceId: string,
): Promise<{
  wrappedEcdh: unknown;
  wrappedMlkem: unknown;
  wrappedSigning: unknown;
} | null> {
  const db = await openDskDb();
  try {
    const wrappedEcdh = await idbGet(
      db,
      shareParticipantDeviceKey(shareId, shareParticipantDeviceId, "ecdh"),
    );
    const wrappedMlkem = await idbGet(
      db,
      shareParticipantDeviceKey(shareId, shareParticipantDeviceId, "mlkem768"),
    );
    const wrappedSigning = await idbGet(
      db,
      shareParticipantDeviceKey(shareId, shareParticipantDeviceId, "hybrid-signing"),
    );
    if (!wrappedEcdh || !wrappedMlkem || !wrappedSigning) return null;
    return { wrappedEcdh, wrappedMlkem, wrappedSigning };
  } finally {
    db.close();
  }
}
