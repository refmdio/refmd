const DB_NAME = "refmd-keys";
const DB_VERSION = 1;
const STORE_NAME = "keystore";

const DSK_KEY = "dsk";
const WRAPPED_UMK_KEY = "wrapped-umk";
const WRAPPED_DEVICE_ECDH_KEY = "wrapped-device-ecdh";
const WRAPPED_DEVICE_SIGNING_KEY = "wrapped-device-signing";

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function idbGet<T>(db: IDBDatabase, key: string): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const store = tx.objectStore(STORE_NAME);
    const req = store.get(key);
    req.onsuccess = () => resolve(req.result as T | undefined);
    req.onerror = () => reject(req.error);
  });
}

function idbPut(db: IDBDatabase, key: string, value: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    const req = store.put(value, key);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

function idbDelete(db: IDBDatabase, key: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);
    const req = store.delete(key);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

interface WrappedBlob {
  ciphertext: ArrayBuffer;
  iv: ArrayBuffer;
}

export async function storeDsk(dsk: CryptoKey): Promise<void> {
  const db = await openDB();
  await idbPut(db, DSK_KEY, dsk);
  db.close();
}

export async function loadDsk(): Promise<CryptoKey | null> {
  try {
    const db = await openDB();
    const dsk = await idbGet<CryptoKey>(db, DSK_KEY);
    db.close();
    return dsk ?? null;
  } catch {
    return null;
  }
}

// ── Raw data reading for Crypto Worker initialization ──────
// These functions read wrapped blobs WITHOUT unwrapping.
// The CryptoKey (DSK) and wrapped blobs are sent to the Worker,
// which performs the unwrapping internally.

export interface DskInitData {
  dsk: CryptoKey;
  wrappedUmk: WrappedBlob | null;
  wrappedDeviceEcdh: WrappedBlob | null;
  wrappedDeviceSigning: WrappedBlob | null;
}

export async function loadDskInitData(): Promise<DskInitData | null> {
  try {
    const db = await openDB();
    const dsk = await idbGet<CryptoKey>(db, DSK_KEY);
    if (!dsk) {
      db.close();
      return null;
    }
    const wrappedUmk = (await idbGet<WrappedBlob>(db, WRAPPED_UMK_KEY)) ?? null;
    const wrappedDeviceEcdh = (await idbGet<WrappedBlob>(db, WRAPPED_DEVICE_ECDH_KEY)) ?? null;
    const wrappedDeviceSigning =
      (await idbGet<WrappedBlob>(db, WRAPPED_DEVICE_SIGNING_KEY)) ?? null;
    db.close();
    return { dsk, wrappedUmk, wrappedDeviceEcdh, wrappedDeviceSigning };
  } catch {
    return null;
  }
}

// ── Pre-wrapped storage (Worker already wrapped with DSK) ────
// Used when the Worker holds keys and wraps them before sending
// the ciphertext to the main thread for IndexedDB persistence.

export async function storeWrappedUmkRaw(wrapped: {
  ciphertext: ArrayBuffer;
  iv: ArrayBuffer;
}): Promise<void> {
  const db = await openDB();
  await idbPut(db, WRAPPED_UMK_KEY, wrapped);
  db.close();
}

export async function storeWrappedDeviceKeysRaw(
  wrappedEcdh: { ciphertext: ArrayBuffer; iv: ArrayBuffer },
  wrappedSigning: { ciphertext: ArrayBuffer; iv: ArrayBuffer },
): Promise<void> {
  const db = await openDB();
  await idbPut(db, WRAPPED_DEVICE_ECDH_KEY, wrappedEcdh);
  await idbPut(db, WRAPPED_DEVICE_SIGNING_KEY, wrappedSigning);
  db.close();
}

export async function clearWrappedUmk(): Promise<void> {
  try {
    const db = await openDB();
    await idbDelete(db, WRAPPED_UMK_KEY);
    db.close();
  } catch {
    // Best effort
  }
}

export async function clearWrappedKeys(): Promise<void> {
  try {
    const db = await openDB();
    await idbDelete(db, DSK_KEY);
    await idbDelete(db, WRAPPED_UMK_KEY);
    await idbDelete(db, WRAPPED_DEVICE_ECDH_KEY);
    await idbDelete(db, WRAPPED_DEVICE_SIGNING_KEY);
    db.close();
  } catch {
    // Best effort
  }
}
