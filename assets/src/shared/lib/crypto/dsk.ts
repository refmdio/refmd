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

export async function generateDsk(): Promise<CryptoKey> {
  const dsk = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  const db = await openDB();
  await idbPut(db, DSK_KEY, dsk);
  db.close();
  return dsk;
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

async function wrapWithDsk(dsk: CryptoKey, plaintext: Uint8Array): Promise<WrappedBlob> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    dsk,
    new Uint8Array(plaintext),
  );
  return { ciphertext, iv: iv.buffer };
}

async function unwrapWithDsk(dsk: CryptoKey, blob: WrappedBlob): Promise<Uint8Array> {
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: blob.iv },
    dsk,
    blob.ciphertext,
  );
  return new Uint8Array(plaintext);
}

export async function storeWrappedUmk(dsk: CryptoKey, umk: Uint8Array): Promise<void> {
  const wrapped = await wrapWithDsk(dsk, umk);
  const db = await openDB();
  await idbPut(db, WRAPPED_UMK_KEY, wrapped);
  db.close();
}

export async function loadWrappedUmk(dsk: CryptoKey): Promise<Uint8Array | null> {
  try {
    const db = await openDB();
    const blob = await idbGet<WrappedBlob>(db, WRAPPED_UMK_KEY);
    db.close();
    if (!blob) return null;
    return await unwrapWithDsk(dsk, blob);
  } catch {
    return null;
  }
}

export async function storeWrappedDeviceKeys(
  dsk: CryptoKey,
  ecdhPrivate: Uint8Array,
  signingPrivate: Uint8Array,
): Promise<void> {
  const wrappedEcdh = await wrapWithDsk(dsk, ecdhPrivate);
  const wrappedSigning = await wrapWithDsk(dsk, signingPrivate);
  const db = await openDB();
  await idbPut(db, WRAPPED_DEVICE_ECDH_KEY, wrappedEcdh);
  await idbPut(db, WRAPPED_DEVICE_SIGNING_KEY, wrappedSigning);
  db.close();
}

export async function loadWrappedDeviceKeys(
  dsk: CryptoKey,
): Promise<{ ecdhPrivate: Uint8Array; signingPrivate: Uint8Array } | null> {
  try {
    const db = await openDB();
    const ecdhBlob = await idbGet<WrappedBlob>(db, WRAPPED_DEVICE_ECDH_KEY);
    const signingBlob = await idbGet<WrappedBlob>(db, WRAPPED_DEVICE_SIGNING_KEY);
    db.close();
    if (!ecdhBlob || !signingBlob) return null;
    const ecdhPrivate = await unwrapWithDsk(dsk, ecdhBlob);
    const signingPrivate = await unwrapWithDsk(dsk, signingBlob);
    return { ecdhPrivate, signingPrivate };
  } catch {
    return null;
  }
}

export async function clearWrappedKeys(): Promise<void> {
  try {
    const db = await openDB();
    await idbDelete(db, WRAPPED_UMK_KEY);
    await idbDelete(db, WRAPPED_DEVICE_ECDH_KEY);
    await idbDelete(db, WRAPPED_DEVICE_SIGNING_KEY);
    db.close();
  } catch {
    // Best effort
  }
}
