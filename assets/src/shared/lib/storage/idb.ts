export function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

export function openIdb(
  name: string,
  version: number,
  onUpgrade: (db: IDBDatabase, oldVersion: number) => void,
  timeoutMs = 30_000,
): Promise<IDBDatabase> {
  if (typeof indexedDB === "undefined") {
    return Promise.reject(new Error("IndexedDB is not available in this environment"));
  }
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`IndexedDB open "${name}" timed out`));
    }, timeoutMs);
    const request = indexedDB.open(name, version);
    request.onerror = () => {
      clearTimeout(timer);
      reject(request.error);
    };
    request.onsuccess = () => {
      clearTimeout(timer);
      const db = request.result;
      db.onversionchange = () => db.close();
      resolve(db);
    };
    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      onUpgrade(db, event.oldVersion);
    };
    request.onblocked = () => {
      clearTimeout(timer);
      reject(new Error(`IndexedDB open "${name}" blocked`));
    };
  });
}

export function idbGet<T>(
  db: IDBDatabase,
  storeName: string,
  key: IDBValidKey,
): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readonly");
    const store = tx.objectStore(storeName);
    const request = store.get(key);
    request.onerror = () => reject(request.error);
    tx.oncomplete = () => {
      resolve(request.result as T | undefined);
      db.close();
    };
    tx.onerror = () => reject(tx.error);
  });
}

export function idbPut(
  db: IDBDatabase,
  storeName: string,
  value: unknown,
  key?: IDBValidKey,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readwrite");
    const store = tx.objectStore(storeName);
    const request = key !== undefined ? store.put(value, key) : store.put(value);
    request.onerror = () => reject(request.error);
    tx.oncomplete = () => {
      resolve();
      db.close();
    };
    tx.onerror = () => reject(tx.error);
  });
}

export function idbDelete(db: IDBDatabase, storeName: string, key: IDBValidKey): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readwrite");
    const store = tx.objectStore(storeName);
    const request = store.delete(key);
    request.onerror = () => reject(request.error);
    tx.oncomplete = () => {
      resolve();
      db.close();
    };
    tx.onerror = () => reject(tx.error);
  });
}

export function idbConditionalPut<T>(
  db: IDBDatabase,
  storeName: string,
  key: IDBValidKey,
  value: T,
  shouldWrite: (existing: T | undefined) => boolean,
): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readwrite");
    const store = tx.objectStore(storeName);
    const getRequest = store.get(key);

    let wrote = false;

    getRequest.onerror = () => reject(getRequest.error);
    getRequest.onsuccess = () => {
      const existing = getRequest.result as T | undefined;
      if (!shouldWrite(existing)) {
        return;
      }

      wrote = true;
      const putRequest = store.keyPath === null ? store.put(value, key) : store.put(value);
      putRequest.onerror = () => reject(putRequest.error);
    };

    tx.oncomplete = () => {
      resolve(wrote);
      db.close();
    };
    tx.onerror = () => reject(tx.error);
  });
}
