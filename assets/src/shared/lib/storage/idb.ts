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

export function idbConditionalPutWithRequiredRecord<T, R>(params: {
  db: IDBDatabase;
  targetStoreName: string;
  targetKey: IDBValidKey;
  targetValue: T;
  requiredStoreName: string;
  requiredKey: IDBValidKey;
  validateRequired: (required: R | undefined) => boolean;
  shouldWrite: (existing: T | undefined) => boolean;
}): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const tx = params.db.transaction(
      [params.targetStoreName, params.requiredStoreName],
      "readwrite",
    );
    const targetStore = tx.objectStore(params.targetStoreName);
    const requiredRequest = tx.objectStore(params.requiredStoreName).get(params.requiredKey);
    let wrote = false;

    requiredRequest.onerror = () => reject(requiredRequest.error);
    requiredRequest.onsuccess = () => {
      if (!params.validateRequired(requiredRequest.result as R | undefined)) {
        tx.abort();
        return;
      }
      const targetRequest = targetStore.get(params.targetKey);
      targetRequest.onerror = () => reject(targetRequest.error);
      targetRequest.onsuccess = () => {
        if (!params.shouldWrite(targetRequest.result as T | undefined)) return;
        wrote = true;
        const putRequest = targetStore.put(params.targetValue);
        putRequest.onerror = () => reject(putRequest.error);
      };
    };

    tx.oncomplete = () => {
      resolve(wrote);
      params.db.close();
    };
    tx.onabort = () => {
      params.db.close();
      reject(new Error("required_record_missing_or_invalid"));
    };
    tx.onerror = () => reject(tx.error);
  });
}

export function idbAtomicConditionalPuts(
  db: IDBDatabase,
  writes: Array<{
    storeName: string;
    key: IDBValidKey;
    value: unknown;
    shouldWrite: (existing: unknown) => boolean;
  }>,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const storeNames = [...new Set(writes.map((write) => write.storeName))];
    const tx = db.transaction(storeNames, "readwrite");
    let conflict = false;

    for (const write of writes) {
      const store = tx.objectStore(write.storeName);
      const request = store.get(write.key);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        if (!write.shouldWrite(request.result)) {
          conflict = true;
          tx.abort();
          return;
        }
        const putRequest =
          store.keyPath === null ? store.put(write.value, write.key) : store.put(write.value);
        putRequest.onerror = () => reject(putRequest.error);
      };
    }

    tx.oncomplete = () => {
      db.close();
      resolve();
    };
    tx.onabort = () => {
      db.close();
      reject(new Error(conflict ? "atomic_pin_merge_conflict" : "atomic_pin_merge_failed"));
    };
    tx.onerror = () => reject(tx.error);
  });
}
