import { type Page } from "@playwright/test";

export async function indexedDbKeysFromDb(
  page: Page,
  dbName: string,
  storeName: string,
): Promise<string[]> {
  return page
    .evaluate(
      async ({ targetDbName, targetStoreName }) => {
        return new Promise<string[]>((resolve) => {
          const request = indexedDB.open(targetDbName);
          request.onsuccess = () => {
            const db = request.result;
            if (!db.objectStoreNames.contains(targetStoreName)) {
              db.close();
              resolve([]);
              return;
            }
            const transaction = db.transaction(targetStoreName, "readonly");
            const store = transaction.objectStore(targetStoreName);
            const keysRequest = store.getAllKeys();
            keysRequest.onsuccess = () => {
              db.close();
              resolve(keysRequest.result.map((key) => String(key)));
            };
            keysRequest.onerror = () => {
              db.close();
              resolve([]);
            };
          };
          request.onerror = () => resolve([]);
        });
      },
      { targetDbName: dbName, targetStoreName: storeName },
    )
    .catch(() => []);
}

export async function indexedDbKeys(page: Page, storeName: string): Promise<string[]> {
  return indexedDbKeysFromDb(page, "refmd-offline", storeName);
}

export async function offlineKeyStoreKeys(page: Page, prefix: string): Promise<string[]> {
  const keys = await indexedDbKeysFromDb(page, "refmd-keys", "keystore");
  return keys.filter((key) => key.startsWith(prefix));
}
