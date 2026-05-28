import { type Page } from "@playwright/test";

type PluginLocalStateSnapshot = {
  databaseApiUnavailable: boolean;
  dbNames: string[];
  errors: string[];
  pluginKeys: string[];
  targetDbNames: string[];
};

export async function pluginLocalStatePresence(page: Page): Promise<{
  cache: boolean;
  credential: boolean;
  databaseApiUnavailable: boolean;
  userLocal: boolean;
}> {
  const snapshot = await pluginLocalStateSnapshot(page);
  return {
    cache: snapshot.pluginKeys.some((key) => key.startsWith("refmd-plugin-cache:")),
    credential: snapshot.pluginKeys.some((key) => key.startsWith("refmd-plugin-credential:")),
    databaseApiUnavailable: snapshot.databaseApiUnavailable,
    userLocal: snapshot.pluginKeys.some((key) => key.startsWith("refmd-plugin-user-local:")),
  };
}

export async function pluginLocalStateSnapshot(page: Page): Promise<PluginLocalStateSnapshot> {
  await page.waitForLoadState("domcontentloaded").catch(() => undefined);
  return page.evaluate(async () => {
    const targetDbNames = new Set([
      "refmd-keys",
      "refmd-trust",
      "refmd-offline",
      "refmd-security",
      "refmd-share-sessions",
    ]);
    const pluginPrefixes = [
      "refmd-plugin-user-local:",
      "refmd-plugin-cache:",
      "refmd-plugin-credential:",
      "refmd-plugin-audit-local:",
    ];

    if (typeof indexedDB.databases !== "function") {
      return {
        databaseApiUnavailable: true,
        dbNames: [],
        errors: ["indexedDB.databases unavailable"],
        pluginKeys: [],
        targetDbNames: [],
      };
    }

    const databaseInfos = await indexedDB.databases();
    const dbNames = databaseInfos
      .map((database) => database.name)
      .filter((name): name is string => typeof name === "string" && name.length > 0)
      .sort();
    const pluginKeys: string[] = [];
    const errors: string[] = [];

    async function openExistingDatabase(name: string): Promise<IDBDatabase | null> {
      return new Promise((resolve) => {
        try {
          const request = indexedDB.open(name);
          request.onsuccess = () => resolve(request.result);
          request.onerror = () => resolve(null);
          request.onblocked = () => resolve(null);
        } catch {
          resolve(null);
        }
      });
    }

    async function scanStoreKeys(db: IDBDatabase, storeName: string): Promise<void> {
      await new Promise<void>((resolve) => {
        try {
          const tx = db.transaction(storeName, "readonly");
          const store = tx.objectStore(storeName);
          const request = store.openKeyCursor();
          request.onsuccess = () => {
            const cursor = request.result;
            if (!cursor) return;
            if (
              typeof cursor.key === "string" &&
              pluginPrefixes.some((prefix) => cursor.key.startsWith(prefix))
            ) {
              pluginKeys.push(cursor.key);
            }
            cursor.continue();
          };
          request.onerror = () => {
            errors.push(`${db.name}:${storeName}:cursor_error`);
          };
          tx.oncomplete = () => resolve();
          tx.onerror = () => {
            errors.push(`${db.name}:${storeName}:transaction_error`);
            resolve();
          };
          tx.onabort = () => {
            errors.push(`${db.name}:${storeName}:transaction_aborted`);
            resolve();
          };
        } catch {
          errors.push(`${db.name}:${storeName}:scan_failed`);
          resolve();
        }
      });
    }

    for (const dbName of dbNames) {
      const db = await openExistingDatabase(dbName);
      if (!db) {
        errors.push(`${dbName}:open_failed`);
        continue;
      }
      try {
        for (const storeName of Array.from(db.objectStoreNames)) {
          await scanStoreKeys(db, storeName);
        }
      } finally {
        db.close();
      }
    }

    return {
      databaseApiUnavailable: false,
      dbNames,
      errors,
      pluginKeys: pluginKeys.sort(),
      targetDbNames: dbNames.filter((name) => targetDbNames.has(name)),
    };
  }).catch(async (error) => {
    const message = String(error);
    if (!isTransientPageEvaluationError(message)) throw error;
    await page.waitForLoadState("domcontentloaded").catch(() => undefined);
    return {
      databaseApiUnavailable: false,
      dbNames: [],
      errors: ["page navigation in progress"],
      pluginKeys: [],
      targetDbNames: [],
    };
  });
}

function isTransientPageEvaluationError(message: string): boolean {
  return (
    message.includes("Execution context was destroyed") ||
    message.includes("most likely because of a navigation") ||
    message.includes("Cannot find context with specified id")
  );
}
