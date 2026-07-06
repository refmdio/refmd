import { openIdb } from "@/shared/lib/storage/idb";

const SECURITY_DB_NAME = "refmd-security";
const SECURITY_DB_VERSION = 1;

export const DOCUMENT_STATE_PIN_STORE_NAME = "document-state-pins";
export const KEY_DIRECTORY_PIN_STORE_NAME = "key-directory-pins";
export const KEY_DIRECTORY_VERIFIED_LINEAGE_STORE_NAME = "key-directory-verified-lineages";

export function openSecurityDb(): Promise<IDBDatabase> {
  return openIdb(SECURITY_DB_NAME, SECURITY_DB_VERSION, (db) => {
    if (!db.objectStoreNames.contains(DOCUMENT_STATE_PIN_STORE_NAME)) {
      db.createObjectStore(DOCUMENT_STATE_PIN_STORE_NAME, { keyPath: "documentId" });
    }
    if (!db.objectStoreNames.contains(KEY_DIRECTORY_PIN_STORE_NAME)) {
      db.createObjectStore(KEY_DIRECTORY_PIN_STORE_NAME, { keyPath: "pinKey" });
    }
    if (!db.objectStoreNames.contains(KEY_DIRECTORY_VERIFIED_LINEAGE_STORE_NAME)) {
      db.createObjectStore(KEY_DIRECTORY_VERIFIED_LINEAGE_STORE_NAME, { keyPath: "key" });
    }
  });
}
