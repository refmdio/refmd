import {
  generateDsk,
  loadDsk,
  storeWrappedUmk,
  loadWrappedUmk,
  storeWrappedDeviceKeys,
  loadWrappedDeviceKeys,
  clearWrappedUmk,
  clearWrappedKeys,
} from "@/shared/lib/crypto/dsk";
import {
  storePdkWrappedUmk,
  loadPdkWrappedUmk,
  storePdkWrappedDeviceKeys,
  loadPdkWrappedDeviceKeys,
  clearPdkWrappedKeys,
} from "@/shared/lib/crypto/pdk";
import { base64UrlEncode, base64UrlDecode } from "@/shared/lib/crypto";
import {
  buildDskUmkCacheAad,
  buildDskDeviceEcdhAad,
  buildDskDeviceSigningAad,
} from "@/shared/lib/crypto/aad";
import { clearAllTofuEntries } from "@/shared/lib/trust-store";

const SESSION_UMK_KEY = "refmd-session-umk";
const DEVICE_ID_KEY = "refmd-device-id";

// PDK is kept in-memory only (disposable, never persisted).
let inMemoryPdk: Uint8Array | null = null;

// ── Device ID persistence ─────────────────────

export function persistDeviceId(deviceId: string): void {
  localStorage.setItem(DEVICE_ID_KEY, deviceId);
}

export function getPersistedDeviceId(): string | null {
  return localStorage.getItem(DEVICE_ID_KEY);
}

// ── Full key persistence (registration) ───────

export interface PersistKeysParams {
  umk: Uint8Array;
  deviceEcdhPrivate: Uint8Array;
  deviceSigningPrivate: Uint8Array;
  pdk?: Uint8Array;
  kmsi: boolean;
  userId: string;
}

export async function persistKeys(params: PersistKeysParams): Promise<void> {
  const { umk, deviceEcdhPrivate, deviceSigningPrivate, pdk, kmsi, userId } = params;

  // Try DSK (IndexedDB non-exportable key)
  let dsk = await loadDsk();
  if (!dsk) {
    try {
      dsk = await generateDsk();
    } catch {
      dsk = null;
    }
  }

  if (dsk) {
    // DSK available: wrap UMK and device keys in IndexedDB
    if (kmsi) {
      await storeWrappedUmk(dsk, umk, buildDskUmkCacheAad(userId));
    }
    await storeWrappedDeviceKeys(
      dsk,
      deviceEcdhPrivate,
      deviceSigningPrivate,
      buildDskDeviceEcdhAad(userId),
      buildDskDeviceSigningAad(userId),
    );
  } else if (pdk) {
    // DSK unavailable: PDK fallback (localStorage + XChaCha20-Poly1305)
    // PDK-wrapped UMK is always stored regardless of KMSI (frontend.md: PDK fallback section)
    storePdkWrappedUmk(pdk, umk, userId);
    storePdkWrappedDeviceKeys(pdk, deviceEcdhPrivate, deviceSigningPrivate, userId);
  }

  // Non-KMSI: store plain UMK in sessionStorage (tab-scoped, lost on browser close)
  // Clear DSK-wrapped UMK so session restore doesn't bypass KMSI=false
  // PDK-wrapped UMK is NOT cleared: it requires password re-entry and is independent of KMSI
  if (!kmsi) {
    sessionStorage.setItem(SESSION_UMK_KEY, base64UrlEncode(umk));
    await clearWrappedUmk();
  }
}

// ── UMK-only persistence (login) ──────────────

export async function persistUmkForLogin(params: {
  umk: Uint8Array;
  pdk: Uint8Array | undefined;
  kmsi: boolean;
  userId: string;
}): Promise<void> {
  const { umk, pdk, kmsi, userId } = params;

  const dsk = await loadDsk();

  if (dsk) {
    if (kmsi) {
      await storeWrappedUmk(dsk, umk, buildDskUmkCacheAad(userId));
    }
  } else {
    // PDK-wrapped UMK is always stored regardless of KMSI (frontend.md: PDK fallback section)
    if (!pdk) {
      throw new Error("Cannot persist UMK: DSK unavailable and PDK not provided");
    }
    storePdkWrappedUmk(pdk, umk, userId);
  }

  // Non-KMSI: store plain UMK in sessionStorage (tab-scoped, lost on browser close)
  // Clear DSK-wrapped UMK only; PDK-wrapped UMK is independent of KMSI
  if (!kmsi) {
    sessionStorage.setItem(SESSION_UMK_KEY, base64UrlEncode(umk));
    await clearWrappedUmk();
  }
}

// ── Key restoration ───────────────────────────

export interface RestoredKeys {
  umk: Uint8Array;
  deviceEcdhPrivate: Uint8Array;
  deviceSigningPrivate: Uint8Array;
}

export async function restoreKeysFromDsk(userId: string): Promise<RestoredKeys | null> {
  const dsk = await loadDsk();
  if (!dsk) return null;

  const umk = await loadWrappedUmk(dsk, buildDskUmkCacheAad(userId));
  const deviceKeys = await loadWrappedDeviceKeys(
    dsk,
    buildDskDeviceEcdhAad(userId),
    buildDskDeviceSigningAad(userId),
  );

  if (!umk || !deviceKeys) return null;

  return {
    umk,
    deviceEcdhPrivate: deviceKeys.ecdhPrivate,
    deviceSigningPrivate: deviceKeys.signingPrivate,
  };
}

export async function restoreDeviceKeysFromDsk(userId: string): Promise<{
  ecdhPrivate: Uint8Array;
  signingPrivate: Uint8Array;
} | null> {
  const dsk = await loadDsk();
  if (!dsk) return null;
  return loadWrappedDeviceKeys(
    dsk,
    buildDskDeviceEcdhAad(userId),
    buildDskDeviceSigningAad(userId),
  );
}

export function restoreKeysFromPdk(pdk: Uint8Array, userId: string): RestoredKeys | null {
  const umk = loadPdkWrappedUmk(pdk, userId);
  const deviceKeys = loadPdkWrappedDeviceKeys(pdk, userId);

  if (!umk || !deviceKeys) return null;

  return {
    umk,
    deviceEcdhPrivate: deviceKeys.ecdhPrivate,
    deviceSigningPrivate: deviceKeys.signingPrivate,
  };
}

export function restoreDeviceKeysFromPdk(
  pdk: Uint8Array,
  userId: string,
): {
  ecdhPrivate: Uint8Array;
  signingPrivate: Uint8Array;
} | null {
  return loadPdkWrappedDeviceKeys(pdk, userId);
}

export function restoreUmkFromSession(): Uint8Array | null {
  const raw = sessionStorage.getItem(SESSION_UMK_KEY);
  if (!raw) return null;
  try {
    return base64UrlDecode(raw);
  } catch {
    return null;
  }
}

export function hasPdkData(): boolean {
  return (
    localStorage.getItem("refmd-pdk-umk") !== null &&
    localStorage.getItem("refmd-pdk-device-ecdh") !== null &&
    localStorage.getItem("refmd-pdk-device-signing") !== null
  );
}

export function persistSessionPdk(pdk: Uint8Array): void {
  inMemoryPdk = pdk;
}

export function restoreSessionPdk(): Uint8Array | null {
  return inMemoryPdk;
}

export async function persistDeviceKeysOnly(
  deviceEcdhPrivate: Uint8Array,
  deviceSigningPrivate: Uint8Array,
  userId: string,
  pdk?: Uint8Array,
): Promise<void> {
  let dsk = await loadDsk();
  if (!dsk) {
    try {
      dsk = await generateDsk();
    } catch {
      dsk = null;
    }
  }

  if (dsk) {
    await storeWrappedDeviceKeys(
      dsk,
      deviceEcdhPrivate,
      deviceSigningPrivate,
      buildDskDeviceEcdhAad(userId),
      buildDskDeviceSigningAad(userId),
    );
  } else {
    const pdkToUse = pdk ?? restoreSessionPdk();
    if (pdkToUse) {
      storePdkWrappedDeviceKeys(pdkToUse, deviceEcdhPrivate, deviceSigningPrivate, userId);
    } else {
      throw new Error("Cannot persist device keys: neither DSK nor PDK available");
    }
  }
}

export function clearSessionUmk(): void {
  sessionStorage.removeItem(SESSION_UMK_KEY);
}

export function clearSessionData(): void {
  sessionStorage.clear();
  inMemoryPdk = null;
}

export async function clearAllPersistedKeys(): Promise<void> {
  await clearWrappedKeys();
  clearPdkWrappedKeys();
  clearSessionUmk();
  inMemoryPdk = null;
  localStorage.removeItem(DEVICE_ID_KEY);
  for (const key of Object.keys(localStorage)) {
    if (key.startsWith("refmd_settings")) localStorage.removeItem(key);
  }
  await clearAllTofuEntries().catch(() => {});
}
