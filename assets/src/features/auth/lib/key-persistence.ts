import {
  generateDsk,
  loadDsk,
  storeWrappedUmk,
  loadWrappedUmk,
  storeWrappedDeviceKeys,
  loadWrappedDeviceKeys,
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

const SESSION_UMK_KEY = "refmd-session-umk";
const DEVICE_ID_KEY = "refmd-device-id";

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
  pdk: Uint8Array;
  kmsi: boolean;
}

export async function persistKeys(params: PersistKeysParams): Promise<void> {
  const { umk, deviceEcdhPrivate, deviceSigningPrivate, pdk, kmsi } = params;

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
      await storeWrappedUmk(dsk, umk);
    }
    await storeWrappedDeviceKeys(dsk, deviceEcdhPrivate, deviceSigningPrivate);
  } else {
    // DSK unavailable: PDK fallback (localStorage + XChaCha20-Poly1305)
    if (kmsi) {
      storePdkWrappedUmk(pdk, umk);
    }
    storePdkWrappedDeviceKeys(pdk, deviceEcdhPrivate, deviceSigningPrivate);
  }

  // Non-KMSI: store plain UMK in sessionStorage (tab-scoped, lost on browser close)
  if (!kmsi) {
    sessionStorage.setItem(SESSION_UMK_KEY, base64UrlEncode(umk));
  }
}

// ── UMK-only persistence (login) ──────────────

export async function persistUmkForLogin(params: {
  umk: Uint8Array;
  pdk: Uint8Array;
  kmsi: boolean;
}): Promise<void> {
  const { umk, pdk, kmsi } = params;

  const dsk = await loadDsk();

  if (dsk) {
    if (kmsi) {
      await storeWrappedUmk(dsk, umk);
    }
  } else {
    if (kmsi) {
      storePdkWrappedUmk(pdk, umk);
    }
  }

  if (!kmsi) {
    sessionStorage.setItem(SESSION_UMK_KEY, base64UrlEncode(umk));
  }
}

// ── Key restoration ───────────────────────────

export interface RestoredKeys {
  umk: Uint8Array;
  deviceEcdhPrivate: Uint8Array;
  deviceSigningPrivate: Uint8Array;
}

export async function restoreKeysFromDsk(): Promise<RestoredKeys | null> {
  const dsk = await loadDsk();
  if (!dsk) return null;

  const umk = await loadWrappedUmk(dsk);
  const deviceKeys = await loadWrappedDeviceKeys(dsk);

  if (!umk || !deviceKeys) return null;

  return {
    umk,
    deviceEcdhPrivate: deviceKeys.ecdhPrivate,
    deviceSigningPrivate: deviceKeys.signingPrivate,
  };
}

export async function restoreDeviceKeysFromDsk(): Promise<{
  ecdhPrivate: Uint8Array;
  signingPrivate: Uint8Array;
} | null> {
  const dsk = await loadDsk();
  if (!dsk) return null;
  return loadWrappedDeviceKeys(dsk);
}

export function restoreKeysFromPdk(
  pdk: Uint8Array,
): RestoredKeys | null {
  const umk = loadPdkWrappedUmk(pdk);
  const deviceKeys = loadPdkWrappedDeviceKeys(pdk);

  if (!umk || !deviceKeys) return null;

  return {
    umk,
    deviceEcdhPrivate: deviceKeys.ecdhPrivate,
    deviceSigningPrivate: deviceKeys.signingPrivate,
  };
}

export function restoreDeviceKeysFromPdk(pdk: Uint8Array): {
  ecdhPrivate: Uint8Array;
  signingPrivate: Uint8Array;
} | null {
  return loadPdkWrappedDeviceKeys(pdk);
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
  return localStorage.getItem("refmd-pdk-umk") !== null;
}

export function clearSessionUmk(): void {
  sessionStorage.removeItem(SESSION_UMK_KEY);
}

export async function clearAllPersistedKeys(): Promise<void> {
  await clearWrappedKeys();
  clearPdkWrappedKeys();
  clearSessionUmk();
  localStorage.removeItem(DEVICE_ID_KEY);
}
