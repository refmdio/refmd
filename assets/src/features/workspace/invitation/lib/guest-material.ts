import type { components } from "@/shared/api";
import { buildGuestInviteRedeemMaterialAad } from "@/shared/lib/crypto/aad";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { deleteDskSecret, loadDsk, loadDskSecret, storeDskSecret } from "@/shared/lib/crypto/dsk";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

type RedeemBody = components["schemas"]["RedeemGuestInvitationRequest"];

interface WrappedBlob {
  ciphertext: string;
  iv: string;
}

export interface GuestRedeemMaterial {
  body: Omit<RedeemBody, "token">;
  publicKeys: {
    identitySigningPublic: string;
    identityEcdhPublic: string;
    deviceSigningPublic: string;
    deviceEcdhPublic: string;
  };
  wrappedKeys?: {
    umk: WrappedBlob;
    deviceEcdh: WrappedBlob;
    deviceSigning: WrappedBlob;
  };
}

const STORAGE_PREFIX = "refmd-guest-redeem:";

export function serializeWrappedBlob(wrapped: {
  ciphertext: ArrayBuffer;
  iv: ArrayBuffer;
}): WrappedBlob {
  return {
    ciphertext: base64UrlEncode(new Uint8Array(wrapped.ciphertext)),
    iv: base64UrlEncode(new Uint8Array(wrapped.iv)),
  };
}

export function deserializeWrappedBlob(wrapped: WrappedBlob): {
  ciphertext: ArrayBuffer;
  iv: ArrayBuffer;
} {
  const decode = (value: string) => {
    const bytes = base64UrlDecode(value);
    return new Uint8Array(bytes).buffer;
  };

  return {
    ciphertext: decode(wrapped.ciphertext),
    iv: decode(wrapped.iv),
  };
}

function encodeWrapped(wrapped: { ciphertext: ArrayBuffer; iv: ArrayBuffer }): string {
  return JSON.stringify({
    ciphertext: Array.from(new Uint8Array(wrapped.ciphertext)),
    iv: Array.from(new Uint8Array(wrapped.iv)),
  });
}

function decodeWrapped(raw: string): { ciphertext: ArrayBuffer; iv: ArrayBuffer } {
  const parsed = JSON.parse(raw) as { ciphertext: number[]; iv: number[] };
  return {
    ciphertext: new Uint8Array(parsed.ciphertext).buffer,
    iv: new Uint8Array(parsed.iv).buffer,
  };
}

async function tokenStorageKey(token: string): Promise<string> {
  const worker = getCryptoWorker();
  const tokenHash = await worker.sha256Hash(base64UrlDecode(token));
  return `${STORAGE_PREFIX}${tokenHash}`;
}

export async function hasGuestRedeemMaterial(token: string): Promise<boolean> {
  const key = await tokenStorageKey(token);
  return (await loadDskSecret<string>(key)) !== null;
}

export async function readGuestRedeemMaterial(token: string): Promise<GuestRedeemMaterial | null> {
  const dsk = await loadDsk();
  if (!dsk) return null;

  const key = await tokenStorageKey(token);
  const raw = await loadDskSecret<string>(key);
  if (!raw) return null;

  const worker = getCryptoWorker();
  await worker.setDsk(dsk);
  try {
    const plaintext = await worker.unwrapWithDsk({
      ...decodeWrapped(raw),
      aad: buildGuestInviteRedeemMaterialAad(key),
    });
    return JSON.parse(new TextDecoder().decode(plaintext)) as GuestRedeemMaterial;
  } catch {
    await deleteDskSecret(key);
    return null;
  }
}

export async function rememberGuestRedeemMaterial(
  token: string,
  material: GuestRedeemMaterial,
): Promise<void> {
  try {
    const dsk = await loadDsk();
    if (!dsk) return;

    const key = await tokenStorageKey(token);
    const worker = getCryptoWorker();
    await worker.setDsk(dsk);
    const wrapped = await worker.wrapWithDsk({
      plaintext: new TextEncoder().encode(JSON.stringify(material)),
      aad: buildGuestInviteRedeemMaterialAad(key),
    });
    await storeDskSecret(key, encodeWrapped(wrapped));
  } catch {
    // Re-entry optimization only; the active session is already established.
  }
}
