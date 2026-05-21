import type { components } from "@/shared/api";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

type RedeemBody = Omit<
  components["schemas"]["RedeemGuestInvitationRequest"],
  "workspace_key_directory_checkpoint" | "workspace_key_directory_events"
>;

export interface GuestRedeemMaterial {
  body: Omit<RedeemBody, "token">;
  publicKeys: {
    identityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
    identityEcdhPublic: string;
    deviceSigningKeyId: string;
    deviceEncryptionKeyId: string;
    deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
    deviceEcdhPublic: string;
  };
}

const STORAGE_PREFIX = "refmd-guest-redeem:";
const ACTIVE_STORAGE_PREFIX = "refmd-guest-active:";

async function tokenStorageKey(token: string): Promise<string> {
  const worker = getCryptoWorker();
  const lookupToken = token.split(".", 1)[0] ?? token;
  const tokenHash = await worker.sha256Hash(base64UrlDecode(lookupToken));
  return `${STORAGE_PREFIX}${tokenHash}`;
}

function activeStorageKey(userId: string, deviceId: string): string {
  return `${ACTIVE_STORAGE_PREFIX}${userId}:${deviceId}`;
}

export async function hasGuestRedeemMaterial(token: string): Promise<boolean> {
  const key = await tokenStorageKey(token);
  const worker = getCryptoWorker();
  if (!(await worker.loadStoredDsk())) return false;
  return (await worker.loadGuestInvitationMaterialWithDsk(key)) !== null;
}

export async function readGuestRedeemMaterial(token: string): Promise<GuestRedeemMaterial | null> {
  return readGuestRedeemMaterialByKey(await tokenStorageKey(token));
}

export async function readActiveGuestRedeemMaterial(
  userId: string,
  deviceId: string,
): Promise<GuestRedeemMaterial | null> {
  return readGuestRedeemMaterialByKey(activeStorageKey(userId, deviceId));
}

async function readGuestRedeemMaterialByKey(key: string): Promise<GuestRedeemMaterial | null> {
  const worker = getCryptoWorker();
  if (!(await worker.loadStoredDsk())) return null;
  try {
    const plaintext = await worker.loadGuestInvitationMaterialWithDsk(key);
    if (!plaintext) return null;
    const material = JSON.parse(new TextDecoder().decode(plaintext)) as GuestRedeemMaterial & {
      wrappedKeys?: unknown;
    };
    delete material.wrappedKeys;
    return material;
  } catch {
    await worker.deleteGuestInvitationMaterialWithDsk(key);
    return null;
  }
}

export async function rememberGuestRedeemMaterial(
  token: string,
  material: GuestRedeemMaterial,
): Promise<void> {
  await rememberGuestRedeemMaterialByKey(await tokenStorageKey(token), material);
  await rememberGuestRedeemMaterialByKey(
    activeStorageKey(material.body.guest_user_id, material.body.device_id),
    material,
  );
}

async function rememberGuestRedeemMaterialByKey(
  key: string,
  material: GuestRedeemMaterial,
): Promise<void> {
  try {
    const worker = getCryptoWorker();
    if (!(await worker.loadStoredDsk())) return;
    await worker.storeGuestInvitationMaterialWithDsk({
      plaintext: new TextEncoder().encode(JSON.stringify(material)),
      tokenHash: key,
    });
  } catch {
    // Re-entry optimization only; the active session is already established.
  }
}
