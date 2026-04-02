import type { WorkerKeyState } from "./state";
import { base64UrlEncode } from "../encoding";
import { getAllTofuEntries, importTofuEntries } from "../../trust-store";
import {
  decryptTrustState,
  encryptTrustState,
  type TrustTransferAadParams,
} from "../trust-transfer";
import {
  handleTofuResult,
  trustDevice,
  updateDeviceLastSeen,
  verifyAllDeviceTofu,
  verifyTofu,
} from "../tofu";
import {
  type HandlerPayload,
  requireDeviceEcdhPrivate,
  requireDeviceId,
  requireDeviceSigningPrivate,
  requireUserId,
} from "./handler-utils";

export async function handleEncryptTrustState(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const targetDeviceEcdhPublic = p.targetDeviceEcdhPublic as Uint8Array;
  const transferNonce = p.transferNonce as Uint8Array;

  const deviceEcdhPrivate = requireDeviceEcdhPrivate(state);
  const deviceSigningPrivate = requireDeviceSigningPrivate(state);
  const userId = requireUserId(state);
  const deviceId = requireDeviceId(state);
  const targetDeviceId = p.targetDeviceId as string;

  const tofuEntries = await getAllTofuEntries();
  if (tofuEntries.length === 0) return { empty: true };

  const aadParams: TrustTransferAadParams = {
    userId,
    senderDeviceId: deviceId,
    targetDeviceId,
  };

  const result = encryptTrustState(
    { tofuEntries, transferNonce },
    deviceEcdhPrivate,
    targetDeviceEcdhPublic,
    deviceSigningPrivate,
    aadParams,
  );

  return {
    ciphertext: result.encryptedState,
    nonce: result.nonce,
    signature: result.signature,
  };
}

export async function handleDecryptTrustState(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const senderDeviceEcdhPublic = p.senderDeviceEcdhPublic as Uint8Array;
  const senderIdentitySigningPublic = p.senderIdentitySigningPublic as Uint8Array;
  const transferNonce = p.transferNonce as Uint8Array;
  const ciphertext = p.ciphertext as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const signature = p.signature as Uint8Array;
  const senderDeviceId = p.senderDeviceId as string;

  const deviceEcdhPrivate = requireDeviceEcdhPrivate(state);
  const userId = requireUserId(state);
  const deviceId = requireDeviceId(state);

  const aadParams: TrustTransferAadParams = {
    userId,
    senderDeviceId,
    targetDeviceId: deviceId,
  };

  const snapshot = decryptTrustState(
    { encryptedState: ciphertext, nonce, signature },
    deviceEcdhPrivate,
    senderDeviceEcdhPublic,
    senderIdentitySigningPublic,
    transferNonce,
    aadParams,
  ) as {
    tofuEntries: Array<{
      userId: string;
      deviceId: string;
      signingPublicKey: Uint8Array;
      ecdhPublicKey: Uint8Array;
      firstSeenAt: number;
      lastSeenAt: number;
    }>;
  };

  await importTofuEntries(snapshot.tofuEntries);

  return { imported: snapshot.tofuEntries.length };
}

export async function handleTofuVerify(p: HandlerPayload): Promise<unknown> {
  const userId = p.userId as string;
  const deviceId = p.deviceId as string;
  const signingPublicKey = p.signingPublicKey as Uint8Array;
  const ecdhPublicKey = p.ecdhPublicKey as Uint8Array;

  const result = await verifyTofu(userId, deviceId, signingPublicKey, ecdhPublicKey);
  return { status: result.status };
}

export async function handleTofuVerifyAllDevices(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const rawDevices = p.devices as Array<{
    userId: string;
    deviceId: string;
    name?: string;
    signingPublicKey: Uint8Array;
    ecdhPublicKey: Uint8Array;
    identitySignature?: string | null;
    clientNonce?: string | null;
  }>;
  const userId = requireUserId(state);

  const devices = rawDevices.map((device) => ({
    id: device.deviceId,
    name: device.name ?? device.deviceId,
    signing_public_key: base64UrlEncode(device.signingPublicKey),
    ecdh_public_key: base64UrlEncode(device.ecdhPublicKey),
    identity_signature: device.identitySignature ?? null,
    client_nonce: device.clientNonce ?? null,
  }));

  const errors = await verifyAllDeviceTofu(
    userId,
    devices as Parameters<typeof verifyAllDeviceTofu>[1],
    state.identitySigningPublic,
  );
  return { errors };
}

export async function handleTofuTrustDevice(p: HandlerPayload): Promise<unknown> {
  await trustDevice({
    userId: p.userId as string,
    deviceId: p.deviceId as string,
    signingPublicKey: p.signingPublicKey as Uint8Array,
    ecdhPublicKey: p.ecdhPublicKey as Uint8Array,
    firstSeenAt: (p.firstSeenAt as number) ?? Date.now(),
    lastSeenAt: (p.lastSeenAt as number) ?? Date.now(),
  });
  return { status: "ok" };
}

export async function handleTofuUpdateLastSeen(p: HandlerPayload): Promise<unknown> {
  await updateDeviceLastSeen(p.userId as string, p.deviceId as string);
  return { status: "ok" };
}

export async function handleTofuHandleResult(p: HandlerPayload): Promise<unknown> {
  await handleTofuResult(p.result as Parameters<typeof handleTofuResult>[0]);
  return { status: "ok" };
}

export async function handleTofuGetAllEntries(): Promise<unknown> {
  const entries = await getAllTofuEntries();
  return {
    entries: entries.map((entry) => ({
      userId: entry.userId,
      deviceId: entry.deviceId,
      signingPublicKey: entry.signingPublicKey,
      ecdhPublicKey: entry.ecdhPublicKey,
      firstSeenAt: entry.firstSeenAt,
      lastSeenAt: entry.lastSeenAt,
    })),
  };
}

export async function handleTofuImportEntries(p: HandlerPayload): Promise<unknown> {
  const entries = p.entries as Array<{
    userId: string;
    deviceId: string;
    signingPublicKey: Uint8Array;
    ecdhPublicKey: Uint8Array;
    firstSeenAt: number;
    lastSeenAt: number;
  }>;
  await importTofuEntries(entries);
  return { status: "ok" };
}
