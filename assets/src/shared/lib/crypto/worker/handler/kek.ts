import type { WorkerKeyState } from "../state";
import { getCachedKek, setActiveKekVersion, setCachedKek } from "../state";
import { buildOfflineKekCacheAad } from "../../aad";
import {
  decryptKekFromDeviceEnvelope,
  decryptKekFromInvitation,
  decryptKekFromMemberEnvelope,
  encryptKekForDevice,
  encryptKekForInvitation,
  encryptKekForMember,
  generateKek,
  unwrapKekFromBackup,
  wrapKekWithUmk,
} from "../../kek";
import {
  dskDecrypt,
  dskEncrypt,
  type HandlerPayload,
  requireDeviceEcdhPrivate,
  requireDsk,
  requireIdentityEcdhPrivate,
  requireKekForWorkspace,
  requireUmk,
} from "./utils";

export function handleGenerateKek(state: WorkerKeyState, p: HandlerPayload): unknown {
  const workspaceId = p.workspaceId as string;
  const keyVersion = (p.keyVersion as number) ?? 1;
  const kek = generateKek();
  setCachedKek(state, workspaceId, kek, keyVersion);
  setActiveKekVersion(state, workspaceId, keyVersion);
  return { keyVersion };
}

export function handleResolveKek(state: WorkerKeyState, p: HandlerPayload): unknown {
  const workspaceId = p.workspaceId as string;
  const keyVersion = p.keyVersion as number | undefined;
  const cached = getCachedKek(state, workspaceId, keyVersion);
  if (!cached) {
    return { found: false };
  }
  return { found: true, keyVersion: cached.keyVersion };
}

export function handleSetActiveKekVersion(state: WorkerKeyState, p: HandlerPayload): unknown {
  const workspaceId = p.workspaceId as string;
  const keyVersion = p.keyVersion as number;
  setActiveKekVersion(state, workspaceId, keyVersion);
  return { status: "ok" };
}

export function handleEncryptKekForDevice(state: WorkerKeyState, p: HandlerPayload): unknown {
  const workspaceId = p.workspaceId as string;
  const userId = p.userId as string;
  const senderDeviceId = p.senderDeviceId as string;
  const targetDeviceId = p.targetDeviceId as string;
  const targetDeviceEcdhPublic = p.targetDeviceEcdhPublic as Uint8Array;
  const keyVersion = p.keyVersion as number;
  const deviceEcdhPrivate = requireDeviceEcdhPrivate(state);
  const { kek } = requireKekForWorkspace(state, workspaceId);

  const { ciphertext, nonce } = encryptKekForDevice(
    kek,
    deviceEcdhPrivate,
    targetDeviceEcdhPublic,
    workspaceId,
    userId,
    senderDeviceId,
    targetDeviceId,
    keyVersion,
  );
  return { encrypted: ciphertext, nonce };
}

export function handleDecryptKekFromDeviceEnvelope(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const workspaceId = p.workspaceId as string;
  const userId = p.userId as string;
  const senderDeviceId = p.senderDeviceId as string;
  const targetDeviceId = p.targetDeviceId as string;
  const senderEcdhPublic = p.senderEcdhPublic as Uint8Array;
  const encryptedKek = p.encryptedKek as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const keyVersion = p.keyVersion as number;
  const deviceEcdhPrivate = requireDeviceEcdhPrivate(state);

  const kek = decryptKekFromDeviceEnvelope(
    encryptedKek,
    nonce,
    deviceEcdhPrivate,
    senderEcdhPublic,
    workspaceId,
    userId,
    senderDeviceId,
    targetDeviceId,
    keyVersion,
  );
  setCachedKek(state, workspaceId, kek, keyVersion);
  return { status: "ok" };
}

export function handleEncryptKekForMember(state: WorkerKeyState, p: HandlerPayload): unknown {
  const workspaceId = p.workspaceId as string;
  const targetUserId = p.targetUserId as string;
  const targetIdentityEcdhPublic = p.targetIdentityEcdhPublic as Uint8Array;
  const senderDeviceId = p.senderDeviceId as string;
  const keyVersion = p.keyVersion as number;
  const deviceEcdhPrivate = requireDeviceEcdhPrivate(state);
  const { kek } = requireKekForWorkspace(state, workspaceId);

  const { ciphertext, nonce } = encryptKekForMember(
    kek,
    deviceEcdhPrivate,
    targetIdentityEcdhPublic,
    workspaceId,
    targetUserId,
    senderDeviceId,
    keyVersion,
  );
  return { encrypted: ciphertext, nonce };
}

export function handleDecryptKekFromMemberEnvelope(
  state: WorkerKeyState,
  p: HandlerPayload,
): unknown {
  const workspaceId = p.workspaceId as string;
  const targetUserId = p.targetUserId as string;
  const senderDeviceId = p.senderDeviceId as string;
  const senderIdentityEcdhPublic = p.senderIdentityEcdhPublic as Uint8Array;
  const encryptedKek = p.encryptedKek as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const keyVersion = p.keyVersion as number;
  const identityEcdhPrivate = requireIdentityEcdhPrivate(state);

  const kek = decryptKekFromMemberEnvelope(
    encryptedKek,
    nonce,
    identityEcdhPrivate,
    senderIdentityEcdhPublic,
    workspaceId,
    targetUserId,
    keyVersion,
    senderDeviceId,
  );
  setCachedKek(state, workspaceId, kek, keyVersion);
  return { status: "ok" };
}

export function handleWrapKekWithUmk(state: WorkerKeyState, p: HandlerPayload): unknown {
  const workspaceId = p.workspaceId as string;
  const userId = p.userId as string;
  const keyVersion = p.keyVersion as number;
  const umk = requireUmk(state);
  const { kek } = requireKekForWorkspace(state, workspaceId);

  const { encryptedKek, nonce } = wrapKekWithUmk(kek, umk, workspaceId, userId, keyVersion);
  return { encrypted: encryptedKek, nonce };
}

export function handleUnwrapKekFromBackup(state: WorkerKeyState, p: HandlerPayload): unknown {
  const workspaceId = p.workspaceId as string;
  const userId = p.userId as string;
  const encryptedKek = p.encryptedKek as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const keyVersion = p.keyVersion as number;
  const umk = requireUmk(state);

  const kek = unwrapKekFromBackup(encryptedKek, nonce, umk, workspaceId, userId, keyVersion);
  setCachedKek(state, workspaceId, kek, keyVersion);
  return { status: "ok" };
}

export function handleEncryptKekForInvitation(state: WorkerKeyState, p: HandlerPayload): unknown {
  const workspaceId = p.workspaceId as string;
  const invitationId = p.invitationId as string;
  const token = p.token as Uint8Array;
  const keyVersion = p.keyVersion as number;
  const { kek } = requireKekForWorkspace(state, workspaceId);

  const { encryptedKek, nonce } = encryptKekForInvitation(
    kek,
    token,
    workspaceId,
    invitationId,
    keyVersion,
  );
  return { encrypted: encryptedKek, nonce };
}

export function handleDecryptKekFromInvitation(state: WorkerKeyState, p: HandlerPayload): unknown {
  const workspaceId = p.workspaceId as string;
  const invitationId = p.invitationId as string;
  const token = p.token as Uint8Array;
  const encryptedKek = p.encryptedKek as Uint8Array;
  const nonce = p.nonce as Uint8Array;
  const keyVersion = p.keyVersion as number;

  const kek = decryptKekFromInvitation(
    encryptedKek,
    nonce,
    token,
    workspaceId,
    invitationId,
    keyVersion,
  );
  setCachedKek(state, workspaceId, kek, keyVersion);
  return { status: "ok" };
}

export function handleCacheKek(state: WorkerKeyState, p: HandlerPayload): unknown {
  const workspaceId = p.workspaceId as string;
  const kek = p.kek as Uint8Array;
  const keyVersion = p.keyVersion as number;
  setCachedKek(state, workspaceId, kek, keyVersion);
  return { status: "ok" };
}

export async function handleWrapKekForOffline(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const workspaceId = p.workspaceId as string;
  const keyVersion = p.keyVersion as number;
  const { kek } = requireKekForWorkspace(state, workspaceId, keyVersion);

  const aad = buildOfflineKekCacheAad(workspaceId, keyVersion);
  return await dskEncrypt(dsk, kek, aad);
}

export async function handleUnwrapKekFromOffline(
  state: WorkerKeyState,
  p: HandlerPayload,
): Promise<unknown> {
  const dsk = requireDsk(state);
  const ciphertext = p.ciphertext as ArrayBuffer;
  const iv = p.iv as ArrayBuffer;
  const workspaceId = p.workspaceId as string;
  const keyVersion = p.keyVersion as number;
  const isActive = (p.isActive as boolean | undefined) ?? true;

  const kek = await dskDecrypt(
    dsk,
    ciphertext,
    iv,
    buildOfflineKekCacheAad(workspaceId, keyVersion),
  );
  setCachedKek(state, workspaceId, kek, keyVersion);
  if (isActive) {
    setActiveKekVersion(state, workspaceId, keyVersion);
  }
  return { restored: true };
}
