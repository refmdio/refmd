import { sharesApi } from "@/shared/api";
import {
  clearLegacyShareParticipantSession,
  clearStoredShareParticipantSessions,
  deleteStoredShareParticipantSession,
  type StoredShareParticipantSession,
  readStoredShareParticipantSession,
  writeStoredShareParticipantSession,
} from "@/shared/lib/auth/share-participant-session-store";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { loadDsk } from "@/shared/lib/crypto/dsk";
import { deriveAuthKeys } from "@/shared/lib/crypto/kdf";
import {
  clearShareDekEncryptionKey,
  setShareDekEncryptionKey,
} from "@/shared/lib/crypto/share-dek";
import { getShareParticipantCryptoWorker } from "@/shared/lib/crypto/worker/scoped";
import { resetPhoenixConnection } from "@/shared/lib/ws/phoenix-channel";

const DEFAULT_DISPLAY_NAME = "Guest";

export async function clearShareParticipantSession(shareSlug?: string): Promise<void> {
  clearLegacyShareParticipantSession();
  clearShareDekEncryptionKey(shareSlug);
  if (shareSlug) {
    await deleteStoredShareParticipantSession(shareSlug);
    return;
  }

  await clearStoredShareParticipantSessions();
}

async function restoreStoredShareParticipantSession(
  stored: StoredShareParticipantSession,
): Promise<StoredShareParticipantSession | null> {
  const worker = getShareParticipantCryptoWorker(stored.shareSlug);
  try {
    await worker.lock();
    await ensureWorkerDskForShare(stored.shareSlug);
    await worker.setUserContext(stored.principalId, stored.deviceId);
    await worker.unwrapDeviceKeysFromDsk({
      wrappedEcdh: stored.wrappedDeviceEcdh,
      wrappedSigning: stored.wrappedDeviceSigning,
      userId: stored.principalId,
    });
    await worker.setInitialized();
    return stored;
  } catch {
    return null;
  }
}

async function ensureWorkerDskForShare(shareSlug: string): Promise<void> {
  const worker = getShareParticipantCryptoWorker(shareSlug);
  const dsk = await loadDsk();
  if (dsk) {
    await worker.setDsk(dsk);
    return;
  }

  await worker.generateDsk();
}

export async function ensureShareParticipantDeviceReady(
  options: {
    requiredShareSlug?: string;
  } = {},
): Promise<StoredShareParticipantSession | null> {
  if (!options.requiredShareSlug) return null;

  const stored = await readStoredShareParticipantSession(options.requiredShareSlug);
  if (!stored) return null;

  const restored = await restoreStoredShareParticipantSession(stored);
  if (restored) return restored;

  await deleteStoredShareParticipantSession(options.requiredShareSlug);
  return null;
}

async function ensureShareParticipantKeypair(shareSlug: string): Promise<void> {
  const worker = getShareParticipantCryptoWorker(shareSlug);
  const existing = await ensureShareParticipantDeviceReady({ requiredShareSlug: shareSlug });

  if (!existing) {
    await worker.lock();
    await ensureWorkerDskForShare(shareSlug);
    await worker.generateDeviceKeys();
  }
}

async function getShareParticipantPublicKeys(shareSlug: string): Promise<{
  deviceSigningPublic: Uint8Array;
  deviceEcdhPublic: Uint8Array;
}> {
  const worker = getShareParticipantCryptoWorker(shareSlug);
  const publicKeys = await worker.getPublicKeys();

  if (!publicKeys.deviceSigningPublic || !publicKeys.deviceEcdhPublic) {
    throw new Error("share_participant_keys_unavailable");
  }

  return {
    deviceSigningPublic: publicKeys.deviceSigningPublic,
    deviceEcdhPublic: publicKeys.deviceEcdhPublic,
  };
}

async function computePasswordChallengeResponse(
  authKeyBase64: string,
  challengeBase64: string,
): Promise<string> {
  const authKey = new Uint8Array(base64UrlDecode(authKeyBase64));
  const challenge = new Uint8Array(base64UrlDecode(challengeBase64));
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    authKey,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, challenge);
  return base64UrlEncode(new Uint8Array(signature));
}

async function finalizeShareParticipantSession(
  shareSlug: string,
  bootstrap: {
    participant: {
      principal_id: string;
      device_id: string;
    };
  },
  publicKeys: {
    deviceSigningPublic: Uint8Array;
    deviceEcdhPublic: Uint8Array;
  },
): Promise<StoredShareParticipantSession> {
  const worker = getShareParticipantCryptoWorker(shareSlug);

  resetPhoenixConnection();

  await ensureWorkerDskForShare(shareSlug);
  await worker.setUserContext(bootstrap.participant.principal_id, bootstrap.participant.device_id);
  await worker.setInitialized();
  const wrappedDeviceKeys = await worker.wrapDeviceKeysWithDsk(bootstrap.participant.principal_id);

  const session: StoredShareParticipantSession = {
    shareSlug,
    principalId: bootstrap.participant.principal_id,
    deviceId: bootstrap.participant.device_id,
    displayName: DEFAULT_DISPLAY_NAME,
    signingPublicKey: base64UrlEncode(publicKeys.deviceSigningPublic),
    encryptionPublicKey: base64UrlEncode(publicKeys.deviceEcdhPublic),
    wrappedDeviceEcdh: wrappedDeviceKeys.wrappedEcdh,
    wrappedDeviceSigning: wrappedDeviceKeys.wrappedSigning,
  };

  await writeStoredShareParticipantSession(session);
  return session;
}

export async function bootstrapShareParticipantSession(shareSlug: string): Promise<{
  bootstrap: Awaited<ReturnType<typeof sharesApi.bootstrap>>;
  session: StoredShareParticipantSession;
}> {
  await ensureShareParticipantKeypair(shareSlug);
  const publicKeys = await getShareParticipantPublicKeys(shareSlug);

  const bootstrap = await sharesApi.bootstrap(shareSlug, {
    display_name: DEFAULT_DISPLAY_NAME,
    device_signing_pub_key: base64UrlEncode(publicKeys.deviceSigningPublic),
    device_encryption_pub_key: base64UrlEncode(publicKeys.deviceEcdhPublic),
  });

  const session = await finalizeShareParticipantSession(shareSlug, bootstrap, publicKeys);

  return { bootstrap, session };
}

export async function bootstrapPasswordProtectedShareParticipantSession(
  shareSlug: string,
  password: string,
): Promise<{
  bootstrap: Awaited<ReturnType<typeof sharesApi.respondChallenge>>;
  session: StoredShareParticipantSession;
}> {
  await ensureShareParticipantKeypair(shareSlug);
  const publicKeys = await getShareParticipantPublicKeys(shareSlug);
  const challenge = await sharesApi.getChallenge(shareSlug);
  const { shareAuthKeyBase64, shareDekEncryptionKeyBase64 } = await deriveAuthKeys(
    password,
    challenge.salt,
    challenge.kdf_params,
  );
  const response = await computePasswordChallengeResponse(shareAuthKeyBase64, challenge.challenge);

  const bootstrap = await sharesApi.respondChallenge(shareSlug, {
    response,
    display_name: DEFAULT_DISPLAY_NAME,
    device_signing_pub_key: base64UrlEncode(publicKeys.deviceSigningPublic),
    device_encryption_pub_key: base64UrlEncode(publicKeys.deviceEcdhPublic),
  });

  setShareDekEncryptionKey(shareSlug, base64UrlDecode(shareDekEncryptionKeyBase64));
  const session = await finalizeShareParticipantSession(shareSlug, bootstrap, publicKeys);

  return { bootstrap, session };
}
