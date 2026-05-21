import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { getShareParticipantCryptoWorker } from "@/shared/lib/crypto/worker/scoped";
import {
  assertHybridSigningPublicKeyMaterial,
  computeSigningKeyId,
} from "@/shared/lib/crypto/signature";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";

export interface ShareSessionTrustAnchor {
  protocol: "refmd.share-session-trust-anchor";
  version: 1;
  shareSlug: string;
  shareTokenHash: string;
  shareId: string;
  scopeKind: "document" | "folder";
  scopeId: string;
  createdEventHash: string;
  latestBootstrapEventHash: string;
  capabilityContextHash: string;
  shareCapabilitySecretCommitment: string;
  passwordCapabilitySecretCommitment: string;
  capabilitySecretHash: string;
  permission: "view" | "edit";
  passwordProtected: boolean;
  workspacePinBootstrapHash: string;
  participantPrincipalId: string;
  participantDeviceId: string;
  sourceKind: "url_fragment" | "password" | "dsk_cache" | "safety_transfer" | "qr";
}

export interface ShareSessionTrustAnchorAad {
  protocol: "refmd.share-session-trust-anchor";
  version: 1;
  share_id: string;
  token_hash: string;
  share_participant_principal_id: string;
  share_participant_device_id: string;
  scope_kind: "document" | "folder";
  scope_id: string;
  permission: "view" | "edit";
  created_event_hash: string;
  capability_context_hash: string;
  share_capability_secret_commitment: string;
  password_capability_secret_commitment: string;
  workspace_pin_bootstrap_hash: string;
}

export interface StoredShareParticipantSession {
  shareSlug: string;
  shareId: string;
  principalId: string;
  deviceId: string;
  sessionId: string;
  redeemAttemptId: string;
  displayName: string;
  signingKeyId: string;
  hybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  encryptionPublicKey: string;
  passwordProtected: boolean;
}

export async function readStoredShareParticipantSession(
  shareSlug: string,
): Promise<StoredShareParticipantSession | null> {
  const worker = getShareParticipantCryptoWorker(shareSlug);
  if (!(await worker.loadStoredDsk())) return null;
  const sessions = await listStoredShareParticipantSessionsForWorker(worker);
  return sessions.find((session) => session.shareSlug === shareSlug) ?? null;
}

export async function listStoredShareParticipantSessions(): Promise<
  StoredShareParticipantSession[]
> {
  const worker = getCryptoWorker();
  if (!(await worker.loadStoredDsk())) return [];
  return listStoredShareParticipantSessionsForWorker(worker);
}

export async function writeStoredShareParticipantSession(
  session: StoredShareParticipantSession,
): Promise<void> {
  const worker = getShareParticipantCryptoWorker(session.shareSlug);
  if (!(await worker.loadStoredDsk())) throw new Error("share_participant_session_dsk_unavailable");
  await worker.storeShareParticipantSessionWithDsk(strictStoredShareParticipantSession(session));
}

export async function restoreStoredShareParticipantSessionMaterial(
  shareSlug: string,
): Promise<StoredShareParticipantSession | null> {
  const session = await readStoredShareParticipantSession(shareSlug);
  if (!session) return null;

  const worker = getShareParticipantCryptoWorker(shareSlug);
  try {
    await worker.restoreShareSecretsFromDsk({
      shareSlug,
      principalId: session.principalId,
      deviceId: session.deviceId,
    });
    await worker.setUserContext(session.principalId, session.deviceId);
    await worker.restoreShareParticipantKeysFromDsk({
      principalId: session.principalId,
      shareId: session.shareId,
      shareParticipantDeviceId: session.deviceId,
      signingKeyId: session.signingKeyId,
    });
    await worker.setInitialized();
    return session;
  } catch {
    return null;
  }
}

export async function deleteStoredShareParticipantSession(shareSlug: string): Promise<void> {
  const worker = getShareParticipantCryptoWorker(shareSlug);
  if (!(await worker.loadStoredDsk())) return;
  await worker.deleteShareParticipantSessionWithDsk(shareSlug);
}

export async function clearStoredShareParticipantSessions(): Promise<void> {
  const worker = getCryptoWorker();
  if (!(await worker.loadStoredDsk())) return;
  await worker.clearShareParticipantSessionsWithDsk();
}

export async function deleteStoredShareParticipantSessionsForDevice(
  deviceId: string,
): Promise<void> {
  try {
    const sessions = await listStoredShareParticipantSessions();
    await Promise.all(
      sessions
        .filter((session) => session.deviceId === deviceId)
        .map((session) => deleteStoredShareParticipantSession(session.shareSlug)),
    );
  } catch {
    // Best effort
  }
}

async function listStoredShareParticipantSessionsForWorker(worker: {
  listShareParticipantSessionsWithDsk(): Promise<object[]>;
}): Promise<StoredShareParticipantSession[]> {
  const sessions = await worker.listShareParticipantSessionsWithDsk();
  return sessions.filter(isStoredShareParticipantSession);
}

function isStoredShareParticipantSession(value: object): value is StoredShareParticipantSession {
  if (!isRecord(value) || !hasExactKeys(value, STORED_SHARE_PARTICIPANT_SESSION_KEYS)) {
    return false;
  }

  if (
    typeof value.shareSlug !== "string" ||
    typeof value.shareId !== "string" ||
    typeof value.principalId !== "string" ||
    typeof value.deviceId !== "string" ||
    typeof value.sessionId !== "string" ||
    typeof value.redeemAttemptId !== "string" ||
    typeof value.displayName !== "string" ||
    typeof value.signingKeyId !== "string" ||
    typeof value.encryptionPublicKey !== "string" ||
    typeof value.passwordProtected !== "boolean"
  ) {
    return false;
  }

  try {
    assertHybridSigningPublicKeyMaterial(value.hybridSigningPublicKeyMaterial);
  } catch {
    return false;
  }

  const material = value.hybridSigningPublicKeyMaterial;
  return (
    material.owner_kind === "share_participant_device" &&
    material.owner_id === value.deviceId &&
    computeSigningKeyId(material) === value.signingKeyId
  );
}

const STORED_SHARE_PARTICIPANT_SESSION_KEYS = [
  "deviceId",
  "displayName",
  "encryptionPublicKey",
  "hybridSigningPublicKeyMaterial",
  "passwordProtected",
  "principalId",
  "redeemAttemptId",
  "sessionId",
  "shareId",
  "shareSlug",
  "signingKeyId",
] as const;

function strictStoredShareParticipantSession(
  session: StoredShareParticipantSession,
): StoredShareParticipantSession {
  const material = session.hybridSigningPublicKeyMaterial;
  const strictMaterial = {
    protocol: material.protocol,
    version: material.version,
    owner_kind: material.owner_kind,
    owner_id: material.owner_id,
    ed25519_public: material.ed25519_public,
    mldsa65_public: material.mldsa65_public,
    suite_id: material.suite_id,
    suite_rank: material.suite_rank,
  };
  assertHybridSigningPublicKeyMaterial(strictMaterial);
  return {
    deviceId: session.deviceId,
    displayName: session.displayName,
    encryptionPublicKey: session.encryptionPublicKey,
    hybridSigningPublicKeyMaterial: strictMaterial,
    passwordProtected: session.passwordProtected,
    principalId: session.principalId,
    redeemAttemptId: session.redeemAttemptId,
    sessionId: session.sessionId,
    shareId: session.shareId,
    shareSlug: session.shareSlug,
    signingKeyId: session.signingKeyId,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys<T extends readonly string[]>(
  value: Record<string, unknown>,
  keys: T,
): value is Record<T[number], unknown> {
  const actual = Object.keys(value).sort();
  return actual.length === keys.length && keys.every((key, index) => actual[index] === key);
}
