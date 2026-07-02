import {
  readShareSlugFromLocation,
  readShareUrlFragmentFromLocation,
  readWorkspacePinBootstrapHashFromLocation,
} from "@/entities/mount";
import { sharesApi } from "@/shared/api";
import type { components } from "@/shared/api/schema";
import {
  clearStoredShareParticipantSessions,
  deleteStoredShareParticipantSession,
  listStoredShareParticipantSessions,
  type ShareSessionTrustAnchor,
  type StoredShareParticipantSession,
  readStoredShareParticipantSession,
  restoreStoredShareParticipantSessionMaterial,
  writeStoredShareParticipantSession,
} from "@/shared/lib/auth/share-participant-session-store";
import { registerBeforeSessionCleanup } from "@/shared/lib/auth/session-cleanup";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import {
  canonicalizeStrictBytes,
  parseJsonStrictBytes,
  type StrictJsonValue,
} from "@/shared/lib/crypto/jcs";
import { getShareParticipantCryptoWorker } from "@/shared/lib/crypto/worker/scoped";
import { resetPhoenixConnection } from "@/shared/lib/ws/phoenix-channel";
import type { HybridEncryptionPublicKeyMaterial } from "@/shared/lib/crypto/hybrid-encryption";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import {
  clearPendingShareParticipantKeypairPrewarm,
  getPendingShareParticipantKeypairPrewarm,
} from "./keypair-prewarm";
import { recordShareSessionPerf } from "./perf";

export { prewarmShareParticipantKeypair } from "./keypair-prewarm";

const DEFAULT_DISPLAY_NAME = "Guest";
const activeShareParticipantSessions = new Map<string, StoredShareParticipantSession>();
const activeShareSessionTrustAnchors = new Map<string, ShareSessionTrustAnchor>();
const pendingShareWorkerDsk = new Map<string, Promise<void>>();
const pendingShareParticipantSessionRestores = new Map<
  string,
  Promise<StoredShareParticipantSession | null>
>();
const BLAKE3_BASE64URL_RE = /^[A-Za-z0-9_-]{43}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

type ShareParticipantDeviceSigningPublicKeyMaterial =
  components["schemas"]["ShareParticipantDeviceSigningPublicKeyMaterial"];
type ShareParticipantDeviceEncryptionPublicKeyMaterial =
  components["schemas"]["ShareParticipantDeviceEncryptionPublicKeyMaterial"];
type ShareParticipantDeviceAuthorization =
  components["schemas"]["ShareParticipantDeviceAuthorization"];
type ShareCapabilityAuthorization = components["schemas"]["ShareCapabilityAuthorization"];
type ShareAuthorizationState = {
  shareId: string;
  scopeKind: "document" | "folder";
  scopeId: string;
  permission: "view" | "edit";
  passwordProtected: boolean;
  createdEventHash: string;
  latestBootstrapEventHash: string;
  capabilityContextHash: string;
  shareCapabilitySecretCommitment: string;
  passwordCapabilitySecretCommitment: string;
};

registerBeforeSessionCleanup(() => clearShareParticipantSession(), { scope: "secure" });

function strictHybridSigningPublicKeyMaterial(
  material: HybridSigningPublicKeyMaterial,
): HybridSigningPublicKeyMaterial {
  return {
    protocol: material.protocol,
    version: material.version,
    owner_kind: material.owner_kind,
    owner_id: material.owner_id,
    ed25519_public: material.ed25519_public,
    mldsa65_public: material.mldsa65_public,
    suite_id: material.suite_id,
    suite_rank: material.suite_rank,
  };
}

function findReusableShareTrustAnchor(shareSlug: string): ShareSessionTrustAnchor | null {
  return activeShareSessionTrustAnchors.get(shareSlug) ?? null;
}

function readShareUrlFragment(): string | null {
  return readShareUrlFragmentFromLocation();
}

function capabilitySecretHashFromFragment(fragment: string): string {
  const value = new URLSearchParams(fragment).get("cap");
  if (!value || !/^[A-Za-z0-9_-]{43}$/.test(value)) {
    throw new Error("share_capability_secret_required");
  }
  return blake3Base64Url(base64UrlDecode(value));
}

function shareSessionTrustAnchorAadObject(anchor: ShareSessionTrustAnchor) {
  return {
    protocol: anchor.protocol,
    version: anchor.version,
    share_id: anchor.shareId,
    token_hash: anchor.shareTokenHash,
    share_participant_principal_id: anchor.participantPrincipalId,
    share_participant_device_id: anchor.participantDeviceId,
    scope_kind: anchor.scopeKind,
    scope_id: anchor.scopeId,
    permission: anchor.permission,
    created_event_hash: anchor.createdEventHash,
    capability_context_hash: anchor.capabilityContextHash,
    share_capability_secret_commitment: anchor.shareCapabilitySecretCommitment,
    password_capability_secret_commitment: anchor.passwordCapabilitySecretCommitment,
    workspace_pin_bootstrap_hash: anchor.workspacePinBootstrapHash,
  } as const;
}

function exactAnchorKeys(anchor: ShareSessionTrustAnchor): boolean {
  const expected = [
    "capabilityContextHash",
    "capabilitySecretHash",
    "createdEventHash",
    "latestBootstrapEventHash",
    "participantDeviceId",
    "participantPrincipalId",
    "passwordCapabilitySecretCommitment",
    "passwordProtected",
    "permission",
    "protocol",
    "scopeId",
    "scopeKind",
    "shareCapabilitySecretCommitment",
    "shareId",
    "shareSlug",
    "shareTokenHash",
    "sourceKind",
    "version",
    "workspacePinBootstrapHash",
  ];
  return JSON.stringify(Object.keys(anchor).sort()) === JSON.stringify(expected);
}

function shareAuthorizationStateFromLanding(
  landing: Awaited<ReturnType<typeof sharesApi.getLanding>>,
) {
  const share = landing.share as typeof landing.share & {
    created_event_hash: string;
    latest_bootstrap_event_hash: string;
    capability_context_hash: string;
  };

  return {
    shareId: share.id,
    scopeKind: share.scope,
    scopeId: share.document_id,
    permission: share.permission,
    passwordProtected: share.password_protected,
    createdEventHash: share.created_event_hash,
    latestBootstrapEventHash: share.latest_bootstrap_event_hash,
    capabilityContextHash: share.capability_context_hash,
    shareCapabilitySecretCommitment: share.share_capability_secret_commitment,
    passwordCapabilitySecretCommitment: share.password_capability_secret_commitment,
  };
}

async function signShareCapabilityAuthorization(params: {
  shareSlug: string;
  shareTokenHash: string;
  workspacePinBootstrapHash: string;
  shareState: ShareAuthorizationState;
}) {
  const artifact = await getShareParticipantCryptoWorker(
    params.shareSlug,
  ).signShareCapabilityAuthorization({
    shareSlug: params.shareSlug,
    shareTokenHash: params.shareTokenHash,
    workspacePinBootstrapHash: params.workspacePinBootstrapHash,
    shareId: params.shareState.shareId,
    scopeKind: params.shareState.scopeKind,
    scopeId: params.shareState.scopeId,
    permission: params.shareState.permission,
    passwordProtected: params.shareState.passwordProtected,
    createdEventHash: params.shareState.createdEventHash,
    latestBootstrapEventHash: params.shareState.latestBootstrapEventHash,
    capabilityContextHash: params.shareState.capabilityContextHash,
    shareCapabilitySecretCommitment: params.shareState.shareCapabilitySecretCommitment,
    passwordCapabilitySecretCommitment: params.shareState.passwordCapabilitySecretCommitment,
  });

  return {
    transcript: artifact.transcript,
    signature: artifact.signature,
  } as ShareCapabilityAuthorization;
}

async function signShareParticipantDeviceAuthorization(params: {
  shareSlug: string;
  shareState: ShareAuthorizationState;
  shareParticipantPrincipalId: string;
  shareParticipantSessionId: string;
}) {
  const artifact = await getShareParticipantCryptoWorker(
    params.shareSlug,
  ).signShareParticipantDeviceAuthorization({
    shareId: params.shareState.shareId,
    shareSessionId: params.shareParticipantSessionId,
    shareParticipantPrincipalId: params.shareParticipantPrincipalId,
    capabilityContextHash: params.shareState.capabilityContextHash,
    shareCreatedEventHash: params.shareState.createdEventHash,
    latestBootstrapEventHash: params.shareState.latestBootstrapEventHash,
    scopeKind: params.shareState.scopeKind,
    scopeId: params.shareState.scopeId,
    permission: params.shareState.permission,
  });

  return {
    transcript: artifact.transcript,
    signature: artifact.signature,
  } as ShareParticipantDeviceAuthorization;
}

function validateShareSessionTrustAnchor(
  anchor: ShareSessionTrustAnchor,
  session: StoredShareParticipantSession,
): ShareSessionTrustAnchor | null {
  if (anchor.protocol !== "refmd.share-session-trust-anchor" || anchor.version !== 1) return null;
  if (!exactAnchorKeys(anchor)) return null;
  if (anchor.shareSlug !== session.shareSlug) return null;
  if (anchor.participantPrincipalId !== session.principalId) return null;
  if (anchor.participantDeviceId !== session.deviceId) return null;
  if (!UUID_RE.test(anchor.shareId)) return null;
  if (anchor.scopeKind !== "document" && anchor.scopeKind !== "folder") return null;
  if (!UUID_RE.test(anchor.scopeId)) return null;
  if (anchor.permission !== "view" && anchor.permission !== "edit") return null;
  if (anchor.passwordProtected !== session.passwordProtected) return null;
  if (!BLAKE3_BASE64URL_RE.test(anchor.workspacePinBootstrapHash)) return null;
  if (!BLAKE3_BASE64URL_RE.test(anchor.capabilitySecretHash)) return null;
  if (!BLAKE3_BASE64URL_RE.test(anchor.shareTokenHash)) return null;
  if (!BLAKE3_BASE64URL_RE.test(anchor.createdEventHash)) return null;
  if (!BLAKE3_BASE64URL_RE.test(anchor.latestBootstrapEventHash)) return null;
  if (!BLAKE3_BASE64URL_RE.test(anchor.capabilityContextHash)) return null;
  if (!BLAKE3_BASE64URL_RE.test(anchor.shareCapabilitySecretCommitment)) return null;
  if (
    anchor.passwordCapabilitySecretCommitment !== "none" &&
    !BLAKE3_BASE64URL_RE.test(anchor.passwordCapabilitySecretCommitment)
  ) {
    return null;
  }
  if (anchor.passwordProtected && anchor.passwordCapabilitySecretCommitment === "none") return null;
  if (!anchor.passwordProtected && anchor.passwordCapabilitySecretCommitment !== "none") {
    return null;
  }
  if (anchor.capabilitySecretHash !== anchor.shareCapabilitySecretCommitment) return null;
  if (
    !["url_fragment", "password", "dsk_cache", "safety_transfer", "qr"].includes(anchor.sourceKind)
  ) {
    return null;
  }
  return anchor;
}

async function loadStoredShareSessionTrustAnchor(
  session: StoredShareParticipantSession,
): Promise<ShareSessionTrustAnchor | null> {
  const worker = getShareParticipantCryptoWorker(session.shareSlug);
  try {
    const plaintext = await worker.loadShareSessionTrustAnchorWithDsk(session.shareSlug);
    if (!plaintext) return null;
    const anchor = parseJsonStrictBytes(plaintext) as unknown as ShareSessionTrustAnchor;
    return validateShareSessionTrustAnchor(anchor, session);
  } catch {
    return null;
  }
}

async function storeShareSessionTrustAnchor(anchor: ShareSessionTrustAnchor): Promise<void> {
  await getShareParticipantCryptoWorker(anchor.shareSlug).storeShareSessionTrustAnchorWithDsk({
    shareSlug: anchor.shareSlug,
    plaintext: canonicalizeStrictBytes(anchor as unknown as StrictJsonValue),
    aadRecord: shareSessionTrustAnchorAadObject(anchor),
  });
}

export async function clearShareParticipantSession(shareSlug?: string): Promise<void> {
  if (shareSlug) {
    await getShareParticipantCryptoWorker(shareSlug).clearShareSecrets(shareSlug);
    await getShareParticipantCryptoWorker(shareSlug).deleteShareSessionTrustAnchorWithDsk(
      shareSlug,
    );
    await getCryptoWorker().clearShareSecrets(shareSlug);
    activeShareParticipantSessions.delete(shareSlug);
    activeShareSessionTrustAnchors.delete(shareSlug);
    resetPhoenixConnection("share");
    await deleteStoredShareParticipantSession(shareSlug);
    return;
  }

  await Promise.allSettled([
    getCryptoWorker().clearShareSecrets(),
    ...[...activeShareParticipantSessions.keys()].map((slug) =>
      Promise.allSettled([
        getShareParticipantCryptoWorker(slug).clearShareSecrets(),
        getShareParticipantCryptoWorker(slug).deleteShareSessionTrustAnchorWithDsk(slug),
      ]),
    ),
  ]);
  activeShareParticipantSessions.clear();
  activeShareSessionTrustAnchors.clear();
  resetPhoenixConnection("share");
  await clearStoredShareParticipantSessions();
}

async function restoreStoredShareParticipantSession(
  stored: StoredShareParticipantSession,
  options: { strict?: boolean } = {},
): Promise<StoredShareParticipantSession | null> {
  const worker = getShareParticipantCryptoWorker(stored.shareSlug);
  try {
    await worker.lock();
    await ensureWorkerDskForShare(stored.shareSlug);
    const restored = await restoreStoredShareParticipantSessionMaterial(stored.shareSlug);
    if (!restored) throw new Error("share_participant_session_unavailable");
    const anchor = await loadStoredShareSessionTrustAnchor(stored);
    if (anchor) {
      activeShareSessionTrustAnchors.set(stored.shareSlug, anchor);
    } else {
      activeShareSessionTrustAnchors.delete(stored.shareSlug);
    }
    return restored;
  } catch (err) {
    if (options.strict) throw err;
    return null;
  }
}

function restoreStoredShareParticipantSessionOnce(
  stored: StoredShareParticipantSession,
  options: { strict?: boolean } = {},
): Promise<StoredShareParticipantSession | null> {
  if (options.strict) return restoreStoredShareParticipantSession(stored, options);

  const pending = pendingShareParticipantSessionRestores.get(stored.shareSlug);
  if (pending) return pending;

  const restore = restoreStoredShareParticipantSession(stored, options).finally(() => {
    pendingShareParticipantSessionRestores.delete(stored.shareSlug);
  });
  pendingShareParticipantSessionRestores.set(stored.shareSlug, restore);
  return restore;
}

export async function readShareSessionTrustAnchor(shareSlug: string): Promise<{
  anchor: ShareSessionTrustAnchor | null;
  session: StoredShareParticipantSession | null;
  workspacePinBootstrapHash: string | null;
  shareCapabilitySecretCommitment: string | null;
  passwordCapabilitySecretCommitment: string | null;
  capabilityContextHash: string | null;
  hasShareDekEncryptionKey: boolean;
}> {
  const startedAt = performance.now();
  recordShareSessionPerf("share_session_trust_anchor_start", { shareSlug });
  const session = await ensureShareParticipantDeviceReady({ requiredShareSlug: shareSlug });
  recordShareSessionPerf("share_session_trust_anchor_session_ready", {
    shareSlug,
    elapsedMs: performance.now() - startedAt,
    found: Boolean(session),
  });
  const anchor = activeShareSessionTrustAnchors.get(shareSlug);
  const worker = getShareParticipantCryptoWorker(shareSlug);
  const hasShareDekEncryptionKey = await worker.hasShareDekEncryptionKey(shareSlug);
  recordShareSessionPerf("share_session_trust_anchor_ready", {
    shareSlug,
    elapsedMs: performance.now() - startedAt,
    hasAnchor: Boolean(anchor),
    hasShareDekEncryptionKey,
  });
  return {
    anchor: anchor ?? null,
    session,
    workspacePinBootstrapHash: anchor?.workspacePinBootstrapHash ?? null,
    shareCapabilitySecretCommitment: anchor?.shareCapabilitySecretCommitment ?? null,
    passwordCapabilitySecretCommitment: anchor?.passwordCapabilitySecretCommitment ?? null,
    capabilityContextHash: anchor?.capabilityContextHash ?? null,
    hasShareDekEncryptionKey,
  };
}

export function assertShareBootstrapMatchesTrustAnchor(
  shareSlug: string,
  anchor: ShareSessionTrustAnchor | null,
  response: {
    share_id: string;
    authorization_share_id?: string;
    scope_kind: "document" | "folder";
    scope_id: string;
    permission: "view" | "edit";
    password_protected: boolean;
    share_token_hash: string;
    created_event_hash: string;
    latest_bootstrap_event_hash: string;
    capability_context_hash: string;
    share_capability_secret_commitment: string;
    password_capability_secret_commitment: string;
  },
): void {
  if (!anchor) throw new Error("share_trust_anchor_unavailable");
  const expectedShareId = response.authorization_share_id ?? response.share_id;
  const checks = [
    anchor.shareSlug === shareSlug,
    anchor.shareId === expectedShareId,
    anchor.scopeKind === response.scope_kind,
    anchor.scopeId === response.scope_id,
    anchor.permission === response.permission,
    anchor.passwordProtected === response.password_protected,
    anchor.shareTokenHash === response.share_token_hash,
    anchor.createdEventHash === response.created_event_hash,
    anchor.capabilityContextHash === response.capability_context_hash,
    anchor.shareCapabilitySecretCommitment === response.share_capability_secret_commitment,
    anchor.passwordCapabilitySecretCommitment === response.password_capability_secret_commitment,
  ];
  if (!checks.every(Boolean)) {
    throw new Error("share_trust_anchor_mismatch");
  }
}

export async function refreshShareSessionTrustAnchorFromBootstrap(
  shareSlug: string,
  anchor: ShareSessionTrustAnchor | null,
  response: {
    share_id: string;
    authorization_share_id?: string;
    scope_kind: "document" | "folder";
    scope_id: string;
    permission: "view" | "edit";
    password_protected: boolean;
    share_token_hash: string;
    created_event_hash: string;
    latest_bootstrap_event_hash: string;
    capability_context_hash: string;
    share_capability_secret_commitment: string;
    password_capability_secret_commitment: string;
  },
): Promise<ShareSessionTrustAnchor | null> {
  assertShareBootstrapMatchesTrustAnchor(shareSlug, anchor, response);
  if (!anchor) return null;

  const refreshed: ShareSessionTrustAnchor = {
    ...anchor,
    shareId: response.authorization_share_id ?? response.share_id,
    scopeKind: response.scope_kind,
    scopeId: response.scope_id,
    permission: response.permission,
    passwordProtected: response.password_protected,
    shareTokenHash: response.share_token_hash,
    createdEventHash: response.created_event_hash,
    latestBootstrapEventHash: response.latest_bootstrap_event_hash,
    capabilityContextHash: response.capability_context_hash,
    shareCapabilitySecretCommitment: response.share_capability_secret_commitment,
    passwordCapabilitySecretCommitment: response.password_capability_secret_commitment,
  };
  await storeShareSessionTrustAnchor(refreshed);
  activeShareSessionTrustAnchors.set(shareSlug, refreshed);
  return refreshed;
}

export async function rememberMountedShareParticipantSession(params: {
  sourceShareSlug: string;
  mountSessionKey: string;
  shareId: string;
}): Promise<void> {
  const sourceSession = await ensureShareParticipantDeviceReady({
    requiredShareSlug: params.sourceShareSlug,
  });
  if (!sourceSession) throw new Error("share_participant_session_unavailable");

  const sourceWorker = getShareParticipantCryptoWorker(params.sourceShareSlug);
  await ensureWorkerDskForShare(params.sourceShareSlug);
  await sourceWorker.persistMountedShareSecretsWithDsk({
    sourceShareSlug: params.sourceShareSlug,
    mountSessionKey: params.mountSessionKey,
    principalId: sourceSession.principalId,
    deviceId: sourceSession.deviceId,
  });
  const mountedSession: StoredShareParticipantSession = {
    ...sourceSession,
    shareId: params.shareId,
    shareSlug: params.mountSessionKey,
    hybridSigningPublicKeyMaterial: strictHybridSigningPublicKeyMaterial(
      sourceSession.hybridSigningPublicKeyMaterial,
    ),
  };
  activeShareParticipantSessions.set(params.mountSessionKey, mountedSession);
  await writeStoredShareParticipantSession(mountedSession);
  await restoreStoredShareParticipantSession(mountedSession, { strict: true });
}

export async function updateMountedShareParticipantSession(params: {
  mountSessionKey: string;
  sessionId: string;
  grant?: "view" | "edit";
}): Promise<void> {
  const existing = await ensureShareParticipantDeviceReady({
    requiredShareSlug: params.mountSessionKey,
  });
  if (!existing) throw new Error("share_participant_session_unavailable");
  const updated: StoredShareParticipantSession = {
    ...existing,
    sessionId: params.sessionId,
    redeemAttemptId: crypto.randomUUID(),
  };
  activeShareParticipantSessions.set(params.mountSessionKey, updated);
  await writeStoredShareParticipantSession(updated);
}

export async function resolveShareSlugForTokenHash(shareTokenHash: string): Promise<string | null> {
  const locationShareSlug = readShareSlugFromLocation();
  if (locationShareSlug && blake3Base64Url(base64UrlDecode(locationShareSlug)) === shareTokenHash) {
    return locationShareSlug;
  }

  const matchesShareTokenHash = (shareSlug: string): boolean => {
    if (!/^[A-Za-z0-9_-]{22}$/.test(shareSlug)) return false;
    try {
      return blake3Base64Url(base64UrlDecode(shareSlug)) === shareTokenHash;
    } catch {
      return false;
    }
  };

  for (const shareSlug of activeShareParticipantSessions.keys()) {
    if (matchesShareTokenHash(shareSlug)) return shareSlug;
  }

  for (const stored of await listStoredShareParticipantSessions()) {
    if (matchesShareTokenHash(stored.shareSlug)) {
      return stored.shareSlug;
    }
  }

  return null;
}

async function ensureWorkerDskForShare(shareSlug: string): Promise<void> {
  const pending = pendingShareWorkerDsk.get(shareSlug);
  if (pending) return pending;

  const worker = getShareParticipantCryptoWorker(shareSlug);
  const ensure = (async () => {
    if (await worker.loadStoredDsk()) {
      return;
    }

    await worker.generateDsk();
  })().finally(() => {
    if (pendingShareWorkerDsk.get(shareSlug) === ensure) {
      pendingShareWorkerDsk.delete(shareSlug);
    }
  });
  pendingShareWorkerDsk.set(shareSlug, ensure);
  return ensure;
}

export async function ensureShareParticipantDeviceReady(
  options: {
    requiredShareSlug?: string;
  } = {},
): Promise<StoredShareParticipantSession | null> {
  if (!options.requiredShareSlug) return null;

  const startedAt = performance.now();
  recordShareSessionPerf("share_session_device_ready_start", {
    shareSlug: options.requiredShareSlug,
  });
  const active = activeShareParticipantSessions.get(options.requiredShareSlug);
  if (active) {
    if (activeShareSessionTrustAnchors.has(options.requiredShareSlug)) {
      recordShareSessionPerf("share_session_device_ready_ready", {
        shareSlug: options.requiredShareSlug,
        elapsedMs: performance.now() - startedAt,
        source: "active-memory",
      });
      return active;
    }
    recordShareSessionPerf("share_session_device_ready_active_restore_start", {
      shareSlug: options.requiredShareSlug,
      elapsedMs: performance.now() - startedAt,
    });
    const restoredActive = await restoreStoredShareParticipantSessionOnce(active);
    if (restoredActive) {
      activeShareParticipantSessions.set(options.requiredShareSlug, restoredActive);
      recordShareSessionPerf("share_session_device_ready_ready", {
        shareSlug: options.requiredShareSlug,
        elapsedMs: performance.now() - startedAt,
        source: "active",
      });
      return restoredActive;
    }
  }

  const stored = await readStoredShareParticipantSession(options.requiredShareSlug).catch(
    () => null,
  );
  recordShareSessionPerf("share_session_device_ready_stored_read", {
    shareSlug: options.requiredShareSlug,
    elapsedMs: performance.now() - startedAt,
    found: Boolean(stored),
  });
  if (!stored) {
    recordShareSessionPerf("share_session_device_ready_ready", {
      shareSlug: options.requiredShareSlug,
      elapsedMs: performance.now() - startedAt,
      source: "missing",
    });
    return null;
  }

  const restored = await restoreStoredShareParticipantSessionOnce(stored);
  if (restored) {
    activeShareParticipantSessions.set(options.requiredShareSlug, restored);
    recordShareSessionPerf("share_session_device_ready_ready", {
      shareSlug: options.requiredShareSlug,
      elapsedMs: performance.now() - startedAt,
      source: "stored",
    });
    return restored;
  }

  recordShareSessionPerf("share_session_device_ready_ready", {
    shareSlug: options.requiredShareSlug,
    elapsedMs: performance.now() - startedAt,
    source: "restore_failed",
  });
  return null;
}

async function ensureShareParticipantKeypair(
  shareSlug: string,
  options: { forceNew?: boolean } = {},
): Promise<void> {
  const pendingPrewarm = getPendingShareParticipantKeypairPrewarm(shareSlug);
  if (pendingPrewarm) {
    const startedAt = performance.now();
    recordShareSessionPerf("share_session_keypair_prewarm_wait_start", {
      shareSlug,
      forceNew: Boolean(options.forceNew),
    });
    const staleSessionDelete = options.forceNew
      ? deleteStoredShareParticipantSession(shareSlug).catch(() => {
          // A forced new share participant session overwrites any stale persisted session.
        })
      : Promise.resolve();
    if (options.forceNew) {
      activeShareParticipantSessions.delete(shareSlug);
    }
    try {
      await pendingPrewarm;
      await staleSessionDelete;
      clearPendingShareParticipantKeypairPrewarm(shareSlug, pendingPrewarm);
      recordShareSessionPerf("share_session_keypair_prewarm_wait_ready", {
        shareSlug,
        elapsedMs: performance.now() - startedAt,
      });
      return;
    } catch (error) {
      await staleSessionDelete;
      recordShareSessionPerf("share_session_keypair_prewarm_wait_failed", {
        shareSlug,
        elapsedMs: performance.now() - startedAt,
        error: error instanceof Error ? error.message : String(error),
      });
      // Fall back to the normal keypair path if an opportunistic prewarm failed.
    }
  }

  const worker = getShareParticipantCryptoWorker(shareSlug);
  const existing = options.forceNew
    ? null
    : await ensureShareParticipantDeviceReady({ requiredShareSlug: shareSlug });

  if (!existing) {
    const generatedAt = performance.now();
    recordShareSessionPerf("share_session_keypair_generate_start", {
      shareSlug,
      forceNew: Boolean(options.forceNew),
    });
    const deviceId = crypto.randomUUID();
    if (options.forceNew) {
      activeShareParticipantSessions.delete(shareSlug);
      await deleteStoredShareParticipantSession(shareSlug).catch(() => {
        // A forced new share participant session overwrites any stale persisted session.
      });
    }
    await worker.lock();
    await worker.generateDeviceKeys({ deviceId, ownerKind: "share_participant_device" });
    recordShareSessionPerf("share_session_keypair_generate_ready", {
      shareSlug,
      elapsedMs: performance.now() - generatedAt,
    });
  }
}

async function getShareParticipantPublicKeys(shareSlug: string): Promise<{
  deviceSigningKeyId: string;
  deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  deviceEcdhPublic: Uint8Array;
  deviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
}> {
  const worker = getShareParticipantCryptoWorker(shareSlug);
  const publicKeys = await worker.getPublicKeys();

  if (
    !publicKeys.deviceSigningKeyId ||
    !publicKeys.deviceHybridSigningPublicKeyMaterial ||
    !publicKeys.deviceEcdhPublic ||
    !publicKeys.deviceHybridEncryptionPublicKeyMaterial
  ) {
    throw new Error("share_participant_keys_unavailable");
  }

  return {
    deviceSigningKeyId: publicKeys.deviceSigningKeyId,
    deviceHybridSigningPublicKeyMaterial: publicKeys.deviceHybridSigningPublicKeyMaterial,
    deviceEcdhPublic: publicKeys.deviceEcdhPublic,
    deviceHybridEncryptionPublicKeyMaterial: publicKeys.deviceHybridEncryptionPublicKeyMaterial,
  };
}

async function finalizeShareParticipantSession(
  shareSlug: string,
  passwordProtected: boolean,
  bootstrap: {
    share_id: string;
    authorization_share_id?: string;
    scope_kind: "document" | "folder";
    scope_id: string;
    created_event_hash: string;
    latest_bootstrap_event_hash: string;
    capability_context_hash: string;
    share_capability_secret_commitment: string;
    password_capability_secret_commitment: string;
    participant: {
      principal_id: string;
      device_id: string;
      session_id: string;
    };
  },
  publicKeys: {
    deviceSigningKeyId: string;
    deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
    deviceEcdhPublic: Uint8Array;
    deviceHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  },
  trustAnchor?: {
    workspacePinBootstrapHash: string | null;
    shareUrlFragment?: string;
    capabilitySecretHash?: string;
    shareTokenHash: string;
    permission: "view" | "edit";
    sourceKind: ShareSessionTrustAnchor["sourceKind"];
  },
  options: {
    onActiveSessionReady?: (state: {
      session: StoredShareParticipantSession;
      trustAnchor: ShareSessionTrustAnchor | null;
    }) => void;
  } = {},
): Promise<StoredShareParticipantSession> {
  const worker = getShareParticipantCryptoWorker(shareSlug);
  const startedAt = performance.now();
  recordShareSessionPerf("share_session_finalize_start", { shareSlug });

  resetPhoenixConnection("share");
  await worker.setUserContext(bootstrap.participant.principal_id, bootstrap.participant.device_id);
  await worker.setInitialized();
  recordShareSessionPerf("share_session_finalize_worker_context_ready", {
    shareSlug,
    elapsedMs: performance.now() - startedAt,
  });
  const shareId = bootstrap.authorization_share_id ?? bootstrap.share_id;
  const session: StoredShareParticipantSession = {
    shareSlug,
    shareId,
    principalId: bootstrap.participant.principal_id,
    deviceId: bootstrap.participant.device_id,
    sessionId: bootstrap.participant.session_id,
    redeemAttemptId: crypto.randomUUID(),
    displayName: DEFAULT_DISPLAY_NAME,
    signingKeyId: publicKeys.deviceSigningKeyId,
    hybridSigningPublicKeyMaterial: strictHybridSigningPublicKeyMaterial(
      publicKeys.deviceHybridSigningPublicKeyMaterial,
    ),
    encryptionPublicKey: base64UrlEncode(publicKeys.deviceEcdhPublic),
    passwordProtected,
  };
  const workspacePinBootstrapHash = trustAnchor?.workspacePinBootstrapHash ?? null;
  let sessionTrustAnchor: ShareSessionTrustAnchor | null = null;
  if (workspacePinBootstrapHash && trustAnchor) {
    sessionTrustAnchor = {
      protocol: "refmd.share-session-trust-anchor",
      version: 1,
      shareSlug,
      shareTokenHash: trustAnchor.shareTokenHash,
      capabilitySecretHash:
        trustAnchor.capabilitySecretHash ??
        capabilitySecretHashFromFragment(trustAnchor.shareUrlFragment ?? ""),
      permission: trustAnchor.permission,
      passwordProtected,
      workspacePinBootstrapHash,
      participantPrincipalId: bootstrap.participant.principal_id,
      participantDeviceId: bootstrap.participant.device_id,
      shareId: bootstrap.authorization_share_id ?? bootstrap.share_id,
      scopeKind: bootstrap.scope_kind,
      scopeId: bootstrap.scope_id,
      createdEventHash: bootstrap.created_event_hash,
      latestBootstrapEventHash: bootstrap.latest_bootstrap_event_hash,
      capabilityContextHash: bootstrap.capability_context_hash,
      shareCapabilitySecretCommitment: bootstrap.share_capability_secret_commitment,
      passwordCapabilitySecretCommitment: bootstrap.password_capability_secret_commitment,
      sourceKind: trustAnchor.sourceKind,
    };
    activeShareSessionTrustAnchors.set(shareSlug, sessionTrustAnchor);
    recordShareSessionPerf("share_session_finalize_anchor_stored", {
      shareSlug,
      elapsedMs: performance.now() - startedAt,
      scope: "active-memory",
    });
  } else {
    activeShareSessionTrustAnchors.delete(shareSlug);
  }

  activeShareParticipantSessions.set(shareSlug, session);
  recordShareSessionPerf("share_session_finalize_active_ready", {
    shareSlug,
    elapsedMs: performance.now() - startedAt,
    hasTrustAnchor: Boolean(sessionTrustAnchor),
  });
  options.onActiveSessionReady?.({ session, trustAnchor: sessionTrustAnchor });

  await ensureWorkerDskForShare(shareSlug);
  recordShareSessionPerf("share_session_finalize_dsk_ready", {
    shareSlug,
    elapsedMs: performance.now() - startedAt,
  });
  await worker.persistShareSecretsWithDsk({
    shareSlug,
    principalId: bootstrap.participant.principal_id,
    deviceId: bootstrap.participant.device_id,
  });
  recordShareSessionPerf("share_session_finalize_secrets_persisted", {
    shareSlug,
    elapsedMs: performance.now() - startedAt,
  });
  await worker.persistShareParticipantKeysWithDsk({
    principalId: bootstrap.participant.principal_id,
    shareId,
    shareParticipantDeviceId: bootstrap.participant.device_id,
    signingKeyId: publicKeys.deviceSigningKeyId,
  });
  recordShareSessionPerf("share_session_finalize_keys_persisted", {
    shareSlug,
    elapsedMs: performance.now() - startedAt,
  });
  const activeAnchor = activeShareSessionTrustAnchors.get(shareSlug) ?? sessionTrustAnchor;
  if (activeAnchor) {
    await storeShareSessionTrustAnchor(activeAnchor);
    recordShareSessionPerf("share_session_finalize_anchor_persisted", {
      shareSlug,
      elapsedMs: performance.now() - startedAt,
    });
  }
  await writeStoredShareParticipantSession(session);
  recordShareSessionPerf("share_session_finalize_ready", {
    shareSlug,
    elapsedMs: performance.now() - startedAt,
  });
  return session;
}

export async function bootstrapShareParticipantSession(
  shareSlug: string,
  options: {
    landing?: Awaited<ReturnType<typeof sharesApi.getLanding>>;
    onActiveSessionReady?: (state: {
      bootstrap: Awaited<ReturnType<typeof sharesApi.bootstrap>>;
      session: StoredShareParticipantSession;
      trustAnchor: ShareSessionTrustAnchor | null;
    }) => void;
  } = {},
): Promise<{
  bootstrap: Awaited<ReturnType<typeof sharesApi.bootstrap>>;
  session: StoredShareParticipantSession;
}> {
  const startedAt = performance.now();
  recordShareSessionPerf("share_session_bootstrap_start", { shareSlug });
  await ensureShareParticipantKeypair(shareSlug, { forceNew: true });
  recordShareSessionPerf("share_session_bootstrap_keypair_ready", {
    shareSlug,
    elapsedMs: performance.now() - startedAt,
  });
  const publicKeys = await getShareParticipantPublicKeys(shareSlug);
  recordShareSessionPerf("share_session_bootstrap_public_keys_ready", {
    shareSlug,
    elapsedMs: performance.now() - startedAt,
  });
  const worker = getShareParticipantCryptoWorker(shareSlug);
  const deviceId = await worker.getDeviceId();
  recordShareSessionPerf("share_session_bootstrap_device_id_ready", {
    shareSlug,
    elapsedMs: performance.now() - startedAt,
  });
  const reusableAnchor = findReusableShareTrustAnchor(shareSlug);
  const landing = options.landing ?? (await sharesApi.getLanding(shareSlug));
  recordShareSessionPerf("share_session_bootstrap_landing_ready", {
    shareSlug,
    elapsedMs: performance.now() - startedAt,
    fromOptions: Boolean(options.landing),
  });
  const shareUrlFragment = readShareUrlFragment();
  if (!shareUrlFragment && !reusableAnchor) throw new Error("share_capability_secret_required");
  const workspacePinBootstrapHash =
    readWorkspacePinBootstrapHashFromLocation() ?? reusableAnchor?.workspacePinBootstrapHash;
  if (!workspacePinBootstrapHash) throw new Error("workspace_pin_bootstrap_hash_required");
  const shareTokenHash = blake3Base64Url(base64UrlDecode(shareSlug));
  await worker.prepareOpenShareSecrets({
    shareSlug,
    ...(shareUrlFragment ? { shareUrlFragment } : {}),
  });
  recordShareSessionPerf("share_session_bootstrap_open_secrets_ready", {
    shareSlug,
    elapsedMs: performance.now() - startedAt,
  });
  const shareParticipantPrincipalId = crypto.randomUUID();
  const shareParticipantSessionId = crypto.randomUUID();
  const shareState = shareAuthorizationStateFromLanding(landing);
  const shareParticipantDeviceAuthorizationPromise = signShareParticipantDeviceAuthorization({
    shareSlug,
    shareState,
    shareParticipantPrincipalId,
    shareParticipantSessionId,
  });
  const shareCapabilityAuthorizationPromise = signShareCapabilityAuthorization({
    shareSlug,
    shareTokenHash,
    workspacePinBootstrapHash,
    shareState,
  });
  const shareParticipantDeviceAuthorization = await shareParticipantDeviceAuthorizationPromise;
  recordShareSessionPerf("share_session_bootstrap_device_authorization_ready", {
    shareSlug,
    elapsedMs: performance.now() - startedAt,
  });
  const shareCapabilityAuthorization = await shareCapabilityAuthorizationPromise;
  recordShareSessionPerf("share_session_bootstrap_capability_authorization_ready", {
    shareSlug,
    elapsedMs: performance.now() - startedAt,
  });
  const dskPrewarmStartedAt = performance.now();
  recordShareSessionPerf("share_session_bootstrap_dsk_prewarm_start", {
    shareSlug,
  });
  void ensureWorkerDskForShare(shareSlug).then(
    () => {
      recordShareSessionPerf("share_session_bootstrap_dsk_prewarm_ready", {
        shareSlug,
        elapsedMs: performance.now() - dskPrewarmStartedAt,
      });
    },
    (error: unknown) => {
      recordShareSessionPerf("share_session_bootstrap_dsk_prewarm_failed", {
        shareSlug,
        elapsedMs: performance.now() - dskPrewarmStartedAt,
        error: error instanceof Error ? error.message : String(error),
      });
    },
  );

  const bootstrap = await sharesApi.bootstrap(shareSlug, {
    display_name: DEFAULT_DISPLAY_NAME,
    share_participant_device_id: deviceId,
    share_participant_principal_id: shareParticipantPrincipalId,
    share_participant_session_id: shareParticipantSessionId,
    hybrid_signing_public_key_material:
      publicKeys.deviceHybridSigningPublicKeyMaterial as ShareParticipantDeviceSigningPublicKeyMaterial,
    hybrid_encryption_public_key_material:
      publicKeys.deviceHybridEncryptionPublicKeyMaterial as ShareParticipantDeviceEncryptionPublicKeyMaterial,
    share_capability_authorization: shareCapabilityAuthorization,
    share_participant_device_authorization: shareParticipantDeviceAuthorization,
  });
  recordShareSessionPerf("share_session_bootstrap_api_ready", {
    shareSlug,
    elapsedMs: performance.now() - startedAt,
  });

  if (reusableAnchor) {
    assertShareBootstrapMatchesTrustAnchor(shareSlug, reusableAnchor, {
      share_id: bootstrap.share_id,
      scope_kind: bootstrap.scope_kind,
      scope_id: bootstrap.scope_id,
      permission: bootstrap.participant.grant,
      password_protected: reusableAnchor.passwordProtected,
      share_token_hash: shareTokenHash,
      created_event_hash: bootstrap.created_event_hash,
      latest_bootstrap_event_hash: bootstrap.latest_bootstrap_event_hash,
      capability_context_hash: bootstrap.capability_context_hash,
      share_capability_secret_commitment: bootstrap.share_capability_secret_commitment,
      password_capability_secret_commitment: bootstrap.password_capability_secret_commitment,
    });
  }

  const passwordProtected = reusableAnchor?.passwordProtected ?? false;
  const session = await finalizeShareParticipantSession(
    shareSlug,
    passwordProtected,
    bootstrap,
    publicKeys,
    {
      workspacePinBootstrapHash: workspacePinBootstrapHash,
      ...(shareUrlFragment
        ? { shareUrlFragment }
        : { capabilitySecretHash: reusableAnchor?.capabilitySecretHash }),
      shareTokenHash,
      permission: reusableAnchor?.permission ?? landing!.share.permission,
      sourceKind: shareUrlFragment ? "url_fragment" : "dsk_cache",
    },
    {
      onActiveSessionReady: ({ session, trustAnchor }) => {
        options.onActiveSessionReady?.({ bootstrap, session, trustAnchor });
      },
    },
  );
  recordShareSessionPerf("share_session_bootstrap_ready", {
    shareSlug,
    elapsedMs: performance.now() - startedAt,
  });

  return { bootstrap, session };
}

export async function bootstrapPasswordProtectedShareParticipantSession(
  shareSlug: string,
  password: string,
): Promise<{
  bootstrap: Awaited<ReturnType<typeof sharesApi.respondChallenge>>;
  session: StoredShareParticipantSession;
}> {
  await ensureShareParticipantKeypair(shareSlug, { forceNew: true });
  const publicKeys = await getShareParticipantPublicKeys(shareSlug);
  const worker = getShareParticipantCryptoWorker(shareSlug);
  const deviceId = await worker.getDeviceId();
  const challenge = await sharesApi.getChallenge(shareSlug);
  const reusableAnchor = findReusableShareTrustAnchor(shareSlug);
  const landing = await sharesApi.getLanding(shareSlug);
  const shareUrlFragment = readShareUrlFragment();
  if (!shareUrlFragment && !reusableAnchor) throw new Error("share_capability_secret_required");
  const workspacePinBootstrapHash =
    readWorkspacePinBootstrapHashFromLocation() ?? reusableAnchor?.workspacePinBootstrapHash;
  if (!workspacePinBootstrapHash) throw new Error("workspace_pin_bootstrap_hash_required");
  const shareTokenHash = blake3Base64Url(base64UrlDecode(shareSlug));
  const { response } = await worker.preparePasswordShareSecrets({
    shareSlug,
    password,
    salt: challenge.salt,
    kdfParams: challenge.kdf_params,
    challenge: challenge.challenge,
    ...(shareUrlFragment ? { shareUrlFragment } : {}),
  });
  const shareParticipantPrincipalId = crypto.randomUUID();
  const shareParticipantSessionId = crypto.randomUUID();
  const shareState = shareAuthorizationStateFromLanding(landing);
  const shareParticipantDeviceAuthorization = await signShareParticipantDeviceAuthorization({
    shareSlug,
    shareState,
    shareParticipantPrincipalId,
    shareParticipantSessionId,
  });
  const shareCapabilityAuthorization = await signShareCapabilityAuthorization({
    shareSlug,
    shareTokenHash,
    workspacePinBootstrapHash,
    shareState,
  });

  const bootstrap = await sharesApi.respondChallenge(shareSlug, {
    response,
    display_name: DEFAULT_DISPLAY_NAME,
    share_participant_device_id: deviceId,
    share_participant_principal_id: shareParticipantPrincipalId,
    share_participant_session_id: shareParticipantSessionId,
    hybrid_signing_public_key_material:
      publicKeys.deviceHybridSigningPublicKeyMaterial as ShareParticipantDeviceSigningPublicKeyMaterial,
    hybrid_encryption_public_key_material:
      publicKeys.deviceHybridEncryptionPublicKeyMaterial as ShareParticipantDeviceEncryptionPublicKeyMaterial,
    share_capability_authorization: shareCapabilityAuthorization,
    share_participant_device_authorization: shareParticipantDeviceAuthorization,
    password_challenge_hash: shareTokenHash,
  });

  if (reusableAnchor) {
    assertShareBootstrapMatchesTrustAnchor(shareSlug, reusableAnchor, {
      share_id: bootstrap.share_id,
      scope_kind: bootstrap.scope_kind,
      scope_id: bootstrap.scope_id,
      permission: bootstrap.participant.grant,
      password_protected: reusableAnchor.passwordProtected,
      share_token_hash: shareTokenHash,
      created_event_hash: bootstrap.created_event_hash,
      latest_bootstrap_event_hash: bootstrap.latest_bootstrap_event_hash,
      capability_context_hash: bootstrap.capability_context_hash,
      share_capability_secret_commitment: bootstrap.share_capability_secret_commitment,
      password_capability_secret_commitment: bootstrap.password_capability_secret_commitment,
    });
  }

  const session = await finalizeShareParticipantSession(shareSlug, true, bootstrap, publicKeys, {
    workspacePinBootstrapHash: workspacePinBootstrapHash,
    ...(shareUrlFragment
      ? { shareUrlFragment }
      : { capabilitySecretHash: reusableAnchor?.capabilitySecretHash }),
    shareTokenHash,
    permission: reusableAnchor?.permission ?? landing!.share.permission,
    sourceKind: shareUrlFragment ? "password" : "dsk_cache",
  });

  return { bootstrap, session };
}
