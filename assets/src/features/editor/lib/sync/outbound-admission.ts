import { authState, deviceState } from "@/entities/session";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { buildDocumentAdmissionKeyDirectoryAppend } from "@/shared/lib/crypto/key-directory/document-admission-events";
import { base64UrlRandom, eventHash } from "@/shared/lib/crypto/key-directory/primitives";
import type { HybridSignature } from "@/shared/lib/crypto/signature-types";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import { verifyAndInstallWorkspacePinBootstrap } from "@/shared/lib/key-directory/workspace-pin-bootstrap";
import {
  assertKeyDirectoryEnvelope,
  type KeyDirectoryEnvelope,
} from "@/shared/lib/crypto/key-directory/types";
import {
  advanceKeyDirectoryPinWithProof,
  getKeyDirectoryPin,
  hashKeyDirectoryCheckpointEnvelope,
  hydrateVerifiedKeyDirectoryLineage,
  lookupVerifiedKeyDirectoryLineage,
} from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { pushWriteSession } from "@/shared/lib/ws/phoenix-channel";
import type { SharedDocumentAccess } from "../../model/document-state/access";
import type { DocumentState, WriteSessionState } from "../../model/document-state/types";
import { getDocumentCryptoWorker } from "./crypto-worker";
import { getLocalDeviceId } from "./share-identity";
import { recordSyncPerf } from "./perf";

export const keyDirectoryAdvanceSymbol: unique symbol = Symbol("refmd.keyDirectoryAdvance");

export interface KeyDirectoryAdvance {
  scopeKind: "workspace";
  scopeId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  checkpointAncestry: KeyDirectoryEnvelope[];
  eventAncestry: KeyDirectoryEnvelope[];
  authorityEventAncestry?: KeyDirectoryEnvelope[];
}

export function documentOperationAdmissionForTransport<T extends Record<string, unknown>>(
  admission: T,
): T {
  return { ...admission };
}

export interface DocumentOperationAdmissionAuthority {
  directory: { checkpoint: KeyDirectoryEnvelope };
  publicDataFields: {
    ownerKind: "device" | "share_participant_device";
    ownerId: string;
    authorityKind: "workspace_device" | "share_participant_device";
    authorityId: string;
    authorityContextKey: string;
    authorityScopeId: string;
    authorityPermissionVersion: number;
    keyCheckpointSequence: number;
    keyCheckpointHash: string;
  };
  authorityBoundary: {
    previous_workspace_event_sequence: number;
    previous_workspace_event_hash: string;
    admission_event_type:
      | "document_update_accepted"
      | "document_write_session_admitted"
      | "document_snapshot_accepted";
    admission_nonce: string;
    min_dek_version: number;
    document_permission_proof_hash: string;
  };
}

const WRITE_SESSION_LIFETIME_MS = 30_000;
const WRITE_SESSION_RENEW_SKEW_MS = 5_000;
const WRITE_SESSION_MAX_UPDATES = 128;
const WRITE_SESSION_MAX_CIPHERTEXT_BYTES = 256 * 1024;

async function resolveWorkspaceDirectoryForAdmission(params: {
  state: DocumentState;
  deviceId: string;
  directoryAccess: SharedDocumentAccess | null;
  shareAccess: SharedDocumentAccess | null;
}): Promise<{ checkpoint: KeyDirectoryEnvelope }> {
  const access = params.directoryAccess;
  if (!access && !params.state._admissionDirectoryRefreshRequired) {
    const cached = await getCachedWorkspaceDirectory(params.state.workspaceId);
    if (cached) return cached;
  }

  if (!access?.workspaceKeyDirectoryCheckpoint) {
    const directory = await fetchVerifiedKeyDirectory({
      scopeKind: "workspace",
      scopeId: params.state.workspaceId,
      rrpDeviceId: params.deviceId,
      popScope: params.shareAccess ? "share" : "user",
      popWorker: params.shareAccess ? getDocumentCryptoWorker(params.state) : undefined,
    });
    params.state._admissionDirectoryRefreshRequired = false;
    return directory;
  }

  const existingPin = await getKeyDirectoryPin("workspace", params.state.workspaceId);
  if (existingPin && !params.state._admissionDirectoryRefreshRequired) {
    const cached = await getCachedWorkspaceDirectory(params.state.workspaceId);
    if (cached) {
      rememberShareWorkspaceCheckpoint(params.state.access, cached.checkpoint);
      return cached;
    }
  }

  if (access.source === "mounted") {
    if (!existingPin) {
      if (!access.workspacePinBootstrapHash || !access.workspacePinBootstrap) {
        throw new Error("workspace_pin_bootstrap_hash_mismatch");
      }
      await verifyAndInstallWorkspacePinBootstrap({
        workspaceId: params.state.workspaceId,
        authenticatedWorkspacePinBootstrapHash: access.workspacePinBootstrapHash,
        bootstrap: access.workspacePinBootstrap,
        checkpointEnvelope: access.workspaceKeyDirectoryCheckpoint,
        operationSequence: checkpointEventHeadSequence(access.workspaceKeyDirectoryCheckpoint),
      });
    }
    return fetchVerifiedKeyDirectory({
      scopeKind: "workspace",
      scopeId: params.state.workspaceId,
      rrpDeviceId: params.deviceId,
      popScope: "share",
      popWorker: getDocumentCryptoWorker(params.state),
    });
  }

  if (existingPin) {
    return fetchVerifiedKeyDirectory({
      scopeKind: "workspace",
      scopeId: params.state.workspaceId,
      rrpDeviceId: params.deviceId,
      popScope: "share",
      popWorker: getDocumentCryptoWorker(params.state),
    });
  }

  if (!access.workspacePinBootstrapHash || !access.workspacePinBootstrap) {
    throw new Error("workspace_pin_bootstrap_hash_mismatch");
  }

  await verifyAndInstallWorkspacePinBootstrap({
    workspaceId: params.state.workspaceId,
    authenticatedWorkspacePinBootstrapHash: access.workspacePinBootstrapHash,
    bootstrap: access.workspacePinBootstrap,
    checkpointEnvelope: access.workspaceKeyDirectoryCheckpoint,
    operationSequence: checkpointEventHeadSequence(access.workspaceKeyDirectoryCheckpoint),
  });
  return fetchVerifiedKeyDirectory({
    scopeKind: "workspace",
    scopeId: params.state.workspaceId,
    rrpDeviceId: params.deviceId,
    popScope: "share",
    popWorker: getDocumentCryptoWorker(params.state),
  });
}

export async function getCachedWorkspaceDirectory(
  workspaceId: string,
): Promise<{ checkpoint: KeyDirectoryEnvelope } | null> {
  const pin = await getKeyDirectoryPin("workspace", workspaceId);
  if (!pin) return null;
  const lineage =
    lookupVerifiedKeyDirectoryLineage("workspace", workspaceId, pin) ??
    (await hydrateVerifiedKeyDirectoryLineage("workspace", workspaceId, pin));
  const checkpoint = lineage?.checkpoints.find((candidate) => {
    const payload = candidate.payload as Record<string, unknown> | undefined;
    return (
      typeof payload?.sequence === "number" &&
      payload.sequence === pin.checkpointSequence &&
      hashKeyDirectoryCheckpointEnvelope(candidate as unknown as Record<string, unknown>) ===
        pin.checkpointHash
    );
  });
  return checkpoint ? { checkpoint: checkpoint as unknown as KeyDirectoryEnvelope } : null;
}

export async function prepareDocumentOperationAdmissionAuthority(
  state: DocumentState,
  documentId: string,
  signingKeyId: string,
  eventType:
    | "document_update_accepted"
    | "document_snapshot_accepted"
    | "document_write_session_admitted",
  keyVersion: number,
): Promise<DocumentOperationAdmissionAuthority> {
  const sessionDevice = deviceState();
  const worker = getDocumentCryptoWorker(state);
  const deviceId =
    getLocalDeviceId(state) ?? sessionDevice?.deviceId ?? (await worker.getDeviceId());

  if (!deviceId) {
    throw new Error("document_admission_actor_unavailable");
  }

  const shareAccess = state.access.kind === "share" ? state.access : null;
  const directoryAccess = state.access.kind === "share" ? state.access : null;
  const directory = await resolveWorkspaceDirectoryForAdmission({
    state,
    deviceId,
    directoryAccess,
    shareAccess,
  });
  const payload = directory.checkpoint.payload as Record<string, unknown> | undefined;
  if (!payload) throw new Error("key_directory_checkpoint_payload_invalid");
  const sequence = payload.sequence;
  if (typeof sequence !== "number") {
    throw new Error("key_directory_checkpoint_payload_invalid");
  }
  const coveredHead = payload.covered_event_head as Record<string, unknown> | undefined;
  const previousSequence = coveredHead?.head_sequence;
  const previousHash = coveredHead?.head_hash;
  if (typeof previousSequence !== "number" || typeof previousHash !== "string") {
    throw new Error("key_directory_checkpoint_head_invalid");
  }
  const keyCheckpointHash = hashKeyDirectoryCheckpointEnvelope(directory.checkpoint);
  const ownerKind = shareAccess ? "share_participant_device" : "device";
  const ownerId = deviceId;
  const authorityKind = shareAccess ? "share_participant_device" : "workspace_device";
  const authorityId = shareAccess
    ? (shareAccess.authorizationShareId ?? shareAccess.shareId)
    : state.workspaceId;
  const authorityScopeId = shareAccess
    ? (shareAccess.authorizationShareId ?? shareAccess.shareId)
    : state.workspaceId;
  const authorityPermissionVersion = state.authorityPermissionVersion;
  const authorityContextKey = shareAccess
    ? `${authorityId}:${shareAccess.participantPrincipalId}`
    : signingKeyId;
  const permissionProof = {
    protocol: "refmd.document-permission-proof",
    version: 1,
    workspace_id: state.workspaceId,
    document_id: documentId,
    authority_kind: authorityKind,
    authority_id: authorityId,
    authority_context_key: authorityContextKey,
    authority_scope_id: authorityScopeId,
    authority_permission_version: authorityPermissionVersion,
    permission: "edit",
  } as const;

  return {
    directory,
    publicDataFields: {
      ownerKind,
      ownerId,
      authorityKind,
      authorityId,
      authorityContextKey,
      authorityScopeId,
      authorityPermissionVersion,
      keyCheckpointSequence: sequence,
      keyCheckpointHash,
    },
    authorityBoundary: {
      previous_workspace_event_sequence: previousSequence,
      previous_workspace_event_hash: previousHash,
      admission_event_type: eventType,
      admission_nonce: base64UrlRandom(32),
      min_dek_version: keyVersion,
      document_permission_proof_hash: blake3Base64Url(
        canonicalizeStrictBytes(permissionProof as unknown as StrictJsonValue),
      ),
    },
  };
}

export async function buildDocumentOperationAdmission(params: {
  documentId: string;
  state: DocumentState;
  eventType:
    | "document_update_accepted"
    | "document_snapshot_accepted"
    | "document_write_session_admitted";
  operationHash?: string;
  signature?: HybridSignature;
  keyVersion: number;
  authority?: DocumentOperationAdmissionAuthority;
  sessionId?: string;
  sessionNonce?: string;
  issuedAtMs?: number;
  expiresAtMs?: number;
  maxUpdateCount?: number;
  maxCiphertextBytes?: number;
}): Promise<{
  admission: {
    workspaceKeyDirectoryEvents: KeyDirectoryEnvelope[];
    workspaceKeyDirectoryCheckpoint: KeyDirectoryEnvelope;
    workspaceKeyDirectoryCheckpointAncestry: KeyDirectoryEnvelope[];
    workspaceKeyDirectoryEventAncestry: KeyDirectoryEnvelope[];
  };
  keyDirectoryAdvance: KeyDirectoryAdvance;
  admissionEventHash: string;
}> {
  const user = authState()?.user;
  const sessionDevice = deviceState();
  const worker = getDocumentCryptoWorker(params.state);
  const deviceId =
    getLocalDeviceId(params.state) ?? sessionDevice?.deviceId ?? (await worker.getDeviceId());

  if (!deviceId) {
    throw new Error("document_admission_actor_unavailable");
  }

  const shareAccess = params.state.access.kind === "share" ? params.state.access : null;
  const authority = params.authority;
  if (!authority) throw new Error("document_admission_authority_required");
  const directory = authority.directory;
  if (!shareAccess && !user?.id) {
    throw new Error("document_admission_actor_unavailable");
  }
  if (
    shareAccess &&
    (!shareAccess.participantSessionId || !shareAccess.participantHybridSigningPublicKeyMaterial)
  ) {
    throw new Error("document_admission_share_actor_unavailable");
  }

  const append = await buildDocumentAdmissionKeyDirectoryAppend({
    workspaceId: params.state.workspaceId,
    documentId: params.documentId,
    ...(shareAccess
      ? {
          shareId: shareAccess.authorizationShareId ?? shareAccess.shareId,
          shareSessionId: shareAccess.participantSessionId,
          shareSlug: shareAccess.shareSlug,
        }
      : {}),
    checkpointEnvelope: directory.checkpoint,
    actor: shareAccess
      ? {
          kind: "share_participant_device",
          principalId: shareAccess.participantPrincipalId,
          deviceId,
          signingKeyId: shareAccess.participantSigningKeyId,
          hybridSigningPublicKeyMaterial: shareAccess.participantHybridSigningPublicKeyMaterial!,
        }
      : {
          userId: user!.id,
          deviceId,
        },
    eventType: params.eventType,
    operationHash: params.operationHash,
    operationSignatureHash: params.signature
      ? blake3Base64Url(canonicalizeStrictBytes(params.signature as unknown as StrictJsonValue))
      : undefined,
    dekVersion: params.keyVersion,
    minDekVersion: params.keyVersion,
    admissionNonce: authority.authorityBoundary.admission_nonce,
    documentPermissionProofHash: authority.authorityBoundary.document_permission_proof_hash,
    sessionId: params.sessionId,
    sessionNonce: params.sessionNonce,
    issuedAtMs: params.issuedAtMs,
    expiresAtMs: params.expiresAtMs,
    maxUpdateCount: params.maxUpdateCount,
    maxCiphertextBytes: params.maxCiphertextBytes,
  });
  return {
    admission: {
      workspaceKeyDirectoryEvents: append.events,
      workspaceKeyDirectoryCheckpoint: append.checkpoint,
      workspaceKeyDirectoryCheckpointAncestry: [directory.checkpoint],
      workspaceKeyDirectoryEventAncestry: append.events,
    },
    keyDirectoryAdvance: {
      scopeKind: "workspace",
      scopeId: params.state.workspaceId,
      checkpointEnvelope: append.checkpoint,
      checkpointAncestry: [directory.checkpoint],
      eventAncestry: append.events,
      authorityEventAncestry: append.events,
    },
    admissionEventHash: eventHash(append.events[0]!.payload as unknown as Record<string, unknown>),
  };
}

export async function ensureDocumentWriteSession(params: {
  documentId: string;
  state: DocumentState;
  signingKeyId: string;
  keyVersion: number;
  nextCiphertextBytes: number;
  forceRefresh?: boolean;
}): Promise<WriteSessionState> {
  const existing = params.state.writeSession;
  const now = Date.now();
  if (!params.forceRefresh && writeSessionUsable(existing, params, now)) {
    params.state.writeSessionError = null;
    return existing;
  }

  const pending = params.state.writeSessionPromise;
  if (pending) {
    const session = await pending;
    if (!params.forceRefresh && writeSessionUsable(session, params, Date.now())) {
      return session;
    }
  }

  if (params.state._admissionDirectoryRefreshRequired) {
    params.state.writeSessionPromise = null;
  }

  const promise = buildWriteSession(params)
    .then((session) => {
      if (params.state.writeSessionPromise === promise) {
        params.state.writeSessionPromise = null;
        params.state.writeSession = session;
        params.state.writeSessionReadyAt = null;
        params.state.writeSessionError = null;
      }
      return session;
    })
    .catch((err) => {
      if (params.state.writeSessionPromise === promise) {
        params.state.writeSessionPromise = null;
        params.state.writeSessionReadyAt = null;
        params.state.writeSessionError = err instanceof Error ? err.message : String(err);
      }
      throw err;
    });
  params.state.writeSessionPromise = promise;
  return promise;
}

export async function persistDocumentWriteSession(params: {
  documentId: string;
  state: DocumentState;
  session: WriteSessionState;
  markReady?: boolean;
}): Promise<void> {
  if (params.state.writeSession === params.session && params.state.writeSessionReadyAt !== null) {
    return;
  }

  const startedAt = performance.now();
  recordSyncPerf("write_session_push_start", {
    documentId: params.documentId,
    signingKeyId: params.session.signingKeyId,
    writeSessionEventHash: params.session.eventHash,
  });
  await pushWriteSession(
    params.documentId,
    {
      admission: documentOperationAdmissionForTransport(params.session.admission),
      publicData: {
        docId: params.documentId,
        signingKeyId: params.session.signingKeyId,
        keyVersion: params.session.keyVersion,
        ...params.session.publicDataFields,
        writeSessionCounter: 0,
      },
    },
    params.state.stateKey,
  );
  recordSyncPerf("write_session_push_ready", {
    documentId: params.documentId,
    signingKeyId: params.session.signingKeyId,
    writeSessionEventHash: params.session.eventHash,
    elapsedMs: performance.now() - startedAt,
  });

  try {
    await advanceKeyDirectoryPinWithProof(params.session.keyDirectoryAdvance);
    recordSyncPerf("write_session_pin_advanced", {
      documentId: params.documentId,
      signingKeyId: params.session.signingKeyId,
      writeSessionEventHash: params.session.eventHash,
      elapsedMs: performance.now() - startedAt,
    });
  } catch (err) {
    if (!(err instanceof Error) || err.message !== "key_directory_checkpoint_rollback") {
      throw err;
    }
    recordSyncPerf("write_session_pin_advance_skipped", {
      documentId: params.documentId,
      signingKeyId: params.session.signingKeyId,
      writeSessionEventHash: params.session.eventHash,
      elapsedMs: performance.now() - startedAt,
      reason: "key_directory_checkpoint_rollback",
    });
  }
  rememberDocumentAdmissionCheckpoint(params.state, { admission: params.session.admission });
  if (params.markReady !== false && params.state.writeSession === params.session) {
    params.state.writeSessionReadyAt = Date.now();
    params.state.writeSessionError = null;
  }
  recordSyncPerf("write_session_persist_ready", {
    documentId: params.documentId,
    signingKeyId: params.session.signingKeyId,
    writeSessionEventHash: params.session.eventHash,
    elapsedMs: performance.now() - startedAt,
  });
}

function writeSessionUsable(
  session: WriteSessionState | null | undefined,
  params: {
    documentId: string;
    state: DocumentState;
    signingKeyId: string;
    keyVersion: number;
    nextCiphertextBytes: number;
  },
  now: number,
): session is WriteSessionState {
  return (
    !!session &&
    !params.state._admissionDirectoryRefreshRequired &&
    session.documentId === params.documentId &&
    session.signingKeyId === params.signingKeyId &&
    session.keyVersion === params.keyVersion &&
    session.expiresAtMs - WRITE_SESSION_RENEW_SKEW_MS > now &&
    session.usedUpdateCount < session.maxUpdateCount &&
    session.usedCiphertextBytes + params.nextCiphertextBytes <= session.maxCiphertextBytes
  );
}

async function buildWriteSession(params: {
  documentId: string;
  state: DocumentState;
  signingKeyId: string;
  keyVersion: number;
}): Promise<WriteSessionState> {
  const now = Date.now();
  const startedAt = performance.now();
  recordSyncPerf("write_session_build_start", {
    documentId: params.documentId,
    signingKeyId: params.signingKeyId,
  });

  const authority = await prepareDocumentOperationAdmissionAuthority(
    params.state,
    params.documentId,
    params.signingKeyId,
    "document_write_session_admitted",
    params.keyVersion,
  );
  recordSyncPerf("write_session_authority_ready", {
    documentId: params.documentId,
    signingKeyId: params.signingKeyId,
    elapsedMs: performance.now() - startedAt,
  });
  const issuedAtMs = now;
  const expiresAtMs = now + WRITE_SESSION_LIFETIME_MS;
  const sessionId = base64UrlRandom(32);
  const sessionNonce = base64UrlRandom(32);
  const { admission, keyDirectoryAdvance, admissionEventHash } =
    await buildDocumentOperationAdmission({
      documentId: params.documentId,
      state: params.state,
      eventType: "document_write_session_admitted",
      keyVersion: params.keyVersion,
      authority,
      sessionId,
      sessionNonce,
      issuedAtMs,
      expiresAtMs,
      maxUpdateCount: WRITE_SESSION_MAX_UPDATES,
      maxCiphertextBytes: WRITE_SESSION_MAX_CIPHERTEXT_BYTES,
    });
  recordSyncPerf("write_session_admission_ready", {
    documentId: params.documentId,
    signingKeyId: params.signingKeyId,
    writeSessionEventHash: admissionEventHash,
    elapsedMs: performance.now() - startedAt,
  });

  const session: WriteSessionState = {
    documentId: params.documentId,
    signingKeyId: params.signingKeyId,
    keyVersion: params.keyVersion,
    sessionId,
    eventHash: admissionEventHash,
    expiresAtMs,
    maxUpdateCount: WRITE_SESSION_MAX_UPDATES,
    maxCiphertextBytes: WRITE_SESSION_MAX_CIPHERTEXT_BYTES,
    usedUpdateCount: 0,
    usedCiphertextBytes: 0,
    admission: documentOperationAdmissionForTransport(admission),
    keyDirectoryAdvance,
    publicDataFields: {
      ...authority.publicDataFields,
      minDekVersion: params.keyVersion,
      writeSessionEventHash: admissionEventHash,
      writeSessionId: sessionId,
    },
    authorityBoundary: {
      write_session_event_hash: admissionEventHash,
      write_session_id: sessionId,
      min_dek_version: params.keyVersion,
      document_permission_proof_hash: authority.authorityBoundary.document_permission_proof_hash,
    },
  };
  params.state._admissionDirectoryRefreshRequired = false;
  return session;
}

export function rememberShareWorkspaceCheckpoint(
  access: DocumentState["access"],
  checkpoint: KeyDirectoryEnvelope,
): void {
  if (access.kind !== "share") return;
  (access as SharedDocumentAccess).workspaceKeyDirectoryCheckpoint = checkpoint;
}

function checkpointSequence(checkpoint: KeyDirectoryEnvelope | null | undefined): number {
  const payload = checkpoint?.payload;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) return 0;
  const sequence = (payload as Record<string, unknown>).sequence;
  return typeof sequence === "number" && Number.isInteger(sequence) ? sequence : 0;
}

function checkpointEventHeadSequence(checkpoint: KeyDirectoryEnvelope | null | undefined): number {
  const payload = checkpoint?.payload as Record<string, unknown> | undefined;
  const head = payload?.covered_event_head as Record<string, unknown> | undefined;
  const sequence = head?.head_sequence;
  if (typeof sequence !== "number" || !Number.isSafeInteger(sequence) || sequence < 0) {
    throw new Error("workspace_key_directory_checkpoint_head_invalid");
  }
  return sequence;
}

export function rememberDocumentAdmissionCheckpoint(
  state: DocumentState,
  envelope: object | null | undefined,
): void {
  if (state.access.kind !== "share") return;
  const admission = (envelope as Record<string, unknown> | null | undefined)?.admission;
  if (!admission || typeof admission !== "object" || Array.isArray(admission)) return;
  const checkpoint = assertKeyDirectoryEnvelope(
    (admission as Record<string, unknown>).workspaceKeyDirectoryCheckpoint,
    "document_admission_checkpoint_invalid",
  );

  const currentSequence = checkpointSequence(state.access.workspaceKeyDirectoryCheckpoint);
  const nextSequence = checkpointSequence(checkpoint);
  if (nextSequence < currentSequence) return;

  rememberShareWorkspaceCheckpoint(state.access, checkpoint);
}

export function hashSnapshotOperation(ciphertext: Uint8Array): string {
  return blake3Base64Url(ciphertext);
}
