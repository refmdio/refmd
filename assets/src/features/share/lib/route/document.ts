import {
  normalizeDocumentBootstrapResponse,
  resolveSharedDocumentBootstrap,
  type CanonicalShareDocumentBootstrap,
  type SharedDocumentBootstrapResult,
} from "../bootstrap/document";
import { resolveShareTitle } from "./title";
import type { ShareSessionTrustAnchor } from "@/shared/lib/auth/share-participant-session-store";
import {
  normalizeShareVerificationDirectory,
  type ShareVerificationDirectory,
} from "@/shared/lib/document/share-verification-directory";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import {
  assertKeyDirectoryEnvelope,
  type KeyDirectoryEnvelope,
} from "@/shared/lib/crypto/key-directory/types";
import { ensureShareWorkspaceKeyDirectoryPin } from "./workspace-pin";
import {
  assertWorkspacePinBootstrapEnvelope,
  type WorkspacePinBootstrapEnvelope,
} from "@/shared/lib/key-directory/workspace-pin-bootstrap";
import {
  readShareSessionTrustAnchor,
  refreshShareSessionTrustAnchorFromBootstrap,
} from "../session/session";
import { getShareParticipantCryptoWorker } from "@/shared/lib/crypto/worker/scoped";
import type { DocumentPayload } from "@/shared/lib/ws/document-payloads";
import { prewarmSharedDekForAccess } from "@/shared/lib/crypto/share-dek-prewarm";

function recordShareRoutePerf(event: string, detail: Record<string, unknown>): void {
  if (typeof window === "undefined" || !window.__REFMD_E2E__) return;
  const payload = {
    event,
    detail,
    at: Date.now(),
    now: performance.now(),
  };
  const target = window as Window & { __refmdE2ESyncPerf?: unknown[] };
  target.__refmdE2ESyncPerf ??= [];
  target.__refmdE2ESyncPerf.push(payload);
  window.dispatchEvent(new CustomEvent("refmd:sync-perf", { detail: payload }));
}

export type ResolvedShareDocumentRoute =
  | {
      kind: "bootstrap-required";
      shareSlug: string;
    }
  | {
      kind: "ready";
      target: {
        documentToken: string;
        documentId: string;
        title: string;
        workspaceId: string;
      };
      access: {
        documentToken: string;
        shareId: string;
        authorizationShareId?: string;
        shareSlug: string;
        participantPrincipalId: string;
        participantDisplayName: string;
        participantDeviceId: string;
        participantSessionId: string;
        participantSigningKeyId: string;
        participantHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
        participantEncryptionPublicKey: string;
        permission: "view" | "edit";
        passwordProtected: boolean;
        workspaceId: string;
        workspacePinBootstrapHash?: string | null;
        workspacePinBootstrap?: WorkspacePinBootstrapEnvelope | null;
        keyVersion: number;
        encryptedKeyRefs: string[];
        workspaceKeyDirectoryCheckpoint?: KeyDirectoryEnvelope | null;
        workspaceKeyDirectoryLatestCheckpoint?: KeyDirectoryEnvelope | null;
        workspaceKeyDirectoryCheckpointAncestry?: KeyDirectoryEnvelope[];
        workspaceKeyDirectoryEventAncestry?: KeyDirectoryEnvelope[];
        workspacePinReady?: Promise<void>;
        shareDekReady?: Promise<void>;
        verificationDirectory: ShareVerificationDirectory;
        shareTrustAnchor?: ShareSessionTrustAnchor | null;
        initialDocument?: DocumentPayload | null;
      };
    };

const PRELOADED_SHARE_DOCUMENT_ROUTE_TTL_MS = 30_000;

const preloadedShareDocumentRoutes = new Map<
  string,
  {
    expiresAt: number;
    promise: Promise<ResolvedShareDocumentRoute>;
  }
>();

function clearExpiredPreloadedShareDocumentRoutes(): void {
  const now = Date.now();
  for (const [documentToken, entry] of preloadedShareDocumentRoutes) {
    if (entry.expiresAt <= now) preloadedShareDocumentRoutes.delete(documentToken);
  }
}

export function preloadShareDocumentRoute(
  documentToken: string,
  shareSlug?: string,
): Promise<ResolvedShareDocumentRoute> {
  clearExpiredPreloadedShareDocumentRoutes();
  const existing = preloadedShareDocumentRoutes.get(documentToken);
  if (existing) {
    recordShareRoutePerf("share_document_route_preload_reused", { documentToken });
    return existing.promise;
  }

  const startedAt = performance.now();
  recordShareRoutePerf("share_document_route_preload_started", { documentToken });
  const promise = resolveShareDocumentRouteFresh(documentToken, shareSlug)
    .then((resolved) => {
      recordShareRoutePerf("share_document_route_preload_ready", {
        documentToken,
        elapsedMs: performance.now() - startedAt,
        kind: resolved.kind,
      });
      return resolved;
    })
    .catch((error: unknown) => {
      if (preloadedShareDocumentRoutes.get(documentToken)?.promise === promise) {
        preloadedShareDocumentRoutes.delete(documentToken);
      }
      recordShareRoutePerf("share_document_route_preload_failed", {
        documentToken,
        elapsedMs: performance.now() - startedAt,
        error: error instanceof Error ? error.message : String(error),
      });
      throw error;
    });
  preloadedShareDocumentRoutes.set(documentToken, {
    expiresAt: Date.now() + PRELOADED_SHARE_DOCUMENT_ROUTE_TTL_MS,
    promise,
  });
  return promise;
}

export function preloadShareDocumentRouteFromBootstrap(
  documentToken: string,
  shareSlug: string,
  response: Record<string, unknown>,
): Promise<ResolvedShareDocumentRoute> {
  clearExpiredPreloadedShareDocumentRoutes();
  const existing = preloadedShareDocumentRoutes.get(documentToken);
  if (existing) {
    recordShareRoutePerf("share_document_route_preload_reused", {
      documentToken,
      source: "coalesced-bootstrap",
    });
    return existing.promise;
  }

  const startedAt = performance.now();
  recordShareRoutePerf("share_document_route_preload_started", {
    documentToken,
    source: "coalesced-bootstrap",
  });
  const promise = resolveShareDocumentRouteFromCanonicalBootstrap(
    documentToken,
    shareSlug,
    response,
  )
    .then((resolved) => {
      recordShareRoutePerf("share_document_route_preload_ready", {
        documentToken,
        elapsedMs: performance.now() - startedAt,
        kind: resolved.kind,
        source: "coalesced-bootstrap",
      });
      return resolved;
    })
    .catch((error: unknown) => {
      if (preloadedShareDocumentRoutes.get(documentToken)?.promise === promise) {
        preloadedShareDocumentRoutes.delete(documentToken);
      }
      recordShareRoutePerf("share_document_route_preload_failed", {
        documentToken,
        elapsedMs: performance.now() - startedAt,
        error: error instanceof Error ? error.message : String(error),
        source: "coalesced-bootstrap",
      });
      throw error;
    });
  preloadedShareDocumentRoutes.set(documentToken, {
    expiresAt: Date.now() + PRELOADED_SHARE_DOCUMENT_ROUTE_TTL_MS,
    promise,
  });
  return promise;
}

export function consumePreloadedShareDocumentRoute(
  documentToken: string,
): Promise<ResolvedShareDocumentRoute> | null {
  clearExpiredPreloadedShareDocumentRoutes();
  const existing = preloadedShareDocumentRoutes.get(documentToken);
  if (!existing) return null;
  preloadedShareDocumentRoutes.delete(documentToken);
  recordShareRoutePerf("share_document_route_preload_consumed", { documentToken });
  return existing.promise;
}

export function resolveShareDocumentRoute(
  documentToken: string,
): Promise<ResolvedShareDocumentRoute> {
  return resolveShareDocumentRouteFresh(documentToken);
}

async function resolveShareDocumentRouteFresh(
  documentToken: string,
  shareSlug?: string,
): Promise<ResolvedShareDocumentRoute> {
  const startedAt = performance.now();
  recordShareRoutePerf("share_document_route_resolve_started", { documentToken });
  const resolved = await resolveSharedDocumentBootstrap(documentToken, shareSlug);
  recordShareRoutePerf("share_document_route_bootstrap_resolved", {
    documentToken,
    elapsedMs: performance.now() - startedAt,
    kind: resolved.kind,
  });
  return resolveShareDocumentRouteFromBootstrapResult(documentToken, resolved, startedAt);
}

async function resolveShareDocumentRouteFromCanonicalBootstrap(
  documentToken: string,
  shareSlug: string,
  response: Record<string, unknown>,
): Promise<ResolvedShareDocumentRoute> {
  const startedAt = performance.now();
  recordShareRoutePerf("share_document_route_resolve_started", {
    documentToken,
    source: "coalesced-bootstrap",
  });
  const preparedResponse = await getShareParticipantCryptoWorker(
    shareSlug,
  ).prepareShareDocumentBootstrap({
    response,
  });
  const canonicalResponse = normalizeDocumentBootstrapResponse(preparedResponse, shareSlug);
  if (!canonicalResponse.initial_document) {
    void startShareWorkspacePinFromBootstrap(
      documentToken,
      canonicalResponse,
      shareSlug,
      startedAt,
      "coalesced-bootstrap",
    );
    recordShareRoutePerf("share_document_route_coalesced_initial_missing", {
      documentToken,
      elapsedMs: performance.now() - startedAt,
    });
    return resolveShareDocumentRouteFresh(documentToken, shareSlug);
  }
  const anchor = await readShareSessionTrustAnchor(shareSlug);
  if (!anchor.session || !anchor.workspacePinBootstrapHash || !anchor.hasShareDekEncryptionKey) {
    return resolveShareDocumentRouteFresh(documentToken, shareSlug);
  }
  const refreshedAnchor = await refreshShareSessionTrustAnchorFromBootstrap(
    shareSlug,
    anchor.anchor,
    canonicalResponse,
  );
  const resolved = {
    kind: "ready",
    response: canonicalResponse,
    session: anchor.session,
    trustAnchor: {
      ...anchor,
      anchor: refreshedAnchor,
      workspacePinBootstrapHash:
        refreshedAnchor?.workspacePinBootstrapHash ?? anchor.workspacePinBootstrapHash,
      shareCapabilitySecretCommitment:
        refreshedAnchor?.shareCapabilitySecretCommitment ?? anchor.shareCapabilitySecretCommitment,
      passwordCapabilitySecretCommitment:
        refreshedAnchor?.passwordCapabilitySecretCommitment ??
        anchor.passwordCapabilitySecretCommitment,
      capabilityContextHash: refreshedAnchor?.capabilityContextHash ?? anchor.capabilityContextHash,
    },
  } as const satisfies SharedDocumentBootstrapResult;
  recordShareRoutePerf("share_document_route_bootstrap_resolved", {
    documentToken,
    elapsedMs: performance.now() - startedAt,
    kind: resolved.kind,
    source: "coalesced-bootstrap",
  });
  return resolveShareDocumentRouteFromBootstrapResult(documentToken, resolved, startedAt);
}

async function resolveShareDocumentRouteFromBootstrapResult(
  documentToken: string,
  resolved: SharedDocumentBootstrapResult,
  startedAt: number,
): Promise<ResolvedShareDocumentRoute> {
  if (resolved.kind === "bootstrap-required") {
    return {
      kind: "bootstrap-required",
      shareSlug: resolved.shareSlug,
    };
  }

  const trustAnchor = resolved.trustAnchor;
  const workspacePinBootstrap =
    resolved.response.workspace_pin_bootstrap === null
      ? null
      : assertWorkspacePinBootstrapEnvelope(
          resolved.response.workspace_pin_bootstrap,
          "share_workspace_pin_bootstrap_invalid",
        );
  const workspaceKeyDirectoryCheckpoint = assertKeyDirectoryEnvelope(
    resolved.response.workspace_key_directory_checkpoint,
    "share_workspace_key_directory_checkpoint_invalid",
  );
  const workspaceKeyDirectoryLatestCheckpoint = optionalKeyDirectoryEnvelope(
    resolved.response.workspace_key_directory_latest_checkpoint,
    "share_workspace_key_directory_latest_checkpoint_invalid",
  );
  const workspaceKeyDirectoryCheckpointAncestry = keyDirectoryEnvelopeArray(
    resolved.response.workspace_key_directory_checkpoint_ancestry,
    "share_workspace_key_directory_checkpoint_ancestry_invalid",
  );
  const workspaceKeyDirectoryEventAncestry = keyDirectoryEnvelopeArray(
    resolved.response.workspace_key_directory_event_ancestry,
    "share_workspace_key_directory_event_ancestry_invalid",
  );

  const workspacePinReady = ensureShareWorkspaceKeyDirectoryPin({
    workspaceId: resolved.response.workspace_id,
    workspacePinBootstrapHash: trustAnchor.workspacePinBootstrapHash,
    workspacePinBootstrap,
    workspaceKeyDirectoryCheckpoint,
    workspaceKeyDirectoryLatestCheckpoint,
    workspaceKeyDirectoryCheckpointAncestry,
    workspaceKeyDirectoryEventAncestry,
    mismatchCode: "share_workspace_pin_bootstrap_hash_mismatch",
  });
  void workspacePinReady
    .then(() => {
      recordShareRoutePerf("share_document_route_pin_ready", {
        documentToken,
        documentId: resolved.response.document_id,
        elapsedMs: performance.now() - startedAt,
      });
    })
    .catch((error: unknown) => {
      recordShareRoutePerf("share_document_route_pin_failed", {
        documentToken,
        documentId: resolved.response.document_id,
        elapsedMs: performance.now() - startedAt,
        error: error instanceof Error ? error.message : String(error),
      });
    });
  const title = await resolveShareTitle(
    {
      ...resolved.response,
      document_id: resolved.response.document_id,
    },
    {
      passwordProtected: resolved.response.password_protected,
      passwordKey: resolved.response.share_slug,
      fallback: "Shared document",
      workspaceId: resolved.response.workspace_id,
      workspacePinBootstrapHash: trustAnchor.workspacePinBootstrapHash,
      workspacePinBootstrap,
    },
  );
  recordShareRoutePerf("share_document_route_title_ready", {
    documentToken,
    documentId: resolved.response.document_id,
    elapsedMs: performance.now() - startedAt,
  });

  const access: Extract<ResolvedShareDocumentRoute, { kind: "ready" }>["access"] = {
    documentToken,
    shareId: resolved.response.share_id,
    authorizationShareId: resolved.response.authorization_share_id ?? resolved.response.share_id,
    shareSlug: resolved.response.share_slug,
    participantPrincipalId: resolved.session.principalId,
    participantDisplayName: resolved.session.displayName,
    participantDeviceId: resolved.session.deviceId,
    participantSessionId: resolved.session.sessionId,
    participantSigningKeyId: resolved.session.signingKeyId,
    participantHybridSigningPublicKeyMaterial: resolved.session.hybridSigningPublicKeyMaterial,
    participantEncryptionPublicKey: resolved.session.encryptionPublicKey,
    permission: resolved.response.permission,
    passwordProtected: resolved.response.password_protected,
    workspaceId: resolved.response.workspace_id,
    workspacePinBootstrapHash: trustAnchor.workspacePinBootstrapHash,
    workspacePinBootstrap,
    keyVersion: resolved.response.key_version,
    encryptedKeyRefs: resolved.response.encrypted_key_refs,
    workspaceKeyDirectoryCheckpoint,
    workspaceKeyDirectoryLatestCheckpoint,
    workspaceKeyDirectoryCheckpointAncestry,
    workspaceKeyDirectoryEventAncestry,
    workspacePinReady,
    verificationDirectory: normalizeShareVerificationDirectory(
      resolved.response.verification_directory,
    ),
    shareTrustAnchor: trustAnchor.anchor,
    initialDocument: resolved.response.initial_document ?? null,
  };
  const shareDekReady = prewarmSharedDekForAccess(access, resolved.response.document_id);
  access.shareDekReady = shareDekReady;
  void shareDekReady
    .then(() => {
      recordShareRoutePerf("share_document_route_dek_ready", {
        documentToken,
        documentId: resolved.response.document_id,
        elapsedMs: performance.now() - startedAt,
      });
    })
    .catch((error: unknown) => {
      recordShareRoutePerf("share_document_route_dek_failed", {
        documentToken,
        documentId: resolved.response.document_id,
        elapsedMs: performance.now() - startedAt,
        error: error instanceof Error ? error.message : String(error),
      });
    });

  const ready = {
    kind: "ready",
    target: {
      documentToken,
      documentId: resolved.response.document_id,
      title,
      workspaceId: resolved.response.workspace_id,
    },
    access,
  } as const satisfies ResolvedShareDocumentRoute;
  recordShareRoutePerf("share_document_route_ready", {
    documentToken,
    documentId: resolved.response.document_id,
    elapsedMs: performance.now() - startedAt,
  });
  return ready;
}

function optionalKeyDirectoryEnvelope(value: unknown, code: string): KeyDirectoryEnvelope | null {
  if (value === undefined || value === null) return null;
  return assertKeyDirectoryEnvelope(value, code);
}

async function startShareWorkspacePinFromBootstrap(
  documentToken: string,
  response: CanonicalShareDocumentBootstrap,
  shareSlug: string,
  startedAt: number,
  source: string,
): Promise<void> {
  try {
    const anchor = await readShareSessionTrustAnchor(shareSlug);
    if (!anchor.workspacePinBootstrapHash || response.workspace_pin_bootstrap === null) return;
    const workspacePinBootstrap = assertWorkspacePinBootstrapEnvelope(
      response.workspace_pin_bootstrap,
      "share_workspace_pin_bootstrap_invalid",
    );
    const workspaceKeyDirectoryCheckpoint = assertKeyDirectoryEnvelope(
      response.workspace_key_directory_checkpoint,
      "share_workspace_key_directory_checkpoint_invalid",
    );
    await ensureShareWorkspaceKeyDirectoryPin({
      workspaceId: response.workspace_id,
      workspacePinBootstrapHash: anchor.workspacePinBootstrapHash,
      workspacePinBootstrap,
      workspaceKeyDirectoryCheckpoint,
      workspaceKeyDirectoryLatestCheckpoint: optionalKeyDirectoryEnvelope(
        response.workspace_key_directory_latest_checkpoint,
        "share_workspace_key_directory_latest_checkpoint_invalid",
      ),
      workspaceKeyDirectoryCheckpointAncestry: keyDirectoryEnvelopeArray(
        response.workspace_key_directory_checkpoint_ancestry,
        "share_workspace_key_directory_checkpoint_ancestry_invalid",
      ),
      workspaceKeyDirectoryEventAncestry: keyDirectoryEnvelopeArray(
        response.workspace_key_directory_event_ancestry,
        "share_workspace_key_directory_event_ancestry_invalid",
      ),
      mismatchCode: "share_workspace_pin_bootstrap_hash_mismatch",
    });
    recordShareRoutePerf("share_document_route_early_pin_ready", {
      documentToken,
      documentId: response.document_id,
      elapsedMs: performance.now() - startedAt,
      source,
    });
  } catch (error) {
    recordShareRoutePerf("share_document_route_early_pin_failed", {
      documentToken,
      documentId: response.document_id,
      elapsedMs: performance.now() - startedAt,
      error: error instanceof Error ? error.message : String(error),
      source,
    });
  }
}

function keyDirectoryEnvelopeArray(value: unknown, code: string): KeyDirectoryEnvelope[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw new Error(code);
  return value.map((entry) => assertKeyDirectoryEnvelope(entry, code));
}
