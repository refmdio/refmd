import { sharesApi } from "@/shared/api";
import { readShareSlugFromLocation } from "@/entities/mount";
import { getShareParticipantCryptoWorker } from "@/shared/lib/crypto/worker/scoped";
import { resetPhoenixConnection } from "@/shared/lib/ws/phoenix-channel";
import type { DocumentPayload } from "@/shared/lib/ws/document-payloads";
import {
  ensureShareParticipantDeviceReady,
  readShareSessionTrustAnchor,
  refreshShareSessionTrustAnchorFromBootstrap,
  resolveShareSlugForTokenHash,
} from "../session/session";

function recordShareBootstrapPerf(event: string, detail: Record<string, unknown>): void {
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

export type CanonicalShareDocumentBootstrap = {
  share_slug: string;
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
  document_id: string;
  workspace_id: string;
  encrypted_title: string | null;
  encrypted_title_nonce: string | null;
  encrypted_title_key_version: number | null;
  key_version: number;
  encrypted_key_refs: string[];
  workspace_pin_bootstrap: unknown;
  workspace_key_directory_checkpoint: unknown;
  workspace_key_directory_latest_checkpoint?: unknown;
  workspace_key_directory_checkpoint_ancestry?: unknown;
  workspace_key_directory_event_ancestry?: unknown;
  verification_directory: unknown;
  initial_document?: DocumentPayload | null;
};

export type SharedDocumentBootstrapResult =
  | {
      kind: "bootstrap-required";
      shareSlug: string;
    }
  | {
      kind: "ready";
      response: CanonicalShareDocumentBootstrap;
      session: NonNullable<Awaited<ReturnType<typeof ensureShareParticipantDeviceReady>>>;
      trustAnchor: Awaited<ReturnType<typeof readShareSessionTrustAnchor>>;
    };

let activeShareSocketSlug: string | null = null;

export function clearActiveShareSocketSlug(): void {
  activeShareSocketSlug = null;
}

export async function resolveSharedDocumentBootstrap(
  documentToken: string,
  preferredShareSlug?: string,
): Promise<SharedDocumentBootstrapResult> {
  const startedAt = performance.now();
  recordShareBootstrapPerf("share_document_bootstrap_started", {
    documentToken,
    hasPreferredShareSlug: typeof preferredShareSlug === "string",
  });
  const locationShareSlug =
    preferredShareSlug ?? (typeof window === "undefined" ? null : readShareSlugFromLocation());
  if (locationShareSlug) {
    recordShareBootstrapPerf("share_document_bootstrap_location_slug", {
      documentToken,
      elapsedMs: performance.now() - startedAt,
    });
    const resolved = await resolveSharedDocumentBootstrapForShareSlug(
      documentToken,
      locationShareSlug,
    );
    recordShareBootstrapPerf("share_document_bootstrap_location_resolved", {
      documentToken,
      elapsedMs: performance.now() - startedAt,
      kind: resolved.kind,
    });
    if (resolved.kind === "ready") {
      recordShareBootstrapPerf("share_document_bootstrap_ready", {
        documentToken,
        elapsedMs: performance.now() - startedAt,
        source: "location",
      });
      return resolved;
    }
  }

  recordShareBootstrapPerf("share_document_bootstrap_requirement_start", {
    documentToken,
    elapsedMs: performance.now() - startedAt,
  });
  const requirement = await sharesApi.getDocumentBootstrapRequirement(documentToken);
  recordShareBootstrapPerf("share_document_bootstrap_requirement_ready", {
    documentToken,
    elapsedMs: performance.now() - startedAt,
    bootstrapRequired:
      "bootstrap_required" in requirement ? requirement.bootstrap_required : "invalid",
  });
  if (!("bootstrap_required" in requirement)) {
    throw new Error("share_bootstrap_requirement_invalid");
  }
  const requirementShareSlug = await resolveShareSlugForTokenHash(requirement.share_token_hash);
  recordShareBootstrapPerf("share_document_bootstrap_share_slug_ready", {
    documentToken,
    elapsedMs: performance.now() - startedAt,
    found: Boolean(requirementShareSlug),
  });

  if (requirement.bootstrap_required) {
    if (!requirementShareSlug) {
      throw new Error("share_session_required");
    }
    recordShareBootstrapPerf("share_document_bootstrap_session_check_start", {
      documentToken,
      elapsedMs: performance.now() - startedAt,
    });
    const session = await ensureShareParticipantDeviceReady({
      requiredShareSlug: requirementShareSlug,
    });
    recordShareBootstrapPerf("share_document_bootstrap_session_check_ready", {
      documentToken,
      elapsedMs: performance.now() - startedAt,
      found: Boolean(session),
    });
    if (
      !session ||
      !(await getShareParticipantCryptoWorker(requirementShareSlug).hasShareDekEncryptionKey(
        requirementShareSlug,
      ))
    ) {
      return {
        kind: "bootstrap-required",
        shareSlug: requirementShareSlug,
      };
    }
  }

  if (!requirementShareSlug) {
    throw new Error("share_session_required");
  }

  const resolved = await resolveSharedDocumentBootstrapForShareSlug(
    documentToken,
    requirementShareSlug,
  );
  recordShareBootstrapPerf("share_document_bootstrap_ready", {
    documentToken,
    elapsedMs: performance.now() - startedAt,
    source: "requirement",
    kind: resolved.kind,
  });
  return resolved;
}

async function resolveSharedDocumentBootstrapForShareSlug(
  documentToken: string,
  shareSlug: string,
): Promise<SharedDocumentBootstrapResult> {
  const startedAt = performance.now();
  recordShareBootstrapPerf("share_document_bootstrap_for_slug_started", {
    documentToken,
    shareSlug,
  });
  const anchor = await readShareSessionTrustAnchor(shareSlug);
  recordShareBootstrapPerf("share_document_bootstrap_anchor_ready", {
    documentToken,
    elapsedMs: performance.now() - startedAt,
    hasWorkspacePinBootstrapHash: Boolean(anchor.workspacePinBootstrapHash),
    hasShareDekEncryptionKey: anchor.hasShareDekEncryptionKey,
  });
  if (!anchor.workspacePinBootstrapHash) {
    return {
      kind: "bootstrap-required",
      shareSlug,
    };
  }

  const session = anchor.session;
  recordShareBootstrapPerf("share_document_bootstrap_session_ready", {
    documentToken,
    elapsedMs: performance.now() - startedAt,
    found: Boolean(session),
    source: "trust_anchor",
  });

  if (!session) {
    return {
      kind: "bootstrap-required",
      shareSlug,
    };
  }

  recordShareBootstrapPerf("share_document_bootstrap_fetch_start", {
    documentToken,
    elapsedMs: performance.now() - startedAt,
  });
  const response = await getShareParticipantCryptoWorker(shareSlug).fetchShareDocumentBootstrap({
    documentToken,
    authenticatedWorkspacePinBootstrapHash: anchor.workspacePinBootstrapHash,
  });
  recordShareBootstrapPerf("share_document_bootstrap_fetch_ready", {
    documentToken,
    elapsedMs: performance.now() - startedAt,
    bootstrapRequired: "bootstrap_required" in response,
  });
  if ("bootstrap_required" in response) {
    return {
      kind: "bootstrap-required",
      shareSlug,
    };
  }
  const canonicalResponse = normalizeDocumentBootstrapResponse(response, shareSlug);
  recordShareBootstrapPerf("share_document_bootstrap_refresh_anchor_start", {
    documentToken,
    elapsedMs: performance.now() - startedAt,
  });
  const refreshedAnchor = await refreshShareSessionTrustAnchorFromBootstrap(
    shareSlug,
    anchor.anchor,
    canonicalResponse,
  );
  recordShareBootstrapPerf("share_document_bootstrap_refresh_anchor_ready", {
    documentToken,
    elapsedMs: performance.now() - startedAt,
    refreshed: Boolean(refreshedAnchor),
  });

  recordShareBootstrapPerf("share_document_bootstrap_has_dek_start", {
    documentToken,
    elapsedMs: performance.now() - startedAt,
  });
  if (!(await getShareParticipantCryptoWorker(shareSlug).hasShareDekEncryptionKey(shareSlug))) {
    return {
      kind: "bootstrap-required",
      shareSlug,
    };
  }
  recordShareBootstrapPerf("share_document_bootstrap_has_dek_ready", {
    documentToken,
    elapsedMs: performance.now() - startedAt,
  });

  if (activeShareSocketSlug !== shareSlug) {
    resetPhoenixConnection("share");
    activeShareSocketSlug = shareSlug;
  }

  return {
    kind: "ready",
    response: canonicalResponse,
    session,
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
  };
}

export function normalizeDocumentBootstrapResponse(
  response: Record<string, unknown>,
  shareSlug: string,
): CanonicalShareDocumentBootstrap {
  return {
    share_slug: shareSlug,
    share_id: stringValue(response.share_id, "share_id_invalid"),
    authorization_share_id: optionalString(response.authorization_share_id),
    scope_kind: scopeKindValue(response.scope_kind),
    scope_id: stringValue(response.scope_id, "scope_id_invalid"),
    permission: permissionValue(response.permission),
    password_protected: booleanValue(response.password_protected, "password_protected_invalid"),
    share_token_hash: stringValue(response.share_token_hash, "share_token_hash_invalid"),
    created_event_hash: stringValue(response.created_event_hash, "created_event_hash_invalid"),
    latest_bootstrap_event_hash: stringValue(
      response.latest_bootstrap_event_hash,
      "latest_bootstrap_event_hash_invalid",
    ),
    capability_context_hash: stringValue(
      response.capability_context_hash,
      "capability_context_hash_invalid",
    ),
    share_capability_secret_commitment: stringValue(
      response.share_capability_secret_commitment,
      "share_capability_secret_commitment_invalid",
    ),
    password_capability_secret_commitment: stringValue(
      response.password_capability_secret_commitment,
      "password_capability_secret_commitment_invalid",
    ),
    document_id: stringValue(response.document_id, "document_id_invalid"),
    workspace_id: stringValue(response.workspace_id, "workspace_id_invalid"),
    encrypted_title: nullableString(response.encrypted_title, "encrypted_title_invalid"),
    encrypted_title_nonce: nullableString(
      response.encrypted_title_nonce,
      "encrypted_title_nonce_invalid",
    ),
    encrypted_title_key_version: nullableNumber(
      response.encrypted_title_key_version,
      "encrypted_title_key_version_invalid",
    ),
    key_version: numberValue(response.key_version, "key_version_invalid"),
    encrypted_key_refs: stringArrayValue(response.encrypted_key_refs, "encrypted_key_refs_invalid"),
    workspace_pin_bootstrap: response.workspace_pin_bootstrap,
    workspace_key_directory_checkpoint: response.workspace_key_directory_checkpoint,
    workspace_key_directory_latest_checkpoint: response.workspace_key_directory_latest_checkpoint,
    workspace_key_directory_checkpoint_ancestry:
      response.workspace_key_directory_checkpoint_ancestry,
    workspace_key_directory_event_ancestry: response.workspace_key_directory_event_ancestry,
    verification_directory: response.verification_directory,
    initial_document: optionalDocumentPayload(response.initial_document),
  };
}

function optionalDocumentPayload(value: unknown): DocumentPayload | null | undefined {
  if (value === undefined || value === null) return value;
  if (typeof value !== "object" || Array.isArray(value)) {
    throw new Error("initial_document_invalid");
  }
  const payload = value as Partial<DocumentPayload>;
  if (
    !("snapshot" in payload) ||
    !Array.isArray(payload.updates) ||
    !Array.isArray(payload.snapshotProofChain) ||
    typeof payload.latestVersion !== "number"
  ) {
    throw new Error("initial_document_invalid");
  }
  return payload as DocumentPayload;
}

function stringValue(value: unknown, code: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(code);
  return value;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function nullableString(value: unknown, code: string): string | null {
  if (value === null) return null;
  return stringValue(value, code);
}

function numberValue(value: unknown, code: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) throw new Error(code);
  return value;
}

function nullableNumber(value: unknown, code: string): number | null {
  if (value === null) return null;
  return numberValue(value, code);
}

function booleanValue(value: unknown, code: string): boolean {
  if (typeof value !== "boolean") throw new Error(code);
  return value;
}

function stringArrayValue(value: unknown, code: string): string[] {
  if (
    !Array.isArray(value) ||
    value.some((item) => typeof item !== "string" || item.length === 0)
  ) {
    throw new Error(code);
  }
  return value;
}

function permissionValue(value: unknown): "view" | "edit" {
  if (value === "view" || value === "edit") return value;
  throw new Error("permission_invalid");
}

function scopeKindValue(value: unknown): "document" | "folder" {
  if (value === "document" || value === "folder") return value;
  throw new Error("scope_kind_invalid");
}
