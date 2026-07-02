import { loadMountTrustAnchor, mountTrustAnchorRequest } from "@/entities/mount";
import { restoreStoredShareParticipantSessionMaterial } from "@/shared/lib/auth/share-participant-session-store";
import {
  assertWorkspacePinBootstrapEnvelope,
  type WorkspacePinBootstrapEnvelope,
} from "@/shared/lib/key-directory/workspace-pin-bootstrap";
import { normalizeShareVerificationDirectory } from "@/shared/lib/document/share-verification-directory";
import {
  assertKeyDirectoryEnvelope,
  type KeyDirectoryEnvelope,
} from "@/shared/lib/crypto/key-directory/types";
import type { DocumentState } from "../../model/document-state/types";
import { setDocumentReadOnly } from "../../model/document-state/signals";
import {
  canSharedAccessWriteDurably,
  type SharedDocumentAccess,
} from "../../model/document-state/access";
import { getDocumentCryptoWorker } from "./crypto-worker";
import type { ShareSessionTrustAnchor } from "@/shared/lib/auth/share-participant-session-store";
import {
  getSharedDekCacheKey,
  prewarmSharedDekForAccess,
} from "@/shared/lib/crypto/share-dek-prewarm";

function optionalKeyDirectoryEnvelope(
  value: unknown,
  fallback: KeyDirectoryEnvelope | null | undefined,
  code: string,
): KeyDirectoryEnvelope | null | undefined {
  if (value === undefined) return fallback;
  if (value === null) return null;
  return assertKeyDirectoryEnvelope(value, code);
}

function optionalKeyDirectoryEnvelopeArray(
  value: unknown,
  fallback: KeyDirectoryEnvelope[] | undefined,
  code: string,
): KeyDirectoryEnvelope[] | undefined {
  if (value === undefined) return fallback;
  if (value === null) return undefined;
  if (!Array.isArray(value)) throw new Error(code);
  return value.map((entry) => assertKeyDirectoryEnvelope(entry, code));
}

function optionalWorkspacePinBootstrapEnvelope(
  value: unknown,
  fallback: WorkspacePinBootstrapEnvelope | null | undefined,
  code: string,
): WorkspacePinBootstrapEnvelope | null | undefined {
  if (value === undefined) return fallback;
  if (value === null) return null;
  return assertWorkspacePinBootstrapEnvelope(value, code);
}

export function getDocumentDekCacheKey(state: DocumentState, documentId: string): string {
  if (state.access.kind === "share") {
    return getSharedDekCacheKey(documentId, state.access.shareId);
  }

  return documentId;
}

function toSharedDocumentAccess(
  previous: SharedDocumentAccess,
  response: Record<string, unknown>,
): SharedDocumentAccess {
  if (!("document_id" in response)) {
    throw new Error("share_bootstrap_required");
  }

  return {
    kind: "share",
    source: previous.source,
    documentToken: previous.documentToken,
    shareId: stringValue(response.share_id, "share_id_invalid"),
    authorizationShareId:
      optionalString(response.authorization_share_id) ??
      stringValue(response.share_id, "share_id_invalid"),
    shareSlug: previous.shareSlug,
    participantPrincipalId: previous.participantPrincipalId,
    participantDisplayName: previous.participantDisplayName,
    participantDeviceId: previous.participantDeviceId,
    participantSessionId: previous.participantSessionId,
    participantSigningKeyId: previous.participantSigningKeyId,
    participantHybridSigningPublicKeyMaterial: previous.participantHybridSigningPublicKeyMaterial,
    participantEncryptionPublicKey: previous.participantEncryptionPublicKey,
    permission: permissionValue(response.permission),
    passwordProtected: booleanValue(response.password_protected, "password_protected_invalid"),
    workspaceId: stringValue(response.workspace_id, "workspace_id_invalid"),
    workspacePinBootstrapHash: previous.workspacePinBootstrapHash,
    workspacePinBootstrap: optionalWorkspacePinBootstrapEnvelope(
      response.workspace_pin_bootstrap,
      previous.workspacePinBootstrap,
      "share_workspace_pin_bootstrap_invalid",
    ),
    keyVersion: numberValue(response.key_version, "key_version_invalid"),
    encryptedKeyRefs: stringArrayValue(response.encrypted_key_refs, "encrypted_key_refs_invalid"),
    workspaceKeyDirectoryCheckpoint: optionalKeyDirectoryEnvelope(
      response.workspace_key_directory_checkpoint,
      previous.workspaceKeyDirectoryCheckpoint,
      "share_workspace_key_directory_checkpoint_invalid",
    ),
    workspaceKeyDirectoryLatestCheckpoint: optionalKeyDirectoryEnvelope(
      response.workspace_key_directory_latest_checkpoint,
      previous.workspaceKeyDirectoryLatestCheckpoint,
      "share_workspace_key_directory_latest_checkpoint_invalid",
    ),
    workspaceKeyDirectoryCheckpointAncestry: optionalKeyDirectoryEnvelopeArray(
      response.workspace_key_directory_checkpoint_ancestry,
      previous.workspaceKeyDirectoryCheckpointAncestry,
      "share_workspace_key_directory_checkpoint_ancestry_invalid",
    ),
    workspaceKeyDirectoryEventAncestry: optionalKeyDirectoryEnvelopeArray(
      response.workspace_key_directory_event_ancestry,
      previous.workspaceKeyDirectoryEventAncestry,
      "share_workspace_key_directory_event_ancestry_invalid",
    ),
    workspacePinReady: previous.workspacePinReady,
    shareDekReady: previous.shareDekReady,
    verificationDirectory: normalizeShareVerificationDirectory(response.verification_directory),
    shareTrustAnchor: updateShareTrustAnchor(previous.shareTrustAnchor, previous, response),
  };
}

function updateShareTrustAnchor(
  previousAnchor: ShareSessionTrustAnchor | null | undefined,
  previous: SharedDocumentAccess,
  response: Record<string, unknown>,
): ShareSessionTrustAnchor | null | undefined {
  if (!("document_id" in response) || !previousAnchor) return previousAnchor;

  return {
    ...previousAnchor,
    shareId:
      optionalString(response.authorization_share_id) ??
      stringValue(response.share_id, "share_id_invalid"),
    scopeKind: scopeKindValue(response.scope_kind),
    scopeId: stringValue(response.scope_id, "scope_id_invalid"),
    permission: permissionValue(response.permission),
    passwordProtected: booleanValue(response.password_protected, "password_protected_invalid"),
    workspacePinBootstrapHash:
      previous.workspacePinBootstrapHash ?? previousAnchor.workspacePinBootstrapHash,
    shareTokenHash: stringValue(response.share_token_hash, "share_token_hash_invalid"),
    createdEventHash: stringValue(response.created_event_hash, "created_event_hash_invalid"),
    latestBootstrapEventHash: stringValue(
      response.latest_bootstrap_event_hash,
      "latest_bootstrap_event_hash_invalid",
    ),
    capabilityContextHash: stringValue(
      response.capability_context_hash,
      "capability_context_hash_invalid",
    ),
    shareCapabilitySecretCommitment: stringValue(
      response.share_capability_secret_commitment,
      "share_capability_secret_commitment_invalid",
    ),
    passwordCapabilitySecretCommitment: stringValue(
      response.password_capability_secret_commitment,
      "password_capability_secret_commitment_invalid",
    ),
  };
}

function toMountedSharedDocumentAccess(
  previous: SharedDocumentAccess,
  response: Record<string, unknown>,
  workspacePinBootstrapHash: string,
): SharedDocumentAccess {
  const document = recordValue(response.document, "mounted_share_document_unavailable");

  return {
    kind: "share",
    source: previous.source,
    documentToken: previous.documentToken,
    mountId: previous.mountId,
    shareId: stringValue(document.share_id, "share_id_invalid"),
    authorizationShareId:
      optionalString(document.authorization_share_id) ??
      previous.authorizationShareId ??
      stringValue(document.share_id, "share_id_invalid"),
    shareSlug: previous.shareSlug,
    participantPrincipalId: previous.participantPrincipalId,
    participantDisplayName: previous.participantDisplayName,
    participantDeviceId: previous.participantDeviceId,
    participantSessionId: previous.participantSessionId,
    participantSigningKeyId: previous.participantSigningKeyId,
    participantHybridSigningPublicKeyMaterial: previous.participantHybridSigningPublicKeyMaterial,
    participantEncryptionPublicKey: previous.participantEncryptionPublicKey,
    permission: permissionValue(document.permission),
    passwordProtected: booleanValue(document.password_protected, "password_protected_invalid"),
    workspaceId: stringValue(document.workspace_id, "workspace_id_invalid"),
    workspacePinBootstrapHash,
    workspacePinBootstrap: optionalWorkspacePinBootstrapEnvelope(
      document.workspace_pin_bootstrap,
      previous.workspacePinBootstrap,
      "mounted_share_workspace_pin_bootstrap_invalid",
    ),
    keyVersion: numberValue(document.key_version, "key_version_invalid"),
    encryptedKeyRefs: stringArrayValue(document.encrypted_key_refs, "encrypted_key_refs_invalid"),
    workspaceKeyDirectoryCheckpoint: optionalKeyDirectoryEnvelope(
      (document as Record<string, unknown>).workspace_key_directory_checkpoint,
      previous.workspaceKeyDirectoryCheckpoint,
      "mounted_share_workspace_key_directory_checkpoint_invalid",
    ),
    workspaceKeyDirectoryLatestCheckpoint: optionalKeyDirectoryEnvelope(
      (document as Record<string, unknown>).workspace_key_directory_latest_checkpoint,
      previous.workspaceKeyDirectoryLatestCheckpoint,
      "mounted_share_workspace_key_directory_latest_checkpoint_invalid",
    ),
    workspaceKeyDirectoryCheckpointAncestry: optionalKeyDirectoryEnvelopeArray(
      (document as Record<string, unknown>).workspace_key_directory_checkpoint_ancestry,
      previous.workspaceKeyDirectoryCheckpointAncestry,
      "mounted_share_workspace_key_directory_checkpoint_ancestry_invalid",
    ),
    workspaceKeyDirectoryEventAncestry: optionalKeyDirectoryEnvelopeArray(
      (document as Record<string, unknown>).workspace_key_directory_event_ancestry,
      previous.workspaceKeyDirectoryEventAncestry,
      "mounted_share_workspace_key_directory_event_ancestry_invalid",
    ),
    workspacePinReady: previous.workspacePinReady,
    shareDekReady: previous.shareDekReady,
    verificationDirectory: normalizeShareVerificationDirectory(document.verification_directory),
    shareTrustAnchor: previous.shareTrustAnchor,
  };
}

export async function refreshSharedDocumentAccess(
  state: DocumentState,
): Promise<SharedDocumentAccess> {
  if (state.access.kind !== "share") {
    throw new Error("share_access_unavailable");
  }

  const previousAccess = state.access;
  const access = previousAccess.mountId
    ? await (async () => {
        const anchor = await loadMountTrustAnchor(previousAccess.mountId!);
        if (!anchor) throw new Error("mount_trust_anchor_unavailable");
        if (!(await restoreStoredShareParticipantSessionMaterial(anchor.shareSessionKey))) {
          throw new Error("share_participant_session_unavailable");
        }
        const response = await getDocumentCryptoWorker(state).fetchMountedShareDocumentBootstrap({
          mountId: previousAccess.mountId!,
          documentToken: previousAccess.documentToken,
          authenticatedWorkspacePinBootstrapHash:
            mountTrustAnchorRequest(anchor).authenticatedWorkspacePinBootstrapHash ?? "",
        });
        const mount = recordValue(response.mount, "mount_invalid");
        if (mount.share_id !== anchor.shareId) {
          throw new Error("mount_trust_anchor_share_mismatch");
        }
        const document = recordValue(response.document, "mounted_share_document_unavailable");
        if (
          (optionalString(document.authorization_share_id) ??
            stringValue(document.share_id, "share_id_invalid")) !== anchor.shareId
        ) {
          throw new Error("mount_trust_anchor_document_mismatch");
        }
        return toMountedSharedDocumentAccess(
          previousAccess,
          response,
          anchor.workspacePinBootstrapHash,
        );
      })()
    : await (async () => {
        if (!previousAccess.workspacePinBootstrapHash) {
          throw new Error("share_bootstrap_required");
        }
        if (!previousAccess.shareTrustAnchor) {
          throw new Error("share_bootstrap_required");
        }
        const response = await getDocumentCryptoWorker(state).fetchShareDocumentBootstrap({
          documentToken: previousAccess.documentToken,
          authenticatedWorkspacePinBootstrapHash: previousAccess.workspacePinBootstrapHash,
        });
        if ("bootstrap_required" in response && response.bootstrap_required) {
          window.location.replace(`/share/${previousAccess.shareSlug}${window.location.hash}`);
          throw new Error("share_bootstrap_required");
        }
        return toSharedDocumentAccess(previousAccess, response);
      })();

  state.access = access;
  state.workspaceId = access.workspaceId;
  setDocumentReadOnly(state.stateKey, !canSharedAccessWriteDurably(access));

  return access;
}

export async function ensureSharedDekCached(
  state: DocumentState,
  documentId: string,
  keyVersion: number,
): Promise<void> {
  if (state.access.kind !== "share") {
    throw new Error("share_access_unavailable");
  }

  if (state.access.source === "mounted") {
    await refreshSharedDocumentAccess(state);
  }
  if (
    state.dekResolved &&
    state.keyVersion >= keyVersion &&
    state.access.keyVersion === keyVersion
  ) {
    return;
  }
  const cacheKey = getSharedDekCacheKey(documentId, state.access.shareId);
  const worker = getDocumentCryptoWorker(state);
  if (await worker.hasDek(documentId, keyVersion, cacheKey)) return;

  let access = state.access;
  if (access.keyVersion !== keyVersion) {
    access = await refreshSharedDocumentAccess(state);
  }

  if (access.keyVersion !== keyVersion) {
    throw new Error(`share_dek_version_unavailable:${keyVersion}`);
  }

  await (keyVersion === access.keyVersion && access.shareDekReady
    ? access.shareDekReady
    : prewarmSharedDekForAccess(access, documentId, keyVersion));

  state.dekResolved = true;
  state.keyVersion = Math.max(state.keyVersion, keyVersion);
}

function recordValue(value: unknown, code: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(code);
  return value as Record<string, unknown>;
}

function stringValue(value: unknown, code: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(code);
  return value;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function numberValue(value: unknown, code: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) throw new Error(code);
  return value;
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
