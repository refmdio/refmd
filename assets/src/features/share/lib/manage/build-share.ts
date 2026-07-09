import type { DocumentResponse } from "@/entities/document";
import { cryptoWorkerReady, deviceState, getKekResolverSession } from "@/entities/session";
import { checkEffectivePermission } from "@/entities/workspace";
import { encryptionApi, sharesApi, workspacesApi, type components } from "@/shared/api";
import { base64UrlDecode, base64UrlEncode, randomBytes } from "@/shared/lib/crypto/encoding";
import { TARGET_KDF_PARAMS } from "@/shared/lib/crypto/kdf-params";
import { resolveKekByVersion } from "@/shared/lib/crypto/kek-resolver";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { getKeyDirectoryPin } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import {
  createWorkspacePinBootstrap,
  type WorkspacePinBootstrapEnvelope,
} from "@/shared/lib/key-directory/workspace-pin-bootstrap";
import {
  buildShareCreatedKeyDirectoryAppend,
  buildShareManagementKeyDirectoryAppend,
  buildWorkspaceBatchCheckpoint,
} from "@/shared/lib/crypto/key-directory/share-events";
import { buildWrapIssuedKeyDirectoryAppend } from "@/shared/lib/crypto/key-directory/wrap-events";
import { hashKeyDirectoryCheckpointEnvelope } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import type { HybridEncryptionPublicKeyMaterial } from "@/shared/lib/crypto/hybrid-encryption";
import type { SignedPqWrapRecord } from "@/shared/lib/crypto/signed-pq-wrap";
import type { KeyDirectoryEnvelope } from "@/shared/lib/crypto/key-directory/types";

type SharePermission = "view" | "edit";
type ShareScope = "document" | "folder";
type ShareAuthorizationPublicKeyMaterial =
  components["schemas"]["ShareCapabilitySigningPublicKeyMaterial"];

export interface CreateShareOptions {
  document: DocumentResponse;
  documents: DocumentResponse[];
  permission: SharePermission;
  password?: string;
  expiresEventSequence?: number | null;
  accessLimit?: number | null;
  exclusions?: string[];
}

interface PreparedShareKey {
  encryptedDek: string;
  nonce: string;
}

interface ShareLinkBackupRecipient {
  userId: string;
  deviceId: string;
  encryptionKeyId: string;
  encryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
}

interface FolderShareKeyTarget {
  documentId: string;
  shareId?: string;
}

function generateShareSlug(): string {
  return base64UrlEncode(randomBytes(16));
}

async function resolveWorkspacePinBootstrap(params: { workspaceId: string }): Promise<{
  hash: string;
  bootstrap: WorkspacePinBootstrapEnvelope;
  checkpoint: KeyDirectoryEnvelope;
}> {
  const device = deviceState();
  if (!device?.deviceId) {
    throw new Error("workspace_pin_bootstrap_device_unavailable");
  }

  const pin = await getKeyDirectoryPin("workspace", params.workspaceId);
  if (!pin) throw new Error("workspace_key_directory_pin_required");
  const directory = await fetchVerifiedKeyDirectory({
    scopeKind: "workspace",
    scopeId: params.workspaceId,
    rrpDeviceId: device.deviceId,
  });
  const bootstrap = await createWorkspacePinBootstrap({
    workspaceId: params.workspaceId,
    checkpointEnvelope: directory.checkpoint,
    actorUserId: requireCurrentUserId(),
    actorDeviceId: device.deviceId,
  });
  return { ...bootstrap, checkpoint: directory.checkpoint };
}

async function listShareLinkBackupRecipients(
  workspaceId: string,
): Promise<ShareLinkBackupRecipient[]> {
  const recipients = new Map<string, ShareLinkBackupRecipient>();
  const [{ members }, { roles }] = await Promise.all([
    workspacesApi.listMembers(workspaceId),
    workspacesApi.listRoles(workspaceId),
  ]);

  await Promise.all(
    members
      .filter((member) => {
        const roleId = member.role_id;
        return (
          checkEffectivePermission(roles, roleId, "document:manage_share") ||
          checkEffectivePermission(roles, roleId, "workspace:admin")
        );
      })
      .map(async (member) => {
        const response = await workspacesApi.listMemberDevices(workspaceId, member.user_id);
        for (const device of response.devices) {
          if (device.revoked_at) continue;
          recipients.set(device.device_id, {
            userId: member.user_id,
            deviceId: device.device_id,
            encryptionKeyId: device.encryption_key_id,
            encryptionPublicKeyMaterial:
              device.hybrid_encryption_public_key_material as unknown as HybridEncryptionPublicKeyMaterial,
          });
        }
      }),
  );

  return [...recipients.values()];
}

function operationCheckpointFromEnvelope(checkpointEnvelope: KeyDirectoryEnvelope) {
  const payload = checkpointEnvelope.payload as Record<string, unknown> | undefined;
  const covered = payload?.covered_event_head as Record<string, unknown> | undefined;
  if (!payload || !covered) throw new Error("key_directory_checkpoint_invalid");
  return {
    sequence: numberField(payload.sequence),
    checkpointHash: hashKeyDirectoryCheckpointEnvelope(checkpointEnvelope),
    coveredHeadSequence: numberField(covered.head_sequence),
    coveredHeadHash: stringField(covered.head_hash),
  };
}

function numberField(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new Error("key_directory_number_invalid");
  }
  return value;
}

function stringField(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("key_directory_string_invalid");
  }
  return value;
}

export async function buildShareSettingsKeyDirectoryAppend(input: {
  workspaceId: string;
  shareId: string;
  expiresEventSequence: number;
  maxViews: number;
}): Promise<{
  workspace_key_directory_events: KeyDirectoryEnvelope[];
  workspace_key_directory_checkpoint: KeyDirectoryEnvelope;
}> {
  const workspacePinBootstrap = await resolveWorkspacePinBootstrap({
    workspaceId: input.workspaceId,
  });
  const sequence = nextWorkspaceEventSequence(workspacePinBootstrap.checkpoint);
  const append = await buildShareManagementKeyDirectoryAppend({
    workspaceId: input.workspaceId,
    actorUserId: requireCurrentUserId(),
    actorDeviceId: requireCurrentDeviceId(),
    checkpointEnvelope: workspacePinBootstrap.checkpoint,
    eventType: "share_metadata_updated",
    body: {
      workspace_id: input.workspaceId,
      share_id: input.shareId,
      expires_event_sequence: input.expiresEventSequence,
      max_views: input.maxViews,
      updated_at_event_sequence: sequence,
      metadata_update_nonce: base64UrlEncode(randomBytes(32)),
    },
  });

  return {
    workspace_key_directory_events: append.events,
    workspace_key_directory_checkpoint: append.checkpoint,
  };
}

export async function buildShareRevokedKeyDirectoryAppend(input: {
  workspaceId: string;
  shareId: string;
  reason?: string;
}): Promise<{
  workspace_key_directory_events: KeyDirectoryEnvelope[];
  workspace_key_directory_checkpoint: KeyDirectoryEnvelope;
}> {
  const workspacePinBootstrap = await resolveWorkspacePinBootstrap({
    workspaceId: input.workspaceId,
  });
  const sequence = nextWorkspaceEventSequence(workspacePinBootstrap.checkpoint);
  const append = await buildShareManagementKeyDirectoryAppend({
    workspaceId: input.workspaceId,
    actorUserId: requireCurrentUserId(),
    actorDeviceId: requireCurrentDeviceId(),
    checkpointEnvelope: workspacePinBootstrap.checkpoint,
    eventType: "share_revoked",
    body: {
      workspace_id: input.workspaceId,
      share_id: input.shareId,
      revoked_at_event_sequence: sequence,
      reason: input.reason ?? "user_revoked",
    },
  });

  return {
    workspace_key_directory_events: append.events,
    workspace_key_directory_checkpoint: append.checkpoint,
  };
}

export async function buildShareExclusionKeyDirectoryAppend(input: {
  workspaceId: string;
  shareId: string;
  add: string[];
  remove: string[];
}): Promise<{
  workspace_key_directory_events: KeyDirectoryEnvelope[];
  workspace_key_directory_checkpoint: KeyDirectoryEnvelope;
}> {
  const workspacePinBootstrap = await resolveWorkspacePinBootstrap({
    workspaceId: input.workspaceId,
  });
  const sequence = nextWorkspaceEventSequence(workspacePinBootstrap.checkpoint);
  const append = await buildShareManagementKeyDirectoryAppend({
    workspaceId: input.workspaceId,
    actorUserId: requireCurrentUserId(),
    actorDeviceId: requireCurrentDeviceId(),
    checkpointEnvelope: workspacePinBootstrap.checkpoint,
    eventType: "share_exclusion_changed",
    body: {
      workspace_id: input.workspaceId,
      share_id: input.shareId,
      added_scope_hashes: input.add.map((scopeId) => shareScopeHash("document", scopeId)),
      removed_scope_hashes: input.remove.map((scopeId) => shareScopeHash("document", scopeId)),
      changed_at_event_sequence: sequence,
      exclusion_change_nonce: base64UrlEncode(randomBytes(32)),
    },
  });

  return {
    workspace_key_directory_events: append.events,
    workspace_key_directory_checkpoint: append.checkpoint,
  };
}

export async function buildShareKeyScopeKeyDirectoryAppend(input: {
  workspaceId: string;
  shareId: string;
  share: {
    permission: SharePermission;
    password_protected: boolean;
    max_views?: number | null;
    expires_event_sequence?: number | null;
  };
  documents: DocumentResponse[];
  addKeys: Array<{ document_id: string; share_id: string }>;
  replaceKeys: Array<{ document_id: string; share_id: string }>;
}): Promise<{
  workspace_key_directory_events: KeyDirectoryEnvelope[];
  workspace_key_directory_checkpoint: KeyDirectoryEnvelope;
}> {
  const workspacePinBootstrap = await resolveWorkspacePinBootstrap({
    workspaceId: input.workspaceId,
  });
  let checkpoint = workspacePinBootstrap.checkpoint;
  const events: KeyDirectoryEnvelope[] = [];
  const documentsById = new Map(input.documents.map((document) => [document.id, document]));

  for (const entry of input.addKeys) {
    const sequence = nextWorkspaceEventSequence(checkpoint);
    const append = await buildShareManagementKeyDirectoryAppend({
      workspaceId: input.workspaceId,
      actorUserId: requireCurrentUserId(),
      actorDeviceId: requireCurrentDeviceId(),
      checkpointEnvelope: checkpoint,
      eventType: "share_key_scope_added",
      body: {
        workspace_id: input.workspaceId,
        share_id: entry.share_id,
        parent_share_id: input.shareId,
        scope_kind: shareScopeKindForDocument(documentsById, entry.document_id),
        scope_id: entry.document_id,
        document_scope_hash: shareScopeHash(
          shareScopeKindForDocument(documentsById, entry.document_id),
          entry.document_id,
        ),
        share_metadata_hash: shareMetadataHash(input.share),
        share_key_version: 1,
        added_at_event_sequence: sequence,
      },
    });
    events.push(...append.events);
    checkpoint = append.checkpoint;
  }

  for (const entry of input.replaceKeys) {
    const sequence = nextWorkspaceEventSequence(checkpoint);
    const append = await buildShareManagementKeyDirectoryAppend({
      workspaceId: input.workspaceId,
      actorUserId: requireCurrentUserId(),
      actorDeviceId: requireCurrentDeviceId(),
      checkpointEnvelope: checkpoint,
      eventType: "share_key_scope_replaced",
      body: {
        workspace_id: input.workspaceId,
        share_id: entry.share_id,
        scope_kind: shareScopeKindForDocument(documentsById, entry.document_id),
        scope_id: entry.document_id,
        document_scope_hash: shareScopeHash(
          shareScopeKindForDocument(documentsById, entry.document_id),
          entry.document_id,
        ),
        share_metadata_hash: shareMetadataHash(input.share),
        share_key_version: 2,
        previous_share_key_version: 1,
        replaced_at_event_sequence: sequence,
      },
    });
    events.push(...append.events);
    checkpoint = append.checkpoint;
  }

  return {
    workspace_key_directory_events: events,
    workspace_key_directory_checkpoint: checkpoint,
  };
}

function activeDescendants(
  root: DocumentResponse,
  documents: DocumentResponse[],
): DocumentResponse[] {
  const byParent = new Map<string | null, DocumentResponse[]>();
  for (const document of documents) {
    if (document.archived_at) continue;
    const siblings = byParent.get(document.parent_id ?? null) ?? [];
    siblings.push(document);
    byParent.set(document.parent_id ?? null, siblings);
  }

  const result: DocumentResponse[] = [];
  const visit = (parentId: string) => {
    for (const child of byParent.get(parentId) ?? []) {
      result.push(child);
      if (child.doc_type === "folder") visit(child.id);
    }
  };

  visit(root.id);
  return result;
}

function expandExcludedDescendants(
  descendants: DocumentResponse[],
  excludedIds: string[],
): Set<string> {
  const byParent = new Map<string | null, DocumentResponse[]>();
  for (const document of descendants) {
    const siblings = byParent.get(document.parent_id ?? null) ?? [];
    siblings.push(document);
    byParent.set(document.parent_id ?? null, siblings);
  }

  const expanded = new Set(excludedIds);
  const visit = (parentId: string) => {
    for (const child of byParent.get(parentId) ?? []) {
      expanded.add(child.id);
      if (child.doc_type === "folder") visit(child.id);
    }
  };

  for (const excludedId of excludedIds) visit(excludedId);
  return expanded;
}

function shareableDescendants(
  root: DocumentResponse,
  documents: DocumentResponse[],
  exclusions: string[] = [],
): DocumentResponse[] {
  const descendants = activeDescendants(root, documents);
  if (exclusions.length === 0) return descendants;

  const descendantIds = new Set(descendants.map((document) => document.id));
  const excludedIds = exclusions.filter((documentId) => descendantIds.has(documentId));
  const expandedExclusions = expandExcludedDescendants(descendants, excludedIds);
  return descendants.filter((document) => !expandedExclusions.has(document.id));
}

async function ensureDocumentDekCached(document: DocumentResponse): Promise<number> {
  const worker = getCryptoWorker();
  const keysResponse = await encryptionApi.getDocumentKeys(document.id);
  const activeKey = keysResponse.keys.find((key) => key.is_active);
  if (!activeKey) throw new Error("No active document key");

  if (await worker.hasDek(document.id, activeKey.key_version)) {
    return activeKey.key_version;
  }

  await resolveKekByVersion(document.workspace_id, activeKey.kek_version, getKekResolverSession());
  await worker.unwrapDek({
    encryptedDek: base64UrlDecode(activeKey.encrypted_dek),
    nonce: base64UrlDecode(activeKey.nonce),
    documentId: document.id,
    workspaceId: document.workspace_id,
    keyVersion: activeKey.key_version,
    kekVersion: activeKey.kek_version,
    isActive: activeKey.is_active,
  });

  return activeKey.key_version;
}

async function prepareShareKey(
  document: DocumentResponse,
  shareId: string,
  shareSlug: string,
): Promise<PreparedShareKey> {
  const keyVersion = await ensureDocumentDekCached(document);
  const wrapped = await getCryptoWorker().wrapPreparedShareDek({
    shareSlug,
    documentId: document.id,
    shareId,
    keyVersion,
  });

  return {
    encryptedDek: base64UrlEncode(wrapped.encryptedDek),
    nonce: base64UrlEncode(wrapped.nonce),
  };
}

export async function prepareFolderShareKeyEntries(
  root: DocumentResponse,
  documents: DocumentResponse[],
  options: {
    shareSlug: string;
    targets?: FolderShareKeyTarget[];
  },
): Promise<
  Array<{
    document_id: string;
    share_id: string;
    encrypted_dek: string;
    nonce: string;
  }>
> {
  const descendants = activeDescendants(root, documents);
  const descendantsById = new Map(descendants.map((document) => [document.id, document]));
  const targets: FolderShareKeyTarget[] =
    options.targets ??
    descendants.map((document) => ({
      documentId: document.id,
    }));

  return Promise.all(
    targets.map(async (target) => {
      const document = descendantsById.get(target.documentId);
      if (!document) throw new Error("Share target is no longer available.");

      const childShareId = target.shareId ?? crypto.randomUUID();
      const childKey = await prepareShareKey(document, childShareId, options.shareSlug);
      return {
        document_id: document.id,
        share_id: childShareId,
        encrypted_dek: childKey.encryptedDek,
        nonce: childKey.nonce,
      };
    }),
  );
}

export async function createManagedShare(options: CreateShareOptions) {
  if (!cryptoWorkerReady()) throw new Error("Crypto worker not ready");

  const root = options.document;
  const scope: ShareScope = root.doc_type === "folder" ? "folder" : "document";
  const shareId = crypto.randomUUID();
  const shareSlug = generateShareSlug();
  const workspacePinBootstrap = await resolveWorkspacePinBootstrap({
    workspaceId: root.workspace_id,
  });
  const workspacePinBootstrapHash = workspacePinBootstrap.hash;
  const password = options.password?.trim() ?? "";

  let passwordFields: { kdf_params: components["schemas"]["KdfParams"]; salt: string } | undefined;
  let authorizationPublicKeyMaterial: ShareAuthorizationPublicKeyMaterial | null = null;
  let shareCapabilitySecretCommitment = "";
  let passwordCapabilitySecretCommitment = "none";
  let authKey: string | undefined;
  let shareUrlFragment = "";

  if (password) {
    const salt = randomBytes(16);
    const prepared = await getCryptoWorker().prepareManagedShareSecrets({
      shareSlug,
      password,
      salt: base64UrlEncode(salt),
      kdfParams: TARGET_KDF_PARAMS,
    });
    passwordFields = prepared.passwordFields;
    shareUrlFragment = prepared.shareUrlFragment;
    shareCapabilitySecretCommitment = prepared.shareCapabilitySecretCommitment;
    passwordCapabilitySecretCommitment = prepared.passwordCapabilitySecretCommitment ?? "none";
    authKey = prepared.authKey;
    authorizationPublicKeyMaterial = prepared.authorizationPublicKeyMaterial;
  } else {
    const prepared = await getCryptoWorker().prepareManagedShareSecrets({
      shareSlug,
    });
    shareCapabilitySecretCommitment = prepared.shareCapabilitySecretCommitment;
    authorizationPublicKeyMaterial = prepared.authorizationPublicKeyMaterial;
    shareUrlFragment = prepared.shareUrlFragment;
  }

  try {
    if (!authorizationPublicKeyMaterial) throw new Error("share_authorization_public_key_required");
    const rootKey = await prepareShareKey(root, shareId, shareSlug);
    const base = {
      id: shareId,
      share_slug: shareSlug,
      token_prefix: shareSlug.slice(0, 4),
      authorization_public_key_material: authorizationPublicKeyMaterial,
      share_capability_secret_commitment: shareCapabilitySecretCommitment,
      password_capability_secret_commitment: passwordCapabilitySecretCommitment,
      permission: options.permission,
      password_protected: Boolean(password),
      authenticated_workspace_pin_bootstrap_hash: workspacePinBootstrapHash,
      authenticated_workspace_pin_bootstrap: workspacePinBootstrap.bootstrap,
      encrypted_dek: rootKey.encryptedDek,
      nonce: rootKey.nonce,
      ...passwordFields,
      ...(authKey ? { auth_key: authKey } : {}),
      expires_event_sequence: options.expiresEventSequence ?? Number.MAX_SAFE_INTEGER,
      max_views: options.accessLimit ?? Number.MAX_SAFE_INTEGER,
    };

    const shareCreatedBody = buildShareCreatedEventBody({
      workspaceId: root.workspace_id,
      shareId,
      scopeKind: scope,
      scopeId: root.id,
      permission: options.permission,
      passwordProtected: Boolean(password),
      accessLimit: options.accessLimit ?? null,
      expiresEventSequence: options.expiresEventSequence ?? null,
      tokenHash: blake3Base64Url(base64UrlDecode(shareSlug)),
      workspacePinBootstrapHash,
      authorizationPublicKeyMaterial,
      shareCapabilitySecretCommitment,
      passwordCapabilitySecretCommitment,
      passwordFields,
    });
    const shareAppend = await buildShareCreatedKeyDirectoryAppend({
      workspaceId: root.workspace_id,
      actorUserId: requireCurrentUserId(),
      actorDeviceId: requireCurrentDeviceId(),
      checkpointEnvelope: workspacePinBootstrap.checkpoint,
      body: shareCreatedBody,
    });
    const createdEvent = shareAppend.events.find(
      (event) =>
        ((event as Record<string, unknown>).payload as Record<string, unknown> | undefined)
          ?.event_type === "share_created",
    ) as Record<string, unknown> | undefined;
    const createdPayload = createdEvent?.payload as Record<string, unknown> | undefined;
    const createdEventHash = createdPayload
      ? blake3Base64Url(canonicalizeStrictBytes(createdPayload as StrictJsonValue))
      : "";
    if (!createdEventHash) throw new Error("share_created_event_hash_unavailable");
    const backupWraps = await buildShareLinkSecretBackupWraps({
      workspaceId: root.workspace_id,
      shareId,
      shareSlug,
      tokenHash: blake3Base64Url(base64UrlDecode(shareSlug)),
      scopeKind: scope,
      scopeId: root.id,
      permission: options.permission,
      passwordProtected: Boolean(password),
      createdEventHash,
      shareCapabilitySecretCommitment,
      passwordCapabilitySecretCommitment,
      workspacePinBootstrapHash,
      checkpoint: shareAppend.checkpoint,
    });

    const workspaceKeyDirectoryEvents = [...shareAppend.events, ...backupWraps.events];
    const workspaceKeyDirectoryCheckpoint = await buildWorkspaceBatchCheckpoint({
      workspaceId: root.workspace_id,
      checkpointEnvelope: workspacePinBootstrap.checkpoint,
      events: workspaceKeyDirectoryEvents,
    });
    const finalOperationCheckpoint = operationCheckpointFromEnvelope(
      workspaceKeyDirectoryCheckpoint,
    );
    const shareLinkSecretBackupWraps = await Promise.all(
      backupWraps.wraps.map((wrap) =>
        getCryptoWorker().finalizeSignedPqWrapOperationCheckpoint({
          record: wrap,
          operationCheckpoint: finalOperationCheckpoint,
        }),
      ),
    );

    const body: components["schemas"]["CreateShareRequest"] =
      scope === "folder"
        ? {
            ...base,
            scope,
            exclusions: options.exclusions ?? [],
            share_keys: await Promise.all(
              shareableDescendants(root, options.documents, options.exclusions).map(
                async (document) => {
                  const childShareId = crypto.randomUUID();
                  const childKey = await prepareShareKey(document, childShareId, shareSlug);
                  return {
                    document_id: document.id,
                    share_id: childShareId,
                    encrypted_dek: childKey.encryptedDek,
                    nonce: childKey.nonce,
                  };
                },
              ),
            ),
            share_link_secret_backup_wraps: shareLinkSecretBackupWraps,
            workspace_key_directory_events: workspaceKeyDirectoryEvents,
            workspace_key_directory_checkpoint: workspaceKeyDirectoryCheckpoint,
          }
        : {
            ...base,
            scope,
            share_link_secret_backup_wraps: shareLinkSecretBackupWraps,
            workspace_key_directory_events: workspaceKeyDirectoryEvents,
            workspace_key_directory_checkpoint: workspaceKeyDirectoryCheckpoint,
          };

    const result = await sharesApi.createDocumentShare(root.id, body);
    return {
      ...result,
      share_url_fragment: shareUrlFragment,
      workspace_pin_bootstrap_hash: workspacePinBootstrapHash,
    };
  } finally {
    await getCryptoWorker().clearShareSecrets(shareSlug);
  }
}

function requireCurrentUserId(): string {
  const userId = getKekResolverSession().auth?.user.id;
  if (!userId) throw new Error("share_actor_user_required");
  return userId;
}

function requireCurrentDeviceId(): string {
  const deviceId = deviceState()?.deviceId;
  if (!deviceId) throw new Error("share_actor_device_required");
  return deviceId;
}

function nextWorkspaceEventSequence(checkpointEnvelope: KeyDirectoryEnvelope): number {
  const payload = checkpointEnvelope.payload as Record<string, unknown> | undefined;
  const coveredHead = payload?.covered_event_head as Record<string, unknown> | undefined;
  const sequence = coveredHead?.head_sequence;
  if (typeof sequence !== "number" || !Number.isSafeInteger(sequence) || sequence < 0) {
    throw new Error("workspace_key_directory_checkpoint_head_invalid");
  }
  return sequence + 1;
}

function shareScopeHash(scopeKind: ShareScope, scopeId: string): string {
  return blake3Base64Url(
    canonicalizeStrictBytes({
      scope_kind: scopeKind,
      scope_id: scopeId,
    }),
  );
}

function shareScopeKindForDocument(
  documentsById: Map<string, DocumentResponse>,
  documentId: string,
): ShareScope {
  return documentsById.get(documentId)?.doc_type === "folder" ? "folder" : "document";
}

function shareMetadataHash(share: {
  permission: SharePermission;
  password_protected: boolean;
  max_views?: number | null;
  expires_event_sequence?: number | null;
}): string {
  return blake3Base64Url(
    canonicalizeStrictBytes({
      permission: share.permission,
      password_protected: share.password_protected,
      max_views: share.max_views ?? Number.MAX_SAFE_INTEGER,
      expires_event_sequence: share.expires_event_sequence ?? Number.MAX_SAFE_INTEGER,
    }),
  );
}

function passwordAuthMetadataHash(input: {
  shareId: string;
  passwordFields?: { kdf_params: components["schemas"]["KdfParams"]; salt: string };
}): string {
  if (!input.passwordFields) return "none";

  const serverAuthKeyWrapAadHash = blake3Base64Url(
    canonicalizeStrictBytes({
      protocol: "refmd",
      version: 1,
      purpose: "server_auth_key_wrap",
      share_id: input.shareId,
    }),
  );

  return blake3Base64Url(
    canonicalizeStrictBytes({
      protocol: "refmd.password-auth-metadata-public",
      version: 1,
      share_id: input.shareId,
      auth_scheme: "argon2id-hmac-authkey",
      salt: input.passwordFields.salt,
      kdf_params: input.passwordFields.kdf_params,
      server_auth_key_wrap_aad_hash: serverAuthKeyWrapAadHash,
    } as StrictJsonValue),
  );
}

export function shareExpiresEventSequence(sequence: number | null): number {
  return sequence ?? Number.MAX_SAFE_INTEGER;
}

function buildShareCreatedEventBody(input: {
  workspaceId: string;
  shareId: string;
  scopeKind: ShareScope;
  scopeId: string;
  permission: SharePermission;
  passwordProtected: boolean;
  accessLimit: number | null;
  expiresEventSequence: number | null;
  tokenHash: string;
  workspacePinBootstrapHash: string;
  authorizationPublicKeyMaterial: ShareAuthorizationPublicKeyMaterial;
  shareCapabilitySecretCommitment: string;
  passwordFields?: { kdf_params: components["schemas"]["KdfParams"]; salt: string };
  passwordCapabilitySecretCommitment: string;
}): Record<string, unknown> {
  const passwordAuthMetadataHashValue = passwordAuthMetadataHash({
    shareId: input.shareId,
    passwordFields: input.passwordFields,
  });
  const maxViews = input.accessLimit ?? Number.MAX_SAFE_INTEGER;
  const redeemAuthorityPolicy = input.passwordProtected ? "password_challenge" : "capability_url";
  const capabilityContextHash = blake3Base64Url(
    canonicalizeStrictBytes({
      protocol: "refmd.share-capability-context",
      version: 1,
      workspace_id: input.workspaceId,
      share_id: input.shareId,
      scope_kind: input.scopeKind,
      scope_id: input.scopeId,
      token_hash: input.tokenHash,
      permission: input.permission,
      share_capability_secret_commitment: input.shareCapabilitySecretCommitment,
      workspace_pin_bootstrap_hash: input.workspacePinBootstrapHash,
      authenticated_bootstrap_source: "url-fragment",
      password_protected: input.passwordProtected,
      password_auth_metadata_hash: passwordAuthMetadataHashValue,
      password_capability_secret_commitment: input.passwordCapabilitySecretCommitment,
      max_views: maxViews,
      redeem_authority_policy: redeemAuthorityPolicy,
    } as unknown as StrictJsonValue),
  );
  return {
    workspace_id: input.workspaceId,
    share_id: input.shareId,
    scope_kind: input.scopeKind,
    scope_id: input.scopeId,
    permission: input.permission,
    share_key_version: 1,
    password_protected: input.passwordProtected,
    authorization_public_key_material: input.authorizationPublicKeyMaterial,
    authorization_public_key_material_hash: blake3Base64Url(
      canonicalizeStrictBytes(input.authorizationPublicKeyMaterial as StrictJsonValue),
    ),
    share_capability_secret_commitment: input.shareCapabilitySecretCommitment,
    password_capability_secret_commitment: input.passwordCapabilitySecretCommitment,
    password_auth_metadata_hash: passwordAuthMetadataHashValue,
    max_views: maxViews,
    expires_event_sequence: input.expiresEventSequence ?? Number.MAX_SAFE_INTEGER,
    redeem_authority_policy: redeemAuthorityPolicy,
    capability_context_hash: capabilityContextHash,
  };
}

async function buildShareLinkSecretBackupWraps(input: {
  workspaceId: string;
  shareId: string;
  shareSlug: string;
  tokenHash: string;
  scopeKind: ShareScope;
  scopeId: string;
  permission: SharePermission;
  passwordProtected: boolean;
  createdEventHash: string;
  shareCapabilitySecretCommitment: string;
  passwordCapabilitySecretCommitment: string;
  workspacePinBootstrapHash: string;
  checkpoint: KeyDirectoryEnvelope;
}): Promise<{
  wraps: SignedPqWrapRecord[];
  events: KeyDirectoryEnvelope[];
  checkpoint: KeyDirectoryEnvelope;
}> {
  const recipients = await listShareLinkBackupRecipients(input.workspaceId);
  if (recipients.length === 0) throw new Error("share_backup_recipient_required");

  let checkpoint = input.checkpoint;
  const events: KeyDirectoryEnvelope[] = [];
  const wraps: SignedPqWrapRecord[] = [];

  for (const recipient of recipients) {
    const keyCheckpointHash = hashKeyDirectoryCheckpointEnvelope(checkpoint);
    const resource = {
      workspace_id: input.workspaceId,
      share_id: input.shareId,
      token_hash: input.tokenHash,
      scope_kind: input.scopeKind,
      scope_id: input.scopeId,
      permission: input.permission,
      password_protected: input.passwordProtected,
      created_event_hash: input.createdEventHash,
      share_capability_secret_commitment: input.shareCapabilitySecretCommitment,
      password_capability_secret_commitment: input.passwordCapabilitySecretCommitment,
      workspace_pin_bootstrap_hash: input.workspacePinBootstrapHash,
      recipient_user_id: recipient.userId,
      recipient_device_id: recipient.deviceId,
      recipient_encryption_key_id: recipient.encryptionKeyId,
      key_checkpoint_hash: keyCheckpointHash,
    };
    let wrap = await getCryptoWorker().createSignedPqShareLinkSecretBackupWrap({
      workspaceId: input.workspaceId,
      shareId: input.shareId,
      shareSlug: input.shareSlug,
      tokenHash: input.tokenHash,
      scopeKind: input.scopeKind,
      scopeId: input.scopeId,
      permission: input.permission,
      passwordProtected: input.passwordProtected,
      createdEventHash: input.createdEventHash,
      shareCapabilitySecretCommitment: input.shareCapabilitySecretCommitment,
      passwordCapabilitySecretCommitment: input.passwordCapabilitySecretCommitment,
      workspacePinBootstrapHash: input.workspacePinBootstrapHash,
      recipientPublicKeyMaterial: recipient.encryptionPublicKeyMaterial,
      senderUserId: requireCurrentUserId(),
      senderDeviceId: requireCurrentDeviceId(),
      resource,
      eventScope: { scope_kind: "workspace", scope_id: input.workspaceId },
      operationCheckpoint: operationCheckpointFromEnvelope(checkpoint),
    });
    const append = await buildWrapIssuedKeyDirectoryAppend({
      scopeKind: "workspace",
      scopeId: input.workspaceId,
      checkpointEnvelope: checkpoint,
      wrapRecord: wrap,
    });
    wrap = await getCryptoWorker().finalizeSignedPqWrapOperationCheckpoint({
      record: wrap,
      operationCheckpoint: operationCheckpointFromEnvelope(append.checkpoint),
    });
    events.push(...append.events);
    checkpoint = append.checkpoint;
    wraps.push(wrap);
  }

  return { wraps, events, checkpoint };
}
