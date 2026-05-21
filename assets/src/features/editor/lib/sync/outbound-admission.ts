import { authState, deviceState } from "@/entities/session";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { buildDocumentAdmissionKeyDirectoryAppend } from "@/shared/lib/crypto/key-directory/document-admission-events";
import { base64UrlRandom } from "@/shared/lib/crypto/key-directory/primitives";
import type { HybridSignature } from "@/shared/lib/crypto/signature-types";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import { verifyAndInstallWorkspacePinBootstrap } from "@/shared/lib/key-directory/workspace-pin-bootstrap";
import {
  assertKeyDirectoryEnvelope,
  type KeyDirectoryEnvelope,
} from "@/shared/lib/crypto/key-directory/types";
import {
  getKeyDirectoryPin,
  hashKeyDirectoryCheckpointEnvelope,
  lookupVerifiedKeyDirectoryLineage,
} from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { pinFromCheckpoint } from "@/shared/lib/anti-rollback/key-directory-pin/verification";
import type { SignedKeyDirectoryEnvelope } from "@/shared/lib/anti-rollback/key-directory-pin/types";
import type { SharedDocumentAccess } from "../../model/document-state/access";
import type { DocumentState } from "../../model/document-state/types";
import { getDocumentCryptoWorker } from "./crypto-worker";
import { getLocalDeviceId } from "./share-identity";

export const keyDirectoryAdvanceSymbol: unique symbol = Symbol("refmd.keyDirectoryAdvance");

export interface KeyDirectoryAdvance {
  scopeKind: "workspace";
  scopeId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  checkpointAncestry: KeyDirectoryEnvelope[];
  eventAncestry: KeyDirectoryEnvelope[];
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
    admission_event_type: "document_update_accepted" | "document_snapshot_accepted";
    admission_nonce: string;
    min_dek_version: number;
    document_permission_proof_hash: string;
  };
}

async function resolveWorkspaceDirectoryForAdmission(params: {
  state: DocumentState;
  deviceId: string;
  directoryAccess: SharedDocumentAccess | null;
  shareAccess: SharedDocumentAccess | null;
}): Promise<{ checkpoint: KeyDirectoryEnvelope }> {
  const access = params.directoryAccess;
  if (!access?.workspaceKeyDirectoryCheckpoint) {
    return fetchVerifiedKeyDirectory({
      scopeKind: "workspace",
      scopeId: params.state.workspaceId,
      popDeviceId: params.deviceId,
      popScope: params.shareAccess ? "share" : "user",
      popWorker: params.shareAccess ? getDocumentCryptoWorker(params.state) : undefined,
    });
  }

  const existingPin = await getKeyDirectoryPin("workspace", params.state.workspaceId);
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
      popDeviceId: params.deviceId,
      popScope: "share",
      popWorker: getDocumentCryptoWorker(params.state),
    });
  }

  if (existingPin) {
    return fetchVerifiedKeyDirectory({
      scopeKind: "workspace",
      scopeId: params.state.workspaceId,
      popDeviceId: params.deviceId,
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
    popDeviceId: params.deviceId,
    popScope: "share",
    popWorker: getDocumentCryptoWorker(params.state),
  });
}

export async function prepareDocumentOperationAdmissionAuthority(
  state: DocumentState,
  documentId: string,
  signingKeyId: string,
  eventType: "document_update_accepted" | "document_snapshot_accepted",
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
  eventType: "document_update_accepted" | "document_snapshot_accepted";
  operationHash: string;
  signature: HybridSignature;
  keyVersion: number;
  authority?: DocumentOperationAdmissionAuthority;
}): Promise<{
  admission: {
    workspaceKeyDirectoryEvents: KeyDirectoryEnvelope[];
    workspaceKeyDirectoryCheckpoint: KeyDirectoryEnvelope;
    workspaceKeyDirectoryCheckpointAncestry: KeyDirectoryEnvelope[];
    workspaceKeyDirectoryEventAncestry: KeyDirectoryEnvelope[];
  };
  keyDirectoryAdvance: KeyDirectoryAdvance;
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
    operationSignatureHash: blake3Base64Url(
      canonicalizeStrictBytes(params.signature as unknown as StrictJsonValue),
    ),
    dekVersion: params.keyVersion,
    minDekVersion: params.keyVersion,
    admissionNonce: authority.authorityBoundary.admission_nonce,
    documentPermissionProofHash: authority.authorityBoundary.document_permission_proof_hash,
  });
  const directoryCheckpoint = directory.checkpoint as unknown as SignedKeyDirectoryEnvelope;
  const directoryPin = pinFromCheckpoint(
    "workspace",
    params.state.workspaceId,
    directoryCheckpoint,
  );
  const lineage = lookupVerifiedKeyDirectoryLineage(
    "workspace",
    params.state.workspaceId,
    directoryPin,
  );

  return {
    admission: {
      workspaceKeyDirectoryEvents: append.events,
      workspaceKeyDirectoryCheckpoint: append.checkpoint,
      workspaceKeyDirectoryCheckpointAncestry: (lineage?.checkpoints as unknown as
        | KeyDirectoryEnvelope[]
        | undefined) ?? [directory.checkpoint],
      workspaceKeyDirectoryEventAncestry: [
        ...((lineage?.events as unknown as KeyDirectoryEnvelope[] | undefined) ?? []),
        ...append.events,
      ],
    },
    keyDirectoryAdvance: {
      scopeKind: "workspace",
      scopeId: params.state.workspaceId,
      checkpointEnvelope: append.checkpoint,
      checkpointAncestry: [directory.checkpoint],
      eventAncestry: append.events,
    },
  };
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
