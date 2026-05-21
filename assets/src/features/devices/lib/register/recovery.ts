import { devicesApi } from "@/shared/api";
import type { ApproveDeviceRequest } from "@/shared/api/devices";
import type { AuthState } from "@/entities/session";
import { setCryptoWorkerReady, setFullSession } from "@/entities/session";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { clientWarn } from "@/shared/lib/logger";
import {
  advanceKeyDirectoryPinWithProof,
  getKeyDirectoryPin,
  hashKeyDirectoryCheckpointEnvelope,
  installTransferredKeyDirectoryCheckpoint,
} from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { buildRecoveryWorkspaceDeviceKeyDirectoryAppend } from "@/shared/lib/crypto/key-directory/device-events";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { persistDeviceId, persistCurrentKeysWithDsk } from "@/shared/lib/auth/key-persistence";
import { RECOVERY_PENDING_DEVICE_STORAGE_KEY } from "@/shared/lib/auth/recovery-pending-device";
import { ensureDskInWorker, persistCurrentDeviceKeys } from "./session-keys";
import { restoreWorkspaceKeks } from "./session-keks";
import type { DeviceRegistrationPublicKeys } from "../../model/register/types";
import type { HybridEncryptionPublicKeyMaterial } from "@/shared/lib/crypto/hybrid-encryption";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import {
  assertKeyDirectoryEnvelope,
  type KeyDirectoryEnvelope,
} from "@/shared/lib/crypto/key-directory/types";

type RecoveryRegistrationResult =
  | {
      kind: "navigate";
      path: string;
    }
  | {
      kind: "needs_password";
      publicKeys: DeviceRegistrationPublicKeys;
    }
  | {
      kind: "done";
      statusMessage: string;
      redirectPath: string;
      dskUnavailableOAuth: boolean;
    };

function signingPublicMaterialJson(material: HybridSigningPublicKeyMaterial): StrictJsonValue {
  return {
    protocol: material.protocol,
    version: material.version,
    suite_id: material.suite_id,
    suite_rank: material.suite_rank,
    owner_kind: material.owner_kind,
    owner_id: material.owner_id,
    ed25519_public: material.ed25519_public,
    mldsa65_public: material.mldsa65_public,
  };
}

function encryptionPublicMaterialJson(
  material: HybridEncryptionPublicKeyMaterial,
): StrictJsonValue {
  return {
    protocol: material.protocol,
    version: material.version,
    suite_id: material.suite_id,
    suite_rank: material.suite_rank,
    owner_kind: material.owner_kind,
    owner_id: material.owner_id,
    x25519_public: material.x25519_public,
    mlkem768_public: material.mlkem768_public,
    hybrid_public: material.hybrid_public,
  };
}

export async function registerRecoveredDevice(params: {
  auth: AuthState;
  completionRedirectPath: string;
  onStatusMessage?: (message: string) => void;
}): Promise<RecoveryRegistrationResult> {
  const { auth, completionRedirectPath, onStatusMessage } = params;
  const worker = getCryptoWorker();
  const publicIdentityKeys = await worker.getPublicKeys();
  if (!publicIdentityKeys.identityHybridSigningPublicKeyMaterial) {
    return {
      kind: "navigate",
      path: "/auth/recovery",
    };
  }

  const pending = readPendingRecoveryDevice();
  const deviceId = pending.deviceId;
  await worker.setUserContext(auth.user.id, deviceId);

  const hasDsk = await ensureDskInWorker();
  const publicKeys = await worker.getPublicKeys();
  if (
    !publicKeys.deviceEcdhPublic ||
    !publicKeys.deviceSigningKeyId ||
    !publicKeys.deviceEncryptionKeyId ||
    !publicKeys.deviceHybridSigningPublicKeyMaterial ||
    !publicKeys.deviceHybridEncryptionPublicKeyMaterial
  ) {
    throw new Error("recovery_pending_device_keys_missing");
  }
  const deviceHybridSigningPublicKeyMaterial = publicKeys.deviceHybridSigningPublicKeyMaterial;
  const deviceHybridEncryptionPublicKeyMaterial =
    publicKeys.deviceHybridEncryptionPublicKeyMaterial;

  if (hasDsk) {
    const persisted = await persistCurrentDeviceKeys(auth.user.id);
    if (!persisted) {
      clientWarn("recovery_device_key_persistence_failed");
    }
  }

  const clientNonce = base64UrlDecode(pending.clientNonce);
  const { signature: deviceSignature } = await worker.createRecoveryDeviceApprovalSignature({
    deviceEcdhPublic: publicKeys.deviceEcdhPublic,
    clientNonce,
    recoverySessionTranscriptHash: pending.recoverySessionTranscriptHash,
    recoveryCapabilityHash: pending.recoveryCapabilityHash,
    pendingRegistrationId: pending.pendingRegistrationId,
    pendingRegistrationChallengeHash: pending.pendingRegistrationChallengeHash,
    pendingRegistrationBindingHash: pending.pendingRegistrationBindingHash,
    approvingKeyCheckpointSequence: pending.candidateUserCheckpointSequence,
    approvingKeyCheckpointHash: pending.candidateUserCheckpointHash,
    targetKeyCheckpointSequence: pending.targetKeyCheckpointSequence,
    targetKeyCheckpointHash: pending.targetKeyCheckpointHash,
  });

  const identityHybridSigningPublicKeyMaterialKey = auth.identityHybridSigningPublicKeyMaterial;
  if (!identityHybridSigningPublicKeyMaterialKey)
    throw new Error("Identity signing public key not available");

  await assertRecoveryWorkspaceCandidatesMatchLocalPins(pending.candidateWorkspaceCheckpoints);

  const userKeyDirectory = pending.userKeyDirectory;
  const workspaceAppends = await Promise.all(
    pending.candidateWorkspaceCheckpoints.map(async ({ workspaceId, checkpoint }) => {
      const append = await buildRecoveryWorkspaceDeviceKeyDirectoryAppend({
        workspaceId,
        userId: auth.user.id,
        checkpointEnvelope: checkpoint,
        recipientDeviceId: deviceId,
        recipientHybridSigningPublicKeyMaterial: deviceHybridSigningPublicKeyMaterial,
        recipientHybridEncryptionPublicKeyMaterial: deviceHybridEncryptionPublicKeyMaterial,
      });
      return {
        workspace_id: workspaceId,
        base_checkpoint: checkpoint,
        events: append.events,
        checkpoint: append.checkpoint,
      };
    }),
  );
  const approveBody: ApproveDeviceRequest = {
    approval_signature_surface: "recovery_device_approval",
    approval_signature: deviceSignature,
    approval_proof: {
      protocol: "refmd.device-approval-proof",
      version: 1,
      approval_signature_surface: "recovery_device_approval",
      approval_transcript_hash: deviceSignature.transcript_hash,
      approval_transcript_owner: "refmd.device.recovery_approval",
      approval_surface_id: "recovery_device_approval",
      approval_surface_variant: "none",
      approving_owner_kind: "identity",
      approving_owner_id: auth.user.id,
      approving_signing_key_id: deviceSignature.signing_key_id,
      approving_key_checkpoint_sequence: pending.candidateUserCheckpointSequence,
      approving_key_checkpoint_hash: pending.candidateUserCheckpointHash,
      target_device_id: deviceId,
      target_device_signing_key_id: publicKeys.deviceSigningKeyId,
      target_device_hybrid_signing_public_key_material_hash: blake3Base64Url(
        canonicalizeStrictBytes(signingPublicMaterialJson(deviceHybridSigningPublicKeyMaterial)),
      ),
      target_device_hybrid_encryption_public_key_material_hash: blake3Base64Url(
        canonicalizeStrictBytes(
          encryptionPublicMaterialJson(deviceHybridEncryptionPublicKeyMaterial),
        ),
      ),
      target_device_encryption_key_id: publicKeys.deviceEncryptionKeyId,
      target_device_client_nonce_hash: blake3Base64Url(clientNonce),
      target_key_checkpoint_sequence: pending.targetKeyCheckpointSequence,
      target_key_checkpoint_hash: pending.targetKeyCheckpointHash,
      surface_details: {
        kind: "recovery_device_approval",
        pending_registration_id: pending.pendingRegistrationId,
        pending_registration_challenge_hash: pending.pendingRegistrationChallengeHash,
        recovery_session_transcript_hash: pending.recoverySessionTranscriptHash,
        recovery_capability_hash: pending.recoveryCapabilityHash,
        pending_registration_binding_hash: pending.pendingRegistrationBindingHash,
      },
    },
    user_key_directory_events: userKeyDirectory.events,
    user_key_directory_checkpoint: userKeyDirectory.checkpoint,
    workspace_key_directory_appends: workspaceAppends,
  };
  const approval = await devicesApi.approve(deviceId, approveBody);
  const approvedDeviceId = approval.device.id;

  if (approvedDeviceId !== deviceId) {
    throw new Error("device_id_mismatch");
  }
  await worker.setUserContext(auth.user.id, deviceId);
  await worker.setInitialized();
  await pinRecoveredCheckpoint({
    scopeKind: "user",
    scopeId: auth.user.id,
    baseCheckpointEnvelope: pending.candidateUserCheckpoint,
    eventEnvelopes: userKeyDirectory.events,
    checkpointEnvelope: userKeyDirectory.checkpoint,
  });
  await Promise.all(
    workspaceAppends.map((append) =>
      pinRecoveredCheckpoint({
        scopeKind: "workspace",
        scopeId: append.workspace_id,
        baseCheckpointEnvelope: append.base_checkpoint,
        eventEnvelopes: append.events,
        checkpointEnvelope: append.checkpoint,
      }),
    ),
  );
  setCryptoWorkerReady(true);

  if (hasDsk) {
    await persistCurrentKeysWithDsk(auth.user.id);
  }

  setFullSession(
    {
      user: auth.user,
      sessionId: auth.sessionId,
      identityHybridSigningPublicKeyMaterial: auth.identityHybridSigningPublicKeyMaterial,
      identityEcdhPublic: auth.identityEcdhPublic,
      expiresAt: auth.expiresAt,
    },
    {
      deviceId,
      deviceSigningKeyId: publicKeys.deviceSigningKeyId,
      deviceHybridSigningPublicKeyMaterial,
      deviceEcdhPublic: publicKeys.deviceEcdhPublic,
    },
  );

  persistDeviceId(deviceId, auth.user.id);
  onStatusMessage?.("Restoring workspace keys...");
  const kekResults = await restoreWorkspaceKeks(
    auth.user.id,
    deviceId,
    auth.identityHybridSigningPublicKeyMaterial,
    auth.identityEcdhPublic,
  );

  await worker.clearTransientKeys();
  sessionStorage.removeItem(RECOVERY_PENDING_DEVICE_STORAGE_KEY);

  return {
    kind: "done",
    statusMessage: formatRecoveryCompletionMessage(kekResults.restored.length),
    redirectPath: completionRedirectPath,
    dskUnavailableOAuth: !hasDsk,
  };
}

async function assertRecoveryWorkspaceCandidatesMatchLocalPins(
  candidates: Array<{
    workspaceId: string;
    checkpoint: KeyDirectoryEnvelope;
  }>,
): Promise<void> {
  await Promise.all(
    candidates.map(async ({ workspaceId, checkpoint }) => {
      const existing = await getKeyDirectoryPin("workspace", workspaceId);
      if (!existing) return;

      const pin = checkpointPin(checkpoint);
      if (
        existing.checkpointSequence !== pin.checkpointSequence ||
        existing.checkpointHash !== pin.checkpointHash ||
        existing.eventHeadSequence !== pin.eventHeadSequence ||
        existing.eventHeadHash !== pin.eventHeadHash
      ) {
        throw new Error("recovery_candidate_workspace_key_directory_pin_conflict");
      }
    }),
  );
}

function checkpointPin(checkpointEnvelope: KeyDirectoryEnvelope): {
  checkpointSequence: number;
  checkpointHash: string;
  eventHeadSequence: number;
  eventHeadHash: string;
} {
  const payload = requireRecord(checkpointEnvelope.payload);
  const coveredHead = requireRecord(payload.covered_event_head);
  return {
    checkpointSequence: requireNumber(payload.sequence),
    checkpointHash: hashKeyDirectoryCheckpointEnvelope(checkpointEnvelope),
    eventHeadSequence: requireNumber(coveredHead.head_sequence),
    eventHeadHash: requireString(coveredHead.head_hash),
  };
}

async function pinRecoveredCheckpoint(params: {
  scopeKind: "user" | "workspace";
  scopeId: string;
  baseCheckpointEnvelope: KeyDirectoryEnvelope;
  eventEnvelopes: KeyDirectoryEnvelope[];
  checkpointEnvelope: KeyDirectoryEnvelope;
}): Promise<void> {
  const existing = await getKeyDirectoryPin(params.scopeKind, params.scopeId);
  if (!existing) {
    await installTransferredKeyDirectoryCheckpoint({
      scopeKind: params.scopeKind,
      scopeId: params.scopeId,
      checkpointEnvelope: params.checkpointEnvelope,
    });
    return;
  }
  await advanceKeyDirectoryPinWithProof({
    scopeKind: params.scopeKind,
    scopeId: params.scopeId,
    checkpointEnvelope: params.checkpointEnvelope,
    checkpointAncestry: [params.baseCheckpointEnvelope],
    eventAncestry: params.eventEnvelopes,
  });
}

function readPendingRecoveryDevice(): {
  deviceId: string;
  clientNonce: string;
  recoverySessionId: string;
  recoverySessionTranscriptHash: string;
  recoveryCapabilityHash: string;
  pendingRegistrationId: string;
  pendingRegistrationChallengeHash: string;
  pendingRegistrationBindingHash: string;
  targetKeyCheckpointSequence: number;
  targetKeyCheckpointHash: string;
  candidateUserCheckpointSequence: number;
  candidateUserCheckpointHash: string;
  candidateUserCheckpoint: KeyDirectoryEnvelope;
  userKeyDirectory: {
    events: KeyDirectoryEnvelope[];
    checkpoint: KeyDirectoryEnvelope;
  };
  candidateWorkspaceCheckpoints: Array<{
    workspaceId: string;
    checkpoint: KeyDirectoryEnvelope;
  }>;
} {
  const raw = sessionStorage.getItem(RECOVERY_PENDING_DEVICE_STORAGE_KEY);
  if (!raw) throw new Error("recovery_pending_device_missing");
  const parsed = JSON.parse(raw) as Record<string, unknown>;
  return {
    deviceId: requireString(parsed.deviceId),
    clientNonce: requireString(parsed.clientNonce),
    recoverySessionId: requireString(parsed.recoverySessionId),
    recoverySessionTranscriptHash: requireString(parsed.recoverySessionTranscriptHash),
    recoveryCapabilityHash: requireString(parsed.recoveryCapabilityHash),
    pendingRegistrationId: requireString(parsed.pendingRegistrationId),
    pendingRegistrationChallengeHash: requireString(parsed.pendingRegistrationChallengeHash),
    pendingRegistrationBindingHash: requireString(parsed.pendingRegistrationBindingHash),
    targetKeyCheckpointSequence: requireNumber(parsed.targetKeyCheckpointSequence),
    targetKeyCheckpointHash: requireString(parsed.targetKeyCheckpointHash),
    candidateUserCheckpointSequence: requireNumber(parsed.candidateUserCheckpointSequence),
    candidateUserCheckpointHash: requireString(parsed.candidateUserCheckpointHash),
    candidateUserCheckpoint: assertKeyDirectoryEnvelope(
      parsed.candidateUserCheckpoint,
      "recovery_context_invalid",
    ),
    userKeyDirectory: requireKeyDirectoryAppend(parsed.userKeyDirectory),
    candidateWorkspaceCheckpoints: requireWorkspaceCheckpoints(
      parsed.candidateWorkspaceCheckpoints,
    ),
  };
}

function requireKeyDirectoryAppend(value: unknown): {
  events: KeyDirectoryEnvelope[];
  checkpoint: KeyDirectoryEnvelope;
} {
  const record = requireRecord(value);
  const events = record.events;
  if (!Array.isArray(events)) throw new Error("recovery_context_invalid");
  return {
    events: events.map((event) => assertKeyDirectoryEnvelope(event, "recovery_context_invalid")),
    checkpoint: assertKeyDirectoryEnvelope(record.checkpoint, "recovery_context_invalid"),
  };
}

function requireWorkspaceCheckpoints(value: unknown): Array<{
  workspaceId: string;
  checkpoint: KeyDirectoryEnvelope;
}> {
  if (!Array.isArray(value)) throw new Error("recovery_context_invalid");
  return value.map((entry) => {
    const record = requireRecord(entry);
    return {
      workspaceId: requireString(record.workspaceId),
      checkpoint: assertKeyDirectoryEnvelope(record.checkpoint, "recovery_context_invalid"),
    };
  });
}

function requireString(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) throw new Error("recovery_context_invalid");
  return value;
}

function requireNumber(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    throw new Error("recovery_context_invalid");
  }
  return value;
}

function requireRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("recovery_context_invalid");
  }
  return value as Record<string, unknown>;
}

function formatRecoveryCompletionMessage(restoredCount: number): string {
  if (restoredCount > 0) {
    return `Recovery complete. Restored ${restoredCount} workspace key(s).`;
  }

  return "Recovery complete!";
}
