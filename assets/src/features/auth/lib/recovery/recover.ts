import type { AuthState } from "@/entities/session";
import { authApi } from "@/shared/api";
import type { components } from "@/shared/api/schema";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { getDeviceName, getDeviceType } from "@/shared/lib/device/metadata";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import { buildPendingRegistrationBindingHash } from "@/shared/lib/crypto/signature-recovery-transcripts";
import { buildDeviceKeyDirectoryAppend } from "@/shared/lib/crypto/key-directory/device-events";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { RECOVERY_PENDING_DEVICE_STORAGE_KEY } from "@/shared/lib/auth/recovery-pending-device";
import {
  advanceKeyDirectoryPinWithProof,
  getKeyDirectoryPin,
  hashKeyDirectoryCheckpointEnvelope,
  hydrateVerifiedKeyDirectoryLineage,
  installVerifiedTransferredKeyDirectoryCheckpoint,
  rememberVerifiedKeyDirectoryLineage,
} from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import {
  pinFromCheckpoint,
  verifyCheckpointAncestry,
  verifyInitialReplay,
} from "@/shared/lib/anti-rollback/key-directory-pin/verification";
import { verifyRotationDeletionEvidences } from "@/shared/lib/anti-rollback/rotation-deletion-evidence";
import {
  verifyAndPinAuditCheckpoint,
  verifyAuditCheckpointCandidate,
} from "@/shared/lib/anti-rollback/audit-checkpoint-pin";
import {
  assertKeyDirectoryEnvelope,
  type KeyDirectoryEnvelope,
} from "@/shared/lib/crypto/key-directory/types";

interface RecoveryAttemptParams {
  auth: AuthState;
  mnemonic: string;
  isPasswordReset: boolean;
  setStatusMessage: (message: string) => void;
}

type RecoveryAttemptResult =
  | {
      kind: "password_set";
      identityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial | null;
      identityEcdhPublic: Uint8Array | null;
    }
  | {
      kind: "device_registration";
      sessionId: string;
      identityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial | null;
      identityEcdhPublic: Uint8Array | null;
    };
type RecoveryDevicePublicKeys = Awaited<
  ReturnType<ReturnType<typeof getCryptoWorker>["generateDeviceKeys"]>
>;
type RecoveryTargetDeviceRegistration =
  components["schemas"]["RecoverySessionRequest"]["target_device_registration"];

export function buildRecoveryTargetDeviceRegistration(params: {
  deviceId: string;
  identitySigningKeyId: string;
  publicKeys: RecoveryDevicePublicKeys;
  clientNonce: Uint8Array;
}): RecoveryTargetDeviceRegistration {
  return {
    name: getDeviceName(),
    device_type: getDeviceType(),
    device_id: params.deviceId,
    identity_signing_key_id: params.identitySigningKeyId,
    device_hybrid_encryption_public_key_material:
      params.publicKeys.hybridEncryptionPublicKeyMaterial,
    device_encryption_key_id: params.publicKeys.encryptionKeyId,
    device_hybrid_signing_public_key_material: params.publicKeys.hybridSigningPublicKeyMaterial,
    device_signing_key_id: params.publicKeys.signingKeyId,
    client_nonce: base64UrlEncode(params.clientNonce),
  };
}

export async function recoverAccount(
  params: RecoveryAttemptParams,
): Promise<RecoveryAttemptResult> {
  const worker = getCryptoWorker();

  params.setStatusMessage("Fetching recovery data...");
  const recovery = await authApi.getRecovery();
  const candidate = recoveryCandidateFromServer(recovery);
  await advanceRecoveryCandidateKeyDirectory(params.auth.user.id, candidate);
  const recoveryAuditPin = await verifyAuditCheckpointCandidate(
    recovery.candidate_user_audit_checkpoint,
    { acquisition: "recovery" },
  );

  params.setStatusMessage("Deriving recovery key...");
  await worker.deriveRuk(params.mnemonic);

  params.setStatusMessage("Decrypting master key...");
  try {
    await worker.unwrapUmkWithRuk({
      encrypted: base64UrlDecode(recovery.recovery_encrypted_umk!),
      nonce: base64UrlDecode(recovery.recovery_nonce!),
      userId: params.auth.user.id,
    });
  } catch {
    throw new Error("Invalid recovery phrase. The mnemonic does not match this account.");
  }

  params.setStatusMessage("Decrypting identity keys...");
  const identityKeyEpoch = recovery.identity_key_epoch;
  if (
    typeof identityKeyEpoch !== "number" ||
    !Number.isSafeInteger(identityKeyEpoch) ||
    identityKeyEpoch < 1
  ) {
    throw new Error("Recovery identity key epoch is invalid.");
  }
  const identityPublic = await worker.importIdentityKeys({
    encryptedHybridEncryptionPrivateKeyMaterial: base64UrlDecode(
      recovery.encrypted_identity_hybrid_encryption_private_key_material!,
    ),
    hybridEncryptionPrivateKeyMaterialNonce: base64UrlDecode(
      recovery.identity_hybrid_encryption_private_key_material_nonce!,
    ),
    encryptionKeyId: recovery.identity_encryption_key_id!,
    encryptedHybridSigningPrivateKeyMaterial: base64UrlDecode(
      recovery.encrypted_identity_hybrid_signing_private_key_material!,
    ),
    hybridSigningPrivateKeyMaterialNonce: base64UrlDecode(
      recovery.identity_hybrid_signing_private_key_material_nonce!,
    ),
    signingKeyId: recovery.identity_signing_key_id!,
    identityKeyEpoch,
    rotationDueAt: recovery.identity_rotation_due_at,
  });

  params.setStatusMessage("Getting recovery challenge...");
  const challengeResponse = await authApi.recoveryChallenge(params.auth.user.email);

  params.setStatusMessage("Preparing recovered device...");
  const deviceId = crypto.randomUUID();
  await worker.setUserContext(params.auth.user.id, deviceId);
  const publicKeys = await worker.generateDeviceKeys({ deviceId });
  const clientNonce = await worker.generateClientNonce();
  const targetDeviceRegistration = buildRecoveryTargetDeviceRegistration({
    deviceId,
    identitySigningKeyId: recovery.identity_signing_key_id!,
    publicKeys,
    clientNonce,
  });
  const pendingRegistrationChallengeHash = blake3Base64Url(
    base64UrlDecode(challengeResponse.challenge),
  );

  const recoverySessionId = crypto.randomUUID();
  await assertRecoveryCandidateMatchesLocalPin(params.auth.user.id, candidate);
  const userKeyDirectory = await buildDeviceKeyDirectoryAppend({
    scopeKind: "user",
    scopeId: params.auth.user.id,
    userId: params.auth.user.id,
    checkpointEnvelope: candidate.candidateUserCheckpoint,
    recipientDeviceId: deviceId,
    recipientHybridSigningPublicKeyMaterial: publicKeys.hybridSigningPublicKeyMaterial,
    recipientHybridEncryptionPublicKeyMaterial: publicKeys.hybridEncryptionPublicKeyMaterial,
  });
  const targetCheckpointPayload = userKeyDirectory.checkpoint.payload as
    | Record<string, unknown>
    | undefined;
  const targetKeyCheckpointSequence =
    typeof targetCheckpointPayload?.sequence === "number" ? targetCheckpointPayload.sequence : null;
  if (targetKeyCheckpointSequence === null) {
    throw new Error("recovery_target_key_directory_checkpoint_invalid");
  }
  const targetKeyCheckpointHash = hashKeyDirectoryCheckpointEnvelope(userKeyDirectory.checkpoint);
  const pendingRegistrationBindingHash = buildPendingRegistrationBindingHash({
    userId: params.auth.user.id,
    pendingRegistrationId: deviceId,
    pendingRegistrationChallengeHash: pendingRegistrationChallengeHash,
    targetDeviceId: deviceId,
    targetDeviceSigningKeyId: publicKeys.signingKeyId,
    targetDeviceHybridSigningPublicKeyMaterial: publicKeys.hybridSigningPublicKeyMaterial,
    targetDeviceHybridEncryptionPublicKeyMaterial: publicKeys.hybridEncryptionPublicKeyMaterial,
    targetDeviceEncryptionKeyId: publicKeys.encryptionKeyId,
    targetDeviceClientNonce: base64UrlEncode(clientNonce),
    targetKeyCheckpointSequence,
    targetKeyCheckpointHash,
  });
  const serverChallengeHash = blake3Base64Url(base64UrlDecode(challengeResponse.challenge));

  params.setStatusMessage("Signing challenge...");
  const {
    signature,
    recoveryAuthorizationKeyId,
    recoveryAuthorizationProof,
    recoveryCapabilityHash,
    recoverySessionTranscriptHash,
  } = await worker.signRecoverySession({
    recoverySessionId,
    serverChallengeHash,
    recipientDeviceId: deviceId,
    pendingRegistrationId: deviceId,
    pendingRegistrationBindingHash,
    ...candidate,
    candidateUserAuditSequence: recoveryAuditPin.event_head_sequence,
    candidateUserAuditHash: recoveryAuditPin.event_head_hash,
  });

  params.setStatusMessage("Creating session...");
  const sessionResponse = await authApi.recoverySession({
    email: params.auth.user.email,
    recovery_session_id: recoverySessionId,
    challenge: challengeResponse.challenge,
    recovery_session_signature: signature,
    recovery_authorization_key_id: recoveryAuthorizationKeyId,
    recovery_authorization_proof: recoveryAuthorizationProof,
    recovery_capability_hash: recoveryCapabilityHash,
    recovery_session_transcript_hash: recoverySessionTranscriptHash,
    pending_registration_id: deviceId,
    recipient_device_id: deviceId,
    pending_registration_binding_hash: pendingRegistrationBindingHash,
    target_key_checkpoint_sequence: targetKeyCheckpointSequence,
    target_key_checkpoint_hash: targetKeyCheckpointHash,
    candidate_user_checkpoint_sequence: candidate.candidateUserCheckpointSequence,
    candidate_user_checkpoint_hash: candidate.candidateUserCheckpointHash,
    candidate_user_event_head_sequence: candidate.candidateUserEventHeadSequence,
    candidate_user_event_head_hash: candidate.candidateUserEventHeadHash,
    candidate_user_checkpoint: candidate.candidateUserCheckpoint,
    candidate_user_event_ancestry: candidate.candidateUserEventAncestry,
    candidate_user_audit_sequence: recoveryAuditPin.event_head_sequence,
    candidate_user_audit_hash: recoveryAuditPin.event_head_hash,
    target_device_registration: targetDeviceRegistration,
  });
  await verifyAndPinAuditCheckpoint(recovery.candidate_user_audit_checkpoint, {
    acquisition: "recovery",
  });
  await verifyAndPinAuditCheckpoint(sessionResponse.audit_checkpoint);
  sessionStorage.setItem(
    RECOVERY_PENDING_DEVICE_STORAGE_KEY,
    JSON.stringify({
      deviceId,
      clientNonce: base64UrlEncode(clientNonce),
      recoverySessionId,
      recoverySessionTranscriptHash,
      recoveryCapabilityHash,
      pendingRegistrationBindingHash,
      pendingRegistrationId: deviceId,
      pendingRegistrationChallengeHash,
      targetKeyCheckpointSequence,
      targetKeyCheckpointHash,
      userKeyDirectory,
      candidateUserCheckpointSequence: candidate.candidateUserCheckpointSequence,
      candidateUserCheckpointHash: candidate.candidateUserCheckpointHash,
      candidateUserCheckpoint: candidate.candidateUserCheckpoint,
      candidateUserCheckpointAncestry: candidate.candidateUserCheckpointAncestry,
      candidateUserEventAncestry: candidate.candidateUserEventAncestry,
      candidateWorkspaceCheckpoints: candidate.candidateWorkspaceCheckpoints,
    }),
  );
  const identityHybridSigningPublicKeyMaterial =
    identityPublic.identityHybridSigningPublicKeyMaterial;

  if (params.isPasswordReset) {
    return {
      kind: "password_set",
      identityHybridSigningPublicKeyMaterial,
      identityEcdhPublic: identityPublic.identityEcdhPublic,
    };
  }

  return {
    kind: "device_registration",
    sessionId: sessionResponse.session_id,
    identityHybridSigningPublicKeyMaterial,
    identityEcdhPublic: identityPublic.identityEcdhPublic,
  };
}

async function assertRecoveryCandidateMatchesLocalPin(
  userId: string,
  candidate: ReturnType<typeof recoveryCandidateFromServer>,
): Promise<void> {
  const existing = await getKeyDirectoryPin("user", userId);
  if (!existing) return;
  if (
    existing.checkpointSequence !== candidate.candidateUserCheckpointSequence ||
    existing.checkpointHash !== candidate.candidateUserCheckpointHash ||
    existing.eventHeadSequence !== candidate.candidateUserEventHeadSequence ||
    existing.eventHeadHash !== candidate.candidateUserEventHeadHash
  ) {
    throw new Error("recovery_candidate_key_directory_pin_conflict");
  }
}

async function advanceRecoveryCandidateKeyDirectory(
  userId: string,
  candidate: ReturnType<typeof recoveryCandidateFromServer>,
): Promise<void> {
  await verifyRecoveryCandidateFullLineage(userId, candidate);
  const existing = await getKeyDirectoryPin("user", userId);
  if (!existing) {
    await installVerifiedTransferredKeyDirectoryCheckpoint({
      scopeKind: "user",
      scopeId: userId,
      checkpointEnvelope: candidate.candidateUserCheckpoint,
    });
    rememberVerifiedKeyDirectoryLineage({
      scopeKind: "user",
      scopeId: userId,
      checkpointEnvelope: candidate.candidateUserCheckpoint,
      checkpointAncestry: candidate.candidateUserCheckpointAncestry,
      eventAncestry: candidate.candidateUserEventAncestry,
    });
    return;
  }

  await hydrateVerifiedKeyDirectoryLineage("user", userId, existing);
  if (
    existing.checkpointSequence === candidate.candidateUserCheckpointSequence &&
    existing.checkpointHash === candidate.candidateUserCheckpointHash &&
    existing.eventHeadSequence === candidate.candidateUserEventHeadSequence &&
    existing.eventHeadHash === candidate.candidateUserEventHeadHash
  ) {
    return;
  }

  const checkpointAncestry = candidate.candidateUserCheckpointAncestry.filter(
    (checkpoint) => Number(checkpoint.payload.sequence) >= existing.checkpointSequence,
  );
  const eventAncestry = candidate.candidateUserEventAncestry.filter(
    (event) => Number(event.payload.sequence) > existing.eventHeadSequence,
  );
  await recoveryVerificationStage("recovery_candidate_pin_advance_failed", () =>
    advanceKeyDirectoryPinWithProof({
      scopeKind: "user",
      scopeId: userId,
      checkpointEnvelope: candidate.candidateUserCheckpoint,
      checkpointAncestry,
      eventAncestry,
      authorityEventAncestry: candidate.candidateUserEventAncestry,
      rotationDeletionEvidences: candidate.candidateUserRotationDeletionEvidences,
    }),
  );
  rememberVerifiedKeyDirectoryLineage({
    scopeKind: "user",
    scopeId: userId,
    checkpointEnvelope: candidate.candidateUserCheckpoint,
    checkpointAncestry: candidate.candidateUserCheckpointAncestry,
    eventAncestry: candidate.candidateUserEventAncestry,
  });
}

async function verifyRecoveryCandidateFullLineage(
  userId: string,
  candidate: ReturnType<typeof recoveryCandidateFromServer>,
): Promise<void> {
  await recoveryVerificationStage("recovery_candidate_replay_failed", () =>
    verifyInitialReplay(
      "user",
      userId,
      candidate.candidateUserEventAncestry,
      candidate.candidateUserCheckpoint,
    ),
  );
  recoveryVerificationStageSync("recovery_candidate_deletion_evidence_failed", () =>
    verifyRotationDeletionEvidences({
      scopeKind: "user",
      scopeId: userId,
      events: candidate.candidateUserEventAncestry,
      evidences: candidate.candidateUserRotationDeletionEvidences,
    }),
  );

  const checkpoints = [
    ...candidate.candidateUserCheckpointAncestry,
    candidate.candidateUserCheckpoint,
  ];
  for (let index = 1; index < checkpoints.length; index += 1) {
    const previous = checkpoints[index - 1]!;
    const next = checkpoints[index]!;
    const previousPin = pinFromCheckpoint("user", userId, previous);
    const nextPin = pinFromCheckpoint("user", userId, next);
    const deltaEvents = candidate.candidateUserEventAncestry.filter((event) => {
      const sequence = Number(event.payload.sequence);
      return sequence > previousPin.eventHeadSequence && sequence <= nextPin.eventHeadSequence;
    });
    const authorityEvents = candidate.candidateUserEventAncestry.filter(
      (event) => Number(event.payload.sequence) <= previousPin.eventHeadSequence,
    );
    await recoveryVerificationStage("recovery_candidate_checkpoint_ancestry_failed", () =>
      verifyCheckpointAncestry(
        "user",
        userId,
        previousPin,
        [previous],
        next,
        deltaEvents,
        authorityEvents,
      ),
    );
  }
}

async function recoveryVerificationStage<T>(code: string, run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    throw new Error(`${code}:${error instanceof Error ? error.message : "unknown"}`);
  }
}

function recoveryVerificationStageSync<T>(code: string, run: () => T): T {
  try {
    return run();
  } catch (error) {
    throw new Error(`${code}:${error instanceof Error ? error.message : "unknown"}`);
  }
}

function recoveryCandidateFromServer(recovery: Record<string, unknown>) {
  const candidateUserCheckpointSequence = requiredNumber(
    recovery.candidate_user_checkpoint_sequence,
    "candidate_user_checkpoint_sequence",
  );
  const candidateUserCheckpointHash = requiredString(
    recovery.candidate_user_checkpoint_hash,
    "candidate_user_checkpoint_hash",
  );
  const candidateUserEventHeadSequence = requiredNumber(
    recovery.candidate_user_event_head_sequence,
    "candidate_user_event_head_sequence",
  );
  const candidateUserEventHeadHash = requiredString(
    recovery.candidate_user_event_head_hash,
    "candidate_user_event_head_hash",
  );
  const candidateUserCheckpoint = assertKeyDirectoryEnvelope(
    recovery.candidate_user_checkpoint,
    "candidate_user_checkpoint_missing",
  );
  const candidateUserCheckpointAncestry = optionalKeyDirectoryEnvelopes(
    recovery.candidate_user_checkpoint_ancestry,
  );
  const candidateUserEventAncestry = requiredKeyDirectoryEnvelopes(
    recovery.candidate_user_event_ancestry,
    "candidate_user_event_ancestry_missing",
  );
  const candidateUserRotationDeletionEvidences = requiredRecords(
    recovery.candidate_user_rotation_deletion_evidences,
    "candidate_user_rotation_deletion_evidences_missing",
  );
  const candidateWorkspaceCheckpoints = requiredWorkspaceCheckpoints(
    recovery.candidate_workspace_checkpoints,
  );
  return {
    candidateUserCheckpointSequence,
    candidateUserCheckpointHash,
    candidateUserEventHeadSequence,
    candidateUserEventHeadHash,
    candidateUserCheckpoint,
    candidateUserCheckpointAncestry,
    candidateUserEventAncestry,
    candidateUserRotationDeletionEvidences,
    candidateWorkspaceCheckpoints,
  };
}

function requiredRecords(value: unknown, code: string): Record<string, unknown>[] {
  if (!Array.isArray(value)) throw new Error(code);
  return value.map((entry) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw new Error(code);
    return entry as Record<string, unknown>;
  });
}

function requiredKeyDirectoryEnvelopes(value: unknown, code: string): KeyDirectoryEnvelope[] {
  if (!Array.isArray(value)) throw new Error(code);
  return value.map((entry) => assertKeyDirectoryEnvelope(entry, code));
}

function optionalKeyDirectoryEnvelopes(value: unknown): KeyDirectoryEnvelope[] {
  if (value === undefined || value === null) return [];
  return requiredKeyDirectoryEnvelopes(value, "key_directory_ancestry_invalid");
}

function requiredWorkspaceCheckpoints(value: unknown): Array<{
  workspaceId: string;
  checkpoint: KeyDirectoryEnvelope;
  checkpointAncestry: KeyDirectoryEnvelope[];
  eventAncestry: KeyDirectoryEnvelope[];
}> {
  if (!Array.isArray(value)) throw new Error("candidate_workspace_checkpoints_missing");
  return value.map((entry) => {
    const record = requiredRecord(entry, "candidate_workspace_checkpoint");
    return {
      workspaceId: requiredString(record.workspace_id, "workspace_id"),
      checkpoint: assertKeyDirectoryEnvelope(record.checkpoint, "workspace_checkpoint_missing"),
      checkpointAncestry: optionalKeyDirectoryEnvelopes(record.checkpoint_ancestry),
      eventAncestry: optionalKeyDirectoryEnvelopes(record.event_ancestry),
    };
  });
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`${field}_missing`);
  return value;
}

function requiredRecord(value: unknown, field: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${field}_missing`);
  }
  return value as Record<string, unknown>;
}

function requiredNumber(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${field}_missing`);
  }
  return value;
}
