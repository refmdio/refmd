import type { AuthState } from "@/entities/session";
import { authApi, devicesApi } from "@/shared/api";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { getDeviceName, getDeviceType } from "@/shared/lib/device/metadata";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import { buildPendingRegistrationBindingHash } from "@/shared/lib/crypto/signature-recovery-transcripts";
import { buildDeviceKeyDirectoryAppend } from "@/shared/lib/crypto/key-directory/device-events";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { RECOVERY_PENDING_DEVICE_STORAGE_KEY } from "@/shared/lib/auth/recovery-pending-device";
import {
  getKeyDirectoryPin,
  hashKeyDirectoryCheckpointEnvelope,
} from "@/shared/lib/anti-rollback/key-directory-pin/pins";
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

export async function recoverAccount(
  params: RecoveryAttemptParams,
): Promise<RecoveryAttemptResult> {
  const worker = getCryptoWorker();

  params.setStatusMessage("Fetching recovery data...");
  const recovery = await authApi.getRecovery();

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
  });

  params.setStatusMessage("Getting recovery challenge...");
  const challengeResponse = await authApi.recoveryChallenge(params.auth.user.email);

  params.setStatusMessage("Preparing recovered device...");
  const deviceId = crypto.randomUUID();
  await worker.setUserContext(params.auth.user.id, deviceId);
  const publicKeys = await worker.generateDeviceKeys({ deviceId });
  const clientNonce = await worker.generateClientNonce();
  const registrationChallenge = await devicesApi.registrationChallenge();
  const pendingRegistrationChallengeHash = blake3Base64Url(
    base64UrlDecode(registrationChallenge.registration_challenge),
  );
  const pendingRegistration = await devicesApi.createRegistration({
    name: getDeviceName(),
    device_type: getDeviceType(),
    device_id: deviceId,
    identity_signing_key_id: recovery.identity_signing_key_id!,
    device_hybrid_encryption_public_key_material: publicKeys.hybridEncryptionPublicKeyMaterial,
    device_encryption_key_id: publicKeys.encryptionKeyId,
    device_hybrid_signing_public_key_material: publicKeys.hybridSigningPublicKeyMaterial,
    device_signing_key_id: publicKeys.signingKeyId,
    client_nonce: base64UrlEncode(clientNonce),
    registration_challenge: registrationChallenge.registration_challenge,
  });
  if (pendingRegistration.status !== "pending")
    throw new Error("recovery_registration_not_pending");

  const recoverySessionId = crypto.randomUUID();
  const candidate = recoveryCandidateFromServer(recovery);
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
  });
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
  const candidateUserEventAncestry = requiredKeyDirectoryEnvelopes(
    recovery.candidate_user_event_ancestry,
    "candidate_user_event_ancestry_missing",
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
    candidateUserEventAncestry,
    candidateWorkspaceCheckpoints,
  };
}

function requiredKeyDirectoryEnvelopes(value: unknown, code: string): KeyDirectoryEnvelope[] {
  if (!Array.isArray(value)) throw new Error(code);
  return value.map((entry) => assertKeyDirectoryEnvelope(entry, code));
}

function requiredWorkspaceCheckpoints(value: unknown): Array<{
  workspaceId: string;
  checkpoint: KeyDirectoryEnvelope;
}> {
  if (!Array.isArray(value)) throw new Error("candidate_workspace_checkpoints_missing");
  return value.map((entry) => {
    const record = requiredRecord(entry, "candidate_workspace_checkpoint");
    return {
      workspaceId: requiredString(record.workspace_id, "workspace_id"),
      checkpoint: assertKeyDirectoryEnvelope(record.checkpoint, "workspace_checkpoint_missing"),
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
