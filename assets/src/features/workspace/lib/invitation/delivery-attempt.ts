import type { components } from "@/shared/api";
import { workspacesApi } from "@/shared/api";
import type { AuthState, DeviceState } from "@/entities/session";
import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { invitationLookupToken } from "./token";

type Lookup = components["schemas"]["InvitationLookupResponse"];
export type DeliveryAttempt = components["schemas"]["InvitationDeliveryAttemptResponse"];

interface LocalDeliveryAttempt {
  attemptId: string;
  contextId: string;
  recipientUserId: string;
  recipientDeviceId: string;
  recipientRedeemNonce: string;
  liveRedeemChallengeHash: string;
}

export class InvitationDeliveryPendingError extends Error {
  readonly attemptId: string;

  constructor(attemptId: string) {
    super("Workspace key delivery is waiting for approval.");
    this.name = "InvitationDeliveryPendingError";
    this.attemptId = attemptId;
  }
}

export class InvitationDeliveryTerminalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvitationDeliveryTerminalError";
  }
}

export async function getApprovedWorkspaceDeliveryAttempt(params: {
  token: string;
  lookup: Lookup;
  auth: AuthState;
  device: DeviceState;
}): Promise<DeliveryAttempt> {
  const { lookup, auth, device } = params;
  if (
    lookup.kind !== "workspace" ||
    lookup.delivery_mode !== "known_recipient" ||
    !lookup.invitation_id ||
    lookup.recipient_user_id !== auth.user.id ||
    !lookup.recipient_device_ids?.includes(device.deviceId)
  ) {
    throw new Error("This invitation belongs to another account or device.");
  }

  const lookupToken = invitationLookupToken(params.token);
  let local = readLocalAttempt(lookupToken);
  let attempt: DeliveryAttempt | null = null;
  if (local) {
    try {
      attempt = await workspacesApi.getInvitationDeliveryAttempt(local.attemptId);
    } catch {
      clearLocalAttempt(lookupToken);
      local = null;
    }
  }

  if (!local || !attempt || attempt.status === "expired") {
    const created = await createWorkspaceAttempt({
      lookupToken,
      lookup,
      auth,
      device,
    });
    local = created.local;
    attempt = created.attempt;
    writeLocalAttempt(lookupToken, local);
  }

  assertAttemptMatchesLocal(attempt, local, lookup);
  if (attempt.status !== "approved" || !attempt.approved_artifacts) {
    throw new InvitationDeliveryPendingError(attempt.redeem_attempt_id);
  }
  return attempt;
}

export async function getApprovedGuestDeliveryAttempt(params: {
  token: string;
  lookup: Lookup;
  auth: AuthState;
  device: DeviceState;
  target: {
    userId: string;
    deviceId: string;
    registration: components["schemas"]["InvitationDeliveryTargetRegistration"];
    registrationProof: Record<string, unknown>;
  };
}): Promise<DeliveryAttempt> {
  const { lookup, auth, device, target } = params;
  if (
    lookup.kind !== "guest" ||
    lookup.delivery_mode !== "known_recipient" ||
    !lookup.invitation_id ||
    lookup.recipient_user_id !== auth.user.id ||
    !lookup.recipient_device_ids?.includes(device.deviceId)
  ) {
    throw new Error("This guest invitation belongs to another account or device.");
  }

  const lookupToken = invitationLookupToken(params.token);
  let local = readLocalAttempt(lookupToken);
  let attempt: DeliveryAttempt | null = null;
  if (local) {
    try {
      attempt = await workspacesApi.getInvitationDeliveryAttempt(local.attemptId);
    } catch {
      clearLocalAttempt(lookupToken);
      throw new InvitationDeliveryTerminalError(
        "Guest invitation key delivery attempt is no longer available.",
      );
    }
  }

  if (attempt?.status === "consumed" || attempt?.status === "expired") {
    clearLocalAttempt(lookupToken);
    throw new InvitationDeliveryTerminalError(
      attempt.status === "consumed"
        ? "Guest invitation key delivery attempt was already consumed."
        : "Guest invitation key delivery attempt expired.",
    );
  }

  if (!local || !attempt) {
    const attemptId = crypto.randomUUID();
    const recipientRedeemNonce = randomBase64Url32();
    const liveRedeemChallengeHash = hash({
      protocol: "refmd.invitation-live-redeem-challenge",
      version: 1,
      redeem_attempt_id: attemptId,
      context_id: lookup.invitation_id,
      recipient_user_id: auth.user.id,
      recipient_device_id: device.deviceId,
      challenge_nonce: randomBase64Url32(),
    });
    local = {
      attemptId,
      contextId: lookup.invitation_id,
      recipientUserId: auth.user.id,
      recipientDeviceId: device.deviceId,
      recipientRedeemNonce,
      liveRedeemChallengeHash,
    };
    attempt = await workspacesApi.createInvitationDeliveryAttempt({
      token: lookupToken,
      redeem_attempt_id: attemptId,
      target_user_id: target.userId,
      target_device_id: target.deviceId,
      target_registration: target.registration,
      target_registration_proof:
        target.registrationProof as unknown as components["schemas"]["CreateInvitationDeliveryAttemptRequest"]["target_registration_proof"],
      recipient_redeem_nonce: recipientRedeemNonce,
      live_redeem_challenge_hash: liveRedeemChallengeHash,
    });
    writeLocalAttempt(lookupToken, local);
  }

  assertAttemptMatchesLocal(attempt, local, lookup, {
    contextKind: "guest_invitation",
    targetUserId: target.userId,
    targetDeviceId: target.deviceId,
  });
  if (attempt.status !== "approved" || !attempt.approved_artifacts) {
    throw new InvitationDeliveryPendingError(attempt.redeem_attempt_id);
  }
  return attempt;
}

export function consumeLocalDeliveryAttempt(token: string): void {
  clearLocalAttempt(invitationLookupToken(token));
}

async function createWorkspaceAttempt(params: {
  lookupToken: string;
  lookup: Lookup;
  auth: AuthState;
  device: DeviceState;
}): Promise<{ local: LocalDeliveryAttempt; attempt: DeliveryAttempt }> {
  const publicKeys = await getCryptoWorker().getPublicKeys();
  if (
    !publicKeys.identityHybridEncryptionPublicKeyMaterial ||
    !publicKeys.identityHybridSigningPublicKeyMaterial ||
    !publicKeys.deviceHybridEncryptionPublicKeyMaterial ||
    !publicKeys.deviceHybridSigningPublicKeyMaterial
  ) {
    throw new Error("Device encryption keys are not available.");
  }
  const invitationId = params.lookup.invitation_id!;
  const attemptId = crypto.randomUUID();
  const recipientRedeemNonce = randomBase64Url32();
  const liveChallenge = {
    protocol: "refmd.invitation-live-redeem-challenge",
    version: 1,
    redeem_attempt_id: attemptId,
    context_id: invitationId,
    recipient_user_id: params.auth.user.id,
    recipient_device_id: params.device.deviceId,
    challenge_nonce: randomBase64Url32(),
  };
  const liveRedeemChallengeHash = hash(liveChallenge);
  const local: LocalDeliveryAttempt = {
    attemptId,
    contextId: invitationId,
    recipientUserId: params.auth.user.id,
    recipientDeviceId: params.device.deviceId,
    recipientRedeemNonce,
    liveRedeemChallengeHash,
  };
  const attempt = await workspacesApi.createInvitationDeliveryAttempt({
    token: params.lookupToken,
    redeem_attempt_id: attemptId,
    target_user_id: params.auth.user.id,
    target_device_id: params.device.deviceId,
    target_registration: {
      identity_hybrid_encryption_public_key_material:
        publicKeys.identityHybridEncryptionPublicKeyMaterial,
      identity_hybrid_signing_public_key_material:
        publicKeys.identityHybridSigningPublicKeyMaterial,
      device_hybrid_encryption_public_key_material:
        publicKeys.deviceHybridEncryptionPublicKeyMaterial,
      device_hybrid_signing_public_key_material: publicKeys.deviceHybridSigningPublicKeyMaterial,
    },
    recipient_redeem_nonce: recipientRedeemNonce,
    live_redeem_challenge_hash: liveRedeemChallengeHash,
  });
  return { local, attempt };
}

function assertAttemptMatchesLocal(
  attempt: DeliveryAttempt,
  local: LocalDeliveryAttempt,
  lookup: Lookup,
  expected: {
    contextKind: "workspace_invitation" | "guest_invitation";
    targetUserId: string;
    targetDeviceId: string;
  } = {
    contextKind: "workspace_invitation",
    targetUserId: local.recipientUserId,
    targetDeviceId: local.recipientDeviceId,
  },
): void {
  const expectedNonceStateHash = hash({
    redeem_attempt_id: local.attemptId,
    recipient_redeem_nonce: local.recipientRedeemNonce,
    recipient_device_id: local.recipientDeviceId,
    context_id: local.contextId,
  });
  if (
    attempt.redeem_attempt_id !== local.attemptId ||
    attempt.context_kind !== expected.contextKind ||
    attempt.context_id !== lookup.invitation_id ||
    attempt.recipient_user_id !== local.recipientUserId ||
    attempt.recipient_device_id !== local.recipientDeviceId ||
    attempt.target_user_id !== expected.targetUserId ||
    attempt.target_device_id !== expected.targetDeviceId ||
    attempt.recipient_redeem_nonce !== local.recipientRedeemNonce ||
    attempt.live_redeem_challenge_hash !== local.liveRedeemChallengeHash ||
    attempt.recipient_nonce_state_hash !== expectedNonceStateHash
  ) {
    throw new Error("Invitation key delivery attempt is malformed.");
  }
}

function storageKey(token: string): string {
  return `refmd-invitation-delivery-attempt:${token}`;
}

function readLocalAttempt(token: string): LocalDeliveryAttempt | null {
  const raw = localStorage.getItem(storageKey(token));
  if (!raw) return null;
  try {
    return JSON.parse(raw) as LocalDeliveryAttempt;
  } catch {
    clearLocalAttempt(token);
    return null;
  }
}

function writeLocalAttempt(token: string, attempt: LocalDeliveryAttempt): void {
  localStorage.setItem(storageKey(token), JSON.stringify(attempt));
}

function clearLocalAttempt(token: string): void {
  localStorage.removeItem(storageKey(token));
}

function randomBase64Url32(): string {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
}

function hash(value: unknown): string {
  return blake3Base64Url(canonicalizeStrictBytes(value as StrictJsonValue));
}
