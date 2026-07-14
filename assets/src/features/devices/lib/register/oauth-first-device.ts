import { authApi, devicesApi, encryptionApi } from "@/shared/api";
import type { AuthState } from "@/entities/session";
import { setCryptoWorkerReady, setFullSession } from "@/entities/session";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { buildInitialKeyDirectoryBootstrap } from "@/shared/lib/crypto/key-directory/initial";
import { computeSigningKeyId } from "@/shared/lib/crypto/signature";
import {
  persistWorkspaceKekForMember,
  persistWorkspaceKekLocally,
} from "@/shared/lib/crypto/workspace-kek-persistence";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { pinInitialKeyDirectoryCheckpoint } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { verifyAndPinSetupAuditCheckpoints } from "@/shared/lib/anti-rollback/setup-audit-checkpoints";
import { persistCurrentKeysWithDsk, persistDeviceId } from "@/shared/lib/auth/key-persistence";
import { getDeviceName, getDeviceType } from "@/shared/lib/device/metadata";
import { ensureDskInWorker } from "./session-keys";

type OAuthFirstDeviceBootstrapResult = {
  dskUnavailableOAuth: boolean;
  recoveryMnemonic: string;
  redirectPath: string;
};

export async function completeOAuthFirstDeviceBootstrap(params: {
  auth: AuthState;
  completionRedirectPath: string;
}): Promise<OAuthFirstDeviceBootstrapResult> {
  const { auth, completionRedirectPath } = params;
  const worker = getCryptoWorker();
  const userId = auth.user.id;
  const deviceId = crypto.randomUUID();

  try {
    await worker.setUserContext(userId, deviceId);

    const hasDsk = await ensureDskInWorker();

    await worker.generateUmk();
    const recovery = await worker.generateRecoveryKey();
    const identityPublic = await worker.generateIdentityKeys();
    const encryptedIdentity = await worker.wrapIdentityKeysForServer(userId);
    const devicePublic = await worker.generateDeviceKeys({ deviceId });

    if (hasDsk) {
      await persistCurrentKeysWithDsk(userId);
    }

    const setup = await authApi.oauthCryptoSetup({
      recovery_encrypted_umk: base64UrlEncode(recovery.encryptedUmk),
      recovery_nonce: base64UrlEncode(recovery.nonce),
      recovery_authorization_public_material: recovery.recoveryAuthorizationPublicKey,
      recovery_authorization_key_id: recovery.recoveryAuthorizationKeyId,
      hybrid_encryption_public_key_material: identityPublic.hybridEncryptionPublicKeyMaterial,
      hybrid_signing_public_key_material: identityPublic.hybridSigningPublicKeyMaterial,
      encrypted_identity_hybrid_encryption_private_key_material: base64UrlEncode(
        encryptedIdentity.encryptedHybridEncryptionPrivateKeyMaterial,
      ),
      identity_hybrid_encryption_private_key_material_nonce: base64UrlEncode(
        encryptedIdentity.hybridEncryptionPrivateKeyMaterialNonce,
      ),
      encrypted_identity_hybrid_signing_private_key_material: base64UrlEncode(
        encryptedIdentity.encryptedHybridSigningPrivateKeyMaterial,
      ),
      identity_hybrid_signing_private_key_material_nonce: base64UrlEncode(
        encryptedIdentity.hybridSigningPrivateKeyMaterialNonce,
      ),
    });

    const clientNonce = await worker.generateClientNonce();
    const bootstrapChallenge = await devicesApi.bootstrapChallenge();
    const pendingRegistrationChallengeHash = blake3Base64Url(
      base64UrlDecode(bootstrapChallenge.registration_challenge),
    );
    const identitySigningKeyId = computeSigningKeyId(identityPublic.hybridSigningPublicKeyMaterial);
    const { signature: identitySignature } = await worker.createGenesisDeviceBootstrapSignature({
      deviceEcdhPublic: devicePublic.ecdhPublic,
      clientNonce,
      registrationChallengeHash: pendingRegistrationChallengeHash,
      identitySigningKeyId,
      userIdentityPublicKeyHash: blake3Base64Url(
        canonicalizeStrictBytes(
          identityPublic.hybridSigningPublicKeyMaterial as unknown as StrictJsonValue,
        ),
      ),
    });
    const initialKeyDirectory = await buildInitialKeyDirectoryBootstrap({
      userId,
      workspaceId: setup.workspace_id,
      workspaceOwnerRoleId: setup.workspace_owner_role_id,
      deviceId,
      identityHybridSigningPublicKeyMaterial: identityPublic.hybridSigningPublicKeyMaterial,
      identityHybridEncryptionPublicKeyMaterial: identityPublic.hybridEncryptionPublicKeyMaterial,
      deviceHybridSigningPublicKeyMaterial: devicePublic.hybridSigningPublicKeyMaterial,
      deviceHybridEncryptionPublicKeyMaterial: devicePublic.hybridEncryptionPublicKeyMaterial,
    });
    const deviceCheckpoint = deviceCheckpointFromEnvelope(initialKeyDirectory.userCheckpoint);

    const bootstrap = await devicesApi.bootstrap({
      name: getDeviceName(),
      device_type: getDeviceType(),
      device_id: deviceId,
      identity_signing_key_id: identitySigningKeyId,
      identity_hybrid_signing_public_key_material: identityPublic.hybridSigningPublicKeyMaterial,
      device_hybrid_signing_public_key_material: devicePublic.hybridSigningPublicKeyMaterial,
      device_signing_key_id: devicePublic.signingKeyId,
      device_hybrid_encryption_public_key_material: devicePublic.hybridEncryptionPublicKeyMaterial,
      device_encryption_key_id: devicePublic.encryptionKeyId,
      client_nonce: base64UrlEncode(clientNonce),
      registration_challenge: bootstrapChallenge.registration_challenge,
      identity_signature: identitySignature,
      user_key_directory_events: initialKeyDirectory.userEvents,
      user_key_directory_checkpoint: initialKeyDirectory.userCheckpoint,
      workspace_key_directory_events: initialKeyDirectory.workspaceEvents,
      workspace_key_directory_checkpoint: initialKeyDirectory.workspaceCheckpoint,
    });
    if (bootstrap.status !== "approved") {
      throw new Error("device_bootstrap_not_approved");
    }

    await pinInitialKeyDirectoryCheckpoint({
      scopeKind: "user",
      scopeId: userId,
      eventEnvelopes: initialKeyDirectory.userEvents,
      checkpointEnvelope: initialKeyDirectory.userCheckpoint,
    });
    await pinInitialKeyDirectoryCheckpoint({
      scopeKind: "workspace",
      scopeId: setup.workspace_id,
      eventEnvelopes: initialKeyDirectory.workspaceEvents,
      checkpointEnvelope: initialKeyDirectory.workspaceCheckpoint,
    });

    persistDeviceId(deviceId, userId);
    await worker
      .storeAuthBootstrap({
        userId,
        email: auth.user.email,
        name: auth.user.name,
        deviceId,
        deviceSigningKeyId: devicePublic.signingKeyId,
        cachedAt: Date.now(),
      })
      .catch(() => {});

    await worker.setUserContext(userId, deviceId);
    await worker.setInitialized();

    setFullSession(
      {
        user: auth.user,
        sessionId: auth.sessionId,
        identityHybridSigningPublicKeyMaterial: identityPublic.hybridSigningPublicKeyMaterial,
        identityEcdhPublic: identityPublic.ecdhPublic,
        expiresAt: auth.expiresAt,
        needsPasswordReentry: false,
      },
      {
        deviceId,
        deviceSigningKeyId: devicePublic.signingKeyId,
        deviceKeyCheckpointSequence: deviceCheckpoint.sequence,
        deviceKeyCheckpointHash: deviceCheckpoint.hash,
        deviceHybridSigningPublicKeyMaterial: devicePublic.hybridSigningPublicKeyMaterial,
        deviceEcdhPublic: devicePublic.ecdhPublic,
      },
    );

    await worker.generateKek(setup.workspace_id);
    await persistWorkspaceKekLocally({
      workspaceId: setup.workspace_id,
      userId,
      deviceId,
      deviceHybridEncryptionPublicKeyMaterial: devicePublic.hybridEncryptionPublicKeyMaterial,
      keyVersion: 1,
      isActive: true,
      keyDirectoryCheckpoint: initialKeyDirectory.workspaceCheckpoint,
    });
    await persistWorkspaceKekForMember({
      workspaceId: setup.workspace_id,
      userId,
      senderDeviceId: deviceId,
      targetUserId: userId,
      targetIdentityHybridEncryptionPublicKeyMaterial:
        identityPublic.hybridEncryptionPublicKeyMaterial,
      keyVersion: 1,
      rrpDeviceId: deviceId,
      ignoreConflict: true,
    });
    const setupAudit = await encryptionApi.setupComplete();
    await verifyAndPinSetupAuditCheckpoints({
      userId,
      rrpDeviceId: deviceId,
      checkpoints: setupAudit,
    });
    setCryptoWorkerReady(true);

    return {
      dskUnavailableOAuth: !hasDsk,
      recoveryMnemonic: recovery.mnemonic,
      redirectPath: completionRedirectPath,
    };
  } finally {
    await worker.clearTransientKeys().catch(() => {});
  }
}

function deviceCheckpointFromEnvelope(envelope: { payload: Record<string, unknown> }): {
  sequence: number;
  hash: string;
} {
  const sequence = envelope.payload.sequence;
  if (typeof sequence !== "number" || !Number.isInteger(sequence) || sequence < 1) {
    throw new Error("device_key_checkpoint_invalid");
  }
  return {
    sequence,
    hash: blake3Base64Url(canonicalizeStrictBytes(envelope.payload as StrictJsonValue)),
  };
}
