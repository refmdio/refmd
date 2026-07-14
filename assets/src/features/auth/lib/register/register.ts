import { base64UrlDecode, base64UrlEncode, randomBytes } from "@/shared/lib/crypto/encoding";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { TARGET_KDF_PARAMS } from "@/shared/lib/crypto/kdf-params";
import {
  persistWorkspaceKekForMember,
  persistWorkspaceKekLocally,
} from "@/shared/lib/crypto/workspace-kek-persistence";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { authApi, devicesApi, encryptionApi } from "@/shared/api";
import { persistDeviceId, persistCurrentKeysWithDsk } from "@/shared/lib/auth/key-persistence";
import { setDeviceState, setCryptoWorkerReady } from "@/entities/session";
import { getDeviceName, getDeviceType } from "@/shared/lib/device/metadata";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import type { HybridEncryptionPublicKeyMaterial } from "@/shared/lib/crypto/hybrid-encryption";
import { buildInitialKeyDirectoryBootstrap } from "@/shared/lib/crypto/key-directory/initial";
import { pinInitialKeyDirectoryCheckpoint } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { verifyAndPinSetupAuditCheckpoints } from "@/shared/lib/anti-rollback/setup-audit-checkpoints";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { computeSigningKeyId } from "@/shared/lib/crypto/signature";
interface RegisterResult {
  userId: string;
  email: string;
  name: string;
  workspaceId: string;
  sessionId: string;
  deviceId: string;
  recoveryMnemonic: string;
  deviceSigningKeyId: string;
  deviceKeyCheckpointSequence: number;
  deviceKeyCheckpointHash: string;
  deviceHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  deviceEcdhPublic: Uint8Array;
  identityHybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  identityHybridEncryptionPublicKeyMaterial: HybridEncryptionPublicKeyMaterial;
  identityEcdhPublic: Uint8Array;
  workerReady: boolean;
}
export async function register(
  email: string,
  name: string,
  password: string,
): Promise<RegisterResult> {
  const worker = getCryptoWorker();
  // Step 1: Generate salt and derive keys (PUK stored transiently in Worker)
  try {
    const salt = randomBytes(16);
    const saltBase64 = base64UrlEncode(salt);
    const { authKey } = await worker.deriveAuthKeys({
      password,
      salt,
      kdfParams: TARGET_KDF_PARAMS,
    });
    const authKeyBase64 = base64UrlEncode(authKey);
    // Step 2: Pre-generate IDs and set Worker context
    const userId = crypto.randomUUID();
    const deviceId = crypto.randomUUID();
    await worker.setUserContext(userId, deviceId);
    // Step 2b: Load or generate DSK in Worker (for key persistence later)
    let hadDsk = false;
    if (await worker.loadStoredDsk()) {
      hadDsk = true;
    } else {
      try {
        await worker.generateDsk();
        hadDsk = true;
      } catch {
        // DSK unavailable
      }
    }
    // Step 3: Generate UMK (stays in Worker) and wrap with PUK
    await worker.generateUmk();
    const umkWrapped = await worker.wrapUmkForServer(userId);
    // Step 4: Generate recovery key (RUK stays in Worker, UMK wrapped internally)
    const recovery = await worker.generateRecoveryKey();
    // Step 5: Generate identity keys and encrypt with UMK (all in Worker)
    const identityPublic = await worker.generateIdentityKeys();
    const encryptedIdentity = await worker.wrapIdentityKeysForServer(userId);
    // Step 6: Generate device keys (stays in Worker)
    const devicePublic = await worker.generateDeviceKeys({ deviceId });
    // Step 6b: Persist keys BEFORE server registration (crash safety)
    if (hadDsk) {
      await persistCurrentKeysWithDsk(userId);
    }
    const clientNonce = await worker.generateClientNonce();
    // Step 7: Register with server
    const registerRes = await authApi.register({
      user_id: userId,
      email,
      name,
      auth_key: authKeyBase64,
      salt: saltBase64,
      encrypted_umk: base64UrlEncode(umkWrapped.encrypted),
      umk_nonce: base64UrlEncode(umkWrapped.nonce),
      kdf_params: TARGET_KDF_PARAMS,
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
    const bootstrapChallenge = await devicesApi.bootstrapChallenge();
    const pendingRegistrationChallengeHash = blake3Base64Url(
      base64UrlDecode(bootstrapChallenge.registration_challenge),
    );
    const { signature: identitySignature } = await worker.createGenesisDeviceBootstrapSignature({
      deviceEcdhPublic: devicePublic.ecdhPublic,
      clientNonce,
      registrationChallengeHash: pendingRegistrationChallengeHash,
      identitySigningKeyId: computeSigningKeyId(identityPublic.hybridSigningPublicKeyMaterial),
      userIdentityPublicKeyHash: blake3Base64Url(
        canonicalizeStrictBytes(
          identityPublic.hybridSigningPublicKeyMaterial as unknown as StrictJsonValue,
        ),
      ),
    });
    const initialKeyDirectory = await buildInitialKeyDirectoryBootstrap({
      userId,
      workspaceId: registerRes.workspace_id,
      workspaceOwnerRoleId: registerRes.workspace_owner_role_id,
      deviceId,
      identityHybridSigningPublicKeyMaterial: identityPublic.hybridSigningPublicKeyMaterial,
      identityHybridEncryptionPublicKeyMaterial: identityPublic.hybridEncryptionPublicKeyMaterial,
      deviceHybridSigningPublicKeyMaterial: devicePublic.hybridSigningPublicKeyMaterial,
      deviceHybridEncryptionPublicKeyMaterial: devicePublic.hybridEncryptionPublicKeyMaterial,
    });
    const deviceCheckpoint = deviceCheckpointFromEnvelope(initialKeyDirectory.userCheckpoint);
    // Step 7b: Bootstrap first device (dedicated endpoint)
    const bootstrapRes = await devicesApi.bootstrap({
      name: getDeviceName(),
      device_type: getDeviceType(),
      device_id: deviceId,
      identity_signing_key_id: computeSigningKeyId(identityPublic.hybridSigningPublicKeyMaterial),
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
    if (bootstrapRes.status !== "approved") {
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
      scopeId: registerRes.workspace_id,
      eventEnvelopes: initialKeyDirectory.workspaceEvents,
      checkpointEnvelope: initialKeyDirectory.workspaceCheckpoint,
    });
    persistDeviceId(deviceId, userId);
    await worker
      .storeAuthBootstrap({
        userId,
        email,
        name,
        deviceId,
        deviceSigningKeyId: devicePublic.signingKeyId,
        cachedAt: Date.now(),
      })
      .catch(() => {
        // Auth bootstrap cache is a cold-start optimization; live session state remains authoritative.
      });
    await worker.setUserContext(userId, deviceId);
    await worker.setInitialized();
    // Step 8: Establish RRP capability
    setDeviceState({
      deviceId,
      deviceSigningKeyId: devicePublic.signingKeyId,
      deviceKeyCheckpointSequence: deviceCheckpoint.sequence,
      deviceKeyCheckpointHash: deviceCheckpoint.hash,
      deviceHybridSigningPublicKeyMaterial: devicePublic.hybridSigningPublicKeyMaterial,
      deviceEcdhPublic: devicePublic.ecdhPublic,
    });
    // Step 9: Generate KEK and save device envelope (RRP required)
    await worker.generateKek(registerRes.workspace_id);
    await persistWorkspaceKekLocally({
      workspaceId: registerRes.workspace_id,
      userId,
      deviceId,
      deviceHybridEncryptionPublicKeyMaterial: devicePublic.hybridEncryptionPublicKeyMaterial,
      keyVersion: 1,
      isActive: true,
      keyDirectoryCheckpoint: initialKeyDirectory.workspaceCheckpoint,
    });
    await persistWorkspaceKekForMember({
      workspaceId: registerRes.workspace_id,
      userId,
      senderDeviceId: deviceId,
      targetUserId: userId,
      targetIdentityHybridEncryptionPublicKeyMaterial:
        identityPublic.hybridEncryptionPublicKeyMaterial,
      keyVersion: 1,
      rrpDeviceId: deviceId,
      ignoreConflict: true,
    });
    // Step 10: Mark encryption setup complete
    const setupAudit = await encryptionApi.setupComplete();
    await verifyAndPinSetupAuditCheckpoints({
      userId,
      rrpDeviceId: deviceId,
      checkpoints: setupAudit,
    });
    setCryptoWorkerReady(true);
    return {
      userId,
      email: registerRes.user.email,
      name: registerRes.user.name,
      workspaceId: registerRes.workspace_id,
      sessionId: registerRes.session_id,
      deviceId,
      recoveryMnemonic: recovery.mnemonic,
      deviceSigningKeyId: devicePublic.signingKeyId,
      deviceKeyCheckpointSequence: deviceCheckpoint.sequence,
      deviceKeyCheckpointHash: deviceCheckpoint.hash,
      deviceHybridSigningPublicKeyMaterial: devicePublic.hybridSigningPublicKeyMaterial,
      deviceEcdhPublic: devicePublic.ecdhPublic,
      identityHybridSigningPublicKeyMaterial: identityPublic.hybridSigningPublicKeyMaterial,
      identityHybridEncryptionPublicKeyMaterial: identityPublic.hybridEncryptionPublicKeyMaterial,
      identityEcdhPublic: identityPublic.ecdhPublic,
      workerReady: true,
    };
  } finally {
    await worker.clearTransientKeys().catch(() => {
      // Transient registration keys expire with the worker/session and are regenerated on retry.
    });
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
