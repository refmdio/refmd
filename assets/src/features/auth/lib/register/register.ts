import { authApi, devicesApi, encryptionApi } from "@/shared/api";
import { persistDeviceId, persistCurrentKeysWithDsk } from "@/shared/lib/auth/key-persistence";
import { pinInitialKeyDirectoryCheckpoint } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { verifyAndPinSetupAuditCheckpoints } from "@/shared/lib/anti-rollback/setup-audit-checkpoints";
import { setCryptoWorkerReady, setDeviceState } from "@/entities/session";
import { getDeviceName, getDeviceType } from "@/shared/lib/device/metadata";
import { base64UrlDecode, base64UrlEncode, randomBytes } from "@/shared/lib/crypto/encoding";
import {
  createGenesisCompoundAuthorization,
  genesisAuditCheckpointHashes,
  materializeGenesisKeyDirectoryBootstrap,
} from "@/shared/lib/crypto/genesis-authorization";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import type { HybridEncryptionPublicKeyMaterial } from "@/shared/lib/crypto/hybrid-encryption";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { TARGET_KDF_PARAMS } from "@/shared/lib/crypto/kdf-params";
import { buildRecoverableIdentitySecretRecord } from "@/shared/lib/crypto/recoverable-identity-secret-record";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import { currentSuitePolicy } from "@/shared/lib/crypto/suite";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";

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
  try {
    const salt = randomBytes(16);
    const { authKey } = await worker.deriveAuthKeys({
      password,
      salt,
      kdfParams: TARGET_KDF_PARAMS,
    });
    const userId = crypto.randomUUID();
    await worker.setUserContext(userId);
    await ensureDsk(worker);

    const registration = await authApi.register({
      protocol: "refmd.password-account-registration",
      version: 1,
      reserved_user_id: userId,
      email,
      display_name: name,
      auth_key_b64u: base64UrlEncode(authKey),
      salt_b64u: base64UrlEncode(salt),
      kdf_type: "argon2id",
      kdf_params: {
        memory_kib: TARGET_KDF_PARAMS.memory,
        iterations: TARGET_KDF_PARAMS.iterations,
        parallelism: TARGET_KDF_PARAMS.parallelism,
      },
    });
    if (!registration.bootstrap_required || registration.reserved_user_id !== userId) {
      throw new Error("genesis_registration_binding_invalid");
    }

    const deviceId = crypto.randomUUID();
    const workspaceId = registration.reserved_workspace_id;
    await worker.setUserContext(userId, deviceId);
    await worker.generateUmk();
    const umkWrapped = await worker.wrapUmkForServer(userId);
    const recovery = await worker.generateRecoveryKey();
    const identityPublic = await worker.generateIdentityKeys();
    const encryptedIdentity = await worker.wrapIdentityKeysForServer(userId, 1);
    const devicePublic = await worker.generateDeviceKeys({ deviceId });
    const clientNonce = await worker.generateClientNonce();
    await worker.generateKek(workspaceId, 1);
    const memberEnvelopePrecommit = await worker.createGenesisWorkspaceMemberEnvelopePrecommit({
      workspaceId,
      userId,
      deviceId,
      recipientPublicKeyMaterial: identityPublic.hybridEncryptionPublicKeyMaterial,
    });
    const challenge = await devicesApi.bootstrapChallenge();
    const policy = currentSuitePolicy();
    const recoverableIdentitySecretRecord = buildRecoverableIdentitySecretRecord({
      id: crypto.randomUUID(),
      userId,
      identityKeyEpoch: 1,
      previousRecordHash: "GENESIS",
      encryptedSigningPrivateMaterial: encryptedIdentity.encryptedHybridSigningPrivateKeyMaterial,
      signingPrivateMaterialNonce: encryptedIdentity.hybridSigningPrivateKeyMaterialNonce,
      encryptedEncryptionPrivateMaterial:
        encryptedIdentity.encryptedHybridEncryptionPrivateKeyMaterial,
      encryptionPrivateMaterialNonce: encryptedIdentity.hybridEncryptionPrivateKeyMaterialNonce,
      signingKeyId: encryptedIdentity.signingKeyId,
      encryptionKeyId: encryptedIdentity.encryptionKeyId,
      isCurrent: true,
    });

    const prepare = {
      registration_id: registration.registration_id,
      user_id: userId,
      workspace_id: workspaceId,
      owner_role_id: registration.reserved_workspace_role_ids.owner,
      name: getDeviceName(),
      device_type: getDeviceType(),
      device_id: deviceId,
      registration_challenge: challenge.registration_challenge,
      client_nonce: base64UrlEncode(clientNonce),
      encrypted_umk: base64UrlEncode(umkWrapped.encrypted),
      encrypted_umk_nonce: base64UrlEncode(umkWrapped.nonce),
      identity_signing_key_id: encryptedIdentity.signingKeyId,
      identity_encryption_key_id: encryptedIdentity.encryptionKeyId,
      identity_hybrid_signing_public_key_material: identityPublic.hybridSigningPublicKeyMaterial,
      identity_hybrid_encryption_public_key_material:
        identityPublic.hybridEncryptionPublicKeyMaterial,
      device_signing_key_id: devicePublic.signingKeyId,
      device_encryption_key_id: devicePublic.encryptionKeyId,
      device_hybrid_signing_public_key_material: devicePublic.hybridSigningPublicKeyMaterial,
      device_hybrid_encryption_public_key_material: devicePublic.hybridEncryptionPublicKeyMaterial,
      initial_suite_policy: {
        suite_policy_version: policy.suite_policy_version,
        min_suite_rank: policy.min_suite_rank,
        allowed_suite_ids: policy.allowed_suite_ids,
      },
      recoverable_identity_secret_record: recoverableIdentitySecretRecord,
      recovery_authorization: {
        recovery_encrypted_umk: base64UrlEncode(recovery.encryptedUmk),
        recovery_nonce: base64UrlEncode(recovery.nonce),
        recovery_authorization_public_material: recovery.recoveryAuthorizationPublicKey,
        recovery_authorization_key_id: recovery.recoveryAuthorizationKeyId,
      },
      workspace_member_envelope_precommit: memberEnvelopePrecommit,
    } as unknown as StrictJsonValue;

    const intent = await devicesApi.bootstrapIntent(prepare);
    const authorization = await createGenesisCompoundAuthorization({
      worker,
      intent,
      prepare,
      registrationChallengeHash: blake3Base64Url(base64UrlDecode(challenge.registration_challenge)),
      deviceEcdhPublic: devicePublic.ecdhPublic,
      clientNonce,
    });
    const bootstrap = await devicesApi.bootstrap(authorization);
    if (bootstrap.status !== "committed") throw new Error("genesis_commit_failed");
    if (
      bootstrap.user_id !== userId ||
      bootstrap.device_id !== deviceId ||
      bootstrap.workspace_id !== workspaceId
    ) {
      throw new Error("genesis_commit_binding_invalid");
    }

    const keyDirectory = materializeGenesisKeyDirectoryBootstrap(intent, authorization);
    await pinInitialKeyDirectoryCheckpoint({
      scopeKind: "user",
      scopeId: userId,
      eventEnvelopes: keyDirectory.userEvents,
      checkpointEnvelope: keyDirectory.userCheckpoint,
    });
    await pinInitialKeyDirectoryCheckpoint({
      scopeKind: "workspace",
      scopeId: workspaceId,
      eventEnvelopes: keyDirectory.workspaceEvents,
      checkpointEnvelope: keyDirectory.workspaceCheckpoint,
    });
    const setupCheckpoints = await encryptionApi.setupComplete();
    const auditCheckpointHashes = genesisAuditCheckpointHashes(intent);
    await verifyAndPinSetupAuditCheckpoints({
      userId,
      rrpDeviceId: deviceId,
      checkpoints: setupCheckpoints,
      genesisAuthority: {
        userId,
        deviceId,
        workspaceId,
        userAuditCheckpointHash: auditCheckpointHashes.user,
        workspaceAuditCheckpointHash: auditCheckpointHashes.workspace,
        userKeyDirectoryCheckpointHash: checkpointRef(keyDirectory.userCheckpoint.payload).hash,
        workspaceKeyDirectoryCheckpointHash: checkpointRef(keyDirectory.workspaceCheckpoint.payload)
          .hash,
      },
    });

    persistDeviceId(deviceId, userId);
    await persistCurrentKeysWithDsk(userId);
    await worker.storeKekForOffline({ workspaceId, keyVersion: 1 });
    await worker.setInitialized();
    const me = await authApi.me();
    const deviceCheckpoint = checkpointRef(keyDirectory.userCheckpoint.payload);
    setDeviceState({
      deviceId,
      deviceSigningKeyId: devicePublic.signingKeyId,
      deviceKeyCheckpointSequence: deviceCheckpoint.sequence,
      deviceKeyCheckpointHash: deviceCheckpoint.hash,
      deviceHybridSigningPublicKeyMaterial: devicePublic.hybridSigningPublicKeyMaterial,
      deviceEcdhPublic: devicePublic.ecdhPublic,
    });
    await worker.storeAuthBootstrap({
      userId,
      email: me.email,
      name: me.name,
      deviceId,
      deviceSigningKeyId: devicePublic.signingKeyId,
      cachedAt: Date.now(),
    });
    setCryptoWorkerReady(true);

    return {
      userId,
      email: me.email,
      name: me.name,
      workspaceId,
      sessionId: me.session_id,
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
    await worker.clearTransientKeys().catch(() => {});
  }
}

async function ensureDsk(worker: ReturnType<typeof getCryptoWorker>): Promise<void> {
  if (!(await worker.loadStoredDsk())) await worker.generateDsk();
}

function checkpointRef(payload: Record<string, unknown>): { sequence: number; hash: string } {
  if (typeof payload.sequence !== "number" || !Number.isSafeInteger(payload.sequence)) {
    throw new Error("device_key_checkpoint_invalid");
  }
  return {
    sequence: payload.sequence,
    hash: blake3Base64Url(canonicalizeStrictBytes(payload as StrictJsonValue)),
  };
}
