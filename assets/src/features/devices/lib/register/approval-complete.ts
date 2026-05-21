import { authApi } from "@/shared/api";
import type { AuthState } from "@/entities/session";
import { setCryptoWorkerReady, setFullSession } from "@/entities/session";
import { installTransferredKeyDirectoryCheckpoint } from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { persistDeviceId, persistCurrentKeysWithDsk } from "@/shared/lib/auth/key-persistence";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { verifySenderDeviceIdentityAndTofu } from "@/shared/lib/crypto/sender-device-verification";
import type { HybridEncryptionPublicKeyMaterial } from "@/shared/lib/crypto/hybrid-encryption";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { loadPersistedDskIntoWorker } from "./session-keys";
import { restoreWorkspaceKeks } from "./session-keks";
import { retryGetUmk } from "./approval-support";
import type { DeviceRegistrationPublicKeys } from "../../model/register/types";

interface IdentityPublicKeys {
  hybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  ecdhPublic: Uint8Array;
}

interface ApprovedDeviceRestorationResult {
  identityPublicKeys: IdentityPublicKeys | null;
  requiresPasswordReentry: boolean;
  dskUnavailableOAuth: boolean;
}

type ApprovedRegistrationResult =
  | {
      kind: "needs_password";
    }
  | {
      kind: "done";
      dskUnavailableOAuth: boolean;
      redirectPath: string;
    };

export async function completeApprovedRegistration(params: {
  auth: AuthState;
  deviceId: string;
  publicKeys: DeviceRegistrationPublicKeys;
  completionRedirectPath: string;
}): Promise<ApprovedRegistrationResult> {
  const restorationResult = await restoreApprovedDeviceSession({
    auth: params.auth,
    deviceId: params.deviceId,
  });
  setCryptoWorkerReady(true);

  setFullSession(
    {
      user: params.auth.user,
      sessionId: params.auth.sessionId,
      identityHybridSigningPublicKeyMaterial:
        restorationResult.identityPublicKeys?.hybridSigningPublicKeyMaterial ?? null,
      identityEcdhPublic: restorationResult.identityPublicKeys?.ecdhPublic ?? null,
      expiresAt: params.auth.expiresAt,
    },
    {
      deviceId: params.deviceId,
      deviceSigningKeyId: params.publicKeys.signingKeyId,
      deviceHybridSigningPublicKeyMaterial: params.publicKeys.hybridSigningPublicKeyMaterial,
      deviceEcdhPublic: params.publicKeys.ecdhPublic,
    },
  );

  persistDeviceId(params.deviceId, params.auth.user.id);

  if (restorationResult.requiresPasswordReentry) {
    return {
      kind: "needs_password",
    };
  }

  return {
    kind: "done",
    dskUnavailableOAuth: restorationResult.dskUnavailableOAuth,
    redirectPath: params.completionRedirectPath,
  };
}

async function restoreApprovedDeviceSession(params: {
  auth: AuthState;
  deviceId: string;
}): Promise<ApprovedDeviceRestorationResult> {
  const { auth, deviceId } = params;
  const worker = getCryptoWorker();

  await worker.setUserContext(auth.user.id, deviceId);

  const umkData = await retryGetUmk(deviceId, 10, 2000, deviceId);
  const me = await authApi.me();
  const expectedIdentityHybridSigningPublicKeyMaterial =
    auth.identityHybridSigningPublicKeyMaterial ??
    (me.identity_hybrid_signing_public_key_material
      ? (me.identity_hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial)
      : null);
  const expectedIdentityEcdhPublic =
    auth.identityEcdhPublic ??
    identityEcdhPublicFromMaterial(
      me.identity_hybrid_encryption_public_key_material as
        | HybridEncryptionPublicKeyMaterial
        | null
        | undefined,
    );

  try {
    await verifySenderDeviceIdentityAndTofu({
      sender: umkData,
      senderUserId: auth.user.id,
      expectedIdentityHybridSigningPublicKeyMaterial,
      expectedIdentityEcdhPublic,
    });
  } catch {
    throw new Error("UMK sender device identity could not be verified.");
  }

  await worker.openInitialAkeUmkDelivery({
    initialAke: (umkData as { initial_ake?: unknown }).initial_ake as never,
    initialKeyDelivery: (umkData as { initial_key_delivery?: unknown })
      .initial_key_delivery as never,
    senderSigningPublicKeyMaterial:
      umkData.sender_hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial,
  });
  const trustedStateBundle = await openDeviceStateTransferDelivery({
    umkData,
    senderSigningPublicKeyMaterial:
      umkData.sender_hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial,
  });
  await openInitialKekDeliveries({
    umkData,
    senderSigningPublicKeyMaterial:
      umkData.sender_hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial,
  });
  await installApprovedDeviceTrustStateBundle({
    trustStateBundle: trustedStateBundle,
    expectedTrustStateBundleHash: deliveryResourceHash(umkData.initial_key_delivery),
    userId: auth.user.id,
    deviceId,
  });

  let identityPublicKeys: IdentityPublicKeys | null = null;
  if (me.key_restore_endpoint_ref) {
    const importedKeys = await worker.importIdentityKeysFromKeyRestore(me.key_restore_endpoint_ref);
    if (!importedKeys.identityHybridSigningPublicKeyMaterial || !importedKeys.identityEcdhPublic) {
      throw new Error("identity_key_restore_material_missing");
    }
    identityPublicKeys = {
      hybridSigningPublicKeyMaterial: importedKeys.identityHybridSigningPublicKeyMaterial,
      ecdhPublic: importedKeys.identityEcdhPublic,
    };
  }

  await worker.setInitialized();

  const hasPersistedDsk = await loadPersistedDskIntoWorker();
  if (hasPersistedDsk) {
    await persistCurrentKeysWithDsk(auth.user.id);
    const publicKeys = await worker.getPublicKeys();
    if (publicKeys.deviceSigningKeyId) {
      await worker
        .storeAuthBootstrap({
          userId: auth.user.id,
          email: auth.user.email,
          name: auth.user.name,
          deviceId,
          deviceSigningKeyId: publicKeys.deviceSigningKeyId,
          cachedAt: Date.now(),
        })
        .catch(() => {
          // Auth bootstrap cache is only a restart shortcut; approved session state is already live.
        });
    }
  }

  if (identityPublicKeys) {
    await restoreWorkspaceKeks(
      auth.user.id,
      deviceId,
      identityPublicKeys.hybridSigningPublicKeyMaterial,
      identityPublicKeys.ecdhPublic,
    );
  }

  const requiresPasswordReentry = !hasPersistedDsk && me.auth_type === "password";
  const dskUnavailableOAuth = !hasPersistedDsk && me.auth_type !== "password";

  await worker.clearTransientKeys();

  return {
    identityPublicKeys,
    requiresPasswordReentry,
    dskUnavailableOAuth,
  };
}

async function openDeviceStateTransferDelivery(params: {
  umkData: Awaited<ReturnType<typeof retryGetUmk>>;
  senderSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
}): Promise<Record<string, unknown>> {
  const delivery = (params.umkData as { device_state_delivery?: unknown }).device_state_delivery;
  if (!isRecord(delivery)) throw new Error("device_state_delivery_missing");
  return getCryptoWorker().openInitialAkeDeviceStateTransferDelivery({
    initialAke: delivery.initial_ake as never,
    initialKeyDelivery: delivery.initial_key_delivery as never,
    senderSigningPublicKeyMaterial: params.senderSigningPublicKeyMaterial,
  });
}

async function openInitialKekDeliveries(params: {
  umkData: Awaited<ReturnType<typeof retryGetUmk>>;
  senderSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
}): Promise<void> {
  const deliveries = (params.umkData as { initial_kek_deliveries?: unknown })
    .initial_kek_deliveries;
  if (!isRecord(deliveries)) throw new Error("initial_kek_deliveries_missing");
  for (const delivery of Object.values(deliveries)) {
    if (!isRecord(delivery)) throw new Error("initial_kek_delivery_invalid");
    await getCryptoWorker().openInitialAkeKekDelivery({
      initialAke: delivery.initial_ake as never,
      initialKeyDelivery: delivery.initial_key_delivery as never,
      senderSigningPublicKeyMaterial: params.senderSigningPublicKeyMaterial,
    });
  }
}

async function installApprovedDeviceTrustStateBundle(params: {
  trustStateBundle: unknown;
  expectedTrustStateBundleHash: string;
  userId: string;
  deviceId: string;
}): Promise<void> {
  if (!isRecord(params.trustStateBundle)) {
    throw new Error("trust_state_bundle_missing");
  }
  if (
    params.trustStateBundle.protocol !== "refmd.trust-state-bundle" ||
    params.trustStateBundle.version !== 1 ||
    params.trustStateBundle.purpose !== "trust_transfer" ||
    params.trustStateBundle.user_id !== params.userId ||
    params.trustStateBundle.target_device_id !== params.deviceId
  ) {
    throw new Error("trust_state_bundle_invalid");
  }

  const actualHash = blake3Base64Url(
    canonicalizeStrictBytes(params.trustStateBundle as unknown as StrictJsonValue),
  );
  if (params.expectedTrustStateBundleHash !== actualHash) {
    throw new Error("trust_state_bundle_hash_mismatch");
  }

  if (!isRecord(params.trustStateBundle.user_checkpoint)) {
    throw new Error("trust_state_bundle_user_checkpoint_invalid");
  }
  await installTransferredKeyDirectoryCheckpoint({
    scopeKind: "user",
    scopeId: params.userId,
    checkpointEnvelope: params.trustStateBundle.user_checkpoint,
  });

  const workspaceCheckpoints = params.trustStateBundle.workspace_checkpoints;
  if (!Array.isArray(workspaceCheckpoints)) {
    throw new Error("trust_state_bundle_workspace_checkpoints_invalid");
  }
  for (const entry of workspaceCheckpoints) {
    if (!isRecord(entry) || typeof entry.workspace_id !== "string" || !isRecord(entry.checkpoint)) {
      throw new Error("trust_state_bundle_workspace_checkpoint_invalid");
    }
    await installTransferredKeyDirectoryCheckpoint({
      scopeKind: "workspace",
      scopeId: entry.workspace_id,
      checkpointEnvelope: entry.checkpoint,
    });
  }
}

function deliveryResourceHash(delivery: unknown): string {
  if (!isRecord(delivery) || !isRecord(delivery.metadata)) {
    throw new Error("initial_key_delivery_metadata_invalid");
  }
  if (typeof delivery.metadata.resource_hash !== "string") {
    throw new Error("initial_key_delivery_resource_hash_invalid");
  }
  return delivery.metadata.resource_hash;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function identityEcdhPublicFromMaterial(
  material: HybridEncryptionPublicKeyMaterial | null | undefined,
): Uint8Array | null {
  return material ? base64UrlDecode(material.x25519_public) : null;
}
