import { authApi, devicesApi } from "@/shared/api";
import type { AuthState } from "@/entities/session";
import { setCryptoWorkerReady, setFullSession } from "@/entities/session";
import {
  advanceKeyDirectoryPinWithProof,
  installTransferredKeyDirectoryCheckpoint,
} from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import {
  assertTransferredWorkspaceAuditPins,
  installTransferredAuditCheckpointPin,
} from "@/shared/lib/anti-rollback/audit-checkpoint-pin";
import { persistDeviceId, persistCurrentKeysWithDsk } from "@/shared/lib/auth/key-persistence";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import type {
  InitialAkeOffer,
  InitialAkeResponderConfirmation,
} from "@/shared/lib/crypto/initial-ake";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { verifySenderDeviceIdentityAndTofu } from "@/shared/lib/crypto/sender-device-verification";
import type { HybridEncryptionPublicKeyMaterial } from "@/shared/lib/crypto/hybrid-encryption";
import type { HybridSigningPublicKeyMaterial } from "@/shared/lib/crypto/signature-types";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { loadPersistedDskIntoWorker } from "./session-keys";
import { restoreWorkspaceKeks } from "./session-keks";
import { retryGetInitialAkeOffers, retryGetUmk } from "./approval-support";
import type { DeviceRegistrationPublicKeys } from "../../model/register/types";

interface IdentityPublicKeys {
  hybridSigningPublicKeyMaterial: HybridSigningPublicKeyMaterial;
  ecdhPublic: Uint8Array;
}

interface ApprovedDeviceRestorationResult {
  identityPublicKeys: IdentityPublicKeys | null;
  deviceKeyCheckpointSequence: number | null;
  deviceKeyCheckpointHash: string | null;
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
      deviceKeyCheckpointSequence: restorationResult.deviceKeyCheckpointSequence,
      deviceKeyCheckpointHash: restorationResult.deviceKeyCheckpointHash,
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

  const exchange = await retryGetInitialAkeOffers(deviceId, 60, 500);
  await verifySenderDeviceIdentityAndTofu({
    sender: exchange,
    senderUserId: auth.user.id,
    expectedIdentityHybridSigningPublicKeyMaterial,
    expectedIdentityEcdhPublic,
  });
  const offers = exchange.offers as unknown as {
    umk_distribution: InitialAkeOffer;
    trust_transfer: InitialAkeOffer;
    device_approval_kek_initial: Record<string, InitialAkeOffer>;
  };
  const responses: {
    umk_distribution: InitialAkeResponderConfirmation;
    trust_transfer: InitialAkeResponderConfirmation;
    device_approval_kek_initial: Record<string, InitialAkeResponderConfirmation>;
  } = {
    umk_distribution: await worker.respondToInitialAkeOffer({
      offer: offers.umk_distribution,
      senderSigningPublicKeyMaterial:
        exchange.sender_hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial,
    }),
    trust_transfer: await worker.respondToInitialAkeOffer({
      offer: offers.trust_transfer,
      senderSigningPublicKeyMaterial:
        exchange.sender_hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial,
    }),
    device_approval_kek_initial: {},
  };
  for (const [workspaceId, offer] of Object.entries(offers.device_approval_kek_initial)) {
    responses.device_approval_kek_initial[workspaceId] = await worker.respondToInitialAkeOffer({
      offer,
      senderSigningPublicKeyMaterial:
        exchange.sender_hybrid_signing_public_key_material as unknown as HybridSigningPublicKeyMaterial,
    });
  }
  await devicesApi.submitInitialAkeResponses(deviceId, { responses });

  const umkData = await retryGetUmk(deviceId, 10, 2000, deviceId);

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
    const kekResults = await restoreWorkspaceKeks(
      auth.user.id,
      deviceId,
      identityPublicKeys.hybridSigningPublicKeyMaterial,
      identityPublicKeys.ecdhPublic,
    );
    if (kekResults.failed.length > 0) {
      throw new Error(
        `approved_device_workspace_key_restore_failed:${kekResults.failed.join(",")}`,
      );
    }
  }

  const requiresPasswordReentry = !hasPersistedDsk && me.auth_type === "password";
  const dskUnavailableOAuth = !hasPersistedDsk && me.auth_type !== "password";

  await worker.clearTransientKeys();

  return {
    identityPublicKeys,
    deviceKeyCheckpointSequence: me.device_key_checkpoint_sequence ?? null,
    deviceKeyCheckpointHash: me.device_key_checkpoint_hash ?? null,
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

  const userLineage = assertTransferredLineage(
    params.trustStateBundle.user_lineage,
    "trust_state_bundle_user_checkpoint_invalid",
  );
  await installTransferredKeyDirectoryCheckpoint({
    scopeKind: "user",
    scopeId: params.userId,
    checkpointEnvelope: userLineage.checkpointAncestry[0]!,
  });
  await installTransferredAuditCheckpointPin(params.trustStateBundle.user_audit_pin);
  await advanceKeyDirectoryPinWithProof({
    scopeKind: "user",
    scopeId: params.userId,
    checkpointEnvelope: userLineage.checkpoint,
    checkpointAncestry: userLineage.checkpointAncestry,
    eventAncestry: userLineage.events,
  });

  const workspaceCheckpoints = params.trustStateBundle.workspace_checkpoints;
  if (!Array.isArray(workspaceCheckpoints)) {
    throw new Error("trust_state_bundle_workspace_checkpoints_invalid");
  }
  const workspaceIds = workspaceCheckpoints.map((entry) => {
    if (!isRecord(entry) || typeof entry.workspace_id !== "string" || !isRecord(entry.lineage)) {
      throw new Error("trust_state_bundle_workspace_checkpoint_invalid");
    }
    return entry.workspace_id;
  });
  const workspaceAuditPins = assertTransferredWorkspaceAuditPins(
    workspaceIds,
    params.trustStateBundle.workspace_audit_pins,
  );

  for (const entry of workspaceCheckpoints) {
    if (!isRecord(entry) || typeof entry.workspace_id !== "string" || !isRecord(entry.lineage)) {
      throw new Error("trust_state_bundle_workspace_checkpoint_invalid");
    }
    const workspaceId = entry.workspace_id;
    const auditPin = workspaceAuditPins.find(
      (pin) => pin.chainScope === `workspace:${workspaceId}`,
    );
    if (!auditPin) throw new Error("trust_state_bundle_workspace_audit_pins_mismatch");
    const lineage = assertTransferredLineage(
      entry.lineage,
      "trust_state_bundle_workspace_checkpoint_invalid",
    );
    await installTransferredKeyDirectoryCheckpoint({
      scopeKind: "workspace",
      scopeId: workspaceId,
      checkpointEnvelope: lineage.checkpointAncestry[0]!,
    });
    await installTransferredAuditCheckpointPin(auditPin);
    await advanceKeyDirectoryPinWithProof({
      scopeKind: "workspace",
      scopeId: workspaceId,
      checkpointEnvelope: lineage.checkpoint,
      checkpointAncestry: lineage.checkpointAncestry,
      eventAncestry: lineage.events,
    });
  }
}

function assertTransferredLineage(
  value: unknown,
  errorCode: string,
): {
  checkpointAncestry: Record<string, unknown>[];
  events: Record<string, unknown>[];
  checkpoint: Record<string, unknown>;
} {
  if (
    !isRecord(value) ||
    !Array.isArray(value.checkpoint_ancestry) ||
    value.checkpoint_ancestry.length < 1 ||
    !value.checkpoint_ancestry.every(isRecord) ||
    !Array.isArray(value.events) ||
    !value.events.every(isRecord) ||
    !isRecord(value.checkpoint)
  ) {
    throw new Error(errorCode);
  }
  return {
    checkpointAncestry: value.checkpoint_ancestry,
    events: value.events,
    checkpoint: value.checkpoint,
  };
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
