import { deviceState, getKekResolverSession } from "@/entities/session";
import { encryptionApi } from "@/shared/api/encryption";
import { getPopHeaders } from "@/shared/lib/auth/pop";
import {
  buildDocumentStatePinKey,
  getDocumentStatePin,
  hasCompleteSnapshotPin,
} from "@/shared/lib/anti-rollback/document-state-pins";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { resolveActiveKek, resolveKekByVersion } from "@/shared/lib/crypto/kek-resolver";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { getShareParticipantCryptoWorker } from "@/shared/lib/crypto/worker/scoped";
import { ensurePhoenixWsToken } from "@/shared/lib/ws/socket";
import type { DocumentState } from "../../../model/document-state/types";
import { buildDeviceKeyCaches, buildDocumentSigningKeyCaches } from "../inbound/signing-keys";
import { completeDekRotationIfNeeded } from "./key-rotation";
import { primeHistoricalDeks } from "./post-init";
import { ensureSharedDekCached } from "../share-access";
import { getLocalSigningPubKeyOrEncode } from "../share-identity";
import { isRawSharedDocumentAccess } from "../../../model/document-state/access";

type DeviceKeyCacheBuildResult = Awaited<ReturnType<typeof buildDeviceKeyCaches>>;

export interface PreparedInitialization {
  localDeviceSigningPubKey: string | undefined;
  deviceKeyCachePromise: Promise<{ result: DeviceKeyCacheBuildResult } | { error: unknown }>;
  oldDekPrimePromise: Promise<void>;
  joinParams: Record<string, unknown>;
}

type AssertInitializationActive = () => void;

export async function prepareInitializationSession(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
  signal: AbortSignal,
  assertActive: AssertInitializationActive,
): Promise<PreparedInitialization> {
  const worker = getCryptoWorker();
  const device = deviceState();
  const localDeviceSigningPubKey = getLocalSigningPubKeyOrEncode(
    state,
    device?.deviceSigningPublic,
  );
  if (!localDeviceSigningPubKey) throw new Error("Device state not available");

  assertActive();
  await ensurePhoenixWsToken(isRawSharedDocumentAccess(state.access) ? "share" : "user");
  assertActive();

  if (state.access.kind === "share") {
    await ensureSharedDekCached(state, documentId, state.access.keyVersion);
    assertActive();

    state.dekResolved = true;
    state.keyVersion = state.access.keyVersion;
    state.readOnly = state.access.permission !== "edit";

    const deviceKeyCachePromise = buildDocumentSigningKeyCaches(state, signal)
      .then((result) => ({ result }))
      .catch((error) => ({ error }));

    const popHeaders = isRawSharedDocumentAccess(state.access)
      ? await getPopHeaders(
          state.access.participantDeviceId,
          signal,
          "share",
          getShareParticipantCryptoWorker(state.access.shareSlug),
        )
      : await getPopHeaders(undefined, signal, "user");
    const existingPin = await getDocumentStatePin(
      buildDocumentStatePinKey(documentId, state.access.shareId),
    ).catch(() => null);
    assertActive();

    state._lastJoinMode = "complete";
    const stateKnownSnapshotId =
      state.activeSnapshotId && state.snapshotProofHash && state.snapshotCiphertextHash
        ? state.activeSnapshotId
        : null;
    const knownSnapshotId =
      (hasCompleteSnapshotPin(existingPin) ? existingPin.latestSnapshotId : null) ??
      stateKnownSnapshotId;

    return {
      localDeviceSigningPubKey,
      deviceKeyCachePromise,
      oldDekPrimePromise: Promise.resolve(),
      joinParams: {
        pop_challenge: popHeaders["X-PoP-Challenge"],
        pop_signature: popHeaders["X-PoP-Signature"],
        mode: "complete",
        ...(knownSnapshotId ? { knownSnapshotId } : {}),
        ...(state.access.mountId ? { mount_id: state.access.mountId } : {}),
      },
    };
  }

  const activeKekPromise = resolveActiveKek(workspaceId, getKekResolverSession(), signal);
  const documentKeysPromise = encryptionApi.getDocumentKeys(documentId, { signal });
  const deviceKeyCachePromise = buildDeviceKeyCaches(workspaceId, signal)
    .then((result) => ({ result }))
    .catch((error) => ({ error }));
  const existingPinPromise = getDocumentStatePin(documentId).catch(() => null);

  const [{ kekVersion: activeKekVersion }, keysResponse] = await Promise.all([
    activeKekPromise,
    documentKeysPromise,
  ]);

  assertActive();

  const keys = keysResponse.keys;
  const activeKey = keys.find((key) => key.is_active);
  if (!activeKey) {
    throw new Error("No active DEK found for document");
  }

  if (activeKey.kek_version !== activeKekVersion) {
    await resolveKekByVersion(workspaceId, activeKey.kek_version, getKekResolverSession(), signal);
    assertActive();
  }

  await worker.unwrapDek({
    encryptedDek: base64UrlDecode(activeKey.encrypted_dek),
    nonce: base64UrlDecode(activeKey.nonce),
    documentId,
    workspaceId,
    keyVersion: activeKey.key_version,
    isActive: true,
    kekVersion: activeKey.kek_version,
  });

  const oldDekPrimePromise = primeHistoricalDeks(
    documentId,
    workspaceId,
    keys,
    activeKekVersion,
    activeKey.key_version,
    signal,
  );

  state.dekResolved = true;
  state.keyVersion = activeKey.key_version;

  state._retryDekRotation = () => completeDekRotationIfNeeded(documentId, workspaceId, state);
  completeDekRotationIfNeeded(documentId, workspaceId, state).catch(() => {});

  setTimeout(async () => {
    if (state.initialized && state._retryDekRotation) {
      try {
        await state._retryDekRotation();
      } catch {
        // Best-effort; will retry on next document open
      }
    }
  }, 30000);

  const [popHeaders, existingPin] = await Promise.all([
    getPopHeaders(undefined, signal),
    existingPinPromise,
  ]);

  assertActive();

  const stateSnapshotId =
    state.activeSnapshotId && state.snapshotProofHash && state.snapshotCiphertextHash
      ? state.activeSnapshotId
      : null;
  const pinSnapshotId = hasCompleteSnapshotPin(existingPin) ? existingPin.latestSnapshotId : null;
  const useDelta =
    !!stateSnapshotId &&
    !!state.lastSavedState &&
    (!pinSnapshotId || pinSnapshotId === stateSnapshotId);
  const joinParams: Record<string, unknown> = {
    pop_challenge: popHeaders["X-PoP-Challenge"],
    pop_signature: popHeaders["X-PoP-Signature"],
    mode: useDelta ? "delta" : "complete",
  };

  state._lastJoinMode = useDelta ? "delta" : "complete";

  const effectiveKnownSnapshot = useDelta ? stateSnapshotId : (pinSnapshotId ?? stateSnapshotId);
  if (effectiveKnownSnapshot) {
    joinParams.knownSnapshotId = effectiveKnownSnapshot;
  }
  if (useDelta) {
    joinParams.knownSnapshotUpdateClocks = { ...state.confirmedClocks };
  }

  return {
    localDeviceSigningPubKey,
    deviceKeyCachePromise,
    oldDekPrimePromise,
    joinParams,
  };
}
