import { deviceState, getKekResolverSession } from "@/entities/session";
import { encryptionApi } from "@/shared/api/encryption";
import { getPopHeaders } from "@/shared/lib/auth/pop";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { resolveActiveKek, resolveKekByVersion } from "@/shared/lib/crypto/kek-resolver";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import type { DocumentState } from "../../../model/document-state/types";
import { buildDeviceKeyCaches } from "../inbound/signing-keys";
import { completeDekRotationIfNeeded } from "./key-rotation";
import { primeHistoricalDeks } from "./post-init";

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
  if (!device) throw new Error("Device state not available");

  const localDeviceSigningPubKey = device.deviceSigningPublic
    ? base64UrlEncode(device.deviceSigningPublic)
    : undefined;

  assertActive();

  const activeKekPromise = resolveActiveKek(workspaceId, getKekResolverSession(), signal);
  const documentKeysPromise = encryptionApi.getDocumentKeys(documentId, { signal });
  const deviceKeyCachePromise = buildDeviceKeyCaches(workspaceId, signal)
    .then((result) => ({ result }))
    .catch((error) => ({ error }));
  const existingPinPromise = import("@/shared/lib/anti-rollback/document-state-pins").then(
    ({ getDocumentStatePin }) => getDocumentStatePin(documentId).catch(() => null),
  );

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

  const knownSnapshotId = state.activeSnapshotId ?? null;
  const pinSnapshotId = existingPin?.latestSnapshotId ?? null;
  const useDelta = !!knownSnapshotId && !!state.lastSavedState;
  const joinParams: Record<string, unknown> = {
    pop_challenge: popHeaders["X-PoP-Challenge"],
    pop_signature: popHeaders["X-PoP-Signature"],
    mode: useDelta ? "delta" : "complete",
  };

  state._lastJoinMode = useDelta ? "delta" : "complete";

  const effectiveKnownSnapshot = knownSnapshotId ?? pinSnapshotId;
  if (effectiveKnownSnapshot) {
    joinParams.knownSnapshotId = effectiveKnownSnapshot;
  }
  if (useDelta) {
    const clocks =
      Object.keys(state.confirmedClocks).length > 0
        ? state.confirmedClocks
        : (existingPin?.perDeviceMaxClocks ?? {});
    joinParams.knownSnapshotUpdateClocks = { ...clocks };
  }

  return {
    localDeviceSigningPubKey,
    deviceKeyCachePromise,
    oldDekPrimePromise,
    joinParams,
  };
}
