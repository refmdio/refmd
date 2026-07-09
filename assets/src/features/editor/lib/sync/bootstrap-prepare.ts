import { deviceState, getKekResolverSession } from "@/entities/session";
import { encryptionApi } from "@/shared/api/encryption";
import { buildChannelRrpResource, getChannelRrpParams } from "@/shared/lib/auth/rrp";
import {
  buildDocumentStatePinKey,
  getDocumentStatePin,
  hasCompleteSnapshotPin,
} from "@/shared/lib/anti-rollback/document-state-pins";
import {
  advanceKeyDirectoryPinWithProof,
  getKeyDirectoryPin,
  hashKeyDirectoryCheckpointEnvelope,
  verifyAndRememberKeyDirectoryLineageFromTrustedAnchor,
} from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { resolveActiveKek, resolveKekByVersion } from "@/shared/lib/crypto/kek-resolver";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { getShareParticipantCryptoWorker } from "@/shared/lib/crypto/worker/scoped";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import { ensurePhoenixWsToken } from "@/shared/lib/ws/socket";
import type { DocumentState } from "../../model/document-state/types";
import { setDocumentReadOnly } from "../../model/document-state/signals";
import {
  applyDeviceKeyCache,
  buildDeviceKeyCaches,
  buildDocumentSigningKeyCaches,
  buildDocumentSigningKeyCachesForInitialPayload,
} from "./inbound-signing-keys";
import { completeDekRotationIfNeeded } from "./bootstrap-key-rotation";
import { primeHistoricalDeks } from "./bootstrap-post-init";
import { ensureSharedDekCached, refreshSharedDocumentAccess } from "./share-access";
import {
  getCachedWorkspaceDirectory,
  rememberShareWorkspaceCheckpoint,
} from "./outbound-admission";
import { getLocalSigningKeyId } from "./share-identity";
import {
  canSharedAccessWriteDurably,
  type SharedDocumentAccess,
} from "../../model/document-state/access";
import { recordSyncPerf } from "./perf";

type DeviceKeyCacheBuildResult = Awaited<ReturnType<typeof buildDeviceKeyCaches>>;
type DeviceKeyCacheOutcome = { result: DeviceKeyCacheBuildResult } | { error: unknown };

export interface PreparedInitialization {
  localDeviceSigningKeyId: string | undefined;
  deviceKeyCachePromise: Promise<DeviceKeyCacheOutcome>;
  preDocumentReadyPromise: Promise<{ ready: true } | { error: unknown }>;
  oldDekPrimePromise: Promise<void>;
  buildJoinParams: () => Promise<Record<string, unknown>>;
  startDeviceKeyCache?: () => void;
}

type AssertInitializationActive = () => void;

function toDeviceKeyCacheOutcome(
  promise: Promise<DeviceKeyCacheBuildResult>,
): Promise<DeviceKeyCacheOutcome> {
  return promise.then(
    (result) => ({ result }),
    (error) => ({ error }),
  );
}

export async function refreshWorkspaceKeyDirectoryForDocumentJoin(
  state: DocumentState,
  workspaceId: string,
  signal?: AbortSignal,
): Promise<void> {
  if (state.access.kind === "share") {
    await refreshSharedDocumentAccess(state);
    if (state.access.kind !== "share") {
      throw new Error("share_access_changed");
    }
    await state.access.workspacePinReady;
    await fetchVerifiedKeyDirectory({
      scopeKind: "workspace",
      scopeId: workspaceId,
      rrpDeviceId: state.access.participantDeviceId,
      popScope: "share",
      popWorker: getShareParticipantCryptoWorker(state.access.shareSlug),
      signal,
    });
  } else {
    const device = deviceState();
    if (!device?.deviceId) throw new Error("key_directory_rrp_device_required");
    await fetchVerifiedKeyDirectory({
      scopeKind: "workspace",
      scopeId: workspaceId,
      rrpDeviceId: device.deviceId,
      signal,
    });
  }

  const workspacePin = await getKeyDirectoryPin("workspace", workspaceId);
  if (!workspacePin) throw new Error("key_directory_pin_required");
}

export async function prepareInitializationSession(
  documentId: string,
  workspaceId: string,
  state: DocumentState,
  signal: AbortSignal,
  assertActive: AssertInitializationActive,
): Promise<PreparedInitialization> {
  const worker = getCryptoWorker();
  const startedAt = performance.now();
  recordSyncPerf("initial_prepare_started", {
    documentId,
    workspaceId,
    accessKind: state.access.kind,
  });
  const device = deviceState();
  const localDeviceSigningKeyId = getLocalSigningKeyId(state) ?? device?.deviceSigningKeyId;
  if (!localDeviceSigningKeyId) throw new Error("Device state not available");

  assertActive();
  const transportScope = state.access.kind === "share" ? "share" : "user";
  await ensurePhoenixWsToken(transportScope);
  recordSyncPerf("initial_prepare_ws_token_ready", {
    documentId,
    elapsedMs: performance.now() - startedAt,
    transportScope,
  });
  assertActive();

  if (state.access.kind === "share") {
    const initialAccess = state.access;
    const initialShareId = initialAccess.shareId;
    const initialShareSlug = initialAccess.shareSlug;
    const shareWorker = getShareParticipantCryptoWorker(initialShareSlug);
    const cachedDirectoryPromise = getCachedWorkspaceDirectory(workspaceId);
    const existingPinPromise = getDocumentStatePin(
      buildDocumentStatePinKey(documentId, initialShareId),
    ).catch(() => null);
    const initialDocument = initialAccess.initialDocument ?? null;
    let liveKeyDirectoryReadyPromise: Promise<void> | null = null;
    const ensureLiveKeyDirectoryReady = () => {
      liveKeyDirectoryReadyPromise ??= ensureInitialShareKeyDirectoryLineage(
        initialAccess,
        workspaceId,
        documentId,
        startedAt,
      );
      return liveKeyDirectoryReadyPromise;
    };
    const buildLiveDeviceKeyCache = () =>
      toDeviceKeyCacheOutcome(
        Promise.all([
          buildDocumentSigningKeyCaches(state, signal),
          ensureLiveKeyDirectoryReady(),
        ]).then(([cache]) => cache),
      );
    const initialSigningKeyCachePromise = initialDocument
      ? toDeviceKeyCacheOutcome(
          ensureLiveKeyDirectoryReady().then(() =>
            buildDocumentSigningKeyCachesForInitialPayload(state, initialDocument, signal),
          ),
        )
      : Promise.resolve(null);
    let startDeviceKeyCache: (() => void) | undefined;
    const deviceKeyCachePromise: Promise<DeviceKeyCacheOutcome> = initialDocument
      ? new Promise((resolve) => {
          let started = false;
          startDeviceKeyCache = () => {
            if (started) return;
            started = true;
            recordSyncPerf("initial_prepare_share_device_cache_deferred_start", {
              documentId,
              elapsedMs: performance.now() - startedAt,
            });
            void buildLiveDeviceKeyCache().then(resolve);
          };
        })
      : buildLiveDeviceKeyCache();

    recordSyncPerf("initial_prepare_share_dek_start", {
      documentId,
      elapsedMs: performance.now() - startedAt,
    });
    const shareDekReadyPromise = ensureSharedDekCached(state, documentId, initialAccess.keyVersion);
    const preDocumentReadyPromise = Promise.all([
      shareDekReadyPromise,
      initialSigningKeyCachePromise,
    ])
      .then(([, initialSigningKeyCacheOutcome]) => {
        if (initialSigningKeyCacheOutcome) {
          if ("error" in initialSigningKeyCacheOutcome) throw initialSigningKeyCacheOutcome.error;
          if (initialSigningKeyCacheOutcome.result.status === "key_changed") {
            throw new Error(
              `TOFU key change detected: device ${initialSigningKeyCacheOutcome.result.warning.deviceId}`,
            );
          }
          applyDeviceKeyCache(state, initialSigningKeyCacheOutcome.result);
        }
        recordSyncPerf("initial_prepare_share_dek_ready", {
          documentId,
          elapsedMs: performance.now() - startedAt,
        });
        state.dekResolved = true;
        state.keyVersion = initialAccess.keyVersion;
        setDocumentReadOnly(state.stateKey, !canSharedAccessWriteDurably(initialAccess));
        return { ready: true as const };
      })
      .catch((error) => ({ error }));
    const activeShareWorker =
      state.access.shareSlug === initialShareSlug
        ? shareWorker
        : getShareParticipantCryptoWorker(state.access.shareSlug);

    recordSyncPerf("initial_prepare_share_directory_start", {
      documentId,
      elapsedMs: performance.now() - startedAt,
      source: "cache",
    });
    let directory = await cachedDirectoryPromise;
    let directorySource: "cache" | "access" | "fetch" = "cache";
    if (!directory) {
      if (state.access.workspaceKeyDirectoryCheckpoint) {
        directorySource = "access";
        directory = { checkpoint: state.access.workspaceKeyDirectoryCheckpoint };
      } else {
        directorySource = "fetch";
        recordSyncPerf("initial_prepare_share_directory_start", {
          documentId,
          elapsedMs: performance.now() - startedAt,
          source: "fetch",
        });
        directory = await fetchVerifiedKeyDirectory({
          scopeKind: "workspace",
          scopeId: workspaceId,
          rrpDeviceId: state.access.participantDeviceId,
          popScope: "share",
          popWorker: activeShareWorker,
          signal,
        });
      }
    }
    recordSyncPerf("initial_prepare_share_directory_ready", {
      documentId,
      elapsedMs: performance.now() - startedAt,
      source: directorySource,
    });
    rememberShareWorkspaceCheckpoint(state.access, directory.checkpoint);
    assertActive();

    const buildJoinParams = async (): Promise<Record<string, unknown>> => {
      if (state.access.kind !== "share") {
        throw new Error("Share access changed during initialization");
      }
      const access = state.access;
      const existingPin =
        access.shareId === initialShareId
          ? await existingPinPromise
          : await getDocumentStatePin(buildDocumentStatePinKey(documentId, access.shareId)).catch(
              () => null,
            );
      await ensureLiveKeyDirectoryReady();
      let workspacePin = await getKeyDirectoryPin("workspace", workspaceId).catch(() => null);
      if (!workspacePin) {
        await fetchVerifiedKeyDirectory({
          scopeKind: "workspace",
          scopeId: workspaceId,
          rrpDeviceId: access.participantDeviceId,
          popScope: "share",
          popWorker:
            access.shareSlug === initialShareSlug
              ? activeShareWorker
              : getShareParticipantCryptoWorker(access.shareSlug),
          signal,
        });
        workspacePin = await getKeyDirectoryPin("workspace", workspaceId);
      }
      if (!workspacePin) throw new Error("key_directory_pin_required");
      assertActive();

      const stateSnapshotId =
        state.activeSnapshotId && state.snapshotProofHash && state.snapshotCiphertextHash
          ? state.activeSnapshotId
          : null;
      const pinSnapshotId = hasCompleteSnapshotPin(existingPin)
        ? existingPin.latestSnapshotId
        : null;
      const useDelta =
        !!stateSnapshotId &&
        !!state.lastSavedState &&
        (!pinSnapshotId || pinSnapshotId === stateSnapshotId);
      const joinPayload: Record<string, unknown> = {
        mode: useDelta ? "delta" : "complete",
        ...(access.source === "mounted" && access.mountId
          ? {
              ...(access.workspacePinBootstrapHash
                ? {
                    authenticated_workspace_pin_bootstrap_hash: access.workspacePinBootstrapHash,
                  }
                : {}),
              mount_id: access.mountId,
              share_id: access.shareId,
            }
          : {}),
      };
      if (workspacePin) {
        joinPayload.workspaceKeyDirectoryPinSequence = workspacePin.checkpointSequence;
        joinPayload.workspaceKeyDirectoryPinHash = workspacePin.checkpointHash;
      }
      state._lastJoinMode = useDelta ? "delta" : "complete";
      const knownSnapshotId = useDelta ? stateSnapshotId : (pinSnapshotId ?? stateSnapshotId);
      if (knownSnapshotId) {
        joinPayload.knownSnapshotId = knownSnapshotId;
      }
      if (useDelta) {
        joinPayload.knownSnapshotUpdateClocks = { ...state.confirmedClocks };
      }
      state._lastJoinDecision = {
        hasLastSavedState: state.lastSavedState !== null,
        hasSnapshotCiphertextHash: state.snapshotCiphertextHash.length > 0,
        hasSnapshotProofHash: state.snapshotProofHash.length > 0,
        knownSnapshotId,
        pinSnapshotId,
        stateSnapshotId,
        useDelta,
      };
      const channelShareId = access.authorizationShareId ?? access.shareId;
      const popWorker =
        access.shareSlug === initialShareSlug
          ? activeShareWorker
          : getShareParticipantCryptoWorker(access.shareSlug);
      const rrpParams = await getChannelRrpParams(
        access.participantDeviceId,
        signal,
        "share",
        popWorker,
        buildChannelRrpResource(documentId, "share", channelShareId, joinPayload),
      );
      recordSyncPerf("initial_prepare_join_rrp_ready", {
        documentId,
        elapsedMs: performance.now() - startedAt,
      });
      return {
        ...rrpParams,
        ...joinPayload,
      };
    };

    return {
      localDeviceSigningKeyId,
      deviceKeyCachePromise,
      preDocumentReadyPromise,
      oldDekPrimePromise: Promise.resolve(),
      buildJoinParams,
      ...(startDeviceKeyCache ? { startDeviceKeyCache } : {}),
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

  const buildJoinParams = async (): Promise<Record<string, unknown>> => {
    const existingPin = await existingPinPromise;
    const cacheOutcome = await deviceKeyCachePromise;
    if ("error" in cacheOutcome) throw cacheOutcome.error;
    let workspacePin = await getKeyDirectoryPin("workspace", workspaceId).catch(() => null);
    if (!workspacePin) {
      if (!device?.deviceId) throw new Error("key_directory_rrp_device_required");
      await fetchVerifiedKeyDirectory({
        scopeKind: "workspace",
        scopeId: workspaceId,
        rrpDeviceId: device.deviceId,
        signal,
      });
      workspacePin = await getKeyDirectoryPin("workspace", workspaceId);
    }
    if (!workspacePin) throw new Error("key_directory_pin_required");

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
      mode: useDelta ? "delta" : "complete",
    };
    if (workspacePin) {
      joinParams.workspaceKeyDirectoryPinSequence = workspacePin.checkpointSequence;
      joinParams.workspaceKeyDirectoryPinHash = workspacePin.checkpointHash;
    }

    state._lastJoinMode = useDelta ? "delta" : "complete";

    const effectiveKnownSnapshot = useDelta ? stateSnapshotId : (pinSnapshotId ?? stateSnapshotId);
    if (effectiveKnownSnapshot) {
      joinParams.knownSnapshotId = effectiveKnownSnapshot;
    }
    if (useDelta) {
      joinParams.knownSnapshotUpdateClocks = { ...state.confirmedClocks };
    }
    state._lastJoinDecision = {
      hasLastSavedState: state.lastSavedState !== null,
      hasSnapshotCiphertextHash: state.snapshotCiphertextHash.length > 0,
      hasSnapshotProofHash: state.snapshotProofHash.length > 0,
      knownSnapshotId: effectiveKnownSnapshot,
      pinSnapshotId,
      stateSnapshotId,
      useDelta,
    };

    const rrpParams = await getChannelRrpParams(
      undefined,
      signal,
      "user",
      undefined,
      buildChannelRrpResource(documentId, "user", undefined, joinParams),
    );

    return { ...rrpParams, ...joinParams };
  };

  return {
    localDeviceSigningKeyId,
    deviceKeyCachePromise,
    preDocumentReadyPromise: Promise.resolve({ ready: true }),
    oldDekPrimePromise,
    buildJoinParams,
  };
}

async function ensureInitialShareKeyDirectoryLineage(
  access: SharedDocumentAccess,
  workspaceId: string,
  documentId: string,
  startedAt: number,
): Promise<void> {
  if (!access.workspaceKeyDirectoryLatestCheckpoint) return;

  await access.workspacePinReady;
  const current = await getKeyDirectoryPin("workspace", workspaceId);
  if (!current) return;

  const latestSequence = checkpointSequence(access.workspaceKeyDirectoryLatestCheckpoint);
  const latestHash = hashKeyDirectoryCheckpointEnvelope(
    access.workspaceKeyDirectoryLatestCheckpoint,
  );
  if (latestSequence < current.checkpointSequence) {
    return;
  }
  if (latestSequence === current.checkpointSequence && latestHash !== current.checkpointHash) {
    throw new Error("share_workspace_key_directory_checkpoint_fork");
  }

  const checkpointAncestry = access.workspaceKeyDirectoryCheckpointAncestry ?? [];
  const eventAncestry = access.workspaceKeyDirectoryEventAncestry ?? [];
  if (latestSequence === current.checkpointSequence && latestHash === current.checkpointHash) {
    if (
      !access.workspaceKeyDirectoryCheckpoint ||
      (checkpointAncestry.length < 1 && eventAncestry.length < 1)
    ) {
      return;
    }
    await verifyAndRememberKeyDirectoryLineageFromTrustedAnchor({
      scopeKind: "workspace",
      scopeId: workspaceId,
      trustedCheckpointEnvelope: access.workspaceKeyDirectoryCheckpoint,
      checkpointEnvelope: access.workspaceKeyDirectoryLatestCheckpoint,
      checkpointAncestry,
      eventAncestry,
      authorityEventAncestry: eventAncestry,
    });
    return;
  }
  const lineage = lineageFromCurrentPin(checkpointAncestry, eventAncestry, current);
  if (latestSequence > current.checkpointSequence) {
    if (!lineage) {
      throw new Error("key_directory_event_ancestry_required");
    }
  }

  recordSyncPerf("initial_prepare_share_lineage_start", {
    documentId,
    elapsedMs: performance.now() - startedAt,
  });
  try {
    await advanceKeyDirectoryPinWithProof({
      scopeKind: "workspace",
      scopeId: workspaceId,
      checkpointEnvelope: access.workspaceKeyDirectoryLatestCheckpoint,
      checkpointAncestry: lineage?.checkpointAncestry ?? checkpointAncestry,
      eventAncestry: lineage?.eventAncestry ?? eventAncestry,
      authorityEventAncestry: eventAncestry,
    });
    recordSyncPerf("initial_prepare_share_lineage_ready", {
      documentId,
      elapsedMs: performance.now() - startedAt,
    });
  } catch (error) {
    if (latestSequence < current.checkpointSequence && isStaleLineageError(error)) return;
    throw error;
  }
}

function lineageFromCurrentPin(
  checkpointAncestry: Array<{ payload?: unknown }>,
  eventAncestry: Array<{ payload?: unknown }>,
  current: {
    checkpointSequence: number;
    checkpointHash: string;
    eventHeadSequence: number;
  },
): {
  checkpointAncestry: Array<{ payload?: unknown }>;
  eventAncestry: Array<{ payload?: unknown }>;
} | null {
  const currentCheckpointIndex = checkpointAncestry.findIndex(
    (checkpoint) =>
      checkpointSequence(checkpoint) === current.checkpointSequence &&
      hashKeyDirectoryCheckpointEnvelope(checkpoint) === current.checkpointHash,
  );
  if (currentCheckpointIndex < 0) return null;
  return {
    checkpointAncestry: checkpointAncestry.slice(currentCheckpointIndex),
    eventAncestry: eventAncestry.filter(
      (event) => keyDirectoryEventSequence(event) > current.eventHeadSequence,
    ),
  };
}

function checkpointSequence(checkpoint: { payload?: unknown }): number {
  const payload = checkpoint.payload;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("workspace_key_directory_checkpoint_sequence_invalid");
  }
  const sequence = (payload as Record<string, unknown>).sequence;
  if (typeof sequence !== "number" || !Number.isSafeInteger(sequence) || sequence < 1) {
    throw new Error("workspace_key_directory_checkpoint_sequence_invalid");
  }
  return sequence;
}

function keyDirectoryEventSequence(event: { payload?: unknown }): number {
  const payload = event.payload;
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new Error("workspace_key_directory_event_sequence_invalid");
  }
  const sequence = (payload as Record<string, unknown>).sequence;
  if (typeof sequence !== "number" || !Number.isSafeInteger(sequence) || sequence < 1) {
    throw new Error("workspace_key_directory_event_sequence_invalid");
  }
  return sequence;
}

function isStaleLineageError(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error.message === "key_directory_checkpoint_rollback" ||
      error.message === "key_directory_checkpoint_anchor_mismatch" ||
      error.message === "key_directory_checkpoint_fork" ||
      error.message === "key_directory_pin_conflict")
  );
}
