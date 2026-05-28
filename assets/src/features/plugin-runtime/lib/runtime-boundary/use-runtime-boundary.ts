import { createEffect, onCleanup, type Accessor } from "solid-js";
import { registerBeforeSessionCleanup } from "@/shared/lib/auth/session-cleanup";
import type { PluginHostRuntimeController } from "../runtime-path/controller";
import type { PluginRuntimePath } from "../runtime-path/runtime-path";
import type { PluginHostRpcSessionValidator } from "../host-rpc/host-rpc";
import { defaultPluginRuntimeBundleLoader } from "./runtime-bundle-loader";
import { createPluginRuntimeNetworkServices } from "./runtime-network";
import type {
  PluginNetworkProxyRegistration,
  PluginNetworkProxyRequestSigner,
} from "../network/host-network";
import type {
  LoadedPluginRuntimeBundle,
  PluginRuntimeBundleLoader,
  PluginRuntimeApplicationDescriptor,
} from "./runtime-types";
import { normalizeRendererSlots } from "./renderer-slot-normalization";

interface ActiveRuntimeBoundary {
  workspaceId: string;
  descriptorKey: string;
  container: HTMLElement;
  path: PluginRuntimePath;
  unregisterSessionClose: () => void;
}

interface PendingRuntimeBoundaryStart {
  workspaceId: string;
  descriptorKey: string;
  activationId: string;
  capabilityGrantId: string;
  bundleHash?: string;
  abortController: AbortController;
}

interface RevokedRuntimeApplication {
  descriptorKey: string | null;
}

interface PluginRuntimeBoundaryDebugState {
  active: Array<{ applicationId: string; descriptorKey: string; workspaceId: string }>;
  descriptorKeys: Array<{
    applicationId: string;
    descriptorKey: string;
    workspaceId: string;
    activationId: string;
    capabilityGrantId: string;
  }>;
  pending: Array<{
    applicationId: string;
    descriptorKey: string;
    workspaceId: string;
    activationId: string;
    capabilityGrantId: string;
    aborted: boolean;
  }>;
  revoked: Array<{ applicationId: string; descriptorKey: string | null }>;
  lastReason: string | null;
  lastError: string | null;
  lastSkipped: string | null;
  updatedAt: string;
  workspaceId: string | null;
}

declare global {
  interface Window {
    __refmdPluginRuntimeBoundaryDebug?: PluginRuntimeBoundaryDebugState;
  }
}

const RUNTIME_LOAD_RETRY_DELAYS_MS = [250, 1_000, 2_500, 5_000, 10_000, 15_000, 30_000] as const;

export interface PluginRuntimeBoundaryInvalidationSink {
  closeByActivation(activationId: string, reason?: string): void | Promise<void>;
  closeByApplication(applicationId: string, reason?: string): void | Promise<void>;
  closeByWorkspace(workspaceId: string, reason?: string): void | Promise<void>;
  closeByBundle(workspaceId: string, bundleHash: string, reason?: string): void | Promise<void>;
  closeByCapabilityGrant(capabilityGrantId: string, reason?: string): void | Promise<void>;
}

export function useThirdPartyPluginRuntimeBoundary(
  controller: PluginHostRuntimeController,
  workspaceId: Accessor<string | null>,
  ownerDocument: Document = document,
  applications: Accessor<readonly PluginRuntimeApplicationDescriptor[]> = () => [],
  loadBundle: PluginRuntimeBundleLoader = defaultPluginRuntimeBundleLoader,
  networkProxyRegistration: Accessor<PluginNetworkProxyRegistration | null> = () => null,
  networkProxyRequestSigner: PluginNetworkProxyRequestSigner | null = null,
): PluginRuntimeBoundaryInvalidationSink {
  const active = new Map<string, ActiveRuntimeBoundary>();
  const pending = new Map<string, PendingRuntimeBoundaryStart>();
  const revokedApplications = new Map<string, RevokedRuntimeApplication>();
  let lastError: string | null = null;
  let lastSkipped: string | null = null;
  let lastWorkspaceId: string | null = null;
  let generation = 0;

  const destroyBoundary = (applicationId: string, reason: string) => {
    abortPendingStart(pending, applicationId, reason);
    const boundary = active.get(applicationId);
    if (!boundary) {
      publishPluginRuntimeBoundaryDebug(active, pending, revokedApplications, [], {
        lastReason: reason,
        lastError,
        lastSkipped,
        workspaceId: lastWorkspaceId,
      });
      return;
    }

    boundary.unregisterSessionClose();
    boundary.path.destroy(reason);
    boundary.container.remove();
    active.delete(applicationId);
    publishPluginRuntimeBoundaryDebug(active, pending, revokedApplications, [], {
      lastReason: reason,
      lastError,
      lastSkipped,
      workspaceId: lastWorkspaceId,
    });
  };

  const destroyAll = (reason: string) => {
    for (const applicationId of Array.from(pending.keys())) {
      abortPendingStart(pending, applicationId, reason);
    }
    for (const applicationId of Array.from(active.keys())) {
      destroyBoundary(applicationId, reason);
    }
  };

  const invalidationSink: PluginRuntimeBoundaryInvalidationSink = {
    closeByActivation(activationId, reason = "activation_closed") {
      for (const [applicationId, start] of Array.from(pending.entries())) {
        if (start.activationId === activationId) {
          if (isAuthorityRevocationCloseReason(reason)) {
            revokedApplications.set(applicationId, { descriptorKey: start.descriptorKey });
          }
          abortPendingStart(pending, applicationId, reason);
        }
      }
      for (const [applicationId, boundary] of Array.from(active.entries())) {
        if (boundary.path.runtime.session.activationId === activationId) {
          if (isAuthorityRevocationCloseReason(reason)) {
            revokedApplications.set(applicationId, { descriptorKey: boundary.descriptorKey });
          }
          destroyBoundary(applicationId, reason);
        }
      }
      publishPluginRuntimeBoundaryDebug(active, pending, revokedApplications, [], {
        lastReason: reason,
        lastError,
        lastSkipped,
        workspaceId: lastWorkspaceId,
      });
    },
    closeByApplication(applicationId, reason = "application_closed") {
      if (isAuthorityRevocationCloseReason(reason)) {
        const descriptorKey =
          active.get(applicationId)?.descriptorKey ?? pending.get(applicationId)?.descriptorKey;
        if (descriptorKey) {
          revokedApplications.set(applicationId, { descriptorKey });
        }
      }
      abortPendingStart(pending, applicationId, reason);
      destroyBoundary(applicationId, reason);
    },
    closeByWorkspace(targetWorkspaceId, reason = "workspace_closed") {
      for (const [applicationId, start] of Array.from(pending.entries())) {
        if (start.workspaceId === targetWorkspaceId) {
          if (isAuthorityRevocationCloseReason(reason)) {
            revokedApplications.set(applicationId, { descriptorKey: start.descriptorKey });
          }
          abortPendingStart(pending, applicationId, reason);
        }
      }
      for (const [applicationId, boundary] of Array.from(active.entries())) {
        if (boundary.workspaceId === targetWorkspaceId) {
          if (isAuthorityRevocationCloseReason(reason)) {
            revokedApplications.set(applicationId, { descriptorKey: boundary.descriptorKey });
          }
          destroyBoundary(applicationId, reason);
        }
      }
      publishPluginRuntimeBoundaryDebug(active, pending, revokedApplications, [], {
        lastReason: reason,
        lastError,
        lastSkipped,
        workspaceId: lastWorkspaceId,
      });
    },
    closeByBundle(targetWorkspaceId, bundleHash, reason = "bundle_closed") {
      for (const [applicationId, start] of Array.from(pending.entries())) {
        if (
          start.workspaceId === targetWorkspaceId &&
          (start.bundleHash === undefined || start.bundleHash === bundleHash)
        ) {
          if (isAuthorityRevocationCloseReason(reason)) {
            revokedApplications.set(applicationId, { descriptorKey: start.descriptorKey });
          }
          abortPendingStart(pending, applicationId, reason);
        }
      }
      for (const [applicationId, boundary] of Array.from(active.entries())) {
        const session = boundary.path.runtime.session;
        if (boundary.workspaceId === targetWorkspaceId && session.bundleHash === bundleHash) {
          if (isAuthorityRevocationCloseReason(reason)) {
            revokedApplications.set(applicationId, { descriptorKey: boundary.descriptorKey });
          }
          destroyBoundary(applicationId, reason);
        }
      }
      publishPluginRuntimeBoundaryDebug(active, pending, revokedApplications, [], {
        lastReason: reason,
        lastError,
        lastSkipped,
        workspaceId: lastWorkspaceId,
      });
    },
    closeByCapabilityGrant(capabilityGrantId, reason = "capability_grant_closed") {
      for (const [applicationId, start] of Array.from(pending.entries())) {
        if (start.capabilityGrantId === capabilityGrantId) {
          if (isAuthorityRevocationCloseReason(reason)) {
            revokedApplications.set(applicationId, { descriptorKey: start.descriptorKey });
          }
          abortPendingStart(pending, applicationId, reason);
        }
      }
      for (const [applicationId, boundary] of Array.from(active.entries())) {
        if (boundary.path.runtime.session.capabilityGrantId === capabilityGrantId) {
          if (isAuthorityRevocationCloseReason(reason)) {
            revokedApplications.set(applicationId, { descriptorKey: boundary.descriptorKey });
          }
          destroyBoundary(applicationId, reason);
        }
      }
      publishPluginRuntimeBoundaryDebug(active, pending, revokedApplications, [], {
        lastReason: reason,
        lastError,
        lastSkipped,
        workspaceId: lastWorkspaceId,
      });
    },
  };

  createEffect(() => {
    const nextWorkspaceId = workspaceId();
    lastWorkspaceId = nextWorkspaceId;
    const descriptors = applications().filter(
      (descriptor) => descriptor.workspaceId === nextWorkspaceId,
    );
    const nextGeneration = ++generation;

    if (!nextWorkspaceId) {
      destroyAll("workspace_changed");
      return;
    }

    void reconcileRuntimes(controller, nextWorkspaceId, descriptors, {
      ownerDocument,
      loadBundle,
      networkProxyRegistration,
      networkProxyRequestSigner,
      active,
      pending,
      revokedApplications,
      getLastError: () => lastError,
      setLastError: (error) => {
        lastError = error;
      },
      getLastSkipped: () => lastSkipped,
      setLastSkipped: (reason) => {
        lastSkipped = reason;
      },
      destroyBoundary,
      isCurrent: () => generation === nextGeneration,
      currentDescriptors: () =>
        applications().filter((descriptor) => descriptor.workspaceId === workspaceId()),
    }).catch((error) => {
      lastError = formatDebugError(error);
      publishPluginRuntimeBoundaryDebug(active, pending, revokedApplications, descriptors, {
        lastReason: "runtime_reconcile_failed",
        lastError,
        lastSkipped,
        workspaceId: nextWorkspaceId,
      });
      console.error("Plugin runtime boundary could not be started.", error);
    });
  });

  const unregisterSessionCleanup = registerBeforeSessionCleanup(
    () => {
      destroyAll("session_cleanup");
    },
    { order: -100 },
  );

  onCleanup(() => {
    unregisterSessionCleanup();
    destroyAll("workspace_cleanup");
  });
  return invalidationSink;
}

async function reconcileRuntimes(
  controller: PluginHostRuntimeController,
  workspaceId: string,
  descriptors: readonly PluginRuntimeApplicationDescriptor[],
  runtime: {
    ownerDocument: Document;
    loadBundle: PluginRuntimeBundleLoader;
    networkProxyRegistration: Accessor<PluginNetworkProxyRegistration | null>;
    networkProxyRequestSigner: PluginNetworkProxyRequestSigner | null;
    active: Map<string, ActiveRuntimeBoundary>;
    pending: Map<string, PendingRuntimeBoundaryStart>;
    revokedApplications: Map<string, RevokedRuntimeApplication>;
    getLastError(): string | null;
    setLastError(error: string | null): void;
    getLastSkipped(): string | null;
    setLastSkipped(reason: string | null): void;
    destroyBoundary(applicationId: string, reason: string): void;
    isCurrent(): boolean;
    currentDescriptors(): readonly PluginRuntimeApplicationDescriptor[];
  },
): Promise<void> {
  const nextApplicationIds = new Set(descriptors.map((descriptor) => descriptor.applicationId));
  const descriptorByApplication = new Map(
    descriptors.map((descriptor) => [descriptor.applicationId, descriptor]),
  );
  for (const [applicationId, revoked] of Array.from(runtime.revokedApplications.entries())) {
    const descriptor = descriptorByApplication.get(applicationId);
    if (!descriptor) {
      runtime.revokedApplications.delete(applicationId);
      continue;
    }

    const descriptorKey = runtimeDescriptorKey(descriptor);
    if (revoked.descriptorKey && revoked.descriptorKey !== descriptorKey) {
      runtime.revokedApplications.delete(applicationId);
      continue;
    }
    if (!revoked.descriptorKey) {
      runtime.revokedApplications.set(applicationId, { descriptorKey });
    }
  }
  for (const [applicationId, pending] of Array.from(runtime.pending.entries())) {
    const descriptor = descriptorByApplication.get(applicationId);
    if (
      !descriptor ||
      pending.workspaceId !== workspaceId ||
      pending.descriptorKey !== runtimeDescriptorKey(descriptor)
    ) {
      abortPendingStart(runtime.pending, applicationId, "runtime_startup_superseded");
    }
  }
  for (const applicationId of Array.from(runtime.active.keys())) {
    if (!nextApplicationIds.has(applicationId)) {
      runtime.destroyBoundary(applicationId, "application_removed");
    }
  }

  for (const descriptor of descriptors) {
    const descriptorKey = runtimeDescriptorKey(descriptor);
    if (runtime.revokedApplications.has(descriptor.applicationId)) {
      runtime.setLastSkipped(`revoked:${descriptor.applicationId}:${descriptorKey}`);
      publishPluginRuntimeBoundaryDebug(
        runtime.active,
        runtime.pending,
        runtime.revokedApplications,
        descriptors,
        {
          lastReason: "runtime_start_skipped_revoked",
          lastError: runtime.getLastError(),
          lastSkipped: runtime.getLastSkipped(),
          workspaceId,
        },
      );
      continue;
    }
    const existing = runtime.active.get(descriptor.applicationId);
    if (existing?.workspaceId === workspaceId && existing.descriptorKey === descriptorKey) {
      runtime.setLastSkipped(`active:${descriptor.applicationId}:${descriptorKey}`);
      continue;
    }
    const pending = runtime.pending.get(descriptor.applicationId);
    if (pending?.workspaceId === workspaceId && pending.descriptorKey === descriptorKey) {
      runtime.setLastSkipped(`pending:${descriptor.applicationId}:${descriptorKey}`);
      continue;
    }
    abortPendingStart(runtime.pending, descriptor.applicationId, "application_changed");
    runtime.destroyBoundary(descriptor.applicationId, "application_changed");

    const abortController = new AbortController();
    const pendingStart: PendingRuntimeBoundaryStart = {
      workspaceId,
      descriptorKey,
      activationId: descriptor.activationId,
      capabilityGrantId: descriptor.capabilityGrantId,
      abortController,
    };
    runtime.pending.set(descriptor.applicationId, pendingStart);
    publishPluginRuntimeBoundaryDebug(
      runtime.active,
      runtime.pending,
      runtime.revokedApplications,
      descriptors,
      {
        lastReason: "runtime_start_pending",
        lastError: runtime.getLastError(),
        lastSkipped: runtime.getLastSkipped(),
        workspaceId,
      },
    );

    let loaded: LoadedPluginRuntimeBundle;
    try {
      try {
        loaded = await runtime.loadBundle(descriptor);
      } catch (error) {
        loaded = await retryRuntimeBundleLoad(runtime, descriptor, abortController.signal, error);
      }
      if (runtime.pending.get(descriptor.applicationId) === pendingStart) {
        pendingStart.bundleHash = loaded.bundleHash;
      }
      runtime.setLastError(null);
    } catch (error) {
      if (
        abortController.signal.aborted ||
        runtime.pending.get(descriptor.applicationId) !== pendingStart
      ) {
        if (runtime.pending.get(descriptor.applicationId) === pendingStart) {
          runtime.pending.delete(descriptor.applicationId);
        }
        publishPluginRuntimeBoundaryDebug(
          runtime.active,
          runtime.pending,
          runtime.revokedApplications,
          descriptors,
          {
            lastReason: "runtime_startup_superseded",
            lastError: runtime.getLastError(),
            lastSkipped: runtime.getLastSkipped(),
            workspaceId,
          },
        );
        continue;
      }
      runtime.setLastError(formatDebugError(error));
      if (runtime.pending.get(descriptor.applicationId) === pendingStart) {
        runtime.pending.delete(descriptor.applicationId);
      }
      publishPluginRuntimeBoundaryDebug(
        runtime.active,
        runtime.pending,
        runtime.revokedApplications,
        descriptors,
        {
          lastReason: "runtime_load_failed",
          lastError: runtime.getLastError(),
          lastSkipped: runtime.getLastSkipped(),
          workspaceId,
        },
      );
      throw error;
    }
    if (!runtime.isCurrent() && runtime.pending.get(descriptor.applicationId) !== pendingStart) {
      abortPendingStart(runtime.pending, descriptor.applicationId, "workspace_changed");
      return;
    }
    if (abortController.signal.aborted) {
      continue;
    }
    if (
      loaded.workspaceId !== workspaceId ||
      loaded.packageId !== descriptor.packageId ||
      loaded.applicationId !== descriptor.applicationId ||
      loaded.activationId !== descriptor.activationId ||
      loaded.ownerScopeKind !== descriptor.ownerScopeKind ||
      loaded.userId !== descriptor.userId ||
      loaded.deviceId !== descriptor.deviceId
    ) {
      abortPendingStart(runtime.pending, descriptor.applicationId, "runtime_startup_superseded");
      continue;
    }

    const ownerDocument = runtime.ownerDocument;
    const container = ownerDocument.createElement("div");
    configureRuntimeBoundaryContainer(container);
    ownerDocument.body.append(container);

    let path: PluginRuntimePath;
    try {
      path = await controller.createRuntimePath({
        container,
        handlers: [],
        pluginId: loaded.pluginId,
        packageId: loaded.packageId,
        applicationId: loaded.applicationId,
        activationId: loaded.activationId,
        ownerScopeKind: loaded.ownerScopeKind,
        workspaceId: loaded.workspaceId,
        userId: loaded.userId,
        deviceId: loaded.deviceId,
        stateHeadHash: descriptor.stateHeadHash,
        consentHeadHash: descriptor.consentHeadHash,
        bundleHash: loaded.bundleHash,
        manifestHash: loaded.manifestHash,
        frameGeneration: loaded.frameGeneration,
        bootNonce: loaded.bootNonce,
        sandboxDocumentUrl: loaded.sandboxDocumentUrl,
        startupSignal: abortController.signal,
        consentEpoch: loaded.consentEpoch,
        permissions: loaded.permissions,
        documentScope: loaded.documentScope,
        networkServices: createPluginRuntimeNetworkServices({
          ...loaded,
          networkProxyRegistration: runtime.networkProxyRegistration(),
          networkProxyRequestSigner: runtime.networkProxyRequestSigner,
        }),
        rendererSlots: normalizeRendererSlots(loaded.rendererSlots),
        highRiskConsents: loaded.highRiskConsents,
        capabilityId: issueRuntimeCapabilityId(),
        capabilityGrantId: descriptor.capabilityGrantId,
        validateSession: runtimeSessionValidator(runtime.currentDescriptors, descriptor, loaded),
        title: descriptor.title,
      });
    } catch (error) {
      container.remove();
      if (runtime.pending.get(descriptor.applicationId) === pendingStart) {
        runtime.pending.delete(descriptor.applicationId);
      }
      if (isRuntimeStartupSupersededError(error)) continue;
      throw error;
    }

    if (
      abortController.signal.aborted ||
      runtime.pending.get(descriptor.applicationId) !== pendingStart
    ) {
      path.destroy("runtime_startup_superseded");
      container.remove();
      publishPluginRuntimeBoundaryDebug(
        runtime.active,
        runtime.pending,
        runtime.revokedApplications,
        descriptors,
        {
          lastReason: "runtime_startup_superseded",
          lastError: runtime.getLastError(),
          lastSkipped: runtime.getLastSkipped(),
          workspaceId,
        },
      );
      continue;
    }
    runtime.pending.delete(descriptor.applicationId);

    const unregisterSessionClose = path.runtime.session.onClose((reason) => {
      const activeBoundary = runtime.active.get(descriptor.applicationId);
      if (
        activeBoundary?.path !== path ||
        activeBoundary.workspaceId !== workspaceId ||
        activeBoundary.descriptorKey !== descriptorKey
      ) {
        return;
      }

      activeBoundary.unregisterSessionClose();
      activeBoundary.container.remove();
      runtime.active.delete(descriptor.applicationId);
      publishPluginRuntimeBoundaryDebug(
        runtime.active,
        runtime.pending,
        runtime.revokedApplications,
        [],
        {
          lastReason: reason,
          lastError: runtime.getLastError(),
          lastSkipped: runtime.getLastSkipped(),
          workspaceId,
        },
      );
    });

    runtime.active.set(descriptor.applicationId, {
      workspaceId,
      descriptorKey,
      container,
      path,
      unregisterSessionClose,
    });
    publishPluginRuntimeBoundaryDebug(
      runtime.active,
      runtime.pending,
      runtime.revokedApplications,
      descriptors,
      {
        lastReason: "runtime_started",
        lastError: runtime.getLastError(),
        lastSkipped: runtime.getLastSkipped(),
        workspaceId,
      },
    );
  }
}

function configureRuntimeBoundaryContainer(container: HTMLElement): void {
  container.setAttribute("data-refmd-plugin-runtime-boundary", "");
  container.setAttribute("aria-hidden", "true");
  container.style.position = "fixed";
  container.style.left = "-1px";
  container.style.top = "-1px";
  container.style.width = "1px";
  container.style.height = "1px";
  container.style.overflow = "hidden";
  container.style.opacity = "0";
  container.style.pointerEvents = "none";
}

function publishPluginRuntimeBoundaryDebug(
  active: Map<string, ActiveRuntimeBoundary>,
  pending: Map<string, PendingRuntimeBoundaryStart>,
  revokedApplications: Map<string, RevokedRuntimeApplication>,
  descriptors: readonly PluginRuntimeApplicationDescriptor[],
  options: {
    lastReason: string | null;
    lastError: string | null;
    lastSkipped: string | null;
    workspaceId: string | null;
  },
): void {
  if (typeof window === "undefined") return;
  window.__refmdPluginRuntimeBoundaryDebug = {
    active: Array.from(active.entries()).map(([applicationId, boundary]) => ({
      applicationId,
      descriptorKey: boundary.descriptorKey,
      workspaceId: boundary.workspaceId,
    })),
    descriptorKeys: descriptors.map((descriptor) => ({
      applicationId: descriptor.applicationId,
      descriptorKey: runtimeDescriptorKey(descriptor),
      workspaceId: descriptor.workspaceId,
      activationId: descriptor.activationId,
      capabilityGrantId: descriptor.capabilityGrantId,
    })),
    pending: Array.from(pending.entries()).map(([applicationId, start]) => ({
      applicationId,
      descriptorKey: start.descriptorKey,
      workspaceId: start.workspaceId,
      activationId: start.activationId,
      capabilityGrantId: start.capabilityGrantId,
      aborted: start.abortController.signal.aborted,
    })),
    revoked: Array.from(revokedApplications.entries()).map(([applicationId, revoked]) => ({
      applicationId,
      descriptorKey: revoked.descriptorKey,
    })),
    lastReason: options.lastReason,
    lastError: options.lastError,
    lastSkipped: options.lastSkipped,
    updatedAt: new Date().toISOString(),
    workspaceId: options.workspaceId,
  };
}

function formatDebugError(error: unknown): string {
  if (error instanceof Error) {
    return `${error.name}: ${error.message}`;
  }
  return String(error);
}

async function retryRuntimeBundleLoad(
  runtime: { loadBundle: PluginRuntimeBundleLoader },
  descriptor: PluginRuntimeApplicationDescriptor,
  signal: AbortSignal,
  firstError: unknown,
): Promise<LoadedPluginRuntimeBundle> {
  let lastError = firstError;
  for (const delayMs of RUNTIME_LOAD_RETRY_DELAYS_MS) {
    if (signal.aborted || !isTransientRuntimeLoadError(lastError)) {
      throw lastError;
    }
    await waitForRuntimeLoadRetry(delayMs, signal);
    if (signal.aborted) throw runtimeStartupSupersededError();
    try {
      return await runtime.loadBundle(descriptor);
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError;
}

function isTransientRuntimeLoadError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return /Failed to fetch|NetworkError|network error/i.test(message);
}

async function waitForRuntimeLoadRetry(ms: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return;
  await new Promise<void>((resolve) => {
    const timeout = window.setTimeout(resolve, ms);
    signal.addEventListener(
      "abort",
      () => {
        window.clearTimeout(timeout);
        resolve();
      },
      { once: true },
    );
  });
}

function runtimeStartupSupersededError(): Error {
  return Object.assign(new Error("runtime_startup_superseded"), {
    code: "runtime_startup_superseded",
  });
}

function abortPendingStart(
  pending: Map<string, PendingRuntimeBoundaryStart>,
  applicationId: string,
  reason: string,
): void {
  const start = pending.get(applicationId);
  if (!start) return;
  pending.delete(applicationId);
  start.abortController.abort(reason);
}

function isRuntimeStartupSupersededError(error: unknown): boolean {
  return (
    error instanceof Error &&
    "code" in error &&
    (error as { code?: unknown }).code === "runtime_startup_superseded"
  );
}

function isAuthorityRevocationCloseReason(reason: string): boolean {
  return (
    reason === "workspace_deleted" ||
    reason === "workspace_left" ||
    reason === "workspace_changed" ||
    reason === "workspace_cleanup" ||
    reason === "plugin_application_deleted" ||
    reason === "plugin_application_disabled" ||
    reason === "plugin_application_policy_denied" ||
    reason === "plugin_activation_deleted" ||
    reason === "plugin_activation_disabled" ||
    reason === "plugin_consent_revoked" ||
    reason === "plugin_bundle_updated" ||
    reason === "plugin_runtime_uninstalled" ||
    reason === "plugin_runtime_activation_deleted"
  );
}

function issueRuntimeCapabilityId(): string {
  if (typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }

  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0"));
  return `${hex.slice(0, 4).join("")}-${hex.slice(4, 6).join("")}-${hex
    .slice(6, 8)
    .join("")}-${hex.slice(8, 10).join("")}-${hex.slice(10).join("")}`;
}

function runtimeSessionValidator(
  descriptors: () => readonly PluginRuntimeApplicationDescriptor[],
  descriptor: PluginRuntimeApplicationDescriptor,
  loaded: LoadedPluginRuntimeBundle,
): PluginHostRpcSessionValidator {
  const expectedDescriptorKey = runtimeDescriptorKey(descriptor);

  return (context, request) => {
    const current = descriptors().find(
      (entry) =>
        entry.workspaceId === descriptor.workspaceId &&
        entry.applicationId === descriptor.applicationId,
    );
    if (!current) {
      return {
        code: "plugin_runtime_revoked",
        message: "plugin runtime application is no longer active",
      };
    }
    if (runtimeDescriptorKey(current) !== expectedDescriptorKey) {
      return {
        code: "plugin_runtime_stale",
        message: "plugin runtime authority state has changed",
      };
    }
    if (
      context.workspaceId !== descriptor.workspaceId ||
      request.workspace_id !== descriptor.workspaceId ||
      context.packageId !== descriptor.packageId ||
      request.package_id !== descriptor.packageId ||
      context.applicationId !== descriptor.applicationId ||
      request.application_id !== descriptor.applicationId ||
      context.activationId !== descriptor.activationId ||
      request.activation_id !== descriptor.activationId ||
      context.ownerScopeKind !== descriptor.ownerScopeKind ||
      request.owner_scope_kind !== descriptor.ownerScopeKind ||
      context.userId !== descriptor.userId ||
      request.user_id !== descriptor.userId ||
      context.deviceId !== descriptor.deviceId ||
      request.device_id !== descriptor.deviceId ||
      context.bundleHash !== loaded.bundleHash ||
      request.bundle_hash !== loaded.bundleHash ||
      context.manifestHash !== loaded.manifestHash ||
      request.manifest_hash !== loaded.manifestHash ||
      context.consentEpoch !== loaded.consentEpoch ||
      request.consent_epoch !== loaded.consentEpoch ||
      context.capabilityGrantId !== descriptor.capabilityGrantId ||
      request.capability_grant_id !== descriptor.capabilityGrantId
    ) {
      return {
        code: "plugin_runtime_stale",
        message: "plugin runtime session no longer matches the approved runtime bundle",
      };
    }

    return null;
  };
}

function runtimeDescriptorKey(descriptor: PluginRuntimeApplicationDescriptor): string {
  return [
    descriptor.workspaceId,
    descriptor.packageId,
    descriptor.applicationId,
    descriptor.activationId,
    descriptor.applicationScopeKind ?? "",
    descriptor.ownerScopeKind,
    descriptor.stateHeadHash,
    descriptor.consentHeadHash,
    descriptor.consentEpoch ?? "",
    descriptor.bundleHash ?? "",
    descriptor.manifestHash ?? "",
    descriptor.resourceManifestHash ?? "",
    descriptor.permissionsHash ?? "",
    descriptor.endpointHash ?? "",
    descriptor.rendererSlotsHash ?? "",
    descriptor.documentScopeHash ?? "",
    descriptor.approvalEventHash ?? "",
    descriptor.signerUserId ?? "",
    descriptor.signerDeviceId ?? "",
    descriptor.capabilityGrantId,
    descriptor.userId,
    descriptor.deviceId,
  ].join(":");
}
