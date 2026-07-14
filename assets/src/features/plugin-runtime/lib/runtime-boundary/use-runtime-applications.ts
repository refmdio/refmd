import { createEffect, createMemo, createResource, onCleanup, type Accessor } from "solid-js";
import { authState, deviceState } from "@/entities/session";
import { client, throwIfError, withUserRrpParams } from "@/shared/api/core";
import {
  securityNotificationsApi,
  type SecurityNotificationInfo,
} from "@/shared/api/security-notifications";
import { registerBeforeSessionCleanup } from "@/shared/lib/auth/session-cleanup";
import type { PluginRuntimeApplicationDescriptor } from "./runtime-types";
import type { PluginHighRiskConsent, PluginPermission } from "../capability/capability-enforcement";
import { isKnownPluginPermission } from "../capability/capability-enforcement";
import type { PluginNetworkEndpointPolicy } from "../network/host-network";
import type { PluginHostMessageRouter } from "../host-rpc/host-rpc";
import { purgePluginApplicationLocalData } from "../storage/host-storage";
import type { PluginRendererSlot } from "../renderer/host-renderer";
import {
  joinDeviceSecurityNotifications,
  joinWorkspaceSecurityNotifications,
  type SecurityNotificationPayload,
} from "@/shared/lib/security/notification-channel";
import type { PluginRuntimeBoundaryInvalidationSink } from "./use-runtime-boundary";
import { getDefaultPluginRendererSlotRegistry } from "../renderer/host-renderer";
import { normalizeRendererSlots } from "./renderer-slot-normalization";
import { guardedPluginRuntimeWorkspaceRequest } from "./runtime-workspace-revocation";

interface PluginRuntimeDescriptorEnvelope {
  plugin_id: string;
  package_id: string;
  application_id: string;
  activation_id: string;
  owner_scope_kind: string;
  application_scope_kind: string;
  workspace_id: string;
  state_head_hash: string;
  consent_head_hash: string;
  consent_epoch: number;
  version?: string;
  bundle_hash: string;
  approval_event_hash: string;
  manifest_hash?: string;
  resource_manifest_hash?: string;
  permissions_hash?: string;
  endpoint_hash?: string;
  renderer_slots_hash?: string;
  document_scope_hash?: string;
  signer_device_id?: string;
  signer_user_id?: string;
  capability_grant_id: string;
  title?: string;
  author?: string;
  permissions?: readonly string[];
  document_scope?: Record<string, unknown>;
  network_endpoints?: readonly Record<string, unknown>[];
  renderer_slots?: readonly Record<string, unknown>[];
  high_risk_consents?: readonly string[];
}

interface PluginRuntimeDescriptorListEnvelope {
  applications?: readonly PluginRuntimeDescriptorEnvelope[];
}
const PLUGIN_RUNTIME_APPLICATION_REFRESH_MS = 120_000;
export const PLUGIN_RUNTIME_APPLICATION_REFRESH_EVENT = "refmd-plugin-runtime-applications-refresh";

interface PluginRuntimeDebugState {
  workspaceId: string | null;
  userId: string | null;
  deviceId: string | null;
  applicationsCount: number;
  applications: readonly {
    pluginId: string;
    applicationId: string;
    rendererSlots?: readonly PluginRendererSlot[];
  }[];
  rendererRegistry: ReturnType<
    ReturnType<typeof getDefaultPluginRendererSlotRegistry>["debugSnapshot"]
  >;
  error: string | null;
  updatedAt: string;
}

declare global {
  interface Window {
    __refmdPluginRuntimeDebug?: PluginRuntimeDebugState;
  }
}
type PluginRuntimeInvalidationRouter = Pick<
  PluginHostMessageRouter,
  | "closeByActivation"
  | "closeByBundle"
  | "closeByCapabilityGrant"
  | "closeByApplication"
  | "closeByWorkspace"
>;

interface PluginRuntimeApplicationsOptions {
  enabled?: Accessor<boolean>;
}

export function usePluginRuntimeApplications(
  workspaceId: Accessor<string | null>,
  router?: PluginHostMessageRouter,
  runtimeBoundary?: PluginRuntimeBoundaryInvalidationSink,
  options: PluginRuntimeApplicationsOptions = {},
): Accessor<readonly PluginRuntimeApplicationDescriptor[]> {
  const enabled = () => options.enabled?.() ?? true;
  let lastDebugIdentity: { workspaceId: string; userId: string; deviceId: string } | null = null;
  let lastDebugApplications: readonly PluginRuntimeApplicationDescriptor[] = [];
  let lastDebugError: unknown = null;
  let sessionCleanupActive = false;
  let sessionCleanupGeneration = 0;
  const runtimeIdentity = createMemo(() => {
    if (!enabled()) return null;
    const currentWorkspaceId = workspaceId();
    const identity = currentPluginRuntimeIdentity();
    return currentWorkspaceId && identity
      ? {
          workspaceId: currentWorkspaceId,
          userId: identity.userId,
          deviceId: identity.deviceId,
        }
      : null;
  });
  const clearRuntimeApplications = () => {
    lastDebugIdentity = null;
    lastDebugApplications = [];
    lastDebugError = null;
    publishPluginRuntimeDebug(lastDebugIdentity, lastDebugApplications, lastDebugError);
  };
  const [resource, { mutate, refetch }] = createResource(runtimeIdentity, async (current) => {
    if (!current) {
      sessionCleanupActive = false;
      clearRuntimeApplications();
      return [];
    }
    if (sessionCleanupActive) {
      clearRuntimeApplications();
      return [];
    }
    const requestCleanupGeneration = sessionCleanupGeneration;
    try {
      const applications = await listPluginRuntimeApplications(current.workspaceId, {
        userId: current.userId,
        deviceId: current.deviceId,
      });
      if (sessionCleanupActive || requestCleanupGeneration !== sessionCleanupGeneration) {
        clearRuntimeApplications();
        return [];
      }
      lastDebugIdentity = current;
      lastDebugApplications = applications;
      lastDebugError = null;
      publishPluginRuntimeDebug(lastDebugIdentity, lastDebugApplications, lastDebugError);
      return applications;
    } catch (error) {
      if (sessionCleanupActive || requestCleanupGeneration !== sessionCleanupGeneration) {
        clearRuntimeApplications();
        return [];
      }
      lastDebugIdentity = current;
      lastDebugApplications = [];
      lastDebugError = error;
      publishPluginRuntimeDebug(lastDebugIdentity, lastDebugApplications, lastDebugError);
      throw error;
    }
  });
  const releaseRendererRegistryDebug = getDefaultPluginRendererSlotRegistry().subscribe(() => {
    publishPluginRuntimeDebug(lastDebugIdentity, lastDebugApplications, lastDebugError);
  });
  const unregisterSessionCleanup = registerBeforeSessionCleanup(
    () => {
      sessionCleanupActive = true;
      sessionCleanupGeneration += 1;
      mutate([]);
      clearRuntimeApplications();
    },
    { order: -90 },
  );
  const refreshTimer = setInterval(() => {
    if (enabled() && runtimeIdentity()) void refetch();
  }, PLUGIN_RUNTIME_APPLICATION_REFRESH_MS);
  const refreshListener = (event: Event) => {
    if (!enabled()) return;
    const currentWorkspaceId = workspaceId();
    if (!currentWorkspaceId || !runtimeIdentity()) return;
    const detail =
      event instanceof CustomEvent && typeof event.detail === "object" ? event.detail : null;
    const targetWorkspaceId =
      detail && "workspaceId" in detail && typeof detail.workspaceId === "string"
        ? detail.workspaceId
        : null;
    if (!targetWorkspaceId || targetWorkspaceId === currentWorkspaceId) void refetch();
  };
  window.addEventListener(PLUGIN_RUNTIME_APPLICATION_REFRESH_EVENT, refreshListener);
  onCleanup(() => {
    unregisterSessionCleanup();
    releaseRendererRegistryDebug();
    clearInterval(refreshTimer);
    window.removeEventListener(PLUGIN_RUNTIME_APPLICATION_REFRESH_EVENT, refreshListener);
  });

  if (router) {
    retainPluginRuntimeSecurityNotifications(
      workspaceId,
      router,
      runtimeBoundary,
      () => {
        if (enabled() && workspaceId()) void refetch();
      },
      enabled,
      () => (resource() ?? []).length > 0,
    );
  }

  return () => resource() ?? [];
}

export function requestPluginRuntimeApplicationsRefresh(workspaceId?: string | null): void {
  window.dispatchEvent(
    new CustomEvent(PLUGIN_RUNTIME_APPLICATION_REFRESH_EVENT, {
      detail: workspaceId ? { workspaceId } : {},
    }),
  );
}

function publishPluginRuntimeDebug(
  identity: { workspaceId: string; userId: string; deviceId: string } | null,
  applications: readonly PluginRuntimeApplicationDescriptor[],
  error: unknown,
): void {
  window.__refmdPluginRuntimeDebug = {
    workspaceId: identity?.workspaceId ?? null,
    userId: identity?.userId ?? null,
    deviceId: identity?.deviceId ?? null,
    applicationsCount: applications.length,
    applications: applications.map((application) => ({
      pluginId: application.pluginId,
      applicationId: application.applicationId,
      rendererSlots: application.rendererSlots,
    })),
    rendererRegistry: getDefaultPluginRendererSlotRegistry().debugSnapshot(),
    error: debugErrorMessage(error),
    updatedAt: new Date().toISOString(),
  };
}

export async function handlePluginRuntimeSecurityNotification(
  payload: Pick<SecurityNotificationPayload, "type" | "action_ref">,
  router: PluginRuntimeInvalidationRouter,
  currentWorkspaceId: string,
  refetch: () => void,
  identity: { userId: string; deviceId: string } | null = currentPluginRuntimeIdentity(),
  runtimeBoundary?: PluginRuntimeBoundaryInvalidationSink,
): Promise<boolean> {
  if (!isPluginRuntimeInvalidation(payload.type)) return false;
  const actionRef = payload.action_ref ?? {};
  const notificationWorkspaceId = stringValue(actionRef.workspace_id);
  if (notificationWorkspaceId && notificationWorkspaceId !== currentWorkspaceId) return false;

  const workspaceId = notificationWorkspaceId || currentWorkspaceId;
  const packageId = stringValue(actionRef.package_id);
  const applicationId = stringValue(actionRef.application_id);
  const activationId = stringValue(actionRef.activation_id);
  const capabilityGrantId = stringValue(actionRef.capability_grant_id);
  const bundleHash = stringValue(actionRef.bundle_hash);
  const reason = payload.type.replaceAll(".", "_");

  if (capabilityGrantId) {
    await runtimeBoundary?.closeByCapabilityGrant(capabilityGrantId, reason);
    router.closeByCapabilityGrant(capabilityGrantId, reason);
  } else if (payload.type === "plugin.runtime_activation_deleted" && activationId) {
    await runtimeBoundary?.closeByActivation(activationId, reason);
    router.closeByActivation(activationId, reason);
  } else if (applicationId) {
    await runtimeBoundary?.closeByApplication(applicationId, reason);
    router.closeByApplication(applicationId, reason);
  } else if (bundleHash) {
    await runtimeBoundary?.closeByBundle(workspaceId, bundleHash, reason);
    router.closeByBundle(workspaceId, bundleHash, reason);
  } else {
    await runtimeBoundary?.closeByWorkspace(workspaceId, reason);
    router.closeByWorkspace(workspaceId, reason);
  }

  refetch();
  if (
    (payload.type === "plugin.runtime_uninstalled" ||
      payload.type === "plugin.runtime_activation_deleted") &&
    packageId &&
    applicationId &&
    activationId &&
    identity
  ) {
    await purgePluginApplicationLocalData({
      workspaceId,
      packageId,
      applicationId,
      activationId,
      userId: identity.userId,
      deviceId: identity.deviceId,
    });
    return true;
  }
  return true;
}

function debugErrorMessage(error: unknown): string | null {
  if (!error) return null;
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  if (typeof error === "number" || typeof error === "boolean" || typeof error === "bigint") {
    return error.toString();
  }
  try {
    return JSON.stringify(error) ?? "unknown";
  } catch {
    return "unknown";
  }
}

function retainPluginRuntimeSecurityNotifications(
  workspaceId: Accessor<string | null>,
  router: PluginHostMessageRouter,
  runtimeBoundary: PluginRuntimeBoundaryInvalidationSink | undefined,
  refetch: () => void,
  enabled: Accessor<boolean>,
  active: Accessor<boolean>,
): void {
  let generation = 0;
  let disposeCurrent: (() => void) | null = null;

  createEffect(() => {
    generation += 1;
    const currentGeneration = generation;
    disposeCurrent?.();
    if (!enabled() || !active()) {
      disposeCurrent = null;
      return;
    }
    const currentWorkspaceId = workspaceId();
    const currentDeviceId = deviceState()?.deviceId ?? null;
    if (!currentWorkspaceId) {
      disposeCurrent = null;
      return;
    }

    const disposers: Array<() => void> = [];
    disposeCurrent = () => {
      for (const dispose of disposers.splice(0)) dispose();
    };
    const callbacks = {
      onNotification(payload: SecurityNotificationPayload) {
        void handlePluginRuntimeSecurityNotification(
          payload,
          router,
          currentWorkspaceId,
          refetch,
          currentPluginRuntimeIdentity(),
          runtimeBoundary,
        ).catch(() => {});
      },
    };
    const retain = (join: Promise<{ dispose: () => void }>) => {
      void join
        .then((handle) => {
          if (generation !== currentGeneration) {
            handle.dispose();
            return;
          }
          disposers.push(handle.dispose);
        })
        .catch(() => {
          // Security notification joins are best-effort subscriptions; polling remains as fallback.
        });
    };

    if (currentDeviceId) {
      reconcilePluginRuntimeNotificationInbox(
        currentDeviceId,
        currentWorkspaceId,
        router,
        refetch,
        runtimeBoundary,
        currentGeneration,
        () => generation,
      );
      retain(joinDeviceSecurityNotifications(currentDeviceId, callbacks));
    }
    retain(joinWorkspaceSecurityNotifications(currentWorkspaceId, callbacks));
  });

  onCleanup(() => {
    generation += 1;
    disposeCurrent?.();
    disposeCurrent = null;
  });
}

export function reconcilePluginRuntimeNotifications(
  notifications: readonly SecurityNotificationInfo[],
  router: PluginRuntimeInvalidationRouter,
  currentWorkspaceId: string,
  refetch: () => void,
  runtimeBoundary?: PluginRuntimeBoundaryInvalidationSink,
): Promise<number> {
  const handled = 0;
  return notifications.reduce<Promise<number>>(async (previousHandled, notification) => {
    const count = await previousHandled;
    const didHandle = await handlePluginRuntimeSecurityNotification(
      {
        type: notification.type,
        action_ref: notification.action_ref,
      },
      router,
      currentWorkspaceId,
      refetch,
      currentPluginRuntimeIdentity(),
      runtimeBoundary,
    );
    return didHandle ? count + 1 : count;
  }, Promise.resolve(handled));
}

function reconcilePluginRuntimeNotificationInbox(
  deviceId: string,
  currentWorkspaceId: string,
  router: PluginHostMessageRouter,
  refetch: () => void,
  runtimeBoundary: PluginRuntimeBoundaryInvalidationSink | undefined,
  currentGeneration: number,
  generationRef: () => number,
): void {
  void securityNotificationsApi
    .list({ recipientKind: "device", recipientId: deviceId })
    .then((notifications) => {
      if (generationRef() !== currentGeneration) return;
      void reconcilePluginRuntimeNotifications(
        notifications,
        router,
        currentWorkspaceId,
        refetch,
        runtimeBoundary,
      ).catch(() => {});
    })
    .catch(() => {
      // Realtime joins and descriptor polling still run; durable inbox is reconciled on the next retain cycle.
    });
}

function isPluginRuntimeInvalidation(type: string): boolean {
  return (
    type === "plugin.runtime_revoked" ||
    type === "plugin.runtime_updated" ||
    type === "plugin.runtime_disabled" ||
    type === "plugin.runtime_activation_deleted" ||
    type === "plugin.runtime_uninstalled"
  );
}

function currentPluginRuntimeIdentity(): { userId: string; deviceId: string } | null {
  const userId = authState()?.user.id;
  const deviceId = deviceState()?.deviceId;
  return userId && deviceId ? { userId, deviceId } : null;
}

export async function listPluginRuntimeApplications(
  workspaceId: string,
  identity: { userId: string; deviceId: string } | null = currentPluginRuntimeIdentity(),
): Promise<readonly PluginRuntimeApplicationDescriptor[]> {
  if (!identity) return [];

  const result = await guardedPluginRuntimeWorkspaceRequest(workspaceId, () =>
    client.GET("/api/workspaces/{workspace_id}/plugin-runtime", {
      params: withUserRrpParams({
        path: { workspace_id: workspaceId },
      }),
    }),
  );
  if (!result) return [];

  const envelope = throwIfError(result) as PluginRuntimeDescriptorListEnvelope;

  return (envelope.applications ?? []).flatMap((entry) => {
    const capabilityGrantId = stringValue(entry.capability_grant_id);
    if (!capabilityGrantId) return [];

    return [
      {
        pluginId: entry.plugin_id,
        packageId: entry.package_id,
        applicationId: entry.application_id,
        activationId: entry.activation_id,
        ownerScopeKind: entry.owner_scope_kind,
        applicationScopeKind: entry.application_scope_kind,
        workspaceId: entry.workspace_id,
        userId: identity.userId,
        deviceId: identity.deviceId,
        stateHeadHash: entry.state_head_hash,
        consentHeadHash: entry.consent_head_hash,
        consentEpoch: entry.consent_epoch,
        version: entry.version,
        bundleHash: entry.bundle_hash,
        manifestHash: entry.manifest_hash,
        resourceManifestHash: entry.resource_manifest_hash,
        permissionsHash: entry.permissions_hash,
        endpointHash: entry.endpoint_hash,
        rendererSlotsHash: entry.renderer_slots_hash,
        documentScopeHash: entry.document_scope_hash,
        approvalEventHash: entry.approval_event_hash,
        signerDeviceId: entry.signer_device_id,
        signerUserId: entry.signer_user_id,
        capabilityGrantId,
        title: entry.title,
        author: entry.author,
        permissions: normalizePermissions(entry.permissions),
        documentScope: normalizeDocumentScope(entry.document_scope),
        networkEndpoints: normalizeNetworkEndpoints(entry.network_endpoints),
        rendererSlots: normalizeRendererSlots(entry.renderer_slots),
        highRiskConsents: normalizeHighRiskConsents(entry.high_risk_consents),
      },
    ];
  });
}

export function normalizeDocumentScope(
  value: Record<string, unknown> | undefined,
): PluginRuntimeApplicationDescriptor["documentScope"] {
  if (!value) return undefined;

  const scope: NonNullable<PluginRuntimeApplicationDescriptor["documentScope"]> = {};
  const activeDocumentReadAllowed = value.activeDocumentReadAllowed === true;
  const selectedDocumentsReadAllowed = value.selectedDocumentsReadAllowed === true;
  const activeDocumentId = stringValue(value.activeDocumentId);
  const selectedDocumentIds = stringList(value.selectedDocumentIds);
  const allowedDocumentIds = stringList(value.allowedDocumentIds);

  if (value.workspaceReadAllowed === true) scope.workspaceReadAllowed = true;
  if (activeDocumentReadAllowed) scope.activeDocumentReadAllowed = true;
  if (selectedDocumentsReadAllowed) scope.selectedDocumentsReadAllowed = true;
  if (activeDocumentId) scope.activeDocumentId = activeDocumentId;
  if (selectedDocumentIds.length > 0) scope.selectedDocumentIds = selectedDocumentIds;
  if (allowedDocumentIds.length > 0) scope.allowedDocumentIds = allowedDocumentIds;

  return Object.keys(scope).length > 0 ? scope : undefined;
}

export function normalizeNetworkEndpoints(
  value: readonly Record<string, unknown>[] | undefined,
): readonly PluginNetworkEndpointPolicy[] {
  if (!Array.isArray(value)) return [];

  return value.flatMap((entry) => {
    const id = stringValue(entry.id);
    const url = stringValue(entry.url);
    const credentialAudience = stringValue(entry.credentialAudience);
    if (!id || !url) return [];

    return [
      {
        id,
        url,
        methods: stringList(entry.methods),
        routes: normalizeNetworkRoutes(entry.routes),
        headers: stringList(entry.headers),
        bodySchema:
          entry.bodySchema === "json" || entry.bodySchema === "text" ? entry.bodySchema : "none",
        maxRequestBytes: positiveInteger(entry.maxRequestBytes, 64 * 1024),
        maxResponseBytes: positiveInteger(entry.maxResponseBytes, 512 * 1024),
        ...(credentialAudience ? { credentialAudience } : {}),
      },
    ];
  });
}

function normalizePermissions(value: readonly string[] | undefined): readonly PluginPermission[] {
  const permissions = Array.isArray(value) ? value : [];
  if (!permissions.every((entry) => typeof entry === "string" && isKnownPluginPermission(entry))) {
    throw new Error("plugin_runtime_permissions_invalid");
  }
  return permissions;
}

function normalizeHighRiskConsents(
  value: readonly string[] | undefined,
): readonly PluginHighRiskConsent[] {
  const known = new Set<PluginHighRiskConsent>([
    "plaintext_document_write",
    "plaintext_network_egress",
    "plaintext_cache_storage",
    "workspace_network_egress",
  ]);
  return (Array.isArray(value) ? value : []).filter((entry): entry is PluginHighRiskConsent =>
    known.has(entry as PluginHighRiskConsent),
  );
}

function normalizeNetworkRoutes(value: unknown): readonly ["proxy"] {
  if (!Array.isArray(value) || value.length !== 1 || value[0] !== "proxy") {
    throw new Error("plugin_runtime_network_route_invalid");
  }
  return ["proxy"];
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" ? value : null;
}

function stringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is string => typeof entry === "string" && entry !== "");
}

function positiveInteger(value: unknown, fallback: number): number {
  return Number.isSafeInteger(value) && Number(value) > 0 ? Number(value) : fallback;
}
