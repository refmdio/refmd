import { createEffect, getOwner, onCleanup, type ParentProps } from "solid-js";
import { useNavigate } from "@solidjs/router";
import { useQueryClient } from "@tanstack/solid-query";
import { useDocuments, useDocumentTitles } from "@/entities/document";
import { useSettings } from "@/entities/settings";
import { currentWorkspaceId, setCurrentWorkspaceId, useWorkspaces } from "@/entities/workspace";
import { useWorkspaceKekRotationMonitor } from "@/app/workspace/use-workspace-kek-rotation-monitor";
import { AppLayout } from "@/app/layout/AppLayout";
import { useCorePluginLifecycle } from "@/app/bootstrap/use-core-plugin-lifecycle";
import { useDocumentWorkspaceRuntime } from "@/app/bootstrap/use-document-workspace-runtime";
import { useOfflineSync } from "@/app/bootstrap/use-offline-sync";
import { usePluginHostRpc } from "./use-plugin-host-rpc";
import { usePluginConsentRequired } from "@/features/plugin-runtime";
import { usePluginRuntimeApplications } from "@/features/plugin-runtime";
import { requestPluginRuntimeApplicationsRefresh } from "@/features/plugin-runtime";
import {
  beginPluginRuntimeApplicationRevocation,
  beginPluginRuntimeWorkspaceRevocation,
  createPluginNetworkProxyRequestSigner,
  releasePluginRuntimeApplicationRevocation,
  releasePluginRuntimeWorkspaceRevocation,
  useThirdPartyPluginRuntimeBoundary,
  waitForPluginRuntimeWorkspaceIdle,
  type PluginNetworkProxyRegistration,
  type PluginRuntimeBoundaryInvalidationSink,
} from "@/features/plugin-runtime";
import { usePendingDevices } from "@/features/devices";
import { installPublicationRenameAutoSync } from "@/features/editor";
import { createWorkspaceWithInitialKek } from "@/features/workspace";
import { retainPanelWorkspace } from "@/features/panel";
import { getDocumentRuntime } from "@/shared/lib/document/manager";
import { setDefaultPluginRenderOwner } from "@/features/plugin-runtime";
import { flushPluginRuntimeTeardown } from "./plugin-runtime-teardown";

export function WorkspaceRoot(props: ParentProps) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { workspaces, allWorkspaces, workspacesNeedingRotation } = useWorkspaces();
  const { pendingCount, refetchPending } = usePendingDevices();
  const panelWorkspaceLease = retainPanelWorkspace();
  const documentWorkspace = panelWorkspaceLease.workspace;
  const workspaceId = () => currentWorkspaceId();
  const { flatDocuments } = useDocuments(workspaceId);
  const { getTitle: getTitleFromDoc } = useDocumentTitles(flatDocuments, workspaceId);
  const disposePluginRenderOwner = setDefaultPluginRenderOwner(getOwner());
  const disposePublicationRenameSync = installPublicationRenameAutoSync();

  onCleanup(disposePluginRenderOwner);
  onCleanup(disposePublicationRenameSync);

  const settings = useSettings();

  const app = useDocumentWorkspaceRuntime(documentWorkspace, navigate, queryClient);
  onCleanup(panelWorkspaceLease.release);
  const pluginHost = usePluginHostRpc(workspaceId, app);
  const pluginRuntimeBoundaryInvalidation: {
    current?: PluginRuntimeBoundaryInvalidationSink;
  } = {};
  const runtimeInvalidationSink: PluginRuntimeBoundaryInvalidationSink = {
    closeByActivation(activationId, reason) {
      pluginRuntimeBoundaryInvalidation.current?.closeByActivation(activationId, reason);
    },
    closeByApplication(applicationId, reason) {
      pluginRuntimeBoundaryInvalidation.current?.closeByApplication(applicationId, reason);
    },
    closeByWorkspace(targetWorkspaceId, reason) {
      pluginRuntimeBoundaryInvalidation.current?.closeByWorkspace(targetWorkspaceId, reason);
    },
    closeByBundle(targetWorkspaceId, bundleHash, reason) {
      pluginRuntimeBoundaryInvalidation.current?.closeByBundle(
        targetWorkspaceId,
        bundleHash,
        reason,
      );
    },
    closeByCapabilityGrant(capabilityGrantId, reason) {
      pluginRuntimeBoundaryInvalidation.current?.closeByCapabilityGrant(capabilityGrantId, reason);
    },
  };
  const pluginRuntimeApplications = usePluginRuntimeApplications(
    workspaceId,
    pluginHost.router,
    runtimeInvalidationSink,
  );
  const effectivePluginNetworkProxyRegistration = () => {
    const activeWorkspaceId = currentWorkspaceId();
    const workspaceProxy = workspacePluginNetworkProxy(
      allWorkspaces().find((workspace) => workspace.id === activeWorkspaceId),
    );
    return pluginNetworkProxyRegistration(workspaceProxy ?? settings.data?.plugin_network_proxy);
  };
  const pluginConsent = usePluginConsentRequired(workspaceId, {
    onConsentChanged() {
      requestPluginRuntimeApplicationsRefresh(workspaceId());
      void refetchPending();
    },
    networkProxyRegistration: effectivePluginNetworkProxyRegistration,
  });
  pluginRuntimeBoundaryInvalidation.current = useThirdPartyPluginRuntimeBoundary(
    pluginHost,
    workspaceId,
    document,
    pluginRuntimeApplications,
    undefined,
    effectivePluginNetworkProxyRegistration,
    createPluginNetworkProxyRequestSigner(),
  );
  useCorePluginLifecycle(app, documentWorkspace);
  useOfflineSync();
  useWorkspaceKekRotationMonitor(workspacesNeedingRotation, queryClient);

  getDocumentRuntime().setTitleResolver((doc) => {
    const found = flatDocuments().find((candidate) => candidate.id === doc.id);
    return found ? getTitleFromDoc(found) : "Untitled";
  });

  let previousWorkspaceId: string | null = null;
  createEffect(() => {
    const workspaceId = currentWorkspaceId();
    if (previousWorkspaceId !== null && workspaceId !== previousWorkspaceId) {
      documentWorkspace.resetWorkspace();
    }
    previousWorkspaceId = workspaceId;
  });

  const handleSelectWorkspace = (workspaceId: string) => {
    setCurrentWorkspaceId(workspaceId);
    navigate("/dashboard");
  };

  const handleCreateWorkspace = async (data: {
    name: string;
    description?: string;
    icon?: string;
  }): Promise<void> => {
    const workspaceId = await createWorkspaceWithInitialKek(data);
    if (!workspaceId) return;

    await queryClient.invalidateQueries({ queryKey: ["workspaces"] });
    setCurrentWorkspaceId(workspaceId);
    navigate("/dashboard");
  };

  const closePluginRuntimeByApplication = async (applicationId: string, reason?: string) => {
    runtimeInvalidationSink.closeByApplication(applicationId, reason);
    pluginHost.router.closeByApplication(applicationId, reason);
    app.workspace.removeSurfacesByOwner(
      (owner) => owner.kind === "third_party" && owner.applicationId === applicationId,
    );
    await flushPluginRuntimeTeardown(() => pluginHost.flushPendingAudit?.() ?? Promise.resolve());
  };

  const closePluginRuntimeByWorkspace = async (targetWorkspaceId: string, reason?: string) => {
    beginPluginRuntimeWorkspaceRevocation(targetWorkspaceId);
    await waitForPluginRuntimeWorkspaceIdle(targetWorkspaceId);
    runtimeInvalidationSink.closeByWorkspace(targetWorkspaceId, reason);
    pluginHost.router.closeByWorkspace(targetWorkspaceId, reason);
    app.workspace.removeSurfacesByOwner(
      (owner) => owner.kind === "third_party" && owner.workspaceId === targetWorkspaceId,
    );
    await flushPluginRuntimeTeardown(() => pluginHost.flushPendingAudit?.() ?? Promise.resolve());
  };

  return (
    <AppLayout
      workspaces={workspaces()}
      currentWorkspaceId={currentWorkspaceId()}
      securityNotificationCount={pendingCount()}
      onSelectWorkspace={handleSelectWorkspace}
      onCreateWorkspace={handleCreateWorkspace}
      beginPluginRuntimeApplicationRevocation={beginPluginRuntimeApplicationRevocation}
      closePluginRuntimeByApplication={closePluginRuntimeByApplication}
      releasePluginRuntimeApplicationRevocation={releasePluginRuntimeApplicationRevocation}
      closePluginRuntimeByWorkspace={closePluginRuntimeByWorkspace}
      releasePluginRuntimeWorkspaceRevocation={releasePluginRuntimeWorkspaceRevocation}
    >
      {props.children}
      {pluginConsent.view()}
    </AppLayout>
  );
}

function pluginNetworkProxyRegistration(value: unknown): PluginNetworkProxyRegistration | null {
  if (!value || typeof value !== "object") return null;
  const proxy = value as Record<string, unknown>;
  if (proxy.enabled === false || proxy.revoked === true) return null;
  if (
    typeof proxy.id !== "string" ||
    typeof proxy.label !== "string" ||
    typeof proxy.base_url !== "string" ||
    (proxy.scope !== "user" && proxy.scope !== "workspace")
  ) {
    return null;
  }
  return {
    id: proxy.id,
    label: proxy.label,
    origin: proxy.base_url,
    scope: proxy.scope,
    operatorLabel: typeof proxy.operator_label === "string" ? proxy.operator_label : proxy.label,
    allowedWorkspaceIds: stringList(proxy.allowed_workspace_ids),
    allowedUserIds: stringList(proxy.allowed_user_ids),
    verificationMaterial: recordValue(proxy.verification_material),
    revoked: proxy.revoked === true,
    policy: recordValue(proxy.policy),
  };
}

function workspacePluginNetworkProxy(workspace: unknown): unknown {
  if (!workspace || typeof workspace !== "object") return null;
  return (workspace as { plugin_network_proxy?: unknown }).plugin_network_proxy ?? null;
}

function stringList(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((entry): entry is string => typeof entry === "string")
    : [];
}

function recordValue(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}
