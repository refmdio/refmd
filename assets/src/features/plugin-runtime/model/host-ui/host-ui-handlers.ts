import {
  PluginHostRpcError,
  type PluginHostMessageRouter,
  type PluginHostRpcContext,
  type PluginHostRpcHandler,
  type PluginHostRpcHandlerOwnerDescriptor,
  type PluginHostRpcHandlerRequest,
  type PluginHostRpcSession,
} from "../../lib/host-rpc/host-rpc";
import type {
  PluginHostRpcOperationPolicy,
  PluginPermission,
} from "../../lib/capability/capability-enforcement";
import {
  UI_OPERATION_SURFACES,
  assertLocalId,
  validatePluginUiContribution,
  validatePluginUiStatusText,
} from "./host-ui-validation";
import {
  isPluginUiCommandResourcePayload,
  issueCommandPlaintextExecutionContext,
  pluginUiCommandInvocationPayload,
} from "./host-ui-command";
import {
  auditCommandInvocation,
  emitCommandInvocationAccepted,
  emitCommandInvocationRejected,
  emitUiCleanupAudit,
  emitUiSecurityAudit,
  errorReasonCode,
  isAcceptedUiAuditFailure,
  type PluginUiCommandInvocationAudit,
} from "./host-ui-audit";
import { ownerKey, pluginContributionId, sameOwner } from "./host-ui-identity";
import {
  PluginUiContributionRegistry,
  openPluginUiModal,
  pluginUiEntryCommandEnabled,
  pluginUiEntryMatchesResource,
  type PluginUiAuxiliaryPaneActionControl,
  type PluginUiAuxiliaryPaneContribution,
  type PluginHostUiServices,
  type PluginUiCommandRef,
  type PluginUiContribution,
  type PluginUiPlaintextCommandContext,
  type PluginUiPlaintextCommandHandle,
  type PluginUiRegistryEntry,
  type PluginUiResourceContext,
  type PluginUiResourceContextProvider,
  type PluginUiStatusContribution,
  type PluginUiSurface,
  type PluginUiTone,
  type PluginUiWorkspaceTileActionControl,
  type PluginUiWorkspaceTileActionContribution,
  type PluginUiWorkspaceTileAvailabilityContext,
} from "./host-ui";

const UI_RPC_POLICY: PluginHostRpcOperationPolicy = { plaintext: null };
const UI_COMMAND_INVOCATION_TIMEOUT_MS = 300_000;
const UI_CONTEXTUAL_TEXT_REFRESH_TIMEOUT_MS = 5_000;
const UI_CONTEXTUAL_TEXT_CONTEXT_TTL_MS = 30_000;
const DEFAULT_CONTEXTUAL_TEXT_MAX_BYTES = 256 * 1024;
const STATUS_IFRAME_MOUNT_DELAY_MS = 50;
const STATUS_IFRAME_MOUNT_RETRY_DELAYS_MS = [0, 100, 250] as const;

type DeferredUiEffect = () => void;

export function registerPluginHostUiHandlers(
  router: PluginHostMessageRouter,
  services: PluginHostUiServices,
  owner?: PluginHostRpcHandlerOwnerDescriptor,
  session?: PluginHostRpcSession,
): (reason?: string) => void {
  if (!owner) {
    throw new PluginHostRpcError(
      "ui_owner_required",
      "UI contribution registration requires an owner",
    );
  }

  const unregisterHandlers: (() => void)[] = [];
  const registeredCommandIds = new Set<string>();
  const registeredStatusIds = new Set<string>();
  const registeredSidebarIds = new Set<string>();
  const registeredWorkspaceTileIds = new Set<string>();
  const registeredAuxiliaryPaneIds = new Set<string>();
  const registeredSettingsIds = new Set<string>();
  const registered: RegisteredUiSurfaceIds = {
    commandIds: registeredCommandIds,
    statusIds: registeredStatusIds,
    sidebarIds: registeredSidebarIds,
    workspaceTileIds: registeredWorkspaceTileIds,
    auxiliaryPaneIds: registeredAuxiliaryPaneIds,
    settingsIds: registeredSettingsIds,
  };
  let disposed = false;
  const unregisterAll = (reason = "owner_cleanup") => {
    if (disposed) return;
    disposed = true;
    const liveEntries = services.registry.list().filter((entry) => sameOwner(entry.owner, owner));
    emitUiCleanupAudit(services, session, "plugin.ui.iframe.lifecycle", owner, {
      localId: "owner",
      contributionId: ownerKey(owner),
      surface: "command",
      reasonCode: reason,
    });
    if (liveEntries.length > 0) {
      emitUiCleanupAudit(services, session, "plugin.ui.iframe.closed_with_live_entries", owner, {
        localId: "owner",
        contributionId: ownerKey(owner),
        surface: "command",
        reasonCode: reason,
      });
    }
    for (const entry of liveEntries) {
      emitUiCleanupAudit(services, session, "plugin.ui.registry_entry_disposed", owner, {
        localId: entry.contribution.local_id,
        contributionId: entry.id,
        surface: entry.contribution.surface,
        reasonCode: reason,
      });
    }
    for (const unregister of [...unregisterHandlers].reverse()) {
      unregister();
    }
    for (const commandId of registeredCommandIds) {
      services.commandSurface?.remove(commandId);
    }
    for (const statusId of registeredStatusIds) {
      services.iframeSurface?.unmount(statusId);
      services.statusSurface?.remove(statusId);
    }
    for (const sidebarId of registeredSidebarIds) {
      services.iframeSurface?.unmount(sidebarId);
      services.sidebarSurface?.remove(sidebarId);
    }
    for (const workspaceTileId of registeredWorkspaceTileIds) {
      services.iframeSurface?.unmount(workspaceTileId);
      services.workspaceTileSurface?.remove(workspaceTileId);
    }
    for (const auxiliaryPaneId of registeredAuxiliaryPaneIds) {
      services.iframeSurface?.unmount(auxiliaryPaneId);
      services.auxiliaryPaneSurface?.remove(auxiliaryPaneId);
    }
    for (const settingsId of registeredSettingsIds) {
      services.iframeSurface?.unmount(settingsId);
      services.settingsSurface?.remove(settingsId);
    }
    registeredCommandIds.clear();
    registeredStatusIds.clear();
    registeredSidebarIds.clear();
    registeredWorkspaceTileIds.clear();
    registeredAuxiliaryPaneIds.clear();
    registeredSettingsIds.clear();
    services.registry.clearOwner(owner);
  };

  try {
    for (const [operation, surface] of Object.entries(UI_OPERATION_SURFACES)) {
      unregisterHandlers.push(
        router.registerOwnerHandler(
          owner,
          operation,
          uiRegistrationHandler(services, owner, surface, registered, session),
          uiRegistrationPolicy(surface),
        ),
      );
    }
    unregisterHandlers.push(
      router.registerOwnerHandler(
        owner,
        "ui.status.update_item",
        uiStatusUpdateHandler(services, owner, registered, session),
        uiRegistrationPolicy("status"),
      ),
    );
    unregisterHandlers.push(
      router.registerOwnerHandler(
        owner,
        "ui.contribution.unregister",
        uiUnregisterHandler(services, owner, registered),
        UI_RPC_POLICY,
      ),
    );
    return unregisterAll;
  } catch (error) {
    unregisterAll();
    throw error;
  }
}

export async function invokePluginUiCommand(
  session: PluginHostRpcSession,
  registry: PluginUiContributionRegistry,
  owner: PluginHostRpcHandlerOwnerDescriptor,
  ref: PluginUiCommandRef,
  payload: unknown = null,
  audit?: PluginUiCommandInvocationAudit,
  plaintextContext?: PluginUiPlaintextCommandContext,
  resourceContext?: PluginUiResourceContext | null,
): Promise<unknown> {
  let entry: PluginUiRegistryEntry | null = null;
  let plaintextHandle: PluginUiPlaintextCommandHandle | undefined;
  try {
    entry = registry.resolveCommandRef(owner, ref);
    if (!session.connected) {
      throw new PluginHostRpcError("session_not_connected", "plugin session is not connected");
    }
    const commandPayload = pluginUiCommandInvocationPayload(
      entry,
      payload,
      registry,
      resourceContext,
    );
    plaintextHandle = issueCommandPlaintextExecutionContext(session, entry, plaintextContext);
    await emitCommandInvocationAccepted(audit, entry);
    return await session.request(
      "ui.command.invoke",
      {
        contribution_id: entry.id,
        local_id: ref.local_id,
        payload: commandPayload,
      },
      undefined,
      UI_COMMAND_INVOCATION_TIMEOUT_MS,
      { policy: UI_RPC_POLICY, executionContextId: plaintextHandle?.executionContextId },
    );
  } catch (error) {
    const closedDuringInvocation =
      error instanceof PluginHostRpcError &&
      (error.code === "session_closed" || error.code === "timeout") &&
      !session.connected;
    if (!closedDuringInvocation) {
      await emitCommandInvocationRejected(audit, entry, ref, errorReasonCode(error));
    }
    throw error;
  } finally {
    plaintextHandle?.dispose?.();
  }
}

function uiRegistrationHandler(
  services: PluginHostUiServices,
  owner: PluginHostRpcHandlerOwnerDescriptor,
  surface: PluginUiSurface,
  registered: RegisteredUiSurfaceIds,
  session: PluginHostRpcSession | undefined,
): PluginHostRpcHandler {
  return async (context: PluginHostRpcContext, request) => {
    let contribution: PluginUiContribution | null = null;
    let id: string | null = null;
    try {
      assertUiRegistrationSessionActive(session, request);
      contribution = contributionPayload(request.payload, surface);
      assertPersistentUiTextAllowed(contribution, session?.permissions);
      assertUiRegistrationSessionActive(session, request);
      if (requiresSandboxIframeSurface(contribution) && !services.iframeSurface) {
        throw new PluginHostRpcError(
          "ui_iframe_surface_unavailable",
          "sandboxed UI iframe surface is unavailable",
        );
      }
      const prepared = services.registry.prepareRegistration(
        owner,
        contribution,
        session?.permissions ?? [],
        session?.documentScope ?? {},
      );
      id = prepared.id;
      contribution = prepared.contribution;
      const deferredEffect = materializeUiContribution(
        services,
        owner,
        contribution,
        id,
        registered,
        session,
        context,
        request,
      );
      assertUiRegistrationSessionActive(session, request);
      await emitUiSecurityAudit(services.auditSink, context, request, {
        type: "plugin.ui.registration.accepted",
        payloadKind: "ui.contribution",
        contributionId: id,
        localId: contribution.local_id,
        surface: contribution.surface,
        result: "allow",
      });
      services.registry.activateRegistration(owner, contribution.local_id);
      deferredEffect?.();
      assertUiRegistrationSessionActive(session, request);
      return { id };
    } catch (error) {
      if (id && contribution) {
        removeUiSurfaceIds(services, id, registered);
        try {
          services.registry.unregister(owner, contribution.local_id);
        } catch {
          // The original rejection is authoritative; cleanup is best effort.
        }
      }
      if (!isAcceptedUiAuditFailure(error) && !isClosedUiRegistration(error, session, request)) {
        await emitUiSecurityAudit(services.auditSink, context, request, {
          type: "plugin.ui.registration.rejected",
          payloadKind: "ui.contribution",
          contributionId: id ?? pluginContributionId(owner, contribution?.local_id ?? "unknown"),
          localId: contribution?.local_id ?? "unknown",
          surface,
          result: "deny",
          reasonCode: errorReasonCode(error),
        });
      }
      throw error;
    }
  };
}

function uiStatusUpdateHandler(
  services: PluginHostUiServices,
  owner: PluginHostRpcHandlerOwnerDescriptor,
  registered: RegisteredUiSurfaceIds,
  session: PluginHostRpcSession | undefined,
): PluginHostRpcHandler {
  return async (context: PluginHostRpcContext, request) => {
    let contribution: PluginUiStatusContribution | null = null;
    let id: string | null = null;
    try {
      assertUiRegistrationSessionActive(session, request);
      const payload = validatePluginUiContribution(contributionPayload(request.payload, "status"));
      if (payload.surface !== "status") {
        throw new PluginHostRpcError("ui_surface_mismatch", "UI contribution surface is invalid");
      }
      contribution = payload;
      assertPersistentUiTextAllowed(contribution, session?.permissions);
      assertUiRegistrationSessionActive(session, request);
      if (requiresSandboxIframeSurface(contribution) && !services.iframeSurface) {
        throw new PluginHostRpcError(
          "ui_iframe_surface_unavailable",
          "sandboxed UI iframe surface is unavailable",
        );
      }

      const entry = services.registry
        .list()
        .find(
          (candidate) =>
            sameOwner(candidate.owner, owner) &&
            candidate.contribution.local_id === contribution?.local_id,
        );
      id = entry?.id ?? pluginContributionId(owner, contribution.local_id);
      if (!entry) {
        throw new PluginHostRpcError(
          "ui_contribution_unknown",
          "UI contribution is not registered for this owner",
        );
      }
      if (entry.contribution.surface !== "status" || !registered.statusIds.has(entry.id)) {
        throw new PluginHostRpcError(
          "ui_status_item_required",
          "UI contribution is not a status item",
        );
      }

      const deferredEffect = materializeStatusContribution(
        services,
        owner,
        contribution,
        entry.id,
        session,
        context,
        request,
      );
      assertUiRegistrationSessionActive(session, request);
      await emitUiSecurityAudit(services.auditSink, context, request, {
        type: "plugin.ui.registration.accepted",
        payloadKind: "ui.contribution",
        contributionId: entry.id,
        localId: contribution.local_id,
        surface: "status",
        result: "allow",
      });
      services.iframeSurface?.unmount(entry.id);
      deferredEffect?.();
      return { id: entry.id };
    } catch (error) {
      if (!isAcceptedUiAuditFailure(error) && !isClosedUiRegistration(error, session, request)) {
        await emitUiSecurityAudit(services.auditSink, context, request, {
          type: "plugin.ui.registration.rejected",
          payloadKind: "ui.contribution",
          contributionId: id ?? pluginContributionId(owner, contribution?.local_id ?? "unknown"),
          localId: contribution?.local_id ?? "unknown",
          surface: "status",
          result: "deny",
          reasonCode: errorReasonCode(error),
        });
      }
      throw error;
    }
  };
}

function assertUiRegistrationSessionActive(
  session: PluginHostRpcSession | undefined,
  request: PluginHostRpcHandlerRequest,
): void {
  if (!session) return;
  if (request.signal.aborted || !session.connected) {
    throw new PluginHostRpcError("session_closed", "plugin session is closed");
  }
}

function isClosedUiRegistration(
  error: unknown,
  session: PluginHostRpcSession | undefined,
  request: PluginHostRpcHandlerRequest,
): boolean {
  if (request.signal.aborted || (session && !session.connected)) return true;
  return error instanceof PluginHostRpcError && error.code === "session_closed";
}

function assertPersistentUiTextAllowed(
  contribution: PluginUiContribution,
  permissions: ReadonlySet<PluginPermission> | undefined,
): void {
  if (!hasPersistentHostText(contribution) || !hasPlaintextReadPermission(permissions)) return;

  throw new PluginHostRpcError(
    "ui_plaintext_display_denied",
    "persistent Host UI text is not available to plaintext-capable plugins",
  );
}

function hasPersistentHostText(contribution: PluginUiContribution): boolean {
  if (contribution.surface === "status") {
    return contribution.value.kind === "text" && contribution.value.text !== undefined;
  }

  return contribution.surface === "document_tree_badge" && contribution.text !== undefined;
}

function requiresSandboxIframeSurface(contribution: PluginUiContribution): boolean {
  switch (contribution.surface) {
    case "status":
      return contribution.value.kind === "iframe";
    case "sidebar_panel":
    case "workspace_tile":
    case "auxiliary_pane":
    case "settings_iframe":
      return true;
    case "declarative_modal":
      return contribution.body.kind === "iframe";
    default:
      return false;
  }
}

function hasPlaintextReadPermission(
  permissions: ReadonlySet<PluginPermission> | undefined,
): boolean {
  if (!permissions) return false;

  for (const permission of permissions) {
    if (
      permission.startsWith("document:read:") ||
      permission.startsWith("plaintext:render:") ||
      permission === "editor:selection:read" ||
      permission === "editor:context:read"
    ) {
      return true;
    }
  }
  return false;
}

function pluginUiCommandContext(
  services: PluginHostUiServices,
  owner: PluginHostRpcHandlerOwnerDescriptor,
  payload?: unknown,
  editor?: unknown,
  view?: unknown,
): PluginUiResourceContext | null {
  const payloadContext = pluginUiCommandPayloadContext(owner, payload, services.resourceContext);
  if (payloadContext) return payloadContext;
  const editorContext =
    editor !== undefined && view !== undefined
      ? services.resourceContext?.editor?.(editor, view)
      : null;
  if (editorContext) return editorContext;
  return (
    services.resourceContext?.activeDocument() ?? services.resourceContext?.workspace() ?? null
  );
}

function pluginUiCommandPayloadContext(
  owner: PluginHostRpcHandlerOwnerDescriptor,
  payload: unknown,
  provider: PluginUiResourceContextProvider | undefined,
): PluginUiResourceContext | null {
  if (!isPluginUiCommandResourcePayload(payload)) return null;

  const base = provider?.workspace() ?? {
    resourceKind: "workspace" as const,
    workspaceId: owner.workspaceId,
  };
  const active = provider?.activeDocument() ?? null;
  const { resource } = payload;
  if (resource.workspace_id && resource.workspace_id !== owner.workspaceId) return null;

  if (resource.kind === "document") {
    if (!resource.document_id) return null;
    const activeDocument = active?.resourceKind === "document" ? active : null;
    const sameActiveDocument = activeDocument?.documentId === resource.document_id;
    return {
      ...base,
      resourceKind: "document",
      documentId: resource.document_id,
      documentOpen: sameActiveDocument ? activeDocument.documentOpen : false,
      selectionPresent: sameActiveDocument ? activeDocument.selectionPresent : false,
    };
  }

  if (resource.kind === "folder") {
    if (!resource.folder_id) return null;
    return { ...base, resourceKind: "folder", folderId: resource.folder_id };
  }

  return { ...base, resourceKind: "workspace", workspaceId: owner.workspaceId };
}

function pluginUiCommandEntryAvailable(
  services: PluginHostUiServices,
  owner: PluginHostRpcHandlerOwnerDescriptor,
  entry: PluginUiRegistryEntry,
  payload?: unknown,
  editor?: unknown,
  view?: unknown,
): boolean {
  const context = pluginUiCommandContext(services, owner, payload, editor, view);
  return context ? pluginUiEntryCommandEnabled(entry, context, services.registry) : false;
}

function materializedPluginUiCommand(
  services: PluginHostUiServices,
  owner: PluginHostRpcHandlerOwnerDescriptor,
  entry: PluginUiRegistryEntry,
  ref: PluginUiCommandRef,
  session: PluginHostRpcSession | undefined,
  context: PluginHostRpcContext,
  request: PluginHostRpcHandlerRequest,
): {
  callback: (payload?: unknown) => void;
  checkCallback: (checking: boolean) => boolean;
} {
  return {
    callback(payload?: unknown) {
      if (!session) {
        throw new PluginHostRpcError("ui_command_session_closed", "plugin session is closed");
      }
      const resourceContext = isPluginUiCommandResourcePayload(payload)
        ? null
        : pluginUiCommandContext(services, owner, payload);
      void invokePluginUiCommand(
        session,
        services.registry,
        owner,
        ref,
        payload ?? null,
        auditCommandInvocation(services.auditSink, context, request),
        services.plaintextContext,
        resourceContext,
      ).catch(() => undefined);
    },
    checkCallback(checking: boolean) {
      const resourceContext = pluginUiCommandContext(services, owner);
      const available = resourceContext
        ? pluginUiEntryCommandEnabled(entry, resourceContext, services.registry)
        : false;
      if (checking || !available) return available;
      if (!session) {
        throw new PluginHostRpcError("ui_command_session_closed", "plugin session is closed");
      }
      void invokePluginUiCommand(
        session,
        services.registry,
        owner,
        ref,
        null,
        auditCommandInvocation(services.auditSink, context, request),
        services.plaintextContext,
        resourceContext,
      ).catch(() => undefined);
      return true;
    },
  };
}

async function invokePluginUiDeclarativeModal(
  services: PluginHostUiServices,
  owner: PluginHostRpcHandlerOwnerDescriptor,
  entry: PluginUiRegistryEntry,
  session: PluginHostRpcSession | undefined,
  context: PluginHostRpcContext,
  request: PluginHostRpcHandlerRequest,
): Promise<void> {
  try {
    if (!session) {
      throw new PluginHostRpcError("ui_command_session_closed", "plugin session is closed");
    }
    if (!session.connected) {
      throw new PluginHostRpcError("session_not_connected", "plugin session is not connected");
    }
    if (!pluginUiCommandEntryAvailable(services, owner, entry)) {
      throw new PluginHostRpcError(
        "ui_command_resource_denied",
        "plugin UI modal is unavailable for the current resource",
      );
    }
    await emitUiSecurityAudit(
      services.auditSink,
      context,
      { requestId: `${request.requestId}:modal:open`, operation: "ui.modal.open" },
      {
        type: "plugin.ui.invocation.accepted",
        payloadKind: "ui.contribution",
        contributionId: entry.id,
        localId: entry.contribution.local_id,
        surface: entry.contribution.surface,
        result: "allow",
      },
    );
    openPluginUiModal(entry.id);
  } catch (error) {
    await emitUiSecurityAudit(
      services.auditSink,
      context,
      { requestId: `${request.requestId}:modal:open:reject`, operation: "ui.modal.open" },
      {
        type: "plugin.ui.invocation.rejected",
        payloadKind: "ui.contribution",
        contributionId: entry.id,
        localId: entry.contribution.local_id,
        surface: entry.contribution.surface,
        result: "deny",
        reasonCode: errorReasonCode(error),
      },
    );
    throw error;
  }
}

function materializeUiContribution(
  services: PluginHostUiServices,
  owner: PluginHostRpcHandlerOwnerDescriptor,
  contribution: PluginUiContribution,
  id: string,
  registered: RegisteredUiSurfaceIds,
  session: PluginHostRpcSession | undefined,
  context: PluginHostRpcContext,
  request: PluginHostRpcHandlerRequest,
): DeferredUiEffect | null {
  const entry: PluginUiRegistryEntry = {
    id,
    owner,
    contribution,
    capabilities: [...(session?.permissions ?? [])],
  };

  if (contribution.surface === "command") {
    const commandSurface = services.commandSurface;
    if (!commandSurface) {
      throw new PluginHostRpcError("ui_surface_unavailable", "Host command surface is unavailable");
    }
    return () => {
      registered.commandIds.add(id);
      addUiSurface(() =>
        commandSurface.add({
          id,
          owner,
          name: contribution.title,
          icon: contribution.icon,
          ...materializedPluginUiCommand(
            services,
            owner,
            entry,
            { kind: "local_command", local_id: contribution.local_id },
            session,
            context,
            request,
          ),
        }),
      );
    };
  }

  if (
    contribution.surface === "menu_item" &&
    (contribution.placement === "command_palette" ||
      contribution.placement === "editor_context_menu")
  ) {
    const commandSurface = services.commandSurface;
    if (!commandSurface) {
      throw new PluginHostRpcError("ui_surface_unavailable", "Host command surface is unavailable");
    }
    return () => {
      registered.commandIds.add(id);
      addUiSurface(() =>
        commandSurface.add({
          id,
          owner,
          name: contribution.title,
          icon: contribution.icon,
          ...materializedPluginUiCommand(
            services,
            owner,
            entry,
            contribution.command_ref,
            session,
            context,
            request,
          ),
        }),
      );
    };
  }

  if (contribution.surface === "declarative_modal") {
    const commandSurface = services.commandSurface;
    if (!commandSurface) {
      throw new PluginHostRpcError("ui_surface_unavailable", "Host command surface is unavailable");
    }
    return () => {
      registered.commandIds.add(id);
      addUiSurface(() =>
        commandSurface.add({
          id,
          owner,
          name: contribution.title,
          icon: contribution.icon,
          callback: () => {
            void invokePluginUiDeclarativeModal(
              services,
              owner,
              entry,
              session,
              context,
              request,
            ).catch(() => undefined);
          },
          checkCallback(checking: boolean) {
            const available = pluginUiCommandEntryAvailable(services, owner, entry);
            if (checking || !available) return available;
            void invokePluginUiDeclarativeModal(
              services,
              owner,
              entry,
              session,
              context,
              request,
            ).catch(() => undefined);
            return true;
          },
        }),
      );
    };
  }

  if (contribution.surface === "status") {
    const statusEffect = materializeStatusContribution(
      services,
      owner,
      contribution,
      id,
      session,
      context,
      request,
    );
    return () => {
      registered.statusIds.add(id);
      statusEffect();
    };
  }

  if (contribution.surface === "document_tree_badge") {
    if (contribution.plaintext_request === "active_document") {
      return () =>
        scheduleDeferredUiEffect(
          () =>
            void refreshPluginUiDocumentTreeBadge(
              services,
              owner,
              contribution,
              id,
              session,
              context,
              request,
            ),
        );
    }
    return null;
  }

  if (contribution.surface === "sidebar_panel") {
    const sidebarSurface = services.sidebarSurface;
    if (!sidebarSurface) {
      throw new PluginHostRpcError("ui_surface_unavailable", "Host sidebar surface is unavailable");
    }
    return () => {
      registered.sidebarIds.add(id);
      addUiSurface(() =>
        sidebarSurface.add({
          id,
          owner,
          title: contribution.title,
          icon: contribution.icon,
          render(container) {
            services.iframeSurface?.mount({
              id,
              surface: "sidebar_panel",
              title: contribution.title,
              container,
            });
          },
          hide: () => services.iframeSurface?.unmount(id),
        }),
      );
    };
  }

  if (contribution.surface === "workspace_tile") {
    const workspaceTileSurface = services.workspaceTileSurface;
    if (!workspaceTileSurface) {
      throw new PluginHostRpcError(
        "ui_surface_unavailable",
        "Host workspace tile surface is unavailable",
      );
    }
    const preferredOpen =
      contribution.preferred_open ??
      (contribution.scope === "document" ? "document_menu" : "manual");
    const commandSurface = preferredOpen === "command" ? services.commandSurface : undefined;
    if (preferredOpen === "command" && (!commandSurface || !workspaceTileSurface.open)) {
      throw new PluginHostRpcError(
        "ui_surface_unavailable",
        "Host workspace tile command open surface is unavailable",
      );
    }
    return () => {
      registered.workspaceTileIds.add(id);
      if (preferredOpen === "command") registered.commandIds.add(id);
      addUiSurface(() => {
        workspaceTileSurface.add({
          id,
          tileId: contribution.tile_id,
          owner,
          title: contribution.title,
          icon: contribution.icon,
          scope: contribution.scope,
          preferredOpen,
          actions: () => materializedWorkspaceTileActions(services, owner, contribution.local_id),
          isAvailable(context) {
            return pluginUiEntryMatchesResource(entry, {
              resourceKind: context.resourceKind,
              workspaceId: context.workspaceId,
              documentId: context.documentId,
              folderId: context.folderId,
              documentOpen: context.documentOpen,
              selectionPresent: context.selectionPresent,
              capabilities: entry.capabilities,
            });
          },
          open(openContext) {
            return authorizePluginWorkspaceTileOpen(
              services,
              entry,
              session,
              context,
              request,
              workspaceTileOpenResourceContext(entry, openContext),
            );
          },
          render(container, renderContext) {
            const resourceContext = workspaceTileRenderResourceContext(entry, renderContext);
            if (!pluginUiEntryMatchesResource(entry, resourceContext)) {
              container.replaceChildren();
              return;
            }
            services.iframeSurface?.mount({
              id,
              mountKey: renderContext?.tileInstanceId,
              surface: "workspace_tile",
              title: contribution.title,
              container,
              resource: {
                tileId: contribution.tile_id,
                ...(renderContext?.documentId ? { documentId: renderContext.documentId } : {}),
                ...(renderContext?.tileInstanceId
                  ? { tileInstanceId: renderContext.tileInstanceId }
                  : {}),
                ...(renderContext?.action ? { action: renderContext.action } : {}),
              },
            });
          },
          hide: (renderContext) =>
            services.iframeSurface?.unmount(renderContext?.tileInstanceId ?? id),
        });

        if (preferredOpen === "command") {
          commandSurface?.add({
            id,
            owner,
            name: contribution.title,
            icon: contribution.icon,
            checkCallback(checking) {
              const target = workspaceTileCommandTarget(services, entry);
              if (!checking && target) {
                void openWorkspaceTileFromCommand(
                  services,
                  entry,
                  session,
                  context,
                  request,
                  target,
                  (documentId) => workspaceTileSurface.open?.(id, documentId),
                );
              }
              return Boolean(target);
            },
            callback() {
              const target = workspaceTileCommandTarget(services, entry);
              if (target) {
                void openWorkspaceTileFromCommand(
                  services,
                  entry,
                  session,
                  context,
                  request,
                  target,
                  (documentId) => workspaceTileSurface.open?.(id, documentId),
                );
              }
            },
          });
        }
      });
    };
  }

  if (contribution.surface === "workspace_tile_action") {
    services.registry.resolveWorkspaceTileRef(owner, contribution.tile_ref.local_id);
    return null;
  }

  if (contribution.surface === "auxiliary_pane") {
    const auxiliaryPaneSurface = services.auxiliaryPaneSurface;
    if (!auxiliaryPaneSurface) {
      throw new PluginHostRpcError(
        "ui_surface_unavailable",
        "Host auxiliary pane surface is unavailable",
      );
    }
    const actions = materializedAuxiliaryPaneActions(
      services,
      owner,
      contribution,
      id,
      session,
      context,
      request,
    );
    return () => {
      registered.auxiliaryPaneIds.add(id);
      addUiSurface(() =>
        auxiliaryPaneSurface.add({
          id,
          owner,
          title: contribution.title,
          icon: contribution.icon,
          allowedLocations: contribution.allowed_locations,
          defaultWidth: contribution.default_width,
          ...(actions ? { actions } : {}),
          render(container) {
            services.iframeSurface?.mount({
              id,
              surface: "auxiliary_pane",
              title: contribution.title,
              container,
            });
          },
          hide: () => services.iframeSurface?.unmount(id),
          close: () => {
            const entry = disposeRegisteredUiSurfaceContribution(
              services,
              owner,
              contribution.local_id,
              id,
              registered,
            );
            emitUiCleanupAudit(services, session, "plugin.ui.registry_entry_disposed", owner, {
              localId: contribution.local_id,
              contributionId: entry?.id ?? id,
              surface: entry?.contribution.surface ?? "auxiliary_pane",
              reasonCode: "host_surface_closed",
            });
          },
        }),
      );
    };
  }

  if (
    contribution.surface === "settings_iframe" ||
    contribution.surface === "settings_declarative"
  ) {
    const settingsSurface = services.settingsSurface;
    if (!settingsSurface) {
      throw new PluginHostRpcError(
        "ui_surface_unavailable",
        "Host settings surface is unavailable",
      );
    }
    return () => {
      registered.settingsIds.add(id);
      addUiSurface(() =>
        settingsSurface.add({
          id,
          owner,
          title: contribution.title,
          render(container) {
            services.settingsRenderer?.(
              container,
              contribution,
              id,
              services.iframeSurface,
              settingsRendererOptions(services, owner, contribution, session, context, request),
            );
          },
          hide: () => services.iframeSurface?.unmount(id),
        }),
      );
    };
  }

  return null;
}

function materializeStatusContribution(
  services: PluginHostUiServices,
  owner: PluginHostRpcHandlerOwnerDescriptor,
  contribution: PluginUiStatusContribution,
  id: string,
  session: PluginHostRpcSession | undefined,
  context: PluginHostRpcContext,
  request: PluginHostRpcHandlerRequest,
): DeferredUiEffect {
  const statusSurface = services.statusSurface;
  if (!statusSurface) {
    throw new PluginHostRpcError("ui_surface_unavailable", "Host status surface is unavailable");
  }
  let iframeContainer: HTMLElement | null = null;
  const addStatus = () =>
    addUiSurface(() =>
      statusSurface.add({
        id,
        owner,
        label: contribution.label,
        maxWidth: contribution.max_width,
        content:
          contribution.value.kind === "text"
            ? { kind: "text", text: contribution.value.text ?? "" }
            : {
                kind: "host_render",
                render(container) {
                  iframeContainer = container;
                },
              },
      }),
    );
  const deferredEffects: DeferredUiEffect[] = [];
  if (contribution.value.kind === "iframe") {
    deferredEffects.push(() =>
      scheduleStatusIframeMount(services, owner, contribution, id, () => iframeContainer),
    );
  }
  if (contribution.plaintext_request === "active_document") {
    deferredEffects.push(() =>
      scheduleDeferredUiEffect(
        () =>
          void refreshPluginUiStatusText(
            services,
            owner,
            contribution,
            id,
            session,
            context,
            request,
          ),
      ),
    );
  }
  return () => {
    addStatus();
    for (const effect of deferredEffects) effect();
  };
}

function scheduleDeferredUiEffect(effect: () => void, delayMs = 0): void {
  globalThis.setTimeout(effect, delayMs);
}

function scheduleStatusIframeMount(
  services: PluginHostUiServices,
  owner: PluginHostRpcHandlerOwnerDescriptor,
  contribution: PluginUiStatusContribution,
  id: string,
  container: () => HTMLElement | null,
): void {
  const mount = (attempt: number): void => {
    scheduleDeferredUiEffect(() => {
      const target = container();
      if (!pluginUiStatusContributionRegistered(services, owner, contribution, id)) return;
      if (!target?.isConnected) {
        if (attempt + 1 < STATUS_IFRAME_MOUNT_RETRY_DELAYS_MS.length) mount(attempt + 1);
        return;
      }
      services.iframeSurface?.mount({
        id,
        surface: "status",
        title: contribution.label ?? contribution.local_id,
        container: target,
      });
    }, STATUS_IFRAME_MOUNT_RETRY_DELAYS_MS[attempt] ?? 0);
  };

  scheduleDeferredUiEffect(() => mount(0), STATUS_IFRAME_MOUNT_DELAY_MS);
}

function pluginUiStatusContributionRegistered(
  services: PluginHostUiServices,
  owner: PluginHostRpcHandlerOwnerDescriptor,
  contribution: PluginUiStatusContribution,
  id: string,
): boolean {
  return services.registry
    .list("status")
    .some(
      (entry) =>
        entry.id === id &&
        sameOwner(entry.owner, owner) &&
        entry.contribution.surface === "status" &&
        entry.contribution.local_id === contribution.local_id,
    );
}

async function refreshPluginUiStatusText(
  services: PluginHostUiServices,
  owner: PluginHostRpcHandlerOwnerDescriptor,
  contribution: PluginUiStatusContribution,
  id: string,
  session: PluginHostRpcSession | undefined,
  context: PluginHostRpcContext,
  request: PluginHostRpcHandlerRequest,
): Promise<void> {
  const text = await requestPluginUiContextualText({
    services,
    owner,
    contribution,
    id,
    session,
    context,
    request,
    operation: "ui.status.refresh",
    payload: { contribution_id: id, local_id: contribution.local_id },
    textFromResponse: statusRefreshText,
  });
  if (text === null) return;
  services.statusSurface?.add({
    id,
    owner,
    label: contribution.label,
    maxWidth: contribution.max_width,
    content: { kind: "text", text },
  });
}

async function refreshPluginUiDocumentTreeBadge(
  services: PluginHostUiServices,
  owner: PluginHostRpcHandlerOwnerDescriptor,
  contribution: Extract<PluginUiContribution, { surface: "document_tree_badge" }>,
  id: string,
  session: PluginHostRpcSession | undefined,
  context: PluginHostRpcContext,
  request: PluginHostRpcHandlerRequest,
): Promise<void> {
  const response = await requestPluginUiContextualTextResponse({
    services,
    owner,
    contribution,
    id,
    session,
    context,
    request,
    operation: "ui.document_tree.badge.refresh",
    payload: { contribution_id: id, local_id: contribution.local_id },
  });
  if (!response) return;
  let text: string;
  let tone: PluginUiTone | undefined;
  try {
    text = badgeRefreshText(response);
    tone = badgeRefreshTone(response, contribution.tone);
  } catch {
    return;
  }
  try {
    services.registry.updateDisplay(owner, contribution.local_id, {
      text,
      ...(tone ? { tone } : {}),
    });
  } catch {
    // The contribution may have been unregistered before the asynchronous refresh returned.
  }
}

interface ContextualTextRequestOptions<T extends PluginUiContribution> {
  services: PluginHostUiServices;
  owner: PluginHostRpcHandlerOwnerDescriptor;
  contribution: T;
  id: string;
  session: PluginHostRpcSession | undefined;
  context: PluginHostRpcContext;
  request: PluginHostRpcHandlerRequest;
  operation: string;
  payload: Record<string, string>;
}

async function requestPluginUiContextualText<T extends PluginUiContribution>(
  options: ContextualTextRequestOptions<T> & {
    textFromResponse(response: unknown): string;
  },
): Promise<string | null> {
  const response = await requestPluginUiContextualTextResponse(options);
  if (response === null) return null;
  try {
    return options.textFromResponse(response);
  } catch {
    return null;
  }
}

async function requestPluginUiContextualTextResponse<T extends PluginUiContribution>(
  options: ContextualTextRequestOptions<T>,
): Promise<unknown> {
  let executionContextId: string | undefined;
  try {
    const issued = issuePluginUiTextRefreshContext(options.services, options.session);
    executionContextId = issued.executionContextId;
    await emitUiSecurityAudit(
      options.services.auditSink,
      options.context,
      {
        requestId: `${options.request.requestId}:${options.operation}`,
        operation: options.operation,
      },
      {
        type: "plugin.ui.invocation.accepted",
        payloadKind: "ui.contribution",
        contributionId: options.id,
        localId: options.contribution.local_id,
        surface: options.contribution.surface,
        result: "allow",
      },
    );
    return await options.session!.request(
      options.operation,
      options.payload,
      { document_id: issued.documentId },
      UI_CONTEXTUAL_TEXT_REFRESH_TIMEOUT_MS,
      { policy: UI_RPC_POLICY, executionContextId },
    );
  } catch (error) {
    await emitUiSecurityAudit(
      options.services.auditSink,
      options.context,
      {
        requestId: `${options.request.requestId}:${options.operation}:reject`,
        operation: options.operation,
      },
      {
        type: "plugin.ui.invocation.rejected",
        payloadKind: "ui.contribution",
        contributionId: options.id,
        localId: options.contribution.local_id,
        surface: options.contribution.surface,
        result: "deny",
        reasonCode: errorReasonCode(error),
      },
    ).catch(() => undefined);
    return null;
  } finally {
    if (executionContextId) options.session?.revokeExecutionContext(executionContextId);
  }
}

function issuePluginUiTextRefreshContext(
  services: PluginHostUiServices,
  session: PluginHostRpcSession | undefined,
): { executionContextId: string; documentId: string } {
  if (!session?.connected) {
    throw new PluginHostRpcError("session_not_connected", "plugin session is not connected");
  }
  if (!session.permissions.has("document:read:active")) {
    throw new PluginHostRpcError(
      "permission_denied",
      "contextual UI text requires active document read permission",
    );
  }
  const activeDocument = services.plaintextContext?.activeDocument() ?? null;
  if (!activeDocument) {
    throw new PluginHostRpcError(
      "ui_plaintext_context_unavailable",
      "active document context is unavailable for contextual UI text",
    );
  }
  const executionContext = session.issueExecutionContext({
    kind: "ui_text_refresh",
    hostInvocation: { kind: "ui_text_refresh", userGesture: false },
    resource: { document_id: activeDocument.documentId },
    plaintextScope: {
      kind: "active_document",
      maxBytes: activeDocument.maxBytes ?? DEFAULT_CONTEXTUAL_TEXT_MAX_BYTES,
    },
    allowedOperations: ["plaintext.read"],
    expiresAtMs: Date.now() + UI_CONTEXTUAL_TEXT_CONTEXT_TTL_MS,
    singleUse: true,
  });
  return {
    executionContextId: executionContext.execution_context_id,
    documentId: activeDocument.documentId,
  };
}

function statusRefreshText(response: unknown): string {
  if (!isRecord(response) || !isRecord(response.value) || response.value.kind !== "text") {
    throw new PluginHostRpcError(
      "ui_refresh_result_invalid",
      "status refresh result must include a text value",
    );
  }
  return validatePluginUiStatusText(response.value.text);
}

function badgeRefreshText(response: unknown): string {
  if (!isRecord(response)) {
    throw new PluginHostRpcError(
      "ui_refresh_result_invalid",
      "document tree badge refresh result must be an object",
    );
  }
  return validatePluginUiStatusText(response.text);
}

function badgeRefreshTone(
  response: unknown,
  fallback: PluginUiTone | undefined,
): PluginUiTone | undefined {
  if (!isRecord(response) || response.tone === undefined) return fallback;
  if (response.tone === "neutral" || response.tone === "info" || response.tone === "warning") {
    return response.tone;
  }
  throw new PluginHostRpcError("ui_refresh_result_invalid", "document tree badge tone is invalid");
}

function materializedWorkspaceTileActions(
  services: PluginHostUiServices,
  owner: PluginHostRpcHandlerOwnerDescriptor,
  tileLocalId: string,
): PluginUiWorkspaceTileActionControl[] | undefined {
  const actions = services.registry
    .list("workspace_tile_action")
    .filter((entry) => {
      const contribution = entry.contribution;
      return (
        sameOwner(entry.owner, owner) &&
        contribution.surface === "workspace_tile_action" &&
        contribution.tile_ref.local_id === tileLocalId
      );
    })
    .map((entry) => {
      const contribution = entry.contribution as PluginUiWorkspaceTileActionContribution;
      return {
        id: entry.id,
        actionId: contribution.action_id,
        title: contribution.title,
        icon: contribution.icon,
        order: contribution.order,
        placement: contribution.placement,
        ...(contribution.document_query ? { documentQuery: contribution.document_query } : {}),
      };
    });

  return actions.length > 0 ? actions : undefined;
}

function materializedAuxiliaryPaneActions(
  services: PluginHostUiServices,
  owner: PluginHostRpcHandlerOwnerDescriptor,
  contribution: PluginUiAuxiliaryPaneContribution,
  paneId: string,
  session: PluginHostRpcSession | undefined,
  context: PluginHostRpcContext,
  request: PluginHostRpcHandlerRequest,
): PluginUiAuxiliaryPaneActionControl[] | undefined {
  if (!contribution.actions?.length) return undefined;

  return contribution.actions.map((action) => {
    const commandEntry = services.registry.resolveCommandRef(owner, action.command_ref);
    const command = materializedPluginUiCommand(
      services,
      owner,
      commandEntry,
      action.command_ref,
      session,
      context,
      request,
    );
    return {
      id: `${paneId}:${action.action_id}`,
      title: action.title,
      icon: action.icon,
      order: action.order,
      invoke() {
        command.callback({
          action: {
            surface: "auxiliary_pane",
            pane_id: contribution.pane_id,
            action_id: action.action_id,
          },
        });
      },
      isAvailable() {
        return command.checkCallback(true);
      },
    };
  });
}

function settingsRendererOptions(
  services: PluginHostUiServices,
  owner: PluginHostRpcHandlerOwnerDescriptor,
  contribution: PluginUiContribution,
  session: PluginHostRpcSession | undefined,
  context: PluginHostRpcContext,
  request: PluginHostRpcHandlerRequest,
): Parameters<NonNullable<PluginHostUiServices["settingsRenderer"]>>[4] {
  if (contribution.surface !== "settings_declarative" || !contribution.submit_command_ref) {
    return undefined;
  }
  const submitCommandRef = contribution.submit_command_ref;

  return {
    submit(payload) {
      if (!session) {
        throw new PluginHostRpcError("ui_command_session_closed", "plugin session is closed");
      }
      const resourceContext = pluginUiCommandContext(services, owner, payload);
      void invokePluginUiCommand(
        session,
        services.registry,
        owner,
        submitCommandRef,
        payload,
        auditCommandInvocation(services.auditSink, context, request),
        services.plaintextContext,
        resourceContext,
      ).catch(() => undefined);
    },
  };
}

function addUiSurface(add: () => void): void {
  try {
    add();
  } catch {
    throw new PluginHostRpcError("ui_surface_add_failed", "Host UI surface registration failed");
  }
}

function removeUiSurfaceIds(
  services: PluginHostUiServices,
  id: string,
  registered: RegisteredUiSurfaceIds,
): void {
  try {
    if (registered.commandIds.delete(id)) services.commandSurface?.remove(id);
    if (registered.statusIds.delete(id)) {
      services.iframeSurface?.unmount(id);
      services.statusSurface?.remove(id);
    }
    if (registered.sidebarIds.delete(id)) services.sidebarSurface?.remove(id);
    if (registered.workspaceTileIds.delete(id)) {
      services.iframeSurface?.unmount(id);
      services.workspaceTileSurface?.remove(id);
    }
    if (registered.auxiliaryPaneIds.delete(id)) {
      services.iframeSurface?.unmount(id);
      services.auxiliaryPaneSurface?.remove(id);
    }
    if (registered.settingsIds.delete(id)) services.settingsSurface?.remove(id);
  } catch {
    // Registration failure remains authoritative; cleanup should not mask it.
  }
}

function uiUnregisterHandler(
  services: PluginHostUiServices,
  owner: PluginHostRpcHandlerOwnerDescriptor,
  registered: RegisteredUiSurfaceIds,
): PluginHostRpcHandler {
  return async (context, request) => {
    if (!isRecord(request.payload)) {
      throw new PluginHostRpcError("ui_payload_invalid", "UI unregister payload must be an object");
    }
    const localId = request.payload.local_id;
    assertLocalId(localId);
    const id = pluginContributionId(owner, localId);
    const entry = disposeRegisteredUiSurfaceContribution(services, owner, localId, id, registered);
    await emitUiSecurityAudit(services.auditSink, context, request, {
      type: "plugin.ui.registry_entry_disposed",
      payloadKind: "ui.contribution",
      contributionId: entry?.id ?? id,
      localId,
      surface: entry?.contribution.surface ?? "command",
      result: "deny",
      reasonCode: "explicit_unregister",
    });
    return { local_id: localId };
  };
}

interface RegisteredUiSurfaceIds {
  commandIds: Set<string>;
  statusIds: Set<string>;
  sidebarIds: Set<string>;
  workspaceTileIds: Set<string>;
  auxiliaryPaneIds: Set<string>;
  settingsIds: Set<string>;
}

function disposeRegisteredUiSurfaceContribution(
  services: PluginHostUiServices,
  owner: PluginHostRpcHandlerOwnerDescriptor,
  localId: string,
  id: string,
  registered: RegisteredUiSurfaceIds,
): PluginUiRegistryEntry | undefined {
  const entry = services.registry
    .list()
    .find(
      (candidate) =>
        sameOwner(candidate.owner, owner) && candidate.contribution.local_id === localId,
    );
  services.registry.unregister(owner, localId);
  services.commandSurface?.remove(id);
  services.statusSurface?.remove(id);
  services.sidebarSurface?.remove(id);
  services.workspaceTileSurface?.remove(id);
  services.auxiliaryPaneSurface?.remove(id);
  services.settingsSurface?.remove(id);
  services.iframeSurface?.unmount(id);
  registered.commandIds.delete(id);
  registered.statusIds.delete(id);
  registered.sidebarIds.delete(id);
  registered.workspaceTileIds.delete(id);
  registered.auxiliaryPaneIds.delete(id);
  registered.settingsIds.delete(id);
  return entry;
}

function workspaceTileRenderResourceContext(
  entry: PluginUiRegistryEntry,
  renderContext: { documentId?: string } | undefined,
): PluginUiResourceContext {
  if (renderContext?.documentId) {
    return {
      resourceKind: "document",
      workspaceId: entry.owner.workspaceId,
      documentId: renderContext.documentId,
      documentOpen: true,
      selectionPresent: false,
      capabilities: entry.capabilities,
    };
  }
  return {
    resourceKind: "workspace",
    workspaceId: entry.owner.workspaceId,
    documentOpen: false,
    selectionPresent: false,
    capabilities: entry.capabilities,
  };
}

function workspaceTileOpenResourceContext(
  entry: PluginUiRegistryEntry,
  context: PluginUiWorkspaceTileAvailabilityContext,
): PluginUiResourceContext {
  return {
    resourceKind: context.resourceKind,
    workspaceId: context.workspaceId ?? entry.owner.workspaceId,
    documentId: context.documentId,
    folderId: context.folderId,
    documentOpen: context.documentOpen,
    selectionPresent: context.selectionPresent,
    capabilities: entry.capabilities,
  };
}

async function authorizePluginWorkspaceTileOpen(
  services: PluginHostUiServices,
  entry: PluginUiRegistryEntry,
  session: PluginHostRpcSession | undefined,
  context: PluginHostRpcContext,
  request: PluginHostRpcHandlerRequest,
  resourceContext: PluginUiResourceContext,
): Promise<boolean> {
  try {
    if (session && !session.connected) {
      throw new PluginHostRpcError("session_not_connected", "plugin session is not connected");
    }
    if (!pluginUiEntryMatchesResource(entry, resourceContext)) {
      throw new PluginHostRpcError(
        "ui_workspace_tile_resource_denied",
        "workspace tile is unavailable for the current resource",
      );
    }
    await emitUiSecurityAudit(
      services.auditSink,
      context,
      {
        requestId: `${request.requestId}:workspace_tile:open`,
        operation: "ui.workspace_tile.open",
      },
      {
        type: "plugin.ui.invocation.accepted",
        payloadKind: "ui.contribution",
        contributionId: entry.id,
        localId: entry.contribution.local_id,
        surface: entry.contribution.surface,
        result: "allow",
      },
    );
    return true;
  } catch (error) {
    if (!isAcceptedUiAuditFailure(error)) {
      try {
        await emitUiSecurityAudit(
          services.auditSink,
          context,
          {
            requestId: `${request.requestId}:workspace_tile:open:reject`,
            operation: "ui.workspace_tile.open",
          },
          {
            type: "plugin.ui.invocation.rejected",
            payloadKind: "ui.contribution",
            contributionId: entry.id,
            localId: entry.contribution.local_id,
            surface: entry.contribution.surface,
            result: "deny",
            reasonCode: errorReasonCode(error),
          },
        );
      } catch {
        return false;
      }
    }
    return false;
  }
}

async function openWorkspaceTileFromCommand(
  services: PluginHostUiServices,
  entry: PluginUiRegistryEntry,
  session: PluginHostRpcSession | undefined,
  context: PluginHostRpcContext,
  request: PluginHostRpcHandlerRequest,
  target: WorkspaceTileCommandTarget,
  open: (documentId?: string) => void,
): Promise<void> {
  const allowed = await authorizePluginWorkspaceTileOpen(
    services,
    entry,
    session,
    context,
    request,
    target.resourceContext,
  );
  if (allowed) open(target.documentId);
}

interface WorkspaceTileCommandTarget {
  documentId?: string;
  resourceContext: PluginUiResourceContext;
}

function workspaceTileCommandTarget(
  services: PluginHostUiServices,
  entry: PluginUiRegistryEntry,
): WorkspaceTileCommandTarget | null {
  if (entry.contribution.surface !== "workspace_tile") return null;

  if (entry.contribution.scope === "document") {
    const activeDocument = services.resourceContext?.activeDocument();
    if (!activeDocument?.documentId) return null;
    const resourceContext = {
      ...activeDocument,
      resourceKind: "document" as const,
      workspaceId: activeDocument.workspaceId ?? entry.owner.workspaceId,
      documentOpen: activeDocument.documentOpen ?? true,
      capabilities: entry.capabilities,
    };
    if (!pluginUiEntryMatchesResource(entry, resourceContext)) return null;
    return { documentId: activeDocument.documentId, resourceContext };
  }

  const workspace = services.resourceContext?.workspace() ?? {
    resourceKind: "workspace" as const,
    workspaceId: entry.owner.workspaceId,
  };
  const workspaceContext = {
    ...workspace,
    resourceKind: "workspace" as const,
    workspaceId: workspace.workspaceId ?? entry.owner.workspaceId,
    documentOpen: false,
    capabilities: entry.capabilities,
  };
  if (!pluginUiEntryMatchesResource(entry, workspaceContext)) return null;
  return { resourceContext: workspaceContext };
}

function uiRegistrationPolicy(surface: PluginUiSurface): PluginHostRpcOperationPolicy {
  const permissions = uiRegistrationPermissions(surface);
  return {
    ...(permissions.length === 1
      ? { requiredPermissions: permissions }
      : { anyRequiredPermissions: permissions }),
    plaintext: null,
  };
}

function uiRegistrationPermissions(surface: PluginUiSurface): readonly `ui:${string}`[] {
  switch (surface) {
    case "status":
      return ["ui:statusbar"];
    case "sidebar_panel":
      return ["ui:sidebar"];
    case "workspace_tile":
    case "workspace_tile_action":
      return ["ui:workspace_tile"];
    case "auxiliary_pane":
      return ["ui:auxiliary_pane"];
    case "document_tree_action":
    case "document_tree_badge":
    case "document_tree_decoration":
    case "document_tree_virtual_section":
      return ["ui:document_tree:*", "ui:sidebar"];
    default:
      return [`ui:${surface}`];
  }
}

function contributionPayload(payload: unknown, surface: PluginUiSurface): PluginUiContribution {
  if (!isRecord(payload)) {
    throw new PluginHostRpcError("ui_payload_invalid", "UI contribution payload must be an object");
  }
  if (payload.surface !== surface) {
    throw new PluginHostRpcError("ui_surface_mismatch", "UI contribution surface is invalid");
  }
  return payload as unknown as PluginUiContribution;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
