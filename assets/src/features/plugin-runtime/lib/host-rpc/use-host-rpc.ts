import { createEffect, onCleanup, type Accessor } from "solid-js";
import { authState, deviceState } from "@/entities/session";
import { registerBeforeSessionCleanup } from "@/shared/lib/auth/session-cleanup";
import {
  getPluginHostMessageRouter,
  retainPluginHostMessageRouter,
  type PluginHostRpcHandlerOwnerDescriptor,
} from "../host-rpc/host-rpc";
import {
  emitPluginSecurityAudit,
  pluginAuditSucceeded,
  type PluginAuditSink,
  type PluginDocumentScope,
  type PluginHostRpcOperationPolicy,
  type PluginResourceRef,
} from "../capability/capability-enforcement";
import {
  createDefaultPluginHostStorageServices,
  retainPluginHostStorageHandlers,
} from "../storage/host-storage";
import { retainPluginHostNetworkHandlers } from "../network/host-network";
import {
  getDefaultPluginUiContributionRegistry,
  setPluginUiModalIframeSurface,
  type PluginUiIframeSurface,
  type PluginUiWorkspaceDocumentQueryInvocation,
} from "../../model/host-ui/host-ui";
import { renderPluginUiSettingsContribution } from "../../ui/host-ui/settings-renderer";
import {
  createPluginRendererSourceStore,
  getDefaultPluginRendererSlotRegistry,
  issuePluginRendererSource,
  requestPluginRendererRender,
  type PluginRendererMountParams,
} from "../renderer/host-renderer";
import {
  createPluginEditorHandle,
  getDefaultPluginEditorContributionRegistry,
  getDefaultPluginEditorPlaintextStore,
  issuePluginEditorPlaintext,
} from "../editor/host-editor";
import {
  createPluginRuntimePath,
  type CreatePluginRuntimePathOptions,
  type PluginRuntimePath,
} from "../runtime-path/runtime-path";
import type { PluginHostRuntimeController } from "../runtime-path/controller";
import { defaultPluginSandboxDocumentSessionLoader } from "../runtime-boundary/runtime-bundle-loader";
import { mergeDefaultRuntimeHandlers } from "./document-handlers";
import { createDurablePluginRuntimeAuditSink } from "./runtime-audit";
import type { FlushablePluginAuditSink } from "./runtime-audit";
import {
  commandEditorPlaintextContext,
  pluginCommandDocumentId,
  pluginEditorHasSelection,
  rendererServicesFromSlots,
} from "./workspace-surfaces";
import type { PluginHostWorkspaceAdapter } from "./workspace-adapter";

function requireWorkspaceAdapter(options: { workspace: PluginHostWorkspaceAdapter } | undefined) {
  if (!options?.workspace) {
    throw new Error("plugin_host_workspace_adapter_required");
  }
  return options.workspace;
}

const PLUGIN_UI_IFRAME_CONNECT_TIMEOUT_MS = 90_000;
const PLUGIN_UI_IFRAME_MOUNT_RETRY_DELAYS_MS = [1_000, 5_000] as const;
const PLUGIN_UI_IFRAME_AUDIT_IDLE_MS = 100;

export function usePluginHostRpc(
  workspaceId?: Accessor<string | null>,
  options?: { workspace: PluginHostWorkspaceAdapter },
): PluginHostRuntimeController {
  const workspace = requireWorkspaceAdapter(options);
  const router = getPluginHostMessageRouter();
  const releasePluginHostMessageRouter = retainPluginHostMessageRouter();
  const releasePluginHostStorageHandlers = retainPluginHostStorageHandlers(
    router,
    createDefaultPluginHostStorageServices(() => {
      const auth = authState();
      const device = deviceState();
      if (!auth || !device) return null;
      return { userId: auth.user.id, deviceId: device.deviceId };
    }),
  );
  const releasePluginHostNetworkHandlers = retainPluginHostNetworkHandlers(router);
  const uiRegistry = getDefaultPluginUiContributionRegistry();
  const rendererSourceStore = createPluginRendererSourceStore();
  const rendererRegistry = getDefaultPluginRendererSlotRegistry();
  const editorPlaintextStore = getDefaultPluginEditorPlaintextStore();
  const editorContributionRegistry = getDefaultPluginEditorContributionRegistry();
  const uiStatusItems = new Map<string, HTMLElement>();
  const uiSettingContainers = new Map<string, HTMLElement>();
  const auditSinks = new Set<FlushablePluginAuditSink>();
  const unregisterSessionCleanup = registerBeforeSessionCleanup(
    () => {
      router.closeAll("session_cleanup");
      workspace.removeSurfacesByOwner?.(() => true);
    },
    { order: -100 },
  );
  let previousWorkspaceId: string | null = null;

  if (workspaceId) {
    createEffect(() => {
      const nextWorkspaceId = workspaceId();
      if (previousWorkspaceId !== null && nextWorkspaceId !== previousWorkspaceId) {
        router.closeByWorkspace(previousWorkspaceId, "workspace_left");
        workspace.removeSurfacesByOwner?.((owner) => owner.workspaceId === previousWorkspaceId);
      }
      previousWorkspaceId = nextWorkspaceId;
    });
  }

  onCleanup(() => {
    unregisterSessionCleanup();
    releasePluginHostNetworkHandlers();
    releasePluginHostStorageHandlers();
    releasePluginHostMessageRouter();
  });

  return {
    router,
    async flushPendingAudit() {
      await Promise.allSettled([...auditSinks].map((sink) => sink.flushPendingAudit()));
    },
    createRuntimePath(options) {
      const frameGeneration = options.frameGeneration;
      const capabilityGrantId = options.capabilityGrantId;
      if (!capabilityGrantId) {
        throw new Error("plugin_runtime_capability_grant_required");
      }
      const owner = {
        pluginId: options.pluginId,
        packageId: options.packageId,
        applicationId: options.applicationId,
        activationId: options.activationId,
        ownerScopeKind: options.ownerScopeKind,
        workspaceId: options.workspaceId,
        userId: options.userId,
        deviceId: options.deviceId,
        bundleHash: options.bundleHash,
        manifestHash: options.manifestHash,
        frameGeneration,
        consentEpoch: options.consentEpoch,
        capabilityGrantId,
      };
      const runtimeAuditSink =
        options.auditSink ??
        createDurablePluginRuntimeAuditSink(() => workspaceId?.() ?? options.workspaceId);
      if (isFlushablePluginAuditSink(runtimeAuditSink)) {
        auditSinks.add(runtimeAuditSink);
      }
      const resolvedRendererServices =
        options.rendererServices ??
        rendererServicesFromSlots(options.rendererSlots, rendererSourceStore);
      const resolvedEditorServices = options.editorServices ?? {
        plaintextStore: editorPlaintextStore,
        contributionRegistry: editorContributionRegistry,
      };
      const runtimeHandlers = mergeDefaultRuntimeHandlers(options.handlers, workspace);
      const documentScope = materializeDocumentScope(options.documentScope, workspace);
      const currentDocumentScope = () => materializeDocumentScope(options.documentScope, workspace);
      const uiIframeRuntimes = new Map<string, PluginRuntimePath>();
      const uiIframeMountTokens = new Map<string, symbol>();
      const uiIframeMountKeysById = new Map<string, Set<string>>();
      const uiIframeModalSurfaceReleases = new Map<string, () => void>();
      const mountUiIframe = (mountOptions: PluginUiIframeMountOptions) => {
        const mountKey = mountOptions.mountKey ?? mountOptions.id;
        unmountUiIframe(mountKey, "plugin_ui_iframe_replaced");
        const token = Symbol(mountKey);
        uiIframeMountTokens.set(mountKey, token);
        const mountKeys = uiIframeMountKeysById.get(mountOptions.id) ?? new Set<string>();
        mountKeys.add(mountKey);
        uiIframeMountKeysById.set(mountOptions.id, mountKeys);
        mountOptions.container.replaceChildren();
        setUiIframeMountState(mountOptions.container, "loading");

        function retryMount(
          attempt: number,
          reason: string,
          path?: PluginRuntimePath,
          error?: unknown,
        ) {
          if (uiIframeMountTokens.get(mountKey) !== token) return;
          if (path && uiIframeRuntimes.get(mountKey) === path) {
            uiIframeRuntimes.delete(mountKey);
          }
          uiIframeModalSurfaceReleases.get(mountKey)?.();
          uiIframeModalSurfaceReleases.delete(mountKey);
          path?.destroy(reason);

          const retryDelayMs = PLUGIN_UI_IFRAME_MOUNT_RETRY_DELAYS_MS[attempt];
          if (retryDelayMs === undefined || !mountOptions.container.isConnected) {
            uiIframeMountTokens.delete(mountKey);
            setUiIframeMountState(mountOptions.container, "failed", reason, error);
            renderUiIframeMountFailure(mountOptions.container, mountOptions.title);
            return;
          }

          setUiIframeMountState(mountOptions.container, "retrying", reason, error);
          window.setTimeout(() => {
            if (uiIframeMountTokens.get(mountKey) !== token) return;
            mountOptions.container.replaceChildren();
            setUiIframeMountState(mountOptions.container, "loading");
            startMountAttempt(attempt + 1);
          }, retryDelayMs);
        }

        function startMountAttempt(attempt: number) {
          void secondarySandboxSessionOptions(options)
            .then((sessionOptions) =>
              createPluginRuntimePath({
                ...options,
                ...sessionOptions,
                documentScope: currentDocumentScope(),
                documentScopeProvider: currentDocumentScope,
                router,
                container: mountOptions.container,
                auditSink: runtimeAuditSink,
                title: mountOptions.title,
                className: "h-full min-h-80 w-full border-0",
                handlers: runtimeHandlers,
                rendererServices: resolvedRendererServices,
                editorServices: resolvedEditorServices,
                uiServices: resolvedUiServices,
              }),
            )
            .then((path) => {
              if (uiIframeMountTokens.get(mountKey) !== token) {
                path.destroy("plugin_ui_iframe_removed");
                return;
              }
              uiIframeRuntimes.set(mountKey, path);
              uiIframeModalSurfaceReleases.set(
                mountKey,
                setPluginUiModalIframeSurface(
                  pluginOwnerFromRuntimePath(options, path),
                  iframeSurface,
                ),
              );
              if (mountOptions.surface === "workspace_tile") {
                queueWorkspaceTileRenderRequest(
                  path,
                  mountOptions,
                  runtimeAuditSink,
                  () => uiIframeMountTokens.get(mountKey) === token,
                );
              }
              void waitForRuntimeSessionConnected(path, PLUGIN_UI_IFRAME_CONNECT_TIMEOUT_MS).then(
                (connected) => {
                  if (uiIframeMountTokens.get(mountKey) !== token) return;
                  if (uiIframeRuntimes.get(mountKey) !== path) return;
                  if (connected) {
                    setUiIframeMountState(mountOptions.container, "connected");
                    return;
                  }
                  retryMount(attempt, "plugin_ui_iframe_connect_timeout", path);
                },
              );
            })
            .catch((error) => {
              retryMount(attempt, "plugin_ui_iframe_mount_failed", undefined, error);
            });
        }

        void waitForUiIframeAuditIdle(runtimeAuditSink)
          .then(() => {
            if (uiIframeMountTokens.get(mountKey) !== token) return;
            startMountAttempt(0);
          })
          .catch((error) => {
            retryMount(0, "plugin_ui_iframe_mount_failed", undefined, error);
          });
      };
      const unmountUiIframe = (id: string, reason = "plugin_ui_iframe_removed") => {
        const mountKeys = uiIframeMountKeysById.get(id);
        if (mountKeys && (mountKeys.size > 1 || !mountKeys.has(id))) {
          uiIframeMountKeysById.delete(id);
          for (const mountKey of mountKeys) unmountUiIframe(mountKey, reason);
          return;
        }

        uiIframeMountTokens.delete(id);
        uiIframeModalSurfaceReleases.get(id)?.();
        uiIframeModalSurfaceReleases.delete(id);
        uiIframeRuntimes.get(id)?.destroy(reason);
        uiIframeRuntimes.delete(id);
        for (const [surfaceId, surfaceMountKeys] of uiIframeMountKeysById) {
          surfaceMountKeys.delete(id);
          if (surfaceMountKeys.size === 0) uiIframeMountKeysById.delete(surfaceId);
        }
      };
      const unmountUiIframes = (reason: string) => {
        for (const id of Array.from(uiIframeRuntimes.keys())) {
          unmountUiIframe(id, reason);
        }
        uiIframeMountTokens.clear();
        uiIframeMountKeysById.clear();
        for (const release of uiIframeModalSurfaceReleases.values()) release();
        uiIframeModalSurfaceReleases.clear();
      };
      const iframeSurface: PluginUiIframeSurface = {
        mount(options) {
          mountUiIframe(options);
        },
        unmount(id) {
          unmountUiIframe(id);
        },
      };
      const releaseModalIframeSurface = setPluginUiModalIframeSurface(owner, iframeSurface);
      const resolvedUiServices: CreatePluginRuntimePathOptions["uiServices"] =
        options.uiServices ?? {
          registry: uiRegistry,
          auditSink: runtimeAuditSink,
          commandSurface: {
            add(command) {
              workspace.addCommand({
                id: command.id,
                name: command.name,
                owner: command.owner,
                fallbackManifestHash: options.manifestHash,
                icon: command.icon,
                callback: command.callback,
                checkCallback: command.checkCallback,
                editorCheckCallback: command.editorCheckCallback,
              });
            },
            remove(commandId) {
              workspace.removeCommand(commandId);
            },
          },
          plaintextContext: {
            activeDocument() {
              const active = workspace.activeDocument();
              if (!active) return null;
              return { documentId: active.id };
            },
            selection(session) {
              const active = workspace.activeDocument();
              const activeEditor = workspace.activeEditorEntry();
              if (!active || !activeEditor || !activeEditor.editor.somethingSelected()) return null;
              const context = commandEditorPlaintextContext(activeEditor.editor, true);
              if (context.kind !== "selection") return null;
              const handle = issuePluginEditorPlaintext({
                session,
                store: editorPlaintextStore,
                editor: createPluginEditorHandle(activeEditor.panelId, active.id),
                plaintextKind: "selection",
                invocationKind: "user_command",
                hostInvocation: { kind: "command", userGesture: true },
                range: context.range,
                plaintext: context.plaintext,
                maxBytes: context.maxBytes,
              });
              return {
                executionContextId: handle.executionContextId,
                dispose: () => handle.dispose(),
              };
            },
            editorContext(session) {
              const active = workspace.activeDocument();
              const activeEditor = workspace.activeEditorEntry();
              if (!active || !activeEditor) return null;
              const context = commandEditorPlaintextContext(activeEditor.editor, false);
              const handle = issuePluginEditorPlaintext({
                session,
                store: editorPlaintextStore,
                editor: createPluginEditorHandle(activeEditor.panelId, active.id),
                plaintextKind: "context",
                invocationKind: "user_command",
                hostInvocation: { kind: "command", userGesture: true },
                range: context.range,
                plaintext: context.plaintext,
                maxBytes: context.maxBytes,
              });
              return {
                executionContextId: handle.executionContextId,
                dispose: () => handle.dispose(),
              };
            },
          },
          resourceContext: {
            workspace() {
              return {
                resourceKind: "workspace",
                workspaceId: options.workspaceId,
                capabilities: [...(options.permissions ?? [])],
              };
            },
            activeDocument() {
              const active = workspace.activeDocument();
              if (!active) return null;
              return {
                resourceKind: "document",
                workspaceId: options.workspaceId,
                documentId: active.id,
                documentOpen: true,
                selectionPresent: pluginEditorHasSelection(workspace.activeEditor()),
                capabilities: [...(options.permissions ?? [])],
              };
            },
            editor(editor, view) {
              const documentId = pluginCommandDocumentId(view);
              const resolvedDocumentId = documentId ?? workspace.activeDocument()?.id ?? null;
              if (!resolvedDocumentId) return null;
              return {
                resourceKind: "document",
                workspaceId: options.workspaceId,
                documentId: resolvedDocumentId,
                documentOpen: true,
                selectionPresent: pluginEditorHasSelection(editor),
                capabilities: [...(options.permissions ?? [])],
              };
            },
          },
          statusSurface: {
            add(item) {
              const existing = uiStatusItems.get(item.id);
              existing?.remove();
              const el = workspace.addStatusBarItem({
                id: item.id,
                owner: item.owner,
                fallbackManifestHash: options.manifestHash,
                label: item.label,
              });
              el.replaceChildren();
              if (item.content.kind === "text") {
                el.textContent = item.content.text;
              } else {
                item.content.render(el);
              }
              if (item.label) el.setAttribute("aria-label", item.label);
              if (item.maxWidth) el.style.maxWidth = `${item.maxWidth}px`;
              uiStatusItems.set(item.id, el);
            },
            remove(itemId) {
              uiStatusItems.get(itemId)?.remove();
              uiStatusItems.delete(itemId);
            },
          },
          sidebarSurface: {
            add(panel) {
              workspace.addSidebarPanel({
                id: panel.id,
                owner: panel.owner,
                fallbackManifestHash: options.manifestHash,
                title: panel.title,
                icon: panel.icon,
                render: panel.render,
              });
            },
            remove(panelId) {
              unmountUiIframe(panelId);
              workspace.removeSidebarPanel(panelId);
            },
          },
          workspaceTileSurface: {
            add(panel) {
              workspace.addWorkspaceTile({
                id: panel.id,
                tileId: panel.tileId,
                owner: panel.owner,
                fallbackManifestHash: options.manifestHash,
                title: panel.title,
                icon: panel.icon,
                scope: panel.scope,
                preferredOpen: panel.preferredOpen,
                actions: panel.actions,
                isAvailable: panel.isAvailable,
                open: panel.open,
                render: panel.render,
                hide: panel.hide,
              });
            },
            remove(panelId) {
              unmountUiIframe(panelId);
              workspace.removeWorkspaceTile(panelId);
            },
            open(panelId, documentId) {
              workspace.openWorkspaceTile?.(panelId, documentId);
            },
          },
          auxiliaryPaneSurface:
            workspace.addAuxiliaryPane && workspace.removeAuxiliaryPane
              ? {
                  add(pane) {
                    workspace.addAuxiliaryPane?.({
                      id: pane.id,
                      owner: pane.owner,
                      fallbackManifestHash: options.manifestHash,
                      title: pane.title,
                      icon: pane.icon,
                      allowedLocations: pane.allowedLocations,
                      defaultWidth: pane.defaultWidth,
                      actions: pane.actions,
                      render: pane.render,
                      hide: pane.hide,
                      close: pane.close,
                    });
                  },
                  remove(paneId) {
                    unmountUiIframe(paneId);
                    workspace.removeAuxiliaryPane?.(paneId);
                  },
                }
              : undefined,
          settingsSurface: {
            add(tab) {
              const existing = uiSettingContainers.get(tab.id);
              existing?.remove();
              const containerEl = workspace.addSettingTab({
                id: tab.id,
                owner: tab.owner,
                fallbackManifestHash: options.manifestHash,
                title: tab.title,
                render: tab.render,
                hide: tab.hide,
              });
              uiSettingContainers.set(tab.id, containerEl);
            },
            remove(tabId) {
              unmountUiIframe(tabId);
              workspace.removeSettingTab(tabId);
              uiSettingContainers.get(tabId)?.remove();
              uiSettingContainers.delete(tabId);
            },
          },
          iframeSurface,
          settingsRenderer: renderPluginUiSettingsContribution,
        };
      const mountRendererSlot = (params: PluginRendererMountParams) => {
        if (!resolvedRendererServices) return null;
        let disposed = false;
        let rendererPath: PluginRuntimePath | null = null;
        let sourceHandle: ReturnType<typeof issuePluginRendererSource> | null = null;
        const dispose = (reason = "plugin_renderer_removed") => {
          disposed = true;
          sourceHandle?.dispose();
          sourceHandle = null;
          rendererPath?.destroy(reason);
          rendererPath = null;
        };

        void secondarySandboxSessionOptions(options)
          .then((sessionOptions) =>
            createPluginRuntimePath({
              ...options,
              ...sessionOptions,
              documentScope: documentScopeForRendererInvocation(
                options.documentScope,
                workspace,
                params.documentId,
              ),
              router,
              container: params.container,
              auditSink: runtimeAuditSink,
              title: params.title ?? `${options.title ?? options.pluginId} renderer`,
              className: "block h-full w-full border-0",
              handlers: runtimeHandlers,
              networkServices: options.networkServices,
              rendererServices: resolvedRendererServices,
            }),
          )
          .then((path) => {
            if (disposed) {
              path.destroy("plugin_renderer_removed");
              return;
            }
            rendererPath = path;
            const iframe = path.runtime.iframe;
            iframe.style.width = "100%";
            iframe.style.minHeight = "48px";
            sourceHandle = issuePluginRendererSource({
              session: path.runtime.session,
              store: rendererSourceStore,
              slot: params.slot,
              documentId: params.documentId,
              blockId: params.blockId ?? null,
              source: params.source,
              maxBytes: params.maxBytes,
              onHeightChange(height) {
                const boundedHeight = `${Math.max(1, Math.ceil(height))}px`;
                iframe.style.height = boundedHeight;
                params.container.style.height = boundedHeight;
              },
            });
            void requestPluginRendererRender(
              path.runtime.session,
              sourceHandle,
              params.slot,
              params.documentId,
              params.blockId ?? null,
            ).catch(() => {
              if (!disposed) dispose("plugin_renderer_invoke_failed");
            });
          })
          .catch(() => {
            if (!disposed) params.container.replaceChildren();
          });

        return { dispose };
      };

      const runtimePathPromise = createPluginRuntimePath({
        ...options,
        capabilityGrantId,
        documentScope,
        documentScopeProvider: currentDocumentScope,
        frameGeneration,
        handlers: runtimeHandlers,
        router,
        auditSink: runtimeAuditSink,
        rendererServices: resolvedRendererServices,
        editorServices: resolvedEditorServices,
        uiServices: resolvedUiServices,
      });

      return runtimePathPromise
        .then((path) => {
          let cleanupDone = false;
          const releaseEditorSession =
            resolvedEditorServices.contributionRegistry?.retainOwnerSession(
              owner,
              path.runtime.session,
            ) ?? (() => {});
          const releaseRendererSlots = resolvedRendererServices
            ? rendererRegistry.register(owner, resolvedRendererServices.slots, mountRendererSlot)
            : () => {};
          const cleanup = (reason = "plugin_runtime_path_destroyed") => {
            if (cleanupDone) return;
            cleanupDone = true;
            releaseRendererSlots();
            releaseEditorSession();
            releaseModalIframeSurface();
            unmountUiIframes(reason);
            workspace.removeSurfacesByOwner?.((candidate) => sameRuntimeOwner(candidate, owner));
          };
          const unregisterBaseClose = path.runtime.session.onClose(cleanup);

          return {
            ...path,
            destroy(reason?: string) {
              const closeReason = reason ?? "plugin_runtime_path_destroyed";
              cleanup(reason);
              unregisterBaseClose();
              path.destroy(reason);
              if (isFlushablePluginAuditSink(runtimeAuditSink)) {
                runtimeAuditSink.close(closeReason);
                void runtimeAuditSink.flushPendingAudit().finally(() => {
                  auditSinks.delete(runtimeAuditSink);
                });
              }
            },
          };
        })
        .catch((error) => {
          releaseModalIframeSurface();
          unmountUiIframes("plugin_runtime_path_registration_failed");
          if (isFlushablePluginAuditSink(runtimeAuditSink)) {
            runtimeAuditSink.close("plugin_runtime_path_registration_failed");
            void runtimeAuditSink.flushPendingAudit().finally(() => {
              auditSinks.delete(runtimeAuditSink);
            });
          }
          throw error;
        });
    },
  };
}

function isFlushablePluginAuditSink(value: PluginAuditSink): value is FlushablePluginAuditSink {
  return typeof (value as { flushPendingAudit?: unknown }).flushPendingAudit === "function";
}

async function waitForUiIframeAuditIdle(auditSink: PluginAuditSink): Promise<void> {
  if (!isFlushablePluginAuditSink(auditSink)) return;
  await auditSink.waitForIdleAudit(PLUGIN_UI_IFRAME_AUDIT_IDLE_MS);
}

function setUiIframeMountState(
  container: HTMLElement,
  state: "loading" | "retrying" | "connected" | "failed",
  reason?: string,
  error?: unknown,
): void {
  container.dataset.refmdPluginUiIframeState = state;
  if (reason) {
    container.dataset.refmdPluginUiIframeReason = reason;
  } else {
    delete container.dataset.refmdPluginUiIframeReason;
  }
  if (error) {
    container.dataset.refmdPluginUiIframeError = uiIframeErrorMessage(error);
  } else {
    delete container.dataset.refmdPluginUiIframeError;
  }
}

function uiIframeErrorMessage(error: unknown): string {
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

function renderUiIframeMountFailure(container: HTMLElement, title: string): void {
  const message = container.ownerDocument.createElement("div");
  message.setAttribute("role", "status");
  message.setAttribute("data-refmd-plugin-ui-iframe-error", "true");
  message.className = "p-3 text-sm text-destructive";
  message.textContent = `${title} could not be loaded.`;
  container.replaceChildren(message);
}

function sameRuntimeOwner(
  first: PluginHostRpcHandlerOwnerDescriptor,
  second: PluginHostRpcHandlerOwnerDescriptor,
): boolean {
  return (
    first.pluginId === second.pluginId &&
    first.packageId === second.packageId &&
    first.applicationId === second.applicationId &&
    first.activationId === second.activationId &&
    first.ownerScopeKind === second.ownerScopeKind &&
    first.workspaceId === second.workspaceId &&
    first.userId === second.userId &&
    first.deviceId === second.deviceId &&
    first.bundleHash === second.bundleHash &&
    (first.manifestHash ?? "") === (second.manifestHash ?? "") &&
    first.frameGeneration === second.frameGeneration &&
    first.consentEpoch === second.consentEpoch &&
    first.capabilityGrantId === second.capabilityGrantId
  );
}

interface PluginUiIframeMountOptions {
  id: string;
  mountKey?: string;
  surface:
    | "status"
    | "sidebar_panel"
    | "workspace_tile"
    | "auxiliary_pane"
    | "settings_iframe"
    | "declarative_modal";
  title: string;
  container: HTMLElement;
  resource?: {
    tileId?: string;
    documentId?: string;
    tileInstanceId?: string;
    action?: WorkspaceTileMountAction;
  };
}

interface WorkspaceTileMountAction {
  actionId: string;
  tileId: string;
  tileInstanceId: string;
  documentId?: string;
  kind?: "tile_action";
  tileActionId?: string;
  documentQuery?: PluginUiWorkspaceDocumentQueryInvocation;
  issuedAtMs: number;
}

type WorkspaceTileInvocationOperation = "ui.workspace_tile.render" | "ui.workspace_tile.action";

interface WorkspaceTileExecutionContext {
  executionContextId: string;
  resource: PluginResourceRef;
  kind?: "tile_action";
  tileActionId?: string;
  documentQuery?: PluginUiWorkspaceDocumentQueryInvocation;
}

type WorkspaceTileExecutionContextResult =
  | WorkspaceTileExecutionContext
  | { auditDenied: true }
  | undefined;

const WORKSPACE_TILE_RENDER_DELIVERY_POLICY: PluginHostRpcOperationPolicy = {
  plaintext: null,
};
const WORKSPACE_TILE_ACTION_CONTEXT_TTL_MS = 30_000;
const WORKSPACE_TILE_ACTION_CONTEXT_MAX_BYTES = 256 * 1024;

function queueWorkspaceTileRenderRequest(
  path: PluginRuntimePath,
  mountOptions: PluginUiIframeMountOptions,
  auditSink: PluginAuditSink,
  shouldSend: () => boolean,
): void {
  void waitForRuntimeSessionConnected(path, PLUGIN_UI_IFRAME_CONNECT_TIMEOUT_MS).then(
    (connected) => {
      if (connected && shouldSend())
        void sendWorkspaceTileRenderRequest(path, mountOptions, auditSink);
    },
  );
}

function waitForRuntimeSessionConnected(
  path: PluginRuntimePath,
  timeoutMs: number,
): Promise<boolean> {
  if (path.runtime.session.connected) return Promise.resolve(true);
  if (path.runtime.session.closed) return Promise.resolve(false);

  return new Promise((resolve) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let unregisterClose: () => void = () => undefined;
    const settle = (value: boolean) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      unregisterClose();
      resolve(value);
    };
    const expiresAt = Date.now() + timeoutMs;
    const poll = () => {
      if (path.runtime.session.connected) {
        settle(true);
        return;
      }
      if (path.runtime.session.closed || Date.now() >= expiresAt) {
        settle(false);
        return;
      }
      timer = setTimeout(poll, 1);
    };

    unregisterClose = path.runtime.session.onClose(() => settle(false));
    poll();
  });
}

async function sendWorkspaceTileRenderRequest(
  path: PluginRuntimePath,
  mountOptions: PluginUiIframeMountOptions,
  auditSink: PluginAuditSink,
): Promise<void> {
  if (mountOptions.surface !== "workspace_tile") return;

  const documentId = mountOptions.resource?.documentId;
  const action = mountOptions.resource?.action;
  const validAction = isCurrentWorkspaceTileAction(
    action,
    mountOptions.id,
    mountOptions.resource?.tileInstanceId,
    documentId,
  )
    ? action
    : undefined;
  const isTileAction = validAction?.kind === "tile_action";
  const operation = isTileAction ? "ui.workspace_tile.action" : "ui.workspace_tile.render";
  const executionContextResult = await issueWorkspaceTileExecutionContext(
    path,
    mountOptions,
    auditSink,
    operation,
  );
  if (executionContextResult && "auditDenied" in executionContextResult) return;
  const executionContext = executionContextResult;
  if (isTileAction && validAction?.documentQuery && !executionContext) return;
  const renderResource = workspaceTileRenderResource(documentId, executionContext?.resource);

  await path.runtime.session
    .request(
      operation,
      {
        tile_id: mountOptions.resource?.tileId ?? mountOptions.id,
        tile_instance_id: mountOptions.resource?.tileInstanceId,
        document_id: documentId,
        ...(isTileAction && validAction?.tileActionId
          ? { action_id: validAction.tileActionId }
          : {}),
        ...(executionContext?.documentQuery
          ? { document_query: executionContext.documentQuery }
          : {}),
      },
      renderResource,
      10_000,
      {
        policy: WORKSPACE_TILE_RENDER_DELIVERY_POLICY,
        ...(executionContext ? { executionContextId: executionContext.executionContextId } : {}),
      },
    )
    .catch(() => undefined);
}

async function issueWorkspaceTileExecutionContext(
  path: PluginRuntimePath,
  mountOptions: PluginUiIframeMountOptions,
  auditSink: PluginAuditSink,
  operation: WorkspaceTileInvocationOperation,
): Promise<WorkspaceTileExecutionContextResult> {
  const action = mountOptions.resource?.action;
  const documentId = mountOptions.resource?.documentId;
  const documentQuery = action?.documentQuery;
  if (
    !isCurrentWorkspaceTileAction(
      action,
      mountOptions.id,
      mountOptions.resource?.tileInstanceId,
      documentId,
    )
  ) {
    return undefined;
  }

  const contextScope = workspaceTileActionPlaintextScope(path, action.actionId, {
    documentId,
    documentQuery,
  });
  if (!contextScope) return undefined;
  if (
    !(await auditWorkspaceTileInvocationContext(path, auditSink, action, contextScope, operation))
  ) {
    return { auditDenied: true };
  }

  const executionContext = path.runtime.session.issueExecutionContext({
    kind: contextScope.contextKind,
    hostInvocation: contextScope.hostInvocation,
    resource: contextScope.resource,
    plaintextScope: {
      kind: contextScope.plaintextScopeKind,
      maxBytes: contextScope.maxBytes,
    },
    allowedOperations: ["plaintext.read"],
    expiresAtMs: Date.now() + WORKSPACE_TILE_ACTION_CONTEXT_TTL_MS,
    singleUse: true,
  });
  return {
    executionContextId: executionContext.execution_context_id,
    resource: contextScope.resource,
    ...(action.kind ? { kind: action.kind } : {}),
    ...(action.tileActionId ? { tileActionId: action.tileActionId } : {}),
    ...("documentQuery" in contextScope && contextScope.documentQuery
      ? { documentQuery: contextScope.documentQuery }
      : {}),
  };
}

async function auditWorkspaceTileInvocationContext(
  path: PluginRuntimePath,
  auditSink: PluginAuditSink,
  action: WorkspaceTileMountAction,
  contextScope:
    | {
        contextKind: "ui_action";
        plaintextScopeKind: "active_document" | "selected_documents";
        resource: PluginResourceRef;
      }
    | {
        contextKind: "user_command";
        plaintextScopeKind: "workspace";
        resource: PluginResourceRef;
        documentQuery: PluginUiWorkspaceDocumentQueryInvocation;
      },
  operation: WorkspaceTileInvocationOperation,
): Promise<boolean> {
  return pluginAuditSucceeded(
    emitPluginSecurityAudit(auditSink, path.runtime.session.securityAuditContext(), {
      type: "plugin.ui.invocation.accepted",
      operation,
      result: "allow",
      actionResult: "allowed",
      requestId: action.actionId,
      contextKind: contextScope.contextKind,
      payloadKind:
        operation === "ui.workspace_tile.action"
          ? "ui.workspace_tile_action"
          : "ui.workspace_tile_render",
      plaintextScopeKind: contextScope.plaintextScopeKind,
      resourceRef: contextScope.resource,
      authorityEventRef: action.tileActionId ?? action.actionId,
    }),
  );
}

function workspaceTileActionPlaintextScope(
  path: PluginRuntimePath,
  actionId: string,
  options: {
    documentId?: string;
    documentQuery?: PluginUiWorkspaceDocumentQueryInvocation;
  },
):
  | {
      contextKind: "ui_action";
      hostInvocation: { kind: "host_action_token"; userGesture: true; tokenId: string };
      plaintextScopeKind: "active_document" | "selected_documents";
      maxBytes: number;
      resource: PluginResourceRef;
    }
  | {
      contextKind: "user_command";
      hostInvocation: { kind: "button"; userGesture: true; tokenId: string };
      plaintextScopeKind: "workspace";
      maxBytes: number;
      resource: PluginResourceRef;
      documentQuery: PluginUiWorkspaceDocumentQueryInvocation;
    }
  | undefined {
  if (options.documentQuery) {
    if (!path.runtime.session.permissions.has("document:read:workspace")) return undefined;
    return {
      contextKind: "user_command",
      hostInvocation: { kind: "button", userGesture: true, tokenId: actionId },
      plaintextScopeKind: "workspace",
      maxBytes: options.documentQuery.max_bytes,
      resource: {
        max_documents: options.documentQuery.max_documents,
        max_bytes: options.documentQuery.max_bytes,
      },
      documentQuery: options.documentQuery,
    };
  }

  if (options.documentId) {
    if (path.runtime.session.permissions.has("document:read:active")) {
      return {
        contextKind: "ui_action",
        hostInvocation: { kind: "host_action_token", userGesture: true, tokenId: actionId },
        plaintextScopeKind: "active_document",
        maxBytes: WORKSPACE_TILE_ACTION_CONTEXT_MAX_BYTES,
        resource: { document_id: options.documentId },
      };
    }
    if (path.runtime.session.permissions.has("document:read:selected")) {
      return {
        contextKind: "ui_action",
        hostInvocation: { kind: "host_action_token", userGesture: true, tokenId: actionId },
        plaintextScopeKind: "selected_documents",
        maxBytes: WORKSPACE_TILE_ACTION_CONTEXT_MAX_BYTES,
        resource: { selected_document_ids: [options.documentId] },
      };
    }
    return undefined;
  }

  return undefined;
}

function workspaceTileRenderResource(
  documentId: string | undefined,
  actionResource: PluginResourceRef | undefined,
): PluginResourceRef | undefined {
  if (!documentId && !actionResource) return undefined;
  return {
    ...actionResource,
    ...(documentId ? { document_id: documentId } : {}),
  };
}

function isCurrentWorkspaceTileAction(
  value: WorkspaceTileMountAction | undefined,
  tileId: string,
  tileInstanceId: string | undefined,
  documentId: string | undefined,
): value is WorkspaceTileMountAction {
  if (!value) return false;
  if (
    value.tileId !== tileId ||
    value.documentId !== documentId ||
    value.tileInstanceId !== tileInstanceId ||
    value.actionId.length === 0
  ) {
    return false;
  }
  const ageMs = Date.now() - value.issuedAtMs;
  return (
    Number.isSafeInteger(value.issuedAtMs) &&
    ageMs >= 0 &&
    ageMs <= WORKSPACE_TILE_ACTION_CONTEXT_TTL_MS
  );
}

type SecondarySandboxSessionOptions = Pick<
  CreatePluginRuntimePathOptions,
  "capabilityGrantId" | "frameGeneration" | "frameScope" | "bootNonce" | "sandboxDocumentUrl"
>;
type ControllerRuntimePathOptions = Parameters<PluginHostRuntimeController["createRuntimePath"]>[0];

async function secondarySandboxSessionOptions(
  options: ControllerRuntimePathOptions,
): Promise<SecondarySandboxSessionOptions> {
  if (!options.sandboxDocumentUrl || !options.bootNonce || options.frameGeneration === undefined) {
    throw new Error("plugin_runtime_sandbox_document_session_required");
  }
  if (!options.stateHeadHash || !options.consentHeadHash) {
    throw new Error("plugin_runtime_pin_context_required");
  }

  const loader = options.sandboxDocumentSessionLoader ?? defaultPluginSandboxDocumentSessionLoader;
  const session = await loader({
    workspaceId: options.workspaceId,
    applicationId: options.applicationId,
    stateHeadHash: options.stateHeadHash,
    consentHeadHash: options.consentHeadHash,
    capabilityGrantId: options.capabilityGrantId,
    frameScope: "secondary",
  });

  return {
    capabilityGrantId: session.capabilityGrantId,
    frameGeneration: session.frameGeneration,
    frameScope: session.frameScope,
    bootNonce: session.bootNonce,
    sandboxDocumentUrl: session.sandboxDocumentUrl,
  };
}

function materializeDocumentScope(
  documentScope: PluginDocumentScope | undefined,
  workspace: PluginHostWorkspaceAdapter,
): PluginDocumentScope | undefined {
  if (!documentScope) return undefined;
  const next: PluginDocumentScope = { ...documentScope };

  if (documentScope.activeDocumentReadAllowed === true) {
    const activeDocumentId = workspace.activeDocument()?.id ?? null;
    next.activeDocumentId = activeDocumentId ?? documentScope.activeDocumentId;
  }

  if (documentScope.selectedDocumentsReadAllowed === true) {
    const selectedDocumentIds =
      workspace.selectedDocuments?.().map((document) => document.id) ?? [];
    next.selectedDocumentIds =
      selectedDocumentIds.length > 0 ? selectedDocumentIds : documentScope.selectedDocumentIds;
  }

  return next;
}

function documentScopeForRendererInvocation(
  documentScope: PluginDocumentScope | undefined,
  workspace: PluginHostWorkspaceAdapter,
  documentId: string,
): PluginDocumentScope {
  const next = materializeDocumentScope(documentScope, workspace) ?? {};
  const allowedDocumentIds = new Set(next.allowedDocumentIds ?? []);
  allowedDocumentIds.add(documentId);
  return { ...next, allowedDocumentIds: [...allowedDocumentIds] };
}

function pluginOwnerFromRuntimePath(
  options: Pick<
    CreatePluginRuntimePathOptions,
    | "pluginId"
    | "packageId"
    | "workspaceId"
    | "applicationId"
    | "activationId"
    | "ownerScopeKind"
    | "userId"
    | "deviceId"
    | "bundleHash"
    | "manifestHash"
    | "consentEpoch"
  >,
  path: PluginRuntimePath,
): PluginHostRpcHandlerOwnerDescriptor {
  return {
    pluginId: options.pluginId,
    packageId: options.packageId,
    workspaceId: options.workspaceId,
    applicationId: options.applicationId,
    activationId: options.activationId,
    ownerScopeKind: options.ownerScopeKind,
    userId: options.userId,
    deviceId: options.deviceId,
    bundleHash: options.bundleHash,
    manifestHash: options.manifestHash,
    frameGeneration: path.runtime.session.frameGeneration,
    consentEpoch: options.consentEpoch,
    capabilityGrantId: path.runtime.session.capabilityGrantId,
  };
}
