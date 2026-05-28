import type { PluginHostRpcOperationPolicy } from "../capability/capability-enforcement";
import type { PluginHostRpcHandler } from "../host-rpc/host-rpc";
import {
  registerPluginHostNetworkHandlers,
  type PluginHostNetworkServices,
} from "../network/host-network";
import {
  registerPluginHostRendererHandlers,
  type PluginHostRendererServices,
} from "../renderer/host-renderer";
import {
  registerPluginHostEditorHandlers,
  type PluginHostEditorServices,
} from "../editor/host-editor";
import {
  registerPluginHostUiHandlers,
  type PluginHostUiServices,
} from "../../model/host-ui/host-ui";
import {
  createPluginSandboxRuntime,
  type CreatePluginSandboxRuntimeOptions,
  type PluginSandboxRuntime,
} from "../sandbox/sandbox-runtime";
import type { PluginHostRpcSession } from "../host-rpc/host-rpc";
import type { PluginSandboxDocumentSessionLoader } from "../runtime-boundary/runtime-types";

export interface PluginRuntimePathHandler {
  operation: string;
  handler: PluginHostRpcHandler;
  policy: PluginHostRpcOperationPolicy;
}

export interface CreatePluginRuntimePathOptions extends CreatePluginSandboxRuntimeOptions {
  handlers: readonly PluginRuntimePathHandler[];
  networkServices?: PluginHostNetworkServices;
  rendererServices?: PluginHostRendererServices;
  editorServices?: PluginHostEditorServices;
  uiServices?: PluginHostUiServices;
  sandboxDocumentSessionLoader?: PluginSandboxDocumentSessionLoader;
}

export interface PluginRuntimePath {
  runtime: PluginSandboxRuntime;
  unregisterHandlers(): void;
  destroy(reason?: string): void;
}

type PluginRuntimeHandlerUnregister = (reason?: string) => void;

export async function createPluginRuntimePath(
  options: CreatePluginRuntimePathOptions,
): Promise<PluginRuntimePath> {
  const unregisterHandlers: PluginRuntimeHandlerUnregister[] = [];
  let handlersRegistered = false;
  let runtime: PluginSandboxRuntime | null = null;

  const unregisterAllHandlers = (reason?: string) => {
    if (!handlersRegistered) return;
    handlersRegistered = false;
    for (const unregister of [...unregisterHandlers].reverse()) {
      unregister(reason);
    }
  };

  const registerRuntimeHandlers = (
    session: PluginHostRpcSession,
  ): PluginRuntimeHandlerUnregister => {
    handlersRegistered = true;
    const owner = {
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
      frameGeneration: session.frameGeneration,
      frameScope: session.frameScope,
      consentEpoch: options.consentEpoch,
      capabilityGrantId: session.capabilityGrantId,
    };

    for (const entry of options.handlers) {
      unregisterHandlers.push(
        options.router.registerOwnerHandler(owner, entry.operation, entry.handler, entry.policy),
      );
    }

    if (options.networkServices) {
      unregisterHandlers.push(
        registerPluginHostNetworkHandlers(options.router, options.networkServices, owner),
      );
    }

    if (options.rendererServices) {
      unregisterHandlers.push(
        registerPluginHostRendererHandlers(options.router, options.rendererServices, owner),
      );
    }

    if (options.editorServices) {
      unregisterHandlers.push(
        registerPluginHostEditorHandlers(
          options.router,
          {
            ...options.editorServices,
            auditSink: options.editorServices.auditSink ?? options.auditSink,
          },
          owner,
          session,
        ),
      );
    }

    if (options.uiServices && (session.frameScope ?? "primary") === "primary") {
      unregisterHandlers.push(
        registerPluginHostUiHandlers(
          options.router,
          { ...options.uiServices, auditSink: options.uiServices.auditSink ?? options.auditSink },
          owner,
          session,
        ),
      );
    }

    return unregisterAllHandlers;
  };

  try {
    runtime = await createPluginSandboxRuntime({
      ...options,
      beforeSandboxDocumentLoad: registerRuntimeHandlers,
    });

    const createdRuntime = runtime;
    const unregisterSessionClose = createdRuntime.session.onClose((reason) => {
      unregisterAllHandlers(reason);
    });
    return {
      runtime: createdRuntime,
      unregisterHandlers: unregisterAllHandlers,
      destroy(reason = "plugin_runtime_path_destroyed") {
        unregisterAllHandlers(reason);
        createdRuntime.destroy(reason);
        unregisterSessionClose();
      },
    };
  } catch (error) {
    unregisterAllHandlers();
    runtime?.destroy("plugin_runtime_path_registration_failed");
    throw error;
  }
}
