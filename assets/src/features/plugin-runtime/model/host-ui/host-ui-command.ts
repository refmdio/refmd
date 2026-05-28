import { PluginHostRpcError, type PluginHostRpcSession } from "../../lib/host-rpc/host-rpc";
import type { PluginPermission } from "../../lib/capability/capability-enforcement";
import { pluginUiCommandResourcePayload } from "./host-ui";
import type {
  PluginUiCommandContribution,
  PluginUiCommandResourcePayload,
  PluginUiContributionRegistry,
  PluginUiPlaintextCommandContext,
  PluginUiPlaintextCommandHandle,
  PluginUiRegistryEntry,
  PluginUiResourceContext,
} from "./host-ui";

export function pluginUiValidatedCommandPayload(
  entry: PluginUiRegistryEntry,
  payload: unknown,
  registry: PluginUiContributionRegistry,
  context: PluginUiResourceContext | null | undefined,
): unknown {
  if (!context) return payload;

  const scopedPayload = pluginUiCommandResourcePayload(entry, context, registry);
  if (!scopedPayload) {
    throw new PluginHostRpcError(
      "ui_command_resource_denied",
      "plugin UI command is unavailable for the current resource",
    );
  }

  if (payload == null) return scopedPayload;
  if (isPluginUiCommandResourcePayload(payload)) {
    if (!samePluginUiCommandResource(payload.resource, scopedPayload.resource)) {
      throw new PluginHostRpcError(
        "ui_command_resource_denied",
        "plugin UI command payload resource does not match the current resource",
      );
    }
    return payload;
  }

  return payload;
}

export function pluginUiCommandInvocationPayload(
  entry: PluginUiRegistryEntry,
  payload: unknown,
  registry: PluginUiContributionRegistry,
  context: PluginUiResourceContext | null | undefined,
): unknown {
  const validated = pluginUiValidatedCommandPayload(entry, payload, registry, context);
  if (entry.contribution.surface !== "command" || !entry.contribution.document_query) {
    return validated;
  }

  const query = entry.contribution.document_query;
  const documentQuery = {
    scope: query.scope,
    max_documents: query.max_documents,
    max_bytes: query.max_bytes,
    ...(query.reason ? { reason: query.reason } : {}),
  };

  if (isRecord(validated)) return { ...validated, document_query: documentQuery };
  return { document_query: documentQuery };
}

export function isPluginUiCommandResourcePayload(
  value: unknown,
): value is PluginUiCommandResourcePayload {
  if (!value || typeof value !== "object") return false;
  const resource = (value as { resource?: unknown }).resource;
  if (!resource || typeof resource !== "object") return false;
  const kind = (resource as { kind?: unknown }).kind;
  return kind === "document" || kind === "folder" || kind === "workspace";
}

function samePluginUiCommandResource(
  first: PluginUiCommandResourcePayload["resource"],
  second: PluginUiCommandResourcePayload["resource"],
): boolean {
  return (
    first.kind === second.kind &&
    first.workspace_id === second.workspace_id &&
    first.document_id === second.document_id &&
    first.folder_id === second.folder_id
  );
}

const COMMAND_PLAINTEXT_CONTEXT_TTL_MS = 30_000;
const DEFAULT_COMMAND_PLAINTEXT_MAX_BYTES = 256 * 1024;
export function issueCommandPlaintextExecutionContext(
  session: PluginHostRpcSession,
  entry: PluginUiRegistryEntry,
  plaintextContext: PluginUiPlaintextCommandContext | undefined,
): PluginUiPlaintextCommandHandle | undefined {
  const contribution = entry.contribution;
  if (contribution.surface !== "command" || contribution.plaintext_request === "none") {
    return undefined;
  }

  if (contribution.document_query) return issueWorkspaceDocumentQueryContext(session, contribution);

  if (!contribution.plaintext_request) return undefined;

  if (contribution.plaintext_request === "selection") {
    assertCommandPlaintextPermission(session, "editor:selection:read");
    const selection = plaintextContext?.selection?.(session) ?? null;
    if (!selection) {
      throw new PluginHostRpcError(
        "ui_plaintext_context_unavailable",
        "selection context is unavailable for this command",
      );
    }
    return selection;
  }

  if (contribution.plaintext_request === "editor_context") {
    assertCommandPlaintextPermission(session, "editor:context:read");
    const editorContext = plaintextContext?.editorContext?.(session) ?? null;
    if (!editorContext) {
      throw new PluginHostRpcError(
        "ui_plaintext_context_unavailable",
        "editor context is unavailable for this command",
      );
    }
    return editorContext;
  }

  if (contribution.plaintext_request !== "active_document") {
    throw new PluginHostRpcError(
      "ui_plaintext_context_unavailable",
      "Host plaintext context is unavailable for this command",
    );
  }

  const activeDocument = plaintextContext?.activeDocument() ?? null;
  if (!activeDocument) {
    throw new PluginHostRpcError(
      "ui_plaintext_context_unavailable",
      "active document context is unavailable for this command",
    );
  }

  const executionContext = session.issueExecutionContext({
    kind: "user_command",
    hostInvocation: { kind: "command", userGesture: true },
    resource: { document_id: activeDocument.documentId },
    plaintextScope: {
      kind: "active_document",
      maxBytes: activeDocument.maxBytes ?? DEFAULT_COMMAND_PLAINTEXT_MAX_BYTES,
    },
    allowedOperations: ["plaintext.read"],
    expiresAtMs: Date.now() + COMMAND_PLAINTEXT_CONTEXT_TTL_MS,
    singleUse: true,
  });
  return { executionContextId: executionContext.execution_context_id };
}

function issueWorkspaceDocumentQueryContext(
  session: PluginHostRpcSession,
  contribution: PluginUiCommandContribution,
): PluginUiPlaintextCommandHandle {
  const query = contribution.document_query;
  if (!query) {
    throw new PluginHostRpcError(
      "ui_plaintext_context_unavailable",
      "workspace document query context is unavailable for this command",
    );
  }

  assertCommandPlaintextPermission(session, "document:read:workspace");
  const executionContext = session.issueExecutionContext({
    kind: "user_command",
    hostInvocation: { kind: "command", userGesture: true },
    resource: {
      max_documents: query.max_documents,
      max_bytes: query.max_bytes,
    },
    plaintextScope: { kind: "workspace", maxBytes: query.max_bytes },
    allowedOperations: ["plaintext.read"],
    expiresAtMs: Date.now() + COMMAND_PLAINTEXT_CONTEXT_TTL_MS,
    singleUse: true,
  });
  return { executionContextId: executionContext.execution_context_id };
}

function assertCommandPlaintextPermission(
  session: PluginHostRpcSession,
  permission: PluginPermission,
): void {
  if (session.permissions.has(permission)) return;
  throw new PluginHostRpcError(
    "permission_denied",
    "command plaintext request requires a matching permission",
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
