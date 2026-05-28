import {
  PluginHostRpcError,
  type PluginHostRpcContext,
  type PluginHostRpcHandlerRequest,
} from "../host-rpc/host-rpc";
import {
  PLUGIN_DOCUMENT_WRITE_MAX_BYTES,
  PLUGIN_DOCUMENT_WRITE_RATE_MAX_REQUESTS,
  PLUGIN_DOCUMENT_WRITE_RATE_WINDOW_MS,
  type PluginHostRpcOperationPolicy,
} from "../capability/capability-enforcement";
import type { PluginRuntimePathHandler } from "../runtime-path/runtime-path";
import type { PluginHostDocumentEditor, PluginHostWorkspaceAdapter } from "./workspace-adapter";

const DEFAULT_DOCUMENT_RPC_OPERATIONS = new Set([
  "documents.getActiveDocument",
  "documents.getSelectedDocuments",
  "documents.queryWorkspaceDocuments",
  "editor.setValue",
  "editor.replaceSelection",
]);

export function mergeDefaultRuntimeHandlers(
  handlers: readonly PluginRuntimePathHandler[],
  workspace: PluginHostWorkspaceAdapter,
): PluginRuntimePathHandler[] {
  const supplied = new Set(handlers.map((handler) => handler.operation));
  return [
    ...createDefaultDocumentRuntimeHandlers(workspace).filter(
      (handler) => !supplied.has(handler.operation),
    ),
    ...handlers,
  ];
}

function createDefaultDocumentRuntimeHandlers(
  workspace: PluginHostWorkspaceAdapter,
): PluginRuntimePathHandler[] {
  return [
    {
      operation: "documents.getActiveDocument",
      policy: activeDocumentPolicy(),
      async handler(_context: PluginHostRpcContext, request: PluginHostRpcHandlerRequest) {
        const resource = resourceRef(request);
        const active = workspace.activeDocument();
        if (active && active.id === resource.document_id) {
          return {
            document_id: active.id,
            title: active.title,
            plaintext: active.editor.getValue(),
          };
        }

        const documentId = typeof resource.document_id === "string" ? resource.document_id : null;
        if (!documentId) throw new Error("active_document_unavailable");
        const document = await workspace.getDocumentById(documentId);
        if (!document) throw new Error("active_document_unavailable");
        try {
          return {
            document_id: document.id,
            title: document.title,
            plaintext: document.text,
          };
        } finally {
          document.release();
        }
      },
    },
    {
      operation: "documents.getSelectedDocuments",
      policy: selectedDocumentsPolicy(),
      async handler(_context: PluginHostRpcContext, request: PluginHostRpcHandlerRequest) {
        const documentIds = resourceRef(request).selected_document_ids ?? [];
        return { documents: await readDocuments(workspace, documentIds) };
      },
    },
    {
      operation: "documents.queryWorkspaceDocuments",
      policy: workspaceDocumentsPolicy(),
      async handler(_context: PluginHostRpcContext, request: PluginHostRpcHandlerRequest) {
        const resource = resourceRef(request);
        const resourceLimit = requiredDocumentLimit(resource.max_documents);
        const limit = Math.min(positiveLimit(request.payload, resourceLimit), resourceLimit);
        const maxBytes = requiredByteLimit(resource.max_bytes);
        const documentIds = workspace
          .documentList()
          .filter((document) => document.docType === "document" && !document.archivedAt)
          .slice(0, limit)
          .map((document) => document.id);
        return { documents: await readDocuments(workspace, documentIds, maxBytes) };
      },
    },
    {
      operation: "editor.setValue",
      policy: documentWritePolicy(),
      handler(_context: PluginHostRpcContext, request: PluginHostRpcHandlerRequest) {
        const documentId = documentWriteDocumentId(request);
        const payload = documentWritePayload(request.payload);
        rejectDocumentWriteMetadataPayload(payload);
        const value = requiredDocumentWriteString(payload.value, "value");
        const editor = editorForDocumentWrite(workspace, documentId);
        requireDocumentSetValue(editor)(value);
        workspace.notifyDocumentChange(documentId, editor);
        return { applied: true, document_id: documentId };
      },
    },
    {
      operation: "editor.replaceSelection",
      policy: documentWritePolicy(),
      handler(_context: PluginHostRpcContext, request: PluginHostRpcHandlerRequest) {
        const documentId = documentWriteDocumentId(request);
        const payload = documentWritePayload(request.payload);
        rejectDocumentWriteMetadataPayload(payload);
        const text = requiredDocumentWriteString(payload.text, "text");
        const editor = editorForDocumentWrite(workspace, documentId);
        requireDocumentReplaceSelection(editor)(text);
        workspace.notifyDocumentChange(documentId, editor);
        return { applied: true, document_id: documentId };
      },
    },
  ].filter((handler) => DEFAULT_DOCUMENT_RPC_OPERATIONS.has(handler.operation));
}

interface DocumentRpcResourceRef {
  document_id?: string | null;
  selected_document_ids?: readonly string[];
  max_documents?: number;
  max_bytes?: number;
}

function resourceRef(request: PluginHostRpcHandlerRequest): DocumentRpcResourceRef {
  if (!request.resource || typeof request.resource !== "object") return {};
  return request.resource as DocumentRpcResourceRef;
}

async function readDocuments(
  workspace: PluginHostWorkspaceAdapter,
  documentIds: readonly string[],
  maxBytes?: number,
) {
  const documents = [];
  let remainingBytes = maxBytes;
  for (const documentId of documentIds) {
    if (remainingBytes !== undefined && remainingBytes <= 0) break;
    const document = await workspace.getDocumentById(documentId);
    if (!document) continue;
    try {
      const payload = {
        document_id: document.id,
        title: document.title,
        plaintext: document.text,
      };
      const payloadBytes = documentPayloadBytes(payload);
      if (remainingBytes !== undefined && payloadBytes > remainingBytes) break;
      documents.push(payload);
      if (remainingBytes !== undefined) remainingBytes -= payloadBytes;
    } finally {
      document.release();
    }
  }
  return documents;
}

function requiredDocumentLimit(value: unknown): number {
  if (!Number.isSafeInteger(value) || Number(value) <= 0 || Number(value) > 500) {
    throw new PluginHostRpcError(
      "invalid_document_limit",
      "workspace document query requires a positive bounded document limit",
    );
  }
  return Number(value);
}

function requiredByteLimit(value: unknown): number {
  if (!Number.isSafeInteger(value) || Number(value) <= 0) {
    throw new PluginHostRpcError(
      "invalid_plaintext_byte_limit",
      "workspace document query requires a positive byte limit",
    );
  }
  return Number(value);
}

function documentPayloadBytes(payload: {
  document_id: string;
  title: string;
  plaintext: string;
}): number {
  return utf8Bytes(payload.document_id) + utf8Bytes(payload.title) + utf8Bytes(payload.plaintext);
}

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function positiveLimit(payload: unknown, fallback: number): number {
  if (
    payload &&
    typeof payload === "object" &&
    "limit" in payload &&
    Number.isSafeInteger(payload.limit) &&
    Number(payload.limit) > 0
  ) {
    return Math.min(Number(payload.limit), fallback);
  }
  return fallback;
}

function activeDocumentPolicy(): PluginHostRpcOperationPolicy {
  return {
    requiredPermissions: ["document:read:active"],
    documentAccess: "active_document",
    plaintext: {
      operation: "plaintext.read",
      requiredPermission: "document:read:active",
      allowedContextKinds: ["user_command", "ui_action", "ui_text_refresh", "typed_action"],
      allowedPlaintextScopes: ["active_document"],
      audit: "required",
    },
  };
}

function selectedDocumentsPolicy(): PluginHostRpcOperationPolicy {
  return {
    requiredPermissions: ["document:read:selected"],
    documentAccess: "selected_documents",
    plaintext: {
      operation: "plaintext.read",
      requiredPermission: "document:read:selected",
      allowedContextKinds: ["user_command", "ui_action", "typed_action"],
      allowedPlaintextScopes: ["selected_documents"],
      audit: "required",
    },
  };
}

function workspaceDocumentsPolicy(): PluginHostRpcOperationPolicy {
  return {
    requiredPermissions: ["document:read:workspace"],
    documentAccess: "workspace_documents",
    plaintext: {
      operation: "plaintext.read",
      requiredPermission: "document:read:workspace",
      allowedContextKinds: ["user_command"],
      allowedPlaintextScopes: ["workspace"],
      audit: "required",
    },
  };
}

function documentWritePolicy(): PluginHostRpcOperationPolicy {
  return {
    requiredPermissions: ["document:write"],
    documentAccess: "allowed_document",
    plaintext: null,
    documentWrite: {
      operation: "document.write",
      sink: "encrypted_document_body",
      maxBytes: PLUGIN_DOCUMENT_WRITE_MAX_BYTES,
      rateLimit: {
        windowMs: PLUGIN_DOCUMENT_WRITE_RATE_WINDOW_MS,
        maxRequests: PLUGIN_DOCUMENT_WRITE_RATE_MAX_REQUESTS,
      },
      highRiskConsent: "required",
    },
  };
}

function documentWriteDocumentId(request: PluginHostRpcHandlerRequest): string {
  const resourceDocumentId = resourceRef(request).document_id;
  if (!resourceDocumentId) {
    throw new PluginHostRpcError(
      "document_write_resource_required",
      "document write requires a document resource",
    );
  }

  const payload = documentWritePayload(request.payload);
  if (payload.document_id !== undefined && payload.document_id !== resourceDocumentId) {
    throw new PluginHostRpcError(
      "document_write_resource_mismatch",
      "document write payload must match the scoped resource",
    );
  }

  return resourceDocumentId;
}

function editorForDocumentWrite(workspace: PluginHostWorkspaceAdapter, documentId: string) {
  const active = workspace.activeDocument();
  if (!active || active.id !== documentId) {
    throw new PluginHostRpcError(
      "document_write_target_unavailable",
      "document write target is not open in the active editor",
    );
  }

  return active.editor;
}

function requireDocumentSetValue(editor: PluginHostDocumentEditor) {
  if (typeof editor.setValue !== "function") {
    throw new PluginHostRpcError(
      "document_write_target_unavailable",
      "document write target cannot replace the document body",
    );
  }
  return editor.setValue.bind(editor);
}

function requireDocumentReplaceSelection(editor: PluginHostDocumentEditor) {
  if (typeof editor.replaceSelection !== "function") {
    throw new PluginHostRpcError(
      "document_write_target_unavailable",
      "document write target cannot replace the current selection",
    );
  }
  return editor.replaceSelection.bind(editor);
}

function documentWritePayload(payload: unknown): Record<string, unknown> {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new PluginHostRpcError(
      "document_write_payload_invalid",
      "document write payload must be an object",
    );
  }

  return payload as Record<string, unknown>;
}

function requiredDocumentWriteString(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new PluginHostRpcError(
      `document_write_${field}_required`,
      "document write payload field must be a string",
    );
  }
  return value;
}

function rejectDocumentWriteMetadataPayload(payload: Record<string, unknown>): void {
  const forbidden = [
    "title",
    "folder_id",
    "parent_id",
    "workspace_metadata",
    "share_metadata",
    "publication_metadata",
    "link_text",
    "application_config",
  ];
  if (forbidden.some((field) => field in payload)) {
    throw new PluginHostRpcError(
      "server_visible_metadata_sink_forbidden",
      "third-party plugin document writes must target encrypted document body only",
    );
  }
}
