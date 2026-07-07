import { describe, expect, it, vi } from "vite-plus/test";
import type { PluginAuditEvent } from "../capability/capability-enforcement";
import {
  PLUGIN_HOST_RPC_PROTOCOL,
  PLUGIN_HOST_RPC_VERSION,
  PluginHostMessageRouter,
  type PluginHostFrameWindow,
  type PluginHostRpcHandlerOwnerDescriptor,
  type PluginHostRpcRequestEnvelope,
} from "../host-rpc/host-rpc";
import {
  createPluginEditorContributionRegistry,
  createPluginEditorHandle,
  createPluginEditorPlaintextStore,
  issuePluginEditorPlaintext,
  pluginEditorDecorationsWithinContext,
  pluginEditorDecorationSourceId,
  pluginEditorDiagnosticsWithinContext,
  pluginEditorSuggestionsWithinContext,
  pluginEditorTextEditsWithinContext,
  registerPluginHostEditorHandlers,
  validatePluginDecorationResult,
  validatePluginDiagnosticsResult,
  validatePluginFormatterResult,
  validatePluginSuggestionResult,
} from "../editor/host-editor";

class FakeFrameWindow implements PluginHostFrameWindow {
  readonly messages: { message: unknown; targetOrigin: string; transfer: Transferable[] }[] = [];

  postMessage(message: unknown, targetOrigin: string, transfer: Transferable[] = []): void {
    this.messages.push({ message, targetOrigin, transfer });
  }
}

function createIdFactory(): () => string {
  let nextId = 0;
  return () => `editor-test-id-${++nextId}`;
}

function assertMessagePort(port: MessagePort | undefined): asserts port is MessagePort {
  expect(port).toBeInstanceOf(MessagePort);
}

function acknowledgeBoot(session: { bootNonce: string; frameGeneration: number }): void {
  void (
    session as unknown as {
      handlePortMessage(message: unknown): Promise<void>;
    }
  ).handlePortMessage({
    protocol: PLUGIN_HOST_RPC_PROTOCOL,
    version: PLUGIN_HOST_RPC_VERSION,
    kind: "boot-ack",
    boot_nonce: session.bootNonce,
    frame_generation: session.frameGeneration,
  });
}

function owner(): PluginHostRpcHandlerOwnerDescriptor {
  return {
    pluginId: "plugin.example",
    packageId: "package.example",
    applicationId: "00000000-0000-4000-8000-000000000011",
    activationId: "activation.example",
    ownerScopeKind: "workspace",
    workspaceId: "00000000-0000-4000-8000-000000000012",
    userId: "user.example",
    deviceId: "device.example",
    bundleHash: "bundle-hash-1",
    manifestHash: "manifest-hash-1",
    frameGeneration: 7,
    consentEpoch: 3,
    capabilityGrantId: "capability-grant-1",
  };
}

function createRouterWithEditor(
  store = createPluginEditorPlaintextStore(),
  formatterInput: "selection" | "context" = "selection",
): {
  router: PluginHostMessageRouter;
  store: ReturnType<typeof createPluginEditorPlaintextStore>;
} {
  const router = new PluginHostMessageRouter({
    windowTarget: { addEventListener() {}, removeEventListener() {} },
    idFactory: createIdFactory(),
  });
  registerPluginHostEditorHandlers(router, {
    plaintextStore: store,
    formatterInput,
  });
  return { router, store };
}

function createOwnerRouterWithEditor(): {
  router: PluginHostMessageRouter;
  registry: ReturnType<typeof createPluginEditorContributionRegistry>;
  auditEvents: PluginAuditEvent[];
} {
  const router = new PluginHostMessageRouter({
    windowTarget: { addEventListener() {}, removeEventListener() {} },
    idFactory: createIdFactory(),
  });
  const registry = createPluginEditorContributionRegistry();
  const auditEvents: PluginAuditEvent[] = [];
  registerPluginHostEditorHandlers(
    router,
    {
      plaintextStore: createPluginEditorPlaintextStore(),
      contributionRegistry: registry,
      auditSink(event) {
        auditEvents.push(event);
        return true;
      },
    },
    owner(),
  );
  return { router, registry, auditEvents };
}

function createOwnerRouterWithEditorAudit(auditSink: (event: PluginAuditEvent) => boolean): {
  router: PluginHostMessageRouter;
  registry: ReturnType<typeof createPluginEditorContributionRegistry>;
} {
  const router = new PluginHostMessageRouter({
    windowTarget: { addEventListener() {}, removeEventListener() {} },
    idFactory: createIdFactory(),
  });
  const registry = createPluginEditorContributionRegistry();
  registerPluginHostEditorHandlers(
    router,
    {
      plaintextStore: createPluginEditorPlaintextStore(),
      contributionRegistry: registry,
      auditSink,
    },
    owner(),
  );
  return { router, registry };
}

function boot(
  router: PluginHostMessageRouter,
  auditEvents: PluginAuditEvent[] = [],
  permissions: Parameters<PluginHostMessageRouter["createSession"]>[0]["permissions"] = [
    "editor:selection:read",
    "editor:context:read",
  ],
) {
  const frame = new FakeFrameWindow();
  const session = router.createSession({
    pluginId: "plugin.example",
    packageId: "package.example",
    applicationId: "00000000-0000-4000-8000-000000000011",
    activationId: "activation.example",
    ownerScopeKind: "workspace",
    workspaceId: "00000000-0000-4000-8000-000000000012",
    userId: "user.example",
    deviceId: "device.example",
    bundleHash: "bundle-hash-1",
    manifestHash: "manifest-hash-1",
    capabilityId: "capability-1",
    capabilityGrantId: "capability-grant-1",
    consentEpoch: 3,
    frameGeneration: 7,
    contentWindow: frame,
    permissions,
    documentScope: { allowedDocumentIds: ["document-1"] },
    validateSession: () => null,
    auditSink(event) {
      auditEvents.push(event);
      return true;
    },
  });

  router.handleWindowMessage({
    data: {
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "boot-ready",
    },
    source: frame,
  } as unknown as MessageEvent);

  const port = frame.messages[0]?.transfer[0] as MessagePort | undefined;
  assertMessagePort(port);
  port.start();
  acknowledgeBoot(session);
  return { session, port };
}

function requestEnvelope(
  overrides: Partial<PluginHostRpcRequestEnvelope> = {},
): PluginHostRpcRequestEnvelope {
  return {
    protocol: PLUGIN_HOST_RPC_PROTOCOL,
    version: PLUGIN_HOST_RPC_VERSION,
    kind: "request",
    request_id: "editor-request",
    request_nonce: `editor-nonce-${Math.random()}`,
    plugin_id: "plugin.example",
    package_id: "package.example",
    application_id: "00000000-0000-4000-8000-000000000011",
    activation_id: "activation.example",
    workspace_id: "00000000-0000-4000-8000-000000000012",
    bundle_hash: "bundle-hash-1",
    manifest_hash: "manifest-hash-1",
    capability_id: "capability-1",
    capability_grant_id: "capability-grant-1",
    consent_epoch: 3,
    frame_generation: 7,
    operation: "editor.getSelection",
    ...overrides,
    owner_scope_kind: overrides.owner_scope_kind ?? "workspace",
    user_id: overrides.user_id ?? "user.example",
    device_id: overrides.device_id ?? "device.example",
  };
}

function waitForPortMessage(port: MessagePort): Promise<unknown> {
  return new Promise((resolve) => {
    const listener = (event: MessageEvent) => {
      if (isBootContextMessage(event.data)) return;
      port.removeEventListener("message", listener as EventListener);
      resolve(event.data);
    };
    port.addEventListener("message", listener as EventListener);
    port.start();
  });
}

function isBootContextMessage(value: unknown): boolean {
  return (
    typeof value === "object" && value !== null && "kind" in value && value.kind === "boot-context"
  );
}

describe("plugin Host RPC editor surface", () => {
  it("registers and unregisters owner-scoped editor contributions through Host RPC", async () => {
    const { router, registry, auditEvents } = createOwnerRouterWithEditor();
    const { port } = boot(router, [], ["ui:editor"]);

    port.postMessage(
      requestEnvelope({
        request_id: "editor-contribution-register",
        request_nonce: "editor-contribution-register-nonce",
        operation: "editor.contribution.register",
        payload: {
          kind: "formatter",
          id: "format.selection",
          title: "Format selection",
          input: "selection",
        },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      request_id: "editor-contribution-register",
      payload: { id: "format.selection" },
    });
    expect(registry.list()).toEqual([
      { kind: "formatter", id: "format.selection", title: "Format selection", input: "selection" },
    ]);
    expect(auditEvents.at(-1)).toMatchObject({
      type: "plugin.ui.registration.accepted",
      operation: "editor.contribution.register",
      result: "allow",
      payloadKind: "ui.contribution",
      correlation: { authority_event_ref: "format.selection" },
    });

    port.postMessage(
      requestEnvelope({
        request_id: "editor-contribution-unregister",
        request_nonce: "editor-contribution-unregister-nonce",
        operation: "editor.contribution.unregister",
        payload: { id: "format.selection" },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      request_id: "editor-contribution-unregister",
      payload: { removed: true },
    });
    expect(registry.list()).toEqual([]);
    expect(auditEvents.at(-1)).toMatchObject({
      type: "plugin.ui.registration.accepted",
      operation: "editor.contribution.unregister",
      result: "allow",
      payloadKind: "ui.contribution",
      correlation: { authority_event_ref: "format.selection" },
    });
  });

  it("rolls back editor contribution registration when audit fails", async () => {
    const { router, registry } = createOwnerRouterWithEditorAudit(() => false);
    const { port } = boot(router, [], ["ui:editor"]);

    port.postMessage(
      requestEnvelope({
        request_id: "editor-contribution-audit-failed",
        request_nonce: "editor-contribution-audit-failed-nonce",
        operation: "editor.contribution.register",
        payload: {
          kind: "formatter",
          id: "format.selection",
          title: "Format selection",
          input: "selection",
        },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      request_id: "editor-contribution-audit-failed",
      error: { code: "editor_contribution_audit_failed" },
    });
    expect(registry.list()).toEqual([]);
  });

  it("rolls back editor contribution registration without accepted audit when the session closes", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginEditorContributionRegistry();
    const auditEvents: PluginAuditEvent[] = [];
    const { session, port } = boot(router, [], ["ui:editor"]);
    const unsubscribe = registry.subscribe(() => {
      unsubscribe();
      session.close("editor_registration_owner_closed");
    });
    registerPluginHostEditorHandlers(
      router,
      {
        plaintextStore: createPluginEditorPlaintextStore(),
        contributionRegistry: registry,
        auditSink(event) {
          auditEvents.push(event);
          return true;
        },
      },
      owner(),
      session,
    );

    port.postMessage(
      requestEnvelope({
        request_id: "editor-contribution-session-closed",
        request_nonce: "editor-contribution-session-closed-nonce",
        operation: "editor.contribution.register",
        payload: {
          kind: "formatter",
          id: "format.selection",
          title: "Format selection",
          input: "selection",
        },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "host-lifecycle",
      lifecycle: "close",
      reason: "editor_registration_owner_closed",
    });
    expect(registry.list()).toEqual([]);
    expect(auditEvents.map((event) => event.type)).not.toContain("plugin.ui.registration.accepted");
    expect(auditEvents.map((event) => event.type)).not.toContain("plugin.ui.registration.rejected");
  });

  it("fails closed when editor contribution audit is unavailable", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginEditorContributionRegistry();
    registerPluginHostEditorHandlers(
      router,
      { plaintextStore: createPluginEditorPlaintextStore(), contributionRegistry: registry },
      owner(),
    );
    const { port } = boot(router, [], ["ui:editor"]);

    port.postMessage(
      requestEnvelope({
        request_id: "editor-contribution-audit-missing",
        request_nonce: "editor-contribution-audit-missing-nonce",
        operation: "editor.contribution.register",
        payload: {
          kind: "formatter",
          id: "format.selection",
          title: "Format selection",
          input: "selection",
        },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      request_id: "editor-contribution-audit-missing",
      error: { code: "editor_contribution_audit_failed" },
    });
    expect(registry.list()).toEqual([]);
  });

  it("rejects editor contribution payloads carrying host editor objects", async () => {
    const { router, registry, auditEvents } = createOwnerRouterWithEditor();
    const { port } = boot(router, [], ["ui:editor"]);

    port.postMessage(
      requestEnvelope({
        request_id: "editor-contribution-forbidden",
        request_nonce: "editor-contribution-forbidden-nonce",
        operation: "editor.contribution.register",
        payload: {
          kind: "diagnostics",
          id: "lint.document",
          title: "Lint document",
          input: "editor_context",
          view: {},
        },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      request_id: "editor-contribution-forbidden",
      error: { code: "editor_contribution_forbidden" },
    });
    expect(registry.list()).toEqual([]);
    expect(auditEvents.at(-1)).toMatchObject({
      type: "plugin.ui.registration.rejected",
      operation: "editor.contribution.register",
      reasonCode: "editor_contribution_forbidden",
      result: "deny",
    });
  });

  it("requires editor contribution inputs before registration", async () => {
    const { router, registry } = createOwnerRouterWithEditor();
    const { port } = boot(router, [], ["ui:editor"]);

    const invalidContributions = [
      {
        request_id: "formatter-missing-input",
        payload: { kind: "formatter", id: "format.missing", title: "Format missing" },
      },
      {
        request_id: "formatter-invalid-input",
        payload: {
          kind: "formatter",
          id: "format.invalid",
          title: "Format invalid",
          input: "context",
        },
      },
      {
        request_id: "diagnostics-missing-input",
        payload: { kind: "diagnostics", id: "lint.missing", title: "Lint missing" },
      },
      {
        request_id: "suggestion-missing-input",
        payload: { kind: "suggestion", id: "suggest.missing", title: "Suggest missing" },
      },
      {
        request_id: "reserved-plugin-prefix",
        payload: {
          kind: "diagnostics",
          id: "plugin:diagnostics",
          title: "Reserved prefix",
          input: "editor_context",
        },
      },
      {
        request_id: "reserved-builtin-prefix",
        payload: {
          kind: "diagnostics",
          id: "builtin:diagnostics",
          title: "Reserved prefix",
          input: "editor_context",
        },
      },
    ];

    for (const contribution of invalidContributions) {
      port.postMessage(
        requestEnvelope({
          request_id: contribution.request_id,
          request_nonce: `${contribution.request_id}-nonce`,
          operation: "editor.contribution.register",
          payload: contribution.payload,
        }),
      );

      await expect(waitForPortMessage(port)).resolves.toMatchObject({
        kind: "error",
        request_id: contribution.request_id,
        error: { code: "editor_contribution_invalid" },
      });
    }

    expect(registry.list()).toEqual([]);
  });

  it("rejects reserved editor contribution ids during unregister", async () => {
    const { router, registry } = createOwnerRouterWithEditor();
    const { port } = boot(router, [], ["ui:editor"]);

    for (const id of ["plugin:diagnostics", "builtin:diagnostics"]) {
      port.postMessage(
        requestEnvelope({
          request_id: `unregister-${id}`,
          request_nonce: `unregister-${id}-nonce`,
          operation: "editor.contribution.unregister",
          payload: { id },
        }),
      );

      await expect(waitForPortMessage(port)).resolves.toMatchObject({
        kind: "error",
        request_id: `unregister-${id}`,
        error: { code: "editor_contribution_invalid" },
      });
    }

    expect(registry.list()).toEqual([]);
  });

  it("requires bounded declarative schema for editor decoration contributions", async () => {
    const { router, registry } = createOwnerRouterWithEditor();
    const { port } = boot(router, [], ["ui:editor"]);

    port.postMessage(
      requestEnvelope({
        request_id: "editor-decoration-register",
        request_nonce: "editor-decoration-register-nonce",
        operation: "editor.contribution.register",
        payload: {
          kind: "decoration",
          id: "mark.visible",
          title: "Mark visible range",
          input: "editor_context",
          trigger: "visible_context",
          max_decorations: 24,
        },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      request_id: "editor-decoration-register",
      payload: { id: "mark.visible" },
    });
    expect(registry.list()).toEqual([
      {
        kind: "decoration",
        id: "mark.visible",
        title: "Mark visible range",
        input: "editor_context",
        trigger: "visible_context",
        max_decorations: 24,
      },
    ]);
  });

  it("delivers selection plaintext through an opaque editor handle", async () => {
    const auditEvents: PluginAuditEvent[] = [];
    const { router, store } = createRouterWithEditor();
    const { session, port } = boot(router, auditEvents);
    const editor = createPluginEditorHandle("editor-1", "document-1");
    const input = issuePluginEditorPlaintext({
      session,
      store,
      editor,
      plaintextKind: "selection",
      invocationKind: "formatter",
      hostInvocation: { kind: "formatter", userGesture: true },
      range: { anchor: 3, head: 12 },
      plaintext: "selected text",
      maxBytes: 128,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "editor-selection",
        request_nonce: "editor-selection-nonce",
        execution_context_id: input.executionContextId,
        resource: {
          document_id: "document-1",
          editor_id: "editor-1",
          selection_range: { anchor: 3, head: 12 },
          max_bytes: 128,
        },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      request_id: "editor-selection",
      payload: {
        document_id: "document-1",
        editor_id: "editor-1",
        range: { anchor: 3, head: 12 },
        plaintext: "selected text",
        editor: {
          protocol: "refmd.plugin-editor-handle",
          editor_id: "editor-1",
        },
      },
    });
    expect(auditEvents.at(-1)).toMatchObject({
      type: "plugin.plaintext_payload.delivered",
      operation: "editor.getSelection",
      contextKind: "formatter",
      plaintextScopeKind: "selection",
    });
  });

  it("rejects selection plaintext without the selection capability", async () => {
    const { router, store } = createRouterWithEditor();
    const { session, port } = boot(router, [], ["editor:context:read"]);
    const editor = createPluginEditorHandle("editor-1", "document-1");
    const input = issuePluginEditorPlaintext({
      session,
      store,
      editor,
      plaintextKind: "selection",
      invocationKind: "formatter",
      hostInvocation: { kind: "formatter", userGesture: true },
      range: { anchor: 0, head: 5 },
      plaintext: "hello",
      maxBytes: 128,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "editor-selection-denied",
        request_nonce: "editor-selection-denied-nonce",
        execution_context_id: input.executionContextId,
        resource: {
          document_id: "document-1",
          editor_id: "editor-1",
          selection_range: { anchor: 0, head: 5 },
          max_bytes: 128,
        },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      request_id: "editor-selection-denied",
      error: { code: "permission_denied" },
    });
  });

  it("delivers bounded suggestion context without exposing editor internals", async () => {
    const auditEvents: PluginAuditEvent[] = [];
    const { router, store } = createRouterWithEditor();
    const { session, port } = boot(router, auditEvents);
    const editor = createPluginEditorHandle("editor-1", "document-1");
    const input = issuePluginEditorPlaintext({
      session,
      store,
      editor,
      plaintextKind: "context",
      invocationKind: "editor_suggestion",
      hostInvocation: { kind: "editor_suggestion_provider", userGesture: false },
      range: { anchor: 0, head: 40 },
      plaintext: "nearby editor context",
      maxBytes: 256,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "suggestion-context",
        request_nonce: "suggestion-context-nonce",
        operation: "suggestion.getContext",
        execution_context_id: input.executionContextId,
        resource: {
          document_id: "document-1",
          editor_id: "editor-1",
          context_range: { anchor: 0, head: 40 },
          max_bytes: 256,
        },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      request_id: "suggestion-context",
      payload: {
        document_id: "document-1",
        editor_id: "editor-1",
        plaintext: "nearby editor context",
      },
    });
    expect(auditEvents.at(-1)).toMatchObject({
      operation: "suggestion.getContext",
      contextKind: "editor_suggestion",
      plaintextScopeKind: "editor_context",
    });
  });

  it("delivers bounded decoration context without exposing editor internals", async () => {
    const auditEvents: PluginAuditEvent[] = [];
    const { router, store } = createRouterWithEditor();
    const { session, port } = boot(router, auditEvents);
    const editor = createPluginEditorHandle("editor-1", "document-1");
    const input = issuePluginEditorPlaintext({
      session,
      store,
      editor,
      plaintextKind: "context",
      invocationKind: "editor_decoration",
      hostInvocation: { kind: "editor_decoration_provider", userGesture: false },
      range: { anchor: 4, head: 32 },
      plaintext: "visible editor context",
      maxBytes: 256,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "decoration-context",
        request_nonce: "decoration-context-nonce",
        operation: "decoration.getContext",
        execution_context_id: input.executionContextId,
        resource: {
          document_id: "document-1",
          editor_id: "editor-1",
          context_range: { anchor: 4, head: 32 },
          max_bytes: 256,
        },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      request_id: "decoration-context",
      payload: {
        document_id: "document-1",
        editor_id: "editor-1",
        plaintext: "visible editor context",
      },
    });
    expect(auditEvents.at(-1)).toMatchObject({
      operation: "decoration.getContext",
      contextKind: "editor_decoration",
      plaintextScopeKind: "editor_context",
    });
  });

  it("delivers empty editor context once", async () => {
    const auditEvents: PluginAuditEvent[] = [];
    const { router, store } = createRouterWithEditor();
    const { session, port } = boot(router, auditEvents);
    const editor = createPluginEditorHandle("editor-1", "document-1");
    const input = issuePluginEditorPlaintext({
      session,
      store,
      editor,
      plaintextKind: "context",
      invocationKind: "editor_decoration",
      hostInvocation: { kind: "editor_decoration_provider", userGesture: false },
      range: { anchor: 0, head: 0 },
      plaintext: "",
      maxBytes: 256,
    });

    const contextRequest = {
      operation: "decoration.getContext",
      execution_context_id: input.executionContextId,
      resource: {
        document_id: "document-1",
        editor_id: "editor-1",
        context_range: { anchor: 0, head: 0 },
        max_bytes: 256,
      },
    } satisfies Partial<PluginHostRpcRequestEnvelope>;

    port.postMessage(
      requestEnvelope({
        request_id: "empty-decoration-context",
        request_nonce: "empty-decoration-context-nonce",
        ...contextRequest,
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      request_id: "empty-decoration-context",
      payload: {
        document_id: "document-1",
        editor_id: "editor-1",
        plaintext: "",
      },
    });
    expect(auditEvents.at(-1)).toMatchObject({
      operation: "decoration.getContext",
      contextKind: "editor_decoration",
      plaintextScopeKind: "editor_context",
    });

    port.postMessage(
      requestEnvelope({
        request_id: "empty-decoration-context-again",
        request_nonce: "empty-decoration-context-again-nonce",
        ...contextRequest,
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      request_id: "empty-decoration-context-again",
      error: { code: "execution_context_consumed" },
    });
  });

  it("rejects editor contributions that carry host editor objects", () => {
    const registry = createPluginEditorContributionRegistry();
    const owner = {
      pluginId: "plugin.example",
      packageId: "package.example",
      workspaceId: "workspace-1",
      applicationId: "application-1",
      activationId: "activation.example",
      ownerScopeKind: "workspace",
      userId: "user.example",
      deviceId: "device.example",
      bundleHash: "bundle-hash-1",
      manifestHash: "manifest-hash-1",
      frameGeneration: 1,
      consentEpoch: 1,
      capabilityGrantId: "grant-1",
    };

    expect(() =>
      registry.register(owner, {
        kind: "diagnostics",
        id: "lint.markdown",
        title: "Markdown lint",
        input: "editor_context",
        extension: {},
      } as never),
    ).toThrowError(
      expect.objectContaining({
        code: "editor_contribution_forbidden",
      }),
    );
  });

  it("exposes owner-scoped contributions with their active runtime session", () => {
    const registry = createPluginEditorContributionRegistry();
    const owner = {
      pluginId: "plugin.example",
      packageId: "package.example",
      workspaceId: "workspace-1",
      applicationId: "application-1",
      activationId: "activation.example",
      ownerScopeKind: "workspace",
      userId: "user.example",
      deviceId: "device.example",
      bundleHash: "bundle-hash-1",
      manifestHash: "manifest-hash-1",
      frameGeneration: 1,
      consentEpoch: 1,
      capabilityGrantId: "grant-1",
    };
    const listener = vi.fn();
    const unsubscribe = registry.subscribe(listener);
    const unregister = registry.register(owner, {
      kind: "formatter",
      id: "format.selection",
      title: "Format selection",
      input: "selection",
    });
    const releaseSession = registry.retainOwnerSession(owner, {
      sessionId: "session-1",
    } as never);

    expect(registry.listEntries()).toMatchObject([
      {
        owner,
        descriptor: {
          kind: "formatter",
          id: "format.selection",
          title: "Format selection",
          input: "selection",
        },
        session: { sessionId: "session-1" },
      },
    ]);
    expect(listener).toHaveBeenCalled();

    releaseSession();
    expect(registry.listEntries()[0]?.session).toBeNull();
    unregister();
    unsubscribe();
  });

  it("emits decoration cleanup sources when an owner session is released", () => {
    const registry = createPluginEditorContributionRegistry();
    const entryOwner = owner();
    const descriptor = {
      kind: "decoration" as const,
      id: "visible.context",
      title: "Visible context",
      input: "editor_context" as const,
      trigger: "visible_context" as const,
      max_decorations: 10,
    };
    registry.register(entryOwner, descriptor);
    const releaseSession = registry.retainOwnerSession(entryOwner, {
      sessionId: "session-1",
    } as never);
    const cleanup = vi.fn();
    const unsubscribe = registry.subscribeDecorationCleanup(cleanup);

    releaseSession();

    expect(cleanup).toHaveBeenCalledWith([
      pluginEditorDecorationSourceId({ owner: entryOwner, descriptor }),
    ]);
    expect(registry.listEntries()[0]?.session).toBeNull();
    unsubscribe();
  });

  it("keys decoration source ids by full owner identity", () => {
    const firstOwner = owner();
    const descriptor = {
      kind: "decoration" as const,
      id: "visible.context",
      title: "Visible context",
      input: "editor_context" as const,
      trigger: "visible_context" as const,
      max_decorations: 10,
    };
    const samePartialOwner = {
      ...firstOwner,
      activationId: "activation.other",
      userId: "user.other",
      deviceId: "device.other",
      capabilityGrantId: "grant-other",
    };

    expect(pluginEditorDecorationSourceId({ owner: firstOwner, descriptor })).not.toBe(
      pluginEditorDecorationSourceId({ owner: samePartialOwner, descriptor }),
    );
  });

  it("emits decoration cleanup sources when owner entries are removed", () => {
    const registry = createPluginEditorContributionRegistry();
    const entryOwner = owner();
    const descriptor = {
      kind: "decoration" as const,
      id: "visible.context",
      title: "Visible context",
      input: "editor_context" as const,
      trigger: "visible_context" as const,
      max_decorations: 10,
    };
    const cleanup = vi.fn();
    const unsubscribeCleanup = registry.subscribeDecorationCleanup(cleanup);
    const unregister = registry.register(entryOwner, descriptor);

    unregister();

    expect(cleanup).toHaveBeenCalledWith([
      pluginEditorDecorationSourceId({ owner: entryOwner, descriptor }),
    ]);

    cleanup.mockClear();
    registry.register(entryOwner, descriptor);
    registry.clearOwner(entryOwner);

    expect(cleanup).toHaveBeenCalledWith([
      pluginEditorDecorationSourceId({ owner: entryOwner, descriptor }),
    ]);
    expect(registry.listEntries()).toEqual([]);
    unsubscribeCleanup();
  });

  it("rolls back owner contributions when handler registration fails", () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginEditorContributionRegistry();
    const owner = {
      pluginId: "plugin.example",
      packageId: "package.example",
      workspaceId: "workspace-1",
      applicationId: "application-1",
      activationId: "activation.example",
      ownerScopeKind: "workspace",
      userId: "user.example",
      deviceId: "device.example",
      bundleHash: "bundle-hash-1",
      manifestHash: "manifest-hash-1",
      frameGeneration: 1,
      consentEpoch: 1,
      capabilityGrantId: "grant-1",
    };
    const unregisterFirst = registerPluginHostEditorHandlers(
      router,
      { plaintextStore: createPluginEditorPlaintextStore() },
      owner,
    );

    try {
      expect(() =>
        registerPluginHostEditorHandlers(
          router,
          {
            plaintextStore: createPluginEditorPlaintextStore(),
            contributionRegistry: registry,
            contributions: [
              { kind: "formatter", id: "format.selection", title: "Format", input: "selection" },
            ],
          },
          owner,
        ),
      ).toThrow("handler already registered");
      expect(registry.list()).toHaveLength(0);
    } finally {
      unregisterFirst();
    }
  });

  it("validates formatter, diagnostics, decoration, and suggestion result schemas", () => {
    expect(
      validatePluginFormatterResult({
        edits: [{ range: { from: 0, to: 4 }, text: "done" }],
      }),
    ).toEqual({ edits: [{ range: { from: 0, to: 4 }, text: "done" }] });
    expect(
      validatePluginDiagnosticsResult({
        diagnostics: [{ range: { from: 0, to: 4 }, severity: "warning", message: "Check heading" }],
      }),
    ).toEqual({
      diagnostics: [{ range: { from: 0, to: 4 }, severity: "warning", message: "Check heading" }],
    });
    expect(
      validatePluginSuggestionResult({
        suggestions: [{ id: "insert.heading", label: "Heading", insert_text: "# " }],
      }),
    ).toEqual({
      suggestions: [{ id: "insert.heading", label: "Heading", insert_text: "# " }],
    });
    expect(
      validatePluginDecorationResult({
        decorations: [
          {
            id: "mark.heading",
            range: { from: 0, to: 4 },
            style: "highlight",
            tone: "info",
          },
        ],
      }),
    ).toEqual({
      decorations: [
        {
          id: "mark.heading",
          range: { from: 0, to: 4 },
          style: "highlight",
          tone: "info",
        },
      ],
    });

    expect(() =>
      validatePluginFormatterResult({
        edits: [{ range: { from: 8, to: 2 }, text: "bad" }],
      }),
    ).toThrowError(expect.objectContaining({ code: "editor_range_invalid" }));
  });

  it("checks editor result ranges against the issued context", () => {
    const contextRange = { anchor: 2, head: 8 };

    expect(
      pluginEditorTextEditsWithinContext(
        [{ range: { from: 2, to: 8 }, text: "inside" }],
        contextRange,
      ),
    ).toBe(true);
    expect(
      pluginEditorTextEditsWithinContext(
        [{ range: { from: 1, to: 8 }, text: "outside" }],
        contextRange,
      ),
    ).toBe(false);

    expect(
      pluginEditorDiagnosticsWithinContext(
        [{ range: { from: 3, to: 7 }, severity: "warning", message: "inside" }],
        contextRange,
      ),
    ).toBe(true);
    expect(
      pluginEditorDiagnosticsWithinContext(
        [{ range: { from: 3, to: 9 }, severity: "warning", message: "outside" }],
        contextRange,
      ),
    ).toBe(false);

    expect(
      pluginEditorSuggestionsWithinContext(
        [
          { id: "insert", label: "Insert", insert_text: "ok" },
          { id: "replace", label: "Replace", insert_text: "ok", range: { from: 2, to: 4 } },
        ],
        contextRange,
      ),
    ).toBe(true);
    expect(
      pluginEditorSuggestionsWithinContext(
        [{ id: "replace", label: "Replace", insert_text: "bad", range: { from: 0, to: 4 } }],
        contextRange,
      ),
    ).toBe(false);

    expect(
      pluginEditorDecorationsWithinContext(
        [{ id: "mark", range: { from: 2, to: 8 }, style: "highlight", tone: "info" }],
        contextRange,
      ),
    ).toBe(true);
    expect(
      pluginEditorDecorationsWithinContext(
        [{ id: "mark", range: { from: 2, to: 10 }, style: "highlight", tone: "info" }],
        contextRange,
      ),
    ).toBe(false);
  });
});
