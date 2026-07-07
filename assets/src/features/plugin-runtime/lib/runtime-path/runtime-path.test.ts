import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";
import type {
  PluginAuditEvent,
  PluginHostRpcOperationPolicy,
} from "../capability/capability-enforcement";
import {
  PLUGIN_HOST_RPC_PROTOCOL,
  PLUGIN_HOST_RPC_VERSION,
  PluginHostMessageRouter,
  type PluginHostFrameWindow,
  type PluginHostRpcRequestEnvelope,
  type PluginHostRpcSession,
} from "../host-rpc/host-rpc";
import {
  createPluginEditorContributionRegistry,
  createPluginEditorHandle,
  createPluginEditorPlaintextStore,
  issuePluginEditorPlaintext,
} from "../editor/host-editor";
import {
  createPluginRendererSourceStore,
  issuePluginRendererSource,
} from "../renderer/host-renderer";
import {
  createPluginUiContributionRegistry,
  pluginContributionId,
} from "../../model/host-ui/host-ui";
import { createPluginRuntimePath, type PluginRuntimePath } from "./runtime-path";

const TEST_PLUGIN_ID = "refmd.test.plugin";
const TEST_PACKAGE_ID = "00000000-0000-4000-8000-000000000100";
const TEST_APPLICATION_ID = "00000000-0000-4000-8000-000000000101";
const TEST_ACTIVATION_ID = "00000000-0000-4000-8000-000000000103";
const TEST_OWNER_SCOPE_KIND = "workspace";
const TEST_WORKSPACE_ID = "00000000-0000-4000-8000-000000000102";
const TEST_USER_ID = "00000000-0000-4000-8000-000000000104";
const TEST_DEVICE_ID = "00000000-0000-4000-8000-000000000105";
const TEST_BUNDLE_HASH = "test-plugin-bundle-hash";
const TEST_MANIFEST_HASH = "test-plugin-manifest-hash";
const TEST_CAPABILITY_ID = "test-plugin-capability";
const TEST_CAPABILITY_GRANT_ID = "test-plugin-capability-grant";
const TEST_ACTIVE_DOCUMENT_ID = "test-plugin-document";

const PING_OPERATION = "test.plugin.ping";
const ACTIVE_DOCUMENT_OPERATION = "test.plugin.getActiveDocument";
const activeDocumentPolicy: PluginHostRpcOperationPolicy = {
  requiredPermissions: ["document:read:active"],
  documentAccess: "active_document",
  plaintext: {
    operation: "plaintext.read",
    requiredPermission: "document:read:active",
    allowedContextKinds: ["user_command", "ui_action", "typed_action"],
    allowedPlaintextScopes: ["active_document"],
    audit: "required",
  },
};

class FakeFrameWindow implements PluginHostFrameWindow {
  readonly messages: { message: unknown; targetOrigin: string; transfer: Transferable[] }[] = [];

  postMessage(message: unknown, targetOrigin: string, transfer: Transferable[] = []): void {
    this.messages.push({ message, targetOrigin, transfer });
  }
}

function installSandboxDocumentLoadDispatch(): () => void {
  const originalSetAttributeDescriptor = Object.getOwnPropertyDescriptor(
    Element.prototype,
    "setAttribute",
  );
  const iframeSetAttributeDescriptor = Object.getOwnPropertyDescriptor(
    HTMLIFrameElement.prototype,
    "setAttribute",
  );
  if (
    !originalSetAttributeDescriptor ||
    typeof originalSetAttributeDescriptor.value !== "function"
  ) {
    throw new Error("HTMLIFrameElement.setAttribute unavailable");
  }

  HTMLIFrameElement.prototype.setAttribute = function patchedSetAttribute(name, value) {
    const result = originalSetAttributeDescriptor.value.call(this, name, value) as void;
    if (name === "src" && String(value).startsWith("/api/plugin-runtime/sandbox-documents/")) {
      queueMicrotask(() => this.dispatchEvent(new Event("load")));
    }
    return result;
  };

  return () => {
    if (iframeSetAttributeDescriptor) {
      Object.defineProperty(
        HTMLIFrameElement.prototype,
        "setAttribute",
        iframeSetAttributeDescriptor,
      );
    } else {
      Reflect.deleteProperty(HTMLIFrameElement.prototype, "setAttribute");
    }
  };
}

interface RuntimePathHandlers {
  issueActiveDocumentContext(session: PluginHostRpcSession, expiresAtMs: number): string;
}

interface TestRuntimePath {
  path: PluginRuntimePath;
  handlers: RuntimePathHandlers;
  auditEvents: PluginAuditEvent[];
}

describe("plugin runtime path", () => {
  let restoreSandboxDocumentLoadDispatch: (() => void) | null = null;

  beforeEach(() => {
    restoreSandboxDocumentLoadDispatch = installSandboxDocumentLoadDispatch();
  });

  afterEach(() => {
    restoreSandboxDocumentLoadDispatch?.();
    restoreSandboxDocumentLoadDispatch = null;
  });

  it("creates a sandbox runtime wired to operation policies", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const container = document.createElement("div");
    document.body.append(container);

    const path = await createTestRuntimePath({
      container,
      router,
      capabilityGrantId: TEST_CAPABILITY_GRANT_ID,
    });

    expect(container.contains(path.path.runtime.iframe)).toBe(true);
    expect(path.path.runtime.iframe.getAttribute("sandbox")).toBe("allow-scripts");
    expect(path.path.runtime.iframe.hasAttribute("srcdoc")).toBe(false);
    expect(path.path.runtime.iframe.getAttribute("src")).toBe(
      "/api/plugin-runtime/sandbox-documents/test-runtime-path",
    );
    expect(path.path.runtime.session.pluginId).toBe(TEST_PLUGIN_ID);
    expect(() => {
      router.registerOwnerHandler(
        {
          pluginId: TEST_PLUGIN_ID,
          packageId: TEST_PACKAGE_ID,
          workspaceId: TEST_WORKSPACE_ID,
          applicationId: TEST_APPLICATION_ID,
          activationId: TEST_ACTIVATION_ID,
          ownerScopeKind: TEST_OWNER_SCOPE_KIND,
          userId: TEST_USER_ID,
          deviceId: TEST_DEVICE_ID,
          bundleHash: TEST_BUNDLE_HASH,
          manifestHash: TEST_MANIFEST_HASH,
          frameGeneration: 1,
          consentEpoch: 1,
          capabilityGrantId: TEST_CAPABILITY_GRANT_ID,
        },
        PING_OPERATION,
        () => ({ ok: true }),
        { plaintext: null },
      );
    }).toThrow("handler already registered");

    path.path.destroy("test_destroy");
    expect(container.contains(path.path.runtime.iframe)).toBe(false);
    const unregisterPing = router.registerOwnerHandler(
      {
        pluginId: TEST_PLUGIN_ID,
        packageId: TEST_PACKAGE_ID,
        workspaceId: TEST_WORKSPACE_ID,
        applicationId: TEST_APPLICATION_ID,
        activationId: TEST_ACTIVATION_ID,
        ownerScopeKind: TEST_OWNER_SCOPE_KIND,
        userId: TEST_USER_ID,
        deviceId: TEST_DEVICE_ID,
        bundleHash: TEST_BUNDLE_HASH,
        manifestHash: TEST_MANIFEST_HASH,
        frameGeneration: 1,
        consentEpoch: 1,
        capabilityGrantId: TEST_CAPABILITY_GRANT_ID,
      },
      PING_OPERATION,
      () => ({ ok: true }),
      { plaintext: null },
    );
    unregisterPing();
    container.remove();
  });

  it("registers owner-scoped handlers before sandbox document load begins", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const registerOwnerHandlerSpy = vi.spyOn(router, "registerOwnerHandler");
    const container = document.createElement("div");
    document.body.append(container);

    const inheritedSetAttributeDescriptor = Object.getOwnPropertyDescriptor(
      Element.prototype,
      "setAttribute",
    );
    const iframeSetAttributeDescriptor = Object.getOwnPropertyDescriptor(
      HTMLIFrameElement.prototype,
      "setAttribute",
    );
    const previousSetAttributeDescriptor =
      iframeSetAttributeDescriptor ?? inheritedSetAttributeDescriptor;
    if (
      !previousSetAttributeDescriptor ||
      typeof previousSetAttributeDescriptor.value !== "function"
    ) {
      throw new Error("HTMLIFrameElement.setAttribute unavailable");
    }
    const ownerHandlersAtSrcSet: number[] = [];
    HTMLIFrameElement.prototype.setAttribute = function patchedSetAttribute(name, value) {
      if (name === "src" && String(value).startsWith("/api/plugin-runtime/sandbox-documents/")) {
        ownerHandlersAtSrcSet.push(registerOwnerHandlerSpy.mock.calls.length);
      }
      return previousSetAttributeDescriptor.value.call(this, name, value) as void;
    };

    try {
      const path = await createTestRuntimePath({
        container,
        router,
        capabilityGrantId: TEST_CAPABILITY_GRANT_ID,
      });

      expect(ownerHandlersAtSrcSet).toEqual([2]);
      path.path.destroy("test_destroy");
    } finally {
      if (iframeSetAttributeDescriptor) {
        Object.defineProperty(
          HTMLIFrameElement.prototype,
          "setAttribute",
          iframeSetAttributeDescriptor,
        );
      } else {
        Reflect.deleteProperty(HTMLIFrameElement.prototype, "setAttribute");
      }
      container.remove();
    }
  });

  it("allows separate runtime owners to register the same operations", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const firstContainer = document.createElement("div");
    const secondContainer = document.createElement("div");
    document.body.append(firstContainer, secondContainer);

    const firstPath = await createTestRuntimePath({
      container: firstContainer,
      router,
      capabilityGrantId: TEST_CAPABILITY_GRANT_ID,
    });
    const secondPath = await createTestRuntimePath({
      container: secondContainer,
      router,
      applicationId: "00000000-0000-4000-8000-000000000202",
      activationId: "activation.example",
      capabilityGrantId: "test-plugin-capability-grant-2",
    });

    expect(firstContainer.contains(firstPath.path.runtime.iframe)).toBe(true);
    expect(secondContainer.contains(secondPath.path.runtime.iframe)).toBe(true);

    secondPath.path.destroy("test_destroy");
    firstPath.path.destroy("test_destroy");
    firstContainer.remove();
    secondContainer.remove();
  });

  it("unregisters earlier handlers when runtime path handler registration fails", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const container = document.createElement("div");
    document.body.append(container);

    await expect(
      createPluginRuntimePath({
        container,
        router,
        handlers: [
          {
            operation: PING_OPERATION,
            handler: () => ({ ok: true }),
            policy: { plaintext: null },
          },
          {
            operation: PING_OPERATION,
            handler: () => ({ ok: false }),
            policy: { plaintext: null },
          },
        ],
        pluginId: TEST_PLUGIN_ID,
        packageId: TEST_PACKAGE_ID,
        applicationId: TEST_APPLICATION_ID,
        activationId: TEST_ACTIVATION_ID,
        ownerScopeKind: TEST_OWNER_SCOPE_KIND,
        userId: TEST_USER_ID,
        deviceId: TEST_DEVICE_ID,
        workspaceId: TEST_WORKSPACE_ID,
        bundleHash: TEST_BUNDLE_HASH,
        manifestHash: TEST_MANIFEST_HASH,
        capabilityId: TEST_CAPABILITY_ID,
        capabilityGrantId: TEST_CAPABILITY_GRANT_ID,
        consentEpoch: 1,
        validateSession: () => null,
        auditSink: () => true,
        frameGeneration: 1,
        bootNonce: "runtime-path-duplicate-handler-boot",
        sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/duplicate-handler",
        title: "Plugin Runtime Path Test",
      }),
    ).rejects.toThrow("handler already registered");

    expect(container.childElementCount).toBe(0);
    const unregisterPing = router.registerHandler(PING_OPERATION, () => ({ ok: true }), {
      plaintext: null,
    });
    unregisterPing();
    container.remove();
  });

  it("exercises non-plaintext and plaintext RPC through Host policy enforcement", async () => {
    const frame = new FakeFrameWindow();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const auditEvents: PluginAuditEvent[] = [];
    const handlers = createRuntimePathHandlers();
    const unregisterHandlers = registerRuntimePathHandlers(router);
    const session = router.createSession({
      pluginId: TEST_PLUGIN_ID,
      packageId: TEST_PACKAGE_ID,
      applicationId: TEST_APPLICATION_ID,
      activationId: TEST_ACTIVATION_ID,
      ownerScopeKind: TEST_OWNER_SCOPE_KIND,
      userId: TEST_USER_ID,
      deviceId: TEST_DEVICE_ID,
      workspaceId: TEST_WORKSPACE_ID,
      bundleHash: TEST_BUNDLE_HASH,
      manifestHash: TEST_MANIFEST_HASH,
      capabilityId: TEST_CAPABILITY_ID,
      capabilityGrantId: TEST_CAPABILITY_GRANT_ID,
      consentEpoch: 1,
      frameGeneration: 1,
      contentWindow: frame,
      permissions: ["document:read:active"],
      documentScope: { activeDocumentId: TEST_ACTIVE_DOCUMENT_ID },
      auditSink(event) {
        auditEvents.push(event);
        return true;
      },
    });
    const port = boot(router, frame, session);

    port.postMessage(requestEnvelope({ operation: PING_OPERATION }));
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "response",
      payload: { ok: true },
    });

    port.postMessage(
      requestEnvelope({
        request_id: "missing-context",
        request_nonce: "missing-context-nonce",
        operation: ACTIVE_DOCUMENT_OPERATION,
        resource: { document_id: TEST_ACTIVE_DOCUMENT_ID },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      request_id: "missing-context",
      error: { code: "execution_context_required" },
    });

    const executionContextId = handlers.issueActiveDocumentContext(session, Date.now() + 60_000);
    port.postMessage(
      requestEnvelope({
        request_id: "plaintext-ok",
        request_nonce: "plaintext-ok-nonce",
        operation: ACTIVE_DOCUMENT_OPERATION,
        execution_context_id: executionContextId,
        resource: { document_id: TEST_ACTIVE_DOCUMENT_ID },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "response",
      request_id: "plaintext-ok",
      payload: {
        documentId: TEST_ACTIVE_DOCUMENT_ID,
        plaintext: "test plugin plaintext",
      },
    });
    expect(auditEvents).toHaveLength(2);
    expect(auditEvents[0]).toMatchObject({
      protocol: "refmd.security-audit-event",
      event_id: expect.any(String),
      class: "security_runtime",
      type: "plugin.plaintext_payload.denied",
      requestId: "missing-context",
      plaintextScopeKind: "active_document",
      reasonCode: "execution_context_required",
      resource: {
        kind: "plugin",
        id: TEST_PLUGIN_ID,
        version_hash: TEST_BUNDLE_HASH,
      },
      created_at: expect.any(String),
    });
    expect(auditEvents[1]).toMatchObject({
      protocol: "refmd.security-audit-event",
      event_id: expect.any(String),
      class: "security_runtime",
      type: "plugin.plaintext_payload.delivered",
      requestId: "plaintext-ok",
      executionContextId,
      contextKind: "user_command",
      plaintextScopeKind: "active_document",
      action: {
        result: "allowed",
      },
      correlation: {
        request_id: "plaintext-ok",
        execution_context_id: executionContextId,
      },
      created_at: expect.any(String),
    });

    unregisterHandlers();
    session.close("test_done");
  });

  it("connects renderer source handlers at the runtime owner boundary", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const container = document.createElement("div");
    document.body.append(container);
    const sourceStore = createPluginRendererSourceStore();
    const path = await createPluginRuntimePath({
      container,
      router,
      handlers: [],
      rendererServices: {
        slots: [{ kind: "block", type: "mermaid" }],
        sourceStore,
      },
      pluginId: TEST_PLUGIN_ID,
      packageId: TEST_PACKAGE_ID,
      applicationId: TEST_APPLICATION_ID,
      activationId: TEST_ACTIVATION_ID,
      ownerScopeKind: TEST_OWNER_SCOPE_KIND,
      userId: TEST_USER_ID,
      deviceId: TEST_DEVICE_ID,
      workspaceId: TEST_WORKSPACE_ID,
      bundleHash: TEST_BUNDLE_HASH,
      manifestHash: TEST_MANIFEST_HASH,
      capabilityId: TEST_CAPABILITY_ID,
      capabilityGrantId: TEST_CAPABILITY_GRANT_ID,
      consentEpoch: 1,
      validateSession: () => null,
      frameGeneration: 1,
      bootNonce: "runtime-path-renderer-boot",
      sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/renderer-runtime",
      title: "Plugin Renderer Runtime Path Test",
      permissions: ["plaintext:render:block:mermaid"],
      documentScope: { allowedDocumentIds: [TEST_ACTIVE_DOCUMENT_ID] },
      auditSink: () => true,
    });

    const postMessageSpy = vi.spyOn(path.runtime.session.contentWindow, "postMessage");

    router.handleWindowMessage({
      data: {
        protocol: PLUGIN_HOST_RPC_PROTOCOL,
        version: PLUGIN_HOST_RPC_VERSION,
        kind: "boot-ready",
      },
      source: path.runtime.session.contentWindow,
    } as unknown as MessageEvent);
    const postMessageCalls = postMessageSpy.mock.calls as unknown as [
      unknown,
      string,
      Transferable[],
    ][];
    const port = postMessageCalls[0]?.[2]?.[0] as MessagePort | undefined;
    assertMessagePort(port);
    port.start();
    acknowledgeBoot(path.runtime.session);

    const source = issuePluginRendererSource({
      session: path.runtime.session,
      store: sourceStore,
      slot: { kind: "block", type: "mermaid" },
      documentId: TEST_ACTIVE_DOCUMENT_ID,
      blockId: "block-1",
      source: "graph TD; A-->B",
      maxBytes: 512,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "runtime-renderer-source",
        request_nonce: "runtime-renderer-source-nonce",
        operation: "renderer.getSource",
        execution_context_id: source.executionContextId,
        resource: { document_id: TEST_ACTIVE_DOCUMENT_ID, block_id: "block-1", max_bytes: 512 },
      }),
    );

    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "response",
      request_id: "runtime-renderer-source",
      payload: {
        kind: "block",
        type: "mermaid",
        source: "graph TD; A-->B",
      },
    });

    path.destroy("test_destroy");
    container.remove();
  });

  it("connects editor plaintext handlers at the runtime owner boundary", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const container = document.createElement("div");
    document.body.append(container);
    const plaintextStore = createPluginEditorPlaintextStore();
    const contributionRegistry = createPluginEditorContributionRegistry();
    const path = await createPluginRuntimePath({
      container,
      router,
      handlers: [],
      editorServices: {
        plaintextStore,
        formatterInput: "selection",
        contributionRegistry,
        contributions: [
          { kind: "command", id: "editor.insert-date", title: "Insert date" },
          { kind: "editor_command", id: "editor.wrap-selection", title: "Wrap selection" },
          {
            kind: "decoration",
            id: "editor.mark-important",
            title: "Mark important",
            input: "editor_context",
            trigger: "visible_context",
            max_decorations: 24,
          },
          {
            kind: "diagnostics",
            id: "editor.lint",
            title: "Lint editor",
            input: "editor_context",
          },
          {
            kind: "suggestion",
            id: "editor.suggest-link",
            title: "Suggest link",
            input: "editor_context",
          },
          {
            kind: "formatter",
            id: "editor.format-selection",
            title: "Format selection",
            input: "selection",
          },
        ],
      },
      pluginId: TEST_PLUGIN_ID,
      packageId: TEST_PACKAGE_ID,
      applicationId: TEST_APPLICATION_ID,
      activationId: TEST_ACTIVATION_ID,
      ownerScopeKind: TEST_OWNER_SCOPE_KIND,
      userId: TEST_USER_ID,
      deviceId: TEST_DEVICE_ID,
      workspaceId: TEST_WORKSPACE_ID,
      bundleHash: TEST_BUNDLE_HASH,
      manifestHash: TEST_MANIFEST_HASH,
      capabilityId: TEST_CAPABILITY_ID,
      capabilityGrantId: TEST_CAPABILITY_GRANT_ID,
      consentEpoch: 1,
      validateSession: () => null,
      frameGeneration: 1,
      bootNonce: "runtime-path-editor-boot",
      sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/editor-runtime",
      title: "Plugin Editor Runtime Path Test",
      permissions: ["editor:selection:read"],
      documentScope: { allowedDocumentIds: [TEST_ACTIVE_DOCUMENT_ID] },
      auditSink: () => true,
    });
    expect(contributionRegistry.list()).toHaveLength(6);

    const postMessageSpy = vi.spyOn(path.runtime.session.contentWindow, "postMessage");

    router.handleWindowMessage({
      data: {
        protocol: PLUGIN_HOST_RPC_PROTOCOL,
        version: PLUGIN_HOST_RPC_VERSION,
        kind: "boot-ready",
      },
      source: path.runtime.session.contentWindow,
    } as unknown as MessageEvent);
    const postMessageCalls = postMessageSpy.mock.calls as unknown as [
      unknown,
      string,
      Transferable[],
    ][];
    const port = postMessageCalls[0]?.[2]?.[0] as MessagePort | undefined;
    assertMessagePort(port);
    port.start();
    acknowledgeBoot(path.runtime.session);

    const editor = createPluginEditorHandle("editor-1", TEST_ACTIVE_DOCUMENT_ID);
    const input = issuePluginEditorPlaintext({
      session: path.runtime.session,
      store: plaintextStore,
      editor,
      plaintextKind: "selection",
      invocationKind: "formatter",
      hostInvocation: { kind: "formatter", userGesture: true },
      range: { anchor: 0, head: 8 },
      plaintext: "selected",
      maxBytes: 128,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "runtime-editor-selection",
        request_nonce: "runtime-editor-selection-nonce",
        operation: "editor.getSelection",
        execution_context_id: input.executionContextId,
        resource: {
          document_id: TEST_ACTIVE_DOCUMENT_ID,
          editor_id: "editor-1",
          selection_range: { anchor: 0, head: 8 },
          max_bytes: 128,
        },
      }),
    );

    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "response",
      request_id: "runtime-editor-selection",
      payload: {
        document_id: TEST_ACTIVE_DOCUMENT_ID,
        editor_id: "editor-1",
        plaintext: "selected",
      },
    });

    path.destroy("test_destroy");
    expect(contributionRegistry.list()).toHaveLength(0);
    container.remove();
  });

  it("connects UI contribution handlers at the runtime owner boundary", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const container = document.createElement("div");
    document.body.append(container);
    const registry = createPluginUiContributionRegistry();
    const path = await createPluginRuntimePath({
      container,
      router,
      handlers: [],
      uiServices: {
        registry,
        commandSurface: {
          add() {},
          remove() {},
        },
      },
      pluginId: TEST_PLUGIN_ID,
      packageId: TEST_PACKAGE_ID,
      applicationId: TEST_APPLICATION_ID,
      activationId: TEST_ACTIVATION_ID,
      ownerScopeKind: TEST_OWNER_SCOPE_KIND,
      userId: TEST_USER_ID,
      deviceId: TEST_DEVICE_ID,
      workspaceId: TEST_WORKSPACE_ID,
      bundleHash: TEST_BUNDLE_HASH,
      manifestHash: TEST_MANIFEST_HASH,
      capabilityId: TEST_CAPABILITY_ID,
      capabilityGrantId: TEST_CAPABILITY_GRANT_ID,
      consentEpoch: 1,
      validateSession: () => null,
      frameGeneration: 1,
      bootNonce: "runtime-path-ui-boot",
      sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/ui-runtime",
      title: "Plugin UI Runtime Path Test",
      permissions: ["ui:command"],
      auditSink: () => true,
    });

    const postMessageSpy = vi.spyOn(path.runtime.session.contentWindow, "postMessage");

    router.handleWindowMessage({
      data: {
        protocol: PLUGIN_HOST_RPC_PROTOCOL,
        version: PLUGIN_HOST_RPC_VERSION,
        kind: "boot-ready",
      },
      source: path.runtime.session.contentWindow,
    } as unknown as MessageEvent);
    const postMessageCalls = postMessageSpy.mock.calls as unknown as [
      unknown,
      string,
      Transferable[],
    ][];
    const port = postMessageCalls[0]?.[2]?.[0] as MessagePort | undefined;
    assertMessagePort(port);
    port.start();
    acknowledgeBoot(path.runtime.session);

    port.postMessage(
      requestEnvelope({
        request_id: "runtime-ui-command",
        request_nonce: "runtime-ui-command-nonce",
        operation: "ui.command.register",
        payload: {
          surface: "command",
          local_id: "open.panel",
          title: "Open panel",
        },
      }),
    );

    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "response",
      request_id: "runtime-ui-command",
      payload: {
        id: pluginContributionId(
          {
            pluginId: TEST_PLUGIN_ID,
            packageId: TEST_PACKAGE_ID,
            applicationId: TEST_APPLICATION_ID,
            activationId: TEST_ACTIVATION_ID,
            ownerScopeKind: TEST_OWNER_SCOPE_KIND,
            userId: TEST_USER_ID,
            deviceId: TEST_DEVICE_ID,
            workspaceId: TEST_WORKSPACE_ID,
            bundleHash: TEST_BUNDLE_HASH,
            manifestHash: TEST_MANIFEST_HASH,
            frameGeneration: 1,
            consentEpoch: 1,
            capabilityGrantId: TEST_CAPABILITY_GRANT_ID,
          },
          "open.panel",
        ),
      },
    });
    expect(registry.list()).toHaveLength(1);

    router.closeByWorkspace(TEST_WORKSPACE_ID, "workspace_left");
    expect(registry.list()).toHaveLength(0);
    expect(container.contains(path.runtime.iframe)).toBe(false);

    path.destroy("test_destroy");
    expect(registry.list()).toHaveLength(0);
    container.remove();
  });

  it("does not connect global UI contribution handlers for secondary frames", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const container = document.createElement("div");
    document.body.append(container);
    const registry = createPluginUiContributionRegistry();
    const path = await createPluginRuntimePath({
      container,
      router,
      handlers: [],
      uiServices: {
        registry,
        commandSurface: {
          add() {
            throw new Error("secondary UI registration must not reach command surface");
          },
          remove() {},
        },
      },
      pluginId: TEST_PLUGIN_ID,
      packageId: TEST_PACKAGE_ID,
      applicationId: TEST_APPLICATION_ID,
      activationId: TEST_ACTIVATION_ID,
      ownerScopeKind: TEST_OWNER_SCOPE_KIND,
      userId: TEST_USER_ID,
      deviceId: TEST_DEVICE_ID,
      workspaceId: TEST_WORKSPACE_ID,
      bundleHash: TEST_BUNDLE_HASH,
      manifestHash: TEST_MANIFEST_HASH,
      capabilityId: TEST_CAPABILITY_ID,
      capabilityGrantId: TEST_CAPABILITY_GRANT_ID,
      consentEpoch: 1,
      validateSession: () => null,
      frameGeneration: 2,
      bootNonce: "runtime-path-secondary-ui-boot",
      sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/secondary-ui-runtime",
      frameScope: "secondary",
      title: "Plugin Secondary UI Runtime Path Test",
      permissions: ["ui:command"],
      auditSink: () => true,
    });

    const postMessageSpy = vi.spyOn(path.runtime.session.contentWindow, "postMessage");

    router.handleWindowMessage({
      data: {
        protocol: PLUGIN_HOST_RPC_PROTOCOL,
        version: PLUGIN_HOST_RPC_VERSION,
        kind: "boot-ready",
      },
      source: path.runtime.session.contentWindow,
    } as unknown as MessageEvent);
    const postMessageCalls = postMessageSpy.mock.calls as unknown as [
      unknown,
      string,
      Transferable[],
    ][];
    const port = postMessageCalls[0]?.[2]?.[0] as MessagePort | undefined;
    assertMessagePort(port);
    port.start();
    acknowledgeBoot(path.runtime.session);

    port.postMessage(
      requestEnvelope({
        request_id: "secondary-runtime-ui-command",
        request_nonce: "secondary-runtime-ui-command-nonce",
        frame_generation: 2,
        operation: "ui.command.register",
        payload: {
          surface: "command",
          local_id: "open.panel",
          title: "Open panel",
        },
      }),
    );

    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      request_id: "secondary-runtime-ui-command",
    });
    expect(registry.list()).toHaveLength(0);

    path.destroy("test_destroy");
    container.remove();
  });

  it("does not route secondary UI registrations to an active primary owner handler", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const primaryContainer = document.createElement("div");
    const secondaryContainer = document.createElement("div");
    document.body.append(primaryContainer, secondaryContainer);
    const registry = createPluginUiContributionRegistry();
    const commandIds: string[] = [];
    const uiServices = {
      registry,
      commandSurface: {
        add(command: { id: string }) {
          commandIds.push(command.id);
        },
        remove(id: string) {
          const index = commandIds.indexOf(id);
          if (index >= 0) commandIds.splice(index, 1);
        },
      },
    };

    const primaryPath = await createPluginRuntimePath({
      container: primaryContainer,
      router,
      handlers: [],
      uiServices,
      pluginId: TEST_PLUGIN_ID,
      packageId: TEST_PACKAGE_ID,
      applicationId: TEST_APPLICATION_ID,
      activationId: TEST_ACTIVATION_ID,
      ownerScopeKind: TEST_OWNER_SCOPE_KIND,
      userId: TEST_USER_ID,
      deviceId: TEST_DEVICE_ID,
      workspaceId: TEST_WORKSPACE_ID,
      bundleHash: TEST_BUNDLE_HASH,
      manifestHash: TEST_MANIFEST_HASH,
      capabilityId: TEST_CAPABILITY_ID,
      capabilityGrantId: TEST_CAPABILITY_GRANT_ID,
      consentEpoch: 1,
      validateSession: () => null,
      frameGeneration: 1,
      bootNonce: "runtime-path-primary-owner-ui-boot",
      sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/primary-owner-ui-runtime",
      title: "Plugin Primary UI Runtime Path Test",
      permissions: ["ui:command", "ui:menu_item"],
      auditSink: () => true,
    });
    const primaryPostMessageSpy = vi.spyOn(
      primaryPath.runtime.session.contentWindow,
      "postMessage",
    );
    router.handleWindowMessage({
      data: {
        protocol: PLUGIN_HOST_RPC_PROTOCOL,
        version: PLUGIN_HOST_RPC_VERSION,
        kind: "boot-ready",
      },
      source: primaryPath.runtime.session.contentWindow,
    } as unknown as MessageEvent);
    const primaryPostMessageCalls = primaryPostMessageSpy.mock.calls as unknown as [
      unknown,
      string,
      Transferable[],
    ][];
    const primaryPort = primaryPostMessageCalls[0]?.[2]?.[0] as MessagePort | undefined;
    assertMessagePort(primaryPort);
    primaryPort.start();
    acknowledgeBoot(primaryPath.runtime.session);

    primaryPort.postMessage(
      requestEnvelope({
        request_id: "primary-runtime-ui-command",
        request_nonce: "primary-runtime-ui-command-nonce",
        operation: "ui.command.register",
        payload: {
          surface: "command",
          local_id: "open.panel",
          title: "Open panel",
        },
      }),
    );

    expect(await waitForPortMessage(primaryPort)).toMatchObject({
      kind: "response",
      request_id: "primary-runtime-ui-command",
    });
    expect(registry.list()).toHaveLength(1);

    const secondaryPath = await createPluginRuntimePath({
      container: secondaryContainer,
      router,
      handlers: [],
      uiServices,
      pluginId: TEST_PLUGIN_ID,
      packageId: TEST_PACKAGE_ID,
      applicationId: TEST_APPLICATION_ID,
      activationId: TEST_ACTIVATION_ID,
      ownerScopeKind: TEST_OWNER_SCOPE_KIND,
      userId: TEST_USER_ID,
      deviceId: TEST_DEVICE_ID,
      workspaceId: TEST_WORKSPACE_ID,
      bundleHash: TEST_BUNDLE_HASH,
      manifestHash: TEST_MANIFEST_HASH,
      capabilityId: TEST_CAPABILITY_ID,
      capabilityGrantId: TEST_CAPABILITY_GRANT_ID,
      consentEpoch: 1,
      validateSession: () => null,
      frameGeneration: 2,
      bootNonce: "runtime-path-secondary-owner-ui-boot",
      sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/secondary-owner-ui-runtime",
      frameScope: "secondary",
      title: "Plugin Secondary UI Runtime Path Test",
      permissions: ["ui:command", "ui:menu_item"],
      auditSink: () => true,
    });
    const secondaryPostMessageSpy = vi.spyOn(
      secondaryPath.runtime.session.contentWindow,
      "postMessage",
    );
    router.handleWindowMessage({
      data: {
        protocol: PLUGIN_HOST_RPC_PROTOCOL,
        version: PLUGIN_HOST_RPC_VERSION,
        kind: "boot-ready",
      },
      source: secondaryPath.runtime.session.contentWindow,
    } as unknown as MessageEvent);
    const secondaryPostMessageCalls = secondaryPostMessageSpy.mock.calls as unknown as [
      unknown,
      string,
      Transferable[],
    ][];
    const secondaryPort = secondaryPostMessageCalls[0]?.[2]?.[0] as MessagePort | undefined;
    assertMessagePort(secondaryPort);
    secondaryPort.start();
    acknowledgeBoot(secondaryPath.runtime.session);

    secondaryPort.postMessage(
      requestEnvelope({
        request_id: "secondary-runtime-ui-menu-denied",
        request_nonce: "secondary-runtime-ui-menu-denied-nonce",
        frame_generation: 2,
        operation: "ui.menu.register_item",
        payload: {
          surface: "menu_item",
          local_id: "tab-action",
          placement: "document_tab_menu",
          title: "Tab action",
          command_ref: { kind: "local_command", local_id: "open.panel" },
        },
      }),
    );

    expect(await waitForPortMessage(secondaryPort)).toMatchObject({
      kind: "error",
      request_id: "secondary-runtime-ui-menu-denied",
      error: { code: "unknown_operation" },
    });
    expect(registry.list()).toHaveLength(1);

    secondaryPath.destroy("test_destroy");
    primaryPath.destroy("test_destroy");
    primaryContainer.remove();
    secondaryContainer.remove();
  });
});

function createRuntimePathHandlerEntries() {
  return [
    {
      operation: PING_OPERATION,
      handler: () => ({ ok: true }),
      policy: { plaintext: null },
    },
    {
      operation: ACTIVE_DOCUMENT_OPERATION,
      handler: () => ({
        documentId: TEST_ACTIVE_DOCUMENT_ID,
        plaintext: "test plugin plaintext",
      }),
      policy: activeDocumentPolicy,
    },
  ] as const;
}

function registerRuntimePathHandlers(router: PluginHostMessageRouter): () => void {
  const unregisterPing = router.registerHandler(PING_OPERATION, () => ({ ok: true }), {
    plaintext: null,
  });
  const unregisterPlaintext = router.registerHandler(
    ACTIVE_DOCUMENT_OPERATION,
    () => ({
      documentId: TEST_ACTIVE_DOCUMENT_ID,
      plaintext: "test plugin plaintext",
    }),
    activeDocumentPolicy,
  );

  return () => {
    unregisterPlaintext();
    unregisterPing();
  };
}

function createRuntimePathHandlers(): RuntimePathHandlers {
  return {
    issueActiveDocumentContext(session, expiresAtMs) {
      return session.issueExecutionContext({
        kind: "user_command",
        hostInvocation: { kind: "command", userGesture: true },
        resource: { document_id: TEST_ACTIVE_DOCUMENT_ID },
        plaintextScope: { kind: "active_document", maxBytes: 1024 },
        allowedOperations: ["plaintext.read"],
        expiresAtMs,
        singleUse: true,
      }).execution_context_id;
    },
  };
}

async function createTestRuntimePath(options: {
  container: HTMLElement;
  router: PluginHostMessageRouter;
  consentEpoch?: number;
  packageId?: string;
  applicationId?: string;
  activationId?: string;
  capabilityGrantId: string;
}): Promise<TestRuntimePath> {
  const auditEvents: PluginAuditEvent[] = [];
  const handlers = createRuntimePathHandlers();
  const path = await createPluginRuntimePath({
    container: options.container,
    router: options.router,
    handlers: createRuntimePathHandlerEntries(),
    pluginId: TEST_PLUGIN_ID,
    packageId: options.packageId ?? TEST_PACKAGE_ID,
    applicationId: options.applicationId ?? TEST_APPLICATION_ID,
    activationId: options.activationId ?? TEST_ACTIVATION_ID,
    ownerScopeKind: TEST_OWNER_SCOPE_KIND,
    workspaceId: TEST_WORKSPACE_ID,
    userId: TEST_USER_ID,
    deviceId: TEST_DEVICE_ID,
    bundleHash: TEST_BUNDLE_HASH,
    manifestHash: TEST_MANIFEST_HASH,
    capabilityId: TEST_CAPABILITY_ID,
    capabilityGrantId: options.capabilityGrantId,
    consentEpoch: options.consentEpoch ?? 1,
    validateSession: () => null,
    frameGeneration: 1,
    bootNonce: "runtime-path-boot-nonce",
    sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/test-runtime-path",
    title: "Plugin Runtime Path Test",
    permissions: ["document:read:active"],
    documentScope: { activeDocumentId: TEST_ACTIVE_DOCUMENT_ID },
    auditSink(event) {
      auditEvents.push(event);
      return true;
    },
  });

  return {
    path,
    handlers,
    auditEvents,
  };
}

function createIdFactory(): () => string {
  let nextId = 0;
  return () => `test-id-${++nextId}`;
}

function boot(
  router: PluginHostMessageRouter,
  frame: FakeFrameWindow,
  session: PluginHostRpcSession,
): MessagePort {
  const handled = router.handleWindowMessage({
    data: {
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "boot-ready",
    },
    source: frame,
  } as unknown as MessageEvent);

  expect(handled).toBe(true);
  const port = frame.messages[0]?.transfer[0] as MessagePort | undefined;
  assertMessagePort(port);
  port.start();
  acknowledgeBoot(session);
  return port;
}

function acknowledgeBoot(session: PluginHostRpcSession): void {
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

function assertMessagePort(port: MessagePort | undefined): asserts port is MessagePort {
  expect(port).toBeInstanceOf(MessagePort);
}

function requestEnvelope(
  overrides: Partial<PluginHostRpcRequestEnvelope> = {},
): PluginHostRpcRequestEnvelope {
  return {
    protocol: PLUGIN_HOST_RPC_PROTOCOL,
    version: PLUGIN_HOST_RPC_VERSION,
    kind: "request",
    request_id: "request-1",
    request_nonce: "nonce-1",
    plugin_id: TEST_PLUGIN_ID,
    package_id: TEST_PACKAGE_ID,
    application_id: TEST_APPLICATION_ID,
    activation_id: TEST_ACTIVATION_ID,
    workspace_id: TEST_WORKSPACE_ID,
    bundle_hash: TEST_BUNDLE_HASH,
    manifest_hash: TEST_MANIFEST_HASH,
    capability_id: TEST_CAPABILITY_ID,
    capability_grant_id: TEST_CAPABILITY_GRANT_ID,
    consent_epoch: 1,
    frame_generation: 1,
    operation: PING_OPERATION,
    ...overrides,
    owner_scope_kind: overrides.owner_scope_kind ?? TEST_OWNER_SCOPE_KIND,
    user_id: overrides.user_id ?? TEST_USER_ID,
    device_id: overrides.device_id ?? TEST_DEVICE_ID,
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
