import { createRoot, createSignal, type Setter } from "solid-js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { workspaceManager } from "@/features/panel";
import { runBeforeSessionCleanup } from "@/shared/lib/auth/session-cleanup";
import type {
  App,
  Command,
  WorkspaceSurfaceOwner,
  WorkspaceTileConfig,
} from "@/shared/lib/workspace/app";
import {
  beginPluginRuntimeWorkspaceRevocation,
  PLUGIN_HOST_RPC_PROTOCOL,
  PLUGIN_HOST_RPC_VERSION,
  releasePluginRuntimeWorkspaceRevocation,
  getPluginHostMessageRouter,
  type PluginHostMessageRouter,
  type PluginHostFrameWindow,
  type PluginHostRpcRequestEnvelope,
} from "@/features/plugin-runtime";
import { createDurablePluginRuntimeAuditSink, usePluginHostRpc } from "./use-plugin-host-rpc";
import type { PluginHostRuntimeController } from "@/features/plugin-runtime";
import hostRpcAdapterSource from "./use-plugin-host-rpc.ts?raw";

class FakeFrameWindow implements PluginHostFrameWindow {
  readonly messages: { message: unknown; targetOrigin: string; transfer: Transferable[] }[] = [];

  postMessage(message: unknown, targetOrigin: string, transfer: Transferable[] = []): void {
    this.messages.push({ message, targetOrigin, transfer });
  }
}

function installSandboxDocumentLoadDispatch(): () => void {
  const originalSetAttribute = HTMLIFrameElement.prototype.setAttribute;

  HTMLIFrameElement.prototype.setAttribute = function patchedSetAttribute(name, value) {
    const result = originalSetAttribute.call(this, name, value);
    if (name === "src" && String(value).startsWith("/api/plugin-runtime/sandbox-documents/")) {
      queueMicrotask(() => this.dispatchEvent(new Event("load")));
    }
    return result;
  };

  return () => {
    HTMLIFrameElement.prototype.setAttribute = originalSetAttribute;
  };
}

function createTestApp(overrides: Partial<App> = {}): App {
  const documents = {
    getActiveDocument: () => null,
    getSelectedDocuments: () => [],
    queryWorkspaceDocuments: () => [],
    getDocumentList: () => [],
    getDocumentById: async () => null,
    getActiveDocumentText: () => null,
    openDocument: () => undefined,
    createDocument: async () => "document-new",
    on: () => ({}) as never,
    offref: () => undefined,
    ...overrides.documents,
  } as App["documents"];

  return {
    workspace: overrides.workspace ?? workspaceManager,
    documents,
    isDarkMode: overrides.isDarkMode ?? (() => false),
  };
}

function assertMessagePort(port: MessagePort | undefined): asserts port is MessagePort {
  expect(port).toBeInstanceOf(MessagePort);
}

function expectNoJsonNull(value: unknown): void {
  if (Array.isArray(value)) {
    value.forEach(expectNoJsonNull);
    return;
  }
  if (value !== null && typeof value === "object") {
    Object.values(value).forEach(expectNoJsonNull);
    return;
  }
  expect(value).not.toBeNull();
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

function runtimeSandboxDocumentSession(id: string) {
  return {
    frameGeneration: 1,
    bootNonce: `boot-${id}`,
    sandboxDocumentUrl: `/api/plugin-runtime/sandbox-documents/${id}`,
  };
}

function createConnectedSession(
  router: PluginHostMessageRouter,
  workspaceId: string,
  applicationId: string,
): ReturnType<PluginHostMessageRouter["createSession"]> {
  const frame = new FakeFrameWindow();
  const session = router.createSession({
    pluginId: "plugin.example",
    packageId: "package.example",
    applicationId,
    activationId: "activation.example",
    ownerScopeKind: "workspace",
    workspaceId,
    userId: "user.example",
    deviceId: "device.example",
    bundleHash: "bundle-hash-1",
    manifestHash: "manifest-hash-1",
    capabilityId: `capability-${applicationId}`,
    capabilityGrantId: `capability-grant-${applicationId}`,
    consentEpoch: 1,
    contentWindow: frame,
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
  return session;
}

describe("usePluginHostRpc", () => {
  let restoreSandboxDocumentLoadDispatch: (() => void) | null = null;

  beforeEach(() => {
    restoreSandboxDocumentLoadDispatch = installSandboxDocumentLoadDispatch();
  });

  afterEach(() => {
    restoreSandboxDocumentLoadDispatch?.();
    restoreSandboxDocumentLoadDispatch = null;
  });

  it("keeps the production Host RPC adapter decoupled from DOM-backed workspace singletons", () => {
    expect(hostRpcAdapterSource).not.toContain("@/features/panel");
    expect(hostRpcAdapterSource).not.toContain("workspaceManager");
    expect(hostRpcAdapterSource).not.toContain("getApp");
    expect(hostRpcAdapterSource).not.toContain('kind: "workspace_plugin"');
  });

  it("confirms durable runtime audit persistence before reporting success", async () => {
    const postAudit = vi.fn<NonNullable<Parameters<typeof createDurablePluginRuntimeAuditSink>[1]>>(
      async () => ({
        data: {},
        response: new Response(null, { status: 204 }),
      }),
    );
    const sink = createDurablePluginRuntimeAuditSink(() => "workspace-one", postAudit);

    await expect(sink(runtimeAuditEvent("workspace-one"))).resolves.toBe(true);
    expect(postAudit).toHaveBeenCalledWith(
      "/api/workspaces/{workspace_id}/plugin-runtime-audit",
      expect.objectContaining({
        body: expect.objectContaining({
          event_id: "audit-event-one",
          plugin_id: "plugin.example",
          package_id: "package.example",
          application_id: "application-one",
          activation_id: "activation.example",
          owner_scope_kind: "workspace",
          capability_grant_id: "capability-grant-one",
          consent_epoch: 1,
          frame_generation: 1,
          workspace_id: "workspace-one",
          bundle_hash: "bundle-hash",
          manifest_hash: "manifest-hash",
          capability_id: "capability-one",
          request_id: "",
          execution_context_id: "",
          context_kind: "",
          payload_kind: "unknown",
          plaintext_scope_kind: "none",
          plaintext_bytes: 0,
          resource_ref: {},
        }),
      }),
    );
    expectNoJsonNull(postAudit.mock.calls[0]?.[1].body);

    postAudit.mockResolvedValueOnce({
      error: { code: "failed" },
      response: new Response(null, { status: 403 }),
    });
    await expect(sink(runtimeAuditEvent("workspace-one"))).resolves.toBe(false);
    await expect(sink(runtimeAuditEvent("workspace-one"))).resolves.toBe(false);
    expect(postAudit).toHaveBeenCalledTimes(2);
  });

  it("retries transient runtime audit persistence failures before failing closed", async () => {
    const postAudit = vi
      .fn<NonNullable<Parameters<typeof createDurablePluginRuntimeAuditSink>[1]>>()
      .mockResolvedValueOnce({
        error: { code: "failed" },
        response: new Response(null, { status: 500 }),
      })
      .mockResolvedValueOnce({
        response: new Response(null, { status: 204 }),
      });
    const sink = createDurablePluginRuntimeAuditSink(() => "workspace-one", postAudit, {
      retryDelaysMs: [0],
    });

    await expect(sink(runtimeAuditEvent("workspace-one"))).resolves.toBe(true);
    expect(postAudit).toHaveBeenCalledTimes(2);
  });

  it("flushes pending durable runtime audit persistence", async () => {
    let resolvePostAudit:
      | ((value: { data?: unknown; error?: unknown; response: Response }) => void)
      | undefined;
    const postAudit = vi.fn<NonNullable<Parameters<typeof createDurablePluginRuntimeAuditSink>[1]>>(
      () =>
        new Promise((resolve) => {
          resolvePostAudit = resolve;
        }),
    );
    const sink = createDurablePluginRuntimeAuditSink(() => "workspace-one", postAudit);

    const request = sink(runtimeAuditEvent("workspace-one"));
    let flushed = false;
    const flush = sink.flushPendingAudit().then(() => {
      flushed = true;
    });
    await Promise.resolve();
    expect(flushed).toBe(false);

    resolvePostAudit?.({
      data: {},
      response: new Response(null, { status: 204 }),
    });

    await expect(request).resolves.toBe(true);
    await flush;
    expect(flushed).toBe(true);
  });

  it("suppresses best-effort cleanup audit posts during workspace revocation", async () => {
    const postAudit = vi.fn<NonNullable<Parameters<typeof createDurablePluginRuntimeAuditSink>[1]>>(
      async () => ({
        data: {},
        response: new Response(null, { status: 204 }),
      }),
    );
    const sink = createDurablePluginRuntimeAuditSink(() => "workspace-one", postAudit);
    const event = runtimeAuditEvent("workspace-one");

    beginPluginRuntimeWorkspaceRevocation("workspace-one");
    try {
      await expect(
        sink({
          ...event,
          type: "plugin.ui.iframe.lifecycle",
          operation: "ui.cleanup",
          result: "deny",
          reasonCode: "workspace_deleted",
          action: {
            ...event.action,
            operation: "ui.cleanup",
            result: "denied",
            reason_code: "workspace_deleted",
          },
        }),
      ).resolves.toBe(false);
    } finally {
      releasePluginRuntimeWorkspaceRevocation("workspace-one");
    }

    expect(postAudit).not.toHaveBeenCalled();
  });

  it("exposes an app-owned runtime boundary controller backed by the central router", async () => {
    let controller: PluginHostRuntimeController;
    const dispose = createRoot((disposeRoot) => {
      controller = usePluginHostRpc(undefined, createTestApp());
      return disposeRoot;
    });
    const container = document.createElement("div");
    document.body.append(container);

    const path = await controller!.createRuntimePath({
      container,
      handlers: [
        {
          operation: "plugin.ping",
          handler: () => ({ ok: true }),
          policy: { plaintext: null },
        },
      ],
      pluginId: "plugin.example",
      packageId: "package.example",
      applicationId: "00000000-0000-4000-8000-000000000001",
      activationId: "activation.example",
      ownerScopeKind: "workspace",
      userId: "user.example",
      deviceId: "device.example",
      workspaceId: "00000000-0000-4000-8000-000000000002",
      bundleHash: "bundle-hash-1",
      manifestHash: "manifest-hash-1",
      capabilityId: "capability-1",
      capabilityGrantId: "capability-grant-1",
      ...runtimeSandboxDocumentSession("app-controller-runtime"),
      consentEpoch: 1,
      validateSession: () => null,
      auditSink: () => true,
      title: "Runtime Plugin",
    });

    expect(container.contains(path.runtime.iframe)).toBe(true);
    expect(path.runtime.iframe.getAttribute("sandbox")).toBe("allow-scripts");
    expect(path.runtime.session.pluginId).toBe("plugin.example");
    expect(controller!.router).toBe(getPluginHostMessageRouter());

    const postMessageSpy = vi.spyOn(path.runtime.session.contentWindow, "postMessage");
    controller!.router.handleWindowMessage({
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

    port.postMessage(runtimePathRequestEnvelope());
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "response",
      request_id: "runtime-path-request",
      payload: { ok: true },
    });

    path.destroy("test_destroy");
    expect(container.contains(path.runtime.iframe)).toBe(false);
    container.remove();
    dispose();
  });

  it("closes plugin Host RPC sessions during session cleanup", async () => {
    const dispose = createRoot((disposeRoot) => {
      usePluginHostRpc(undefined, createTestApp());
      return disposeRoot;
    });
    const router = getPluginHostMessageRouter();
    const session = createConnectedSession(
      router,
      "00000000-0000-4000-8000-000000000002",
      "00000000-0000-4000-8000-000000000001",
    );
    expect(session.connected).toBe(true);
    workspaceManager.addCommand({
      id: "session-cleanup-plugin-command",
      name: "Session cleanup plugin command",
      owner: thirdPartySurfaceOwner(
        "00000000-0000-4000-8000-000000000002",
        "00000000-0000-4000-8000-000000000001",
      ),
    });

    await runBeforeSessionCleanup({ secure: false });

    expect(session.connected).toBe(false);
    expect(
      workspaceManager
        .listCommands()
        .some((command) => command.id === "session-cleanup-plugin-command"),
    ).toBe(false);
    dispose();
  });

  it("registers the fail-closed plugin network Host RPC surface at app bootstrap", async () => {
    let controller: PluginHostRuntimeController;
    const dispose = createRoot((disposeRoot) => {
      controller = usePluginHostRpc(undefined, createTestApp());
      return disposeRoot;
    });
    const container = document.createElement("div");
    document.body.append(container);

    const path = await controller!.createRuntimePath({
      container,
      handlers: [
        {
          operation: "plugin.ui.echo",
          handler: () => ({ ok: true }),
          policy: { plaintext: null },
        },
      ],
      pluginId: "plugin.example",
      packageId: "package.example",
      applicationId: "00000000-0000-4000-8000-000000000001",
      activationId: "activation.example",
      ownerScopeKind: "workspace",
      userId: "user.example",
      deviceId: "device.example",
      workspaceId: "00000000-0000-4000-8000-000000000002",
      bundleHash: "bundle-hash-1",
      manifestHash: "manifest-hash-1",
      capabilityId: "capability-1",
      capabilityGrantId: "capability-grant-1",
      ...runtimeSandboxDocumentSession("network-runtime"),
      consentEpoch: 1,
      permissions: ["network:fetch"],
      auditSink: () => true,
      validateSession: () => null,
      title: "Runtime Plugin",
    });

    const postMessageSpy = vi.spyOn(path.runtime.session.contentWindow, "postMessage");
    controller!.router.handleWindowMessage({
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

    port.postMessage(networkRequestEnvelope());

    const networkResponse = await waitForPortMessage(port);
    expect(networkResponse).toMatchObject({
      kind: "error",
      error: { code: "network_endpoint_unknown" },
    });

    path.destroy("test_destroy");
    container.remove();
    dispose();
  });

  it("uses runtime-owned network endpoint policy when a plugin runtime declares it", async () => {
    let controller: PluginHostRuntimeController;
    const dispose = createRoot((disposeRoot) => {
      controller = usePluginHostRpc(undefined, createTestApp());
      return disposeRoot;
    });
    const container = document.createElement("div");
    document.body.append(container);

    const proxyExecutor = vi.fn(async () => ({
      status: 200,
      headers: { "content-type": "application/json" },
      bodyText: '{"ok":true}',
    }));
    const path = await controller!.createRuntimePath({
      container,
      handlers: [
        {
          operation: "plugin.ui.echo",
          handler: () => ({ ok: true }),
          policy: { plaintext: null },
        },
      ],
      networkServices: {
        endpointPolicy: vi.fn(async () => ({
          id: "github-rest",
          url: "https://api.github.com/repos/refmdio/refmd/issues",
          methods: ["GET"] as const,
          routes: ["proxy"] as const,
          headers: ["accept"] as const,
          bodySchema: "none" as const,
          maxRequestBytes: 1024,
          maxResponseBytes: 2048,
        })),
        proxyExecutor,
        proxyRegistration: vi.fn(async () => ({
          id: "org-proxy",
          label: "Org Proxy",
          origin: "https://proxy.example",
          scope: "workspace" as const,
        })),
      },
      pluginId: "plugin.example",
      packageId: "package.example",
      applicationId: "00000000-0000-4000-8000-000000000001",
      activationId: "activation.example",
      ownerScopeKind: "workspace",
      userId: "user.example",
      deviceId: "device.example",
      workspaceId: "00000000-0000-4000-8000-000000000002",
      bundleHash: "bundle-hash-1",
      manifestHash: "manifest-hash-1",
      capabilityId: "capability-1",
      capabilityGrantId: "capability-grant-1",
      ...runtimeSandboxDocumentSession("network-policy-runtime"),
      consentEpoch: 1,
      permissions: ["network:fetch"],
      auditSink: () => true,
      validateSession: () => null,
      title: "Runtime Plugin",
    });

    const postMessageSpy = vi.spyOn(path.runtime.session.contentWindow, "postMessage");
    controller!.router.handleWindowMessage({
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
      networkRequestEnvelope({
        payload: {
          endpoint_id: "github-rest",
          route: "proxy",
          method: "GET",
          headers: { accept: "application/json" },
        },
      }),
    );

    const networkResponse = await waitForPortMessage(port);
    expect(networkResponse).toMatchObject({
      kind: "response",
      payload: {
        route: "proxy",
        proxy_id: "org-proxy",
        status: 200,
        body_text: '{"ok":true}',
      },
    });
    expect(proxyExecutor).toHaveBeenCalledWith(
      expect.objectContaining({
        url: "https://api.github.com/repos/refmdio/refmd/issues",
        route: "proxy",
      }),
    );

    path.destroy("test_destroy");
    container.remove();
    dispose();
  });

  it("registers document body write handlers on the runtime Host RPC path", async () => {
    let controller: PluginHostRuntimeController;
    const setValue = vi.fn();
    const replaceSelection = vi.fn();
    const app = createTestApp({
      documents: {
        getActiveDocument: () => ({
          id: "document-1",
          title: "Current",
          editor: {
            getValue: () => "before",
            setValue,
            replaceSelection,
          },
        }),
        getSelectedDocuments: () => [],
        queryWorkspaceDocuments: () => [],
        getDocumentList: () => [],
        getDocumentById: async () => null,
        getActiveDocumentText: () => null,
        openDocument: () => undefined,
        createDocument: async () => "document-new",
        on: () => ({}) as never,
        offref: () => undefined,
      } as unknown as App["documents"],
      workspace: {
        addCommand: (command: Command) => command,
        removeCommand: () => undefined,
        listCommands: () => [],
      } as unknown as App["workspace"],
    });
    const dispose = createRoot((disposeRoot) => {
      controller = usePluginHostRpc(undefined, app);
      return disposeRoot;
    });
    const container = document.createElement("div");
    document.body.append(container);

    const path = await controller!.createRuntimePath({
      container,
      handlers: [
        {
          operation: "plugin.ui.echo",
          handler: () => ({ ok: true }),
          policy: { plaintext: null },
        },
      ],
      pluginId: "plugin.example",
      packageId: "package.example",
      applicationId: "00000000-0000-4000-8000-000000000001",
      activationId: "activation.example",
      ownerScopeKind: "workspace",
      userId: "user.example",
      deviceId: "device.example",
      workspaceId: "00000000-0000-4000-8000-000000000002",
      bundleHash: "bundle-hash-1",
      manifestHash: "manifest-hash-1",
      capabilityId: "capability-1",
      capabilityGrantId: "capability-grant-1",
      ...runtimeSandboxDocumentSession("workspace-read-runtime"),
      consentEpoch: 1,
      permissions: ["document:write"],
      documentScope: { allowedDocumentIds: ["document-1"] },
      auditSink: () => true,
      validateSession: () => null,
      title: "Runtime Plugin",
    });

    const port = connectIframe(controller!.router, path.runtime.iframe);
    port.postMessage(
      runtimePathRequestEnvelope({
        operation: "editor.setValue",
        payload: { value: "after" },
        resource: { document_id: "document-1" },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      payload: { applied: true, document_id: "document-1" },
    });
    expect(setValue).toHaveBeenCalledWith("after");

    port.postMessage(
      runtimePathRequestEnvelope({
        request_id: "runtime-path-replace-selection",
        request_nonce: "runtime-path-replace-selection-nonce",
        operation: "editor.replaceSelection",
        payload: { text: "inserted" },
        resource: { document_id: "document-1" },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      payload: { applied: true, document_id: "document-1" },
    });
    expect(replaceSelection).toHaveBeenCalledWith("inserted");

    path.destroy("test_destroy");
    container.remove();
    dispose();
  });

  it("bounds workspace document query construction by the Host-issued byte limit", async () => {
    let controller: PluginHostRuntimeController;
    const releaseDocument = vi.fn();
    const getDocumentById = vi.fn(async (documentId: string) => {
      const documents = {
        "doc-one": { id: "doc-one", title: "One", text: "alpha" },
        "doc-two": { id: "doc-two", title: "Two", text: "beta beta" },
        "doc-three": { id: "doc-three", title: "Three", text: "gamma" },
      } as const;
      const document = documents[documentId as keyof typeof documents];
      return document ? { ...document, release: releaseDocument } : null;
    });
    const app = createTestApp({
      documents: {
        getActiveDocument: () => null,
        getSelectedDocuments: () => [],
        queryWorkspaceDocuments: () => [],
        getDocumentList: () => [
          { id: "doc-one", title: "One", docType: "document", archivedAt: null },
          { id: "doc-two", title: "Two", docType: "document", archivedAt: null },
          { id: "doc-three", title: "Three", docType: "document", archivedAt: null },
        ],
        getDocumentById,
        getActiveDocumentText: () => null,
        openDocument: () => undefined,
        createDocument: async () => "document-new",
        on: () => ({}) as never,
        offref: () => undefined,
      } as unknown as App["documents"],
      workspace: {
        addCommand: (command: Command) => command,
        removeCommand: () => undefined,
        listCommands: () => [],
      } as unknown as App["workspace"],
    });
    const dispose = createRoot((disposeRoot) => {
      controller = usePluginHostRpc(undefined, app);
      return disposeRoot;
    });
    const container = document.createElement("div");
    document.body.append(container);

    const path = await controller!.createRuntimePath({
      container,
      handlers: [],
      pluginId: "plugin.example",
      packageId: "package.example",
      applicationId: "00000000-0000-4000-8000-000000000001",
      activationId: "activation.example",
      ownerScopeKind: "workspace",
      userId: "user.example",
      deviceId: "device.example",
      workspaceId: "00000000-0000-4000-8000-000000000002",
      bundleHash: "bundle-hash-1",
      manifestHash: "manifest-hash-1",
      capabilityId: "capability-1",
      capabilityGrantId: "capability-grant-1",
      ...runtimeSandboxDocumentSession("ui-command-runtime"),
      consentEpoch: 1,
      permissions: ["document:read:workspace"],
      documentScope: { workspaceReadAllowed: true },
      validateSession: () => null,
      auditSink: () => true,
      title: "Runtime Plugin",
    });
    const port = connectIframe(controller!.router, path.runtime.iframe);
    const executionContext = path.runtime.session.issueExecutionContext({
      kind: "user_command",
      hostInvocation: { kind: "command", userGesture: true },
      resource: { max_documents: 3, max_bytes: 24 },
      plaintextScope: { kind: "workspace", maxBytes: 24 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
    });

    port.postMessage(
      runtimePathRequestEnvelope({
        request_id: "workspace-query",
        request_nonce: "workspace-query-nonce",
        operation: "documents.queryWorkspaceDocuments",
        execution_context_id: executionContext.execution_context_id,
        resource: { max_documents: 3, max_bytes: 24 },
        payload: { limit: 3 },
      }),
    );

    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "response",
      request_id: "workspace-query",
      payload: {
        documents: [{ document_id: "doc-one", title: "One", plaintext: "alpha" }],
      },
    });
    expect(getDocumentById).toHaveBeenCalledTimes(2);
    expect(getDocumentById).toHaveBeenNthCalledWith(1, "doc-one");
    expect(getDocumentById).toHaveBeenNthCalledWith(2, "doc-two");
    expect(getDocumentById).not.toHaveBeenCalledWith("doc-three");
    expect(releaseDocument).toHaveBeenCalledTimes(2);

    path.destroy("test_destroy");
    container.remove();
    dispose();
  });

  it("issues bounded workspace document query contexts for workspace tile actions", async () => {
    let controller: PluginHostRuntimeController;
    let capturedTile: WorkspaceTileConfig | null = null;
    const auditSink = vi.fn(() => true);
    const releaseDocument = vi.fn();
    const getDocumentById = vi.fn(async (documentId: string) => {
      const documents = {
        "doc-one": { id: "doc-one", title: "One", text: "alpha" },
        "doc-two": { id: "doc-two", title: "Two", text: "beta" },
        "doc-three": { id: "doc-three", title: "Three", text: "gamma" },
      } as const;
      const document = documents[documentId as keyof typeof documents];
      return document ? { ...document, release: releaseDocument } : null;
    });
    const app = createTestApp({
      documents: {
        getActiveDocument: () => null,
        getSelectedDocuments: () => [],
        queryWorkspaceDocuments: () => [],
        getDocumentList: () => [
          { id: "doc-one", title: "One", docType: "document", archivedAt: null },
          { id: "doc-two", title: "Two", docType: "document", archivedAt: null },
          { id: "doc-three", title: "Three", docType: "document", archivedAt: null },
        ],
        getDocumentById,
        getActiveDocumentText: () => null,
        openDocument: () => undefined,
        createDocument: async () => "document-new",
        on: () => ({}) as never,
        offref: () => undefined,
      } as unknown as App["documents"],
      workspace: {
        addCommand: (command: Command) => command,
        removeCommand: () => undefined,
        listCommands: () => [],
        addStatusBarItem: () => document.createElement("div"),
        addSidebarPanel: () => undefined,
        removeSidebarPanel: () => undefined,
        addWorkspaceTile: (tile: WorkspaceTileConfig) => {
          capturedTile = tile;
        },
        openWorkspaceTile: () => undefined,
        removeWorkspaceTile: () => {
          capturedTile = null;
        },
        getWorkspaceTiles: () => (capturedTile ? [capturedTile] : []),
        addAuxiliaryPane: () => undefined,
        removeAuxiliaryPane: () => undefined,
        getAuxiliaryPanes: () => [],
        addSettingTab: () => undefined,
        removeSettingTab: () => undefined,
        removeSurfacesByOwner: () => undefined,
      } as unknown as App["workspace"],
    });
    const sandboxDocumentSessionLoader = vi.fn(async () => ({
      sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/workspace-tile-ui",
      bootNonce: "boot-ui-one",
      frameGeneration: 2,
      frameScope: "secondary" as const,
      capabilityGrantId: "capability-grant-1",
    }));
    const dispose = createRoot((disposeRoot) => {
      controller = usePluginHostRpc(undefined, app);
      return disposeRoot;
    });
    const container = document.createElement("div");
    document.body.append(container);

    const path = await controller!.createRuntimePath({
      container,
      handlers: [],
      pluginId: "plugin.example",
      packageId: "package.example",
      applicationId: "00000000-0000-4000-8000-000000000001",
      activationId: "activation.example",
      ownerScopeKind: "workspace",
      userId: "user.example",
      deviceId: "device.example",
      workspaceId: "00000000-0000-4000-8000-000000000002",
      bundleHash: "bundle-hash-1",
      manifestHash: "manifest-hash-1",
      capabilityId: "capability-1",
      capabilityGrantId: "capability-grant-1",
      stateHeadHash: "state-head-1",
      consentHeadHash: "consent-head-1",
      frameGeneration: 1,
      bootNonce: "boot-parent-one",
      sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/parent-session-one",
      sandboxDocumentSessionLoader,
      consentEpoch: 1,
      permissions: ["ui:workspace_tile", "document:read:workspace"],
      documentScope: { workspaceReadAllowed: true },
      validateSession: () => null,
      auditSink,
      title: "Runtime Plugin",
    });
    const mainPort = connectIframe(controller!.router, path.runtime.iframe);

    mainPort.postMessage(
      runtimePathRequestEnvelope({
        request_id: "workspace-tile-register",
        request_nonce: "workspace-tile-register-nonce",
        operation: "ui.workspace.register_tile",
        payload: {
          surface: "workspace_tile",
          local_id: "board",
          tile_id: "board",
          title: "Board",
          scope: "workspace",
        },
      }),
    );
    expect(await waitForPortMessage(mainPort)).toMatchObject({ kind: "response" });
    mainPort.postMessage(
      runtimePathRequestEnvelope({
        request_id: "workspace-tile-action-register",
        request_nonce: "workspace-tile-action-register-nonce",
        operation: "ui.workspace.register_tile_action",
        payload: {
          surface: "workspace_tile_action",
          local_id: "board.refresh",
          tile_ref: { kind: "local_tile", local_id: "board" },
          action_id: "refresh",
          title: "Refresh",
          placement: "refresh",
          document_query: { scope: "workspace", max_documents: 2, max_bytes: 64 },
        },
      }),
    );
    expect(await waitForPortMessage(mainPort)).toMatchObject({ kind: "response" });

    const tile = capturedTile as WorkspaceTileConfig | null;
    if (!tile) throw new Error("workspace_tile_not_registered");
    const tileAction = tile.actions?.()?.[0];
    if (!tileAction) throw new Error("workspace_tile_action_not_registered");

    const tileContainer = document.createElement("div");
    document.body.append(tileContainer);
    tile.render(tileContainer, {
      tileInstanceId: "tile-instance-one",
      action: {
        actionId: "tile-action-one",
        tileId: tile.id,
        tileInstanceId: "tile-instance-one",
        kind: "tile_action",
        tileActionId: tileAction.actionId,
        documentQuery: tileAction.documentQuery,
        issuedAtMs: Date.now(),
      },
    });
    const uiIframe = await waitForIframe(tileContainer);
    const uiPort = connectIframe(controller!.router, uiIframe);
    const renderRequest = (await waitForPortMessage(uiPort)) as PluginHostRpcRequestEnvelope;
    expect(renderRequest).toMatchObject({
      kind: "request",
      operation: "ui.workspace_tile.action",
      execution_context_id: expect.any(String),
      resource: { max_documents: 2, max_bytes: 64 },
      payload: {
        tile_id: "board",
        tile_instance_id: "tile-instance-one",
        action_id: "refresh",
        document_query: { scope: "workspace", max_documents: 2, max_bytes: 64 },
      },
    });
    if (typeof renderRequest.execution_context_id !== "string") {
      throw new Error("workspace_tile_execution_context_missing");
    }
    expect(auditSink).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "plugin.ui.invocation.accepted",
        operation: "ui.workspace_tile.action",
        payloadKind: "ui.workspace_tile_action",
        plaintextScopeKind: "workspace",
        requestId: "tile-action-one",
        executionContextId: null,
        resourceRef: { max_documents: 2, max_bytes: 64 },
        result: "allow",
      }),
    );

    uiPort.postMessage(
      runtimePathRequestEnvelope({
        request_id: "workspace-tile-query",
        request_nonce: "workspace-tile-query-nonce",
        operation: "documents.queryWorkspaceDocuments",
        frame_generation: 2,
        execution_context_id: renderRequest.execution_context_id,
        resource: renderRequest.resource,
        payload: { limit: 2 },
      }),
    );
    expect(await waitForPortMessage(uiPort)).toMatchObject({
      kind: "response",
      request_id: "workspace-tile-query",
      payload: {
        documents: [
          { document_id: "doc-one", title: "One", plaintext: "alpha" },
          { document_id: "doc-two", title: "Two", plaintext: "beta" },
        ],
      },
    });
    expect(getDocumentById).toHaveBeenCalledTimes(2);
    expect(getDocumentById).not.toHaveBeenCalledWith("doc-three");

    uiPort.postMessage({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: renderRequest.request_id,
      payload: { rendered: true },
    });

    path.destroy("test_destroy");
    tileContainer.remove();
    container.remove();
    dispose();
  });

  it("does not invoke workspace tile document query actions when pre-invoke audit fails", async () => {
    let controller: PluginHostRuntimeController;
    let capturedTile: WorkspaceTileConfig | null = null;
    const auditSink = vi.fn((event) => event.type !== "plugin.ui.invocation.accepted");
    const app = createTestApp({
      workspace: {
        addCommand: (command: Command) => command,
        removeCommand: () => undefined,
        listCommands: () => [],
        addStatusBarItem: () => document.createElement("div"),
        addSidebarPanel: () => undefined,
        removeSidebarPanel: () => undefined,
        addWorkspaceTile: (tile: WorkspaceTileConfig) => {
          capturedTile = tile;
        },
        openWorkspaceTile: () => undefined,
        removeWorkspaceTile: () => {
          capturedTile = null;
        },
        getWorkspaceTiles: () => (capturedTile ? [capturedTile] : []),
        addAuxiliaryPane: () => undefined,
        removeAuxiliaryPane: () => undefined,
        getAuxiliaryPanes: () => [],
        addSettingTab: () => undefined,
        removeSettingTab: () => undefined,
        removeSurfacesByOwner: () => undefined,
      } as unknown as App["workspace"],
    });
    const sandboxDocumentSessionLoader = vi.fn(async () => ({
      sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/workspace-tile-audit-denied",
      bootNonce: "boot-ui-denied",
      frameGeneration: 2,
      frameScope: "secondary" as const,
      capabilityGrantId: "capability-grant-1",
    }));
    const dispose = createRoot((disposeRoot) => {
      controller = usePluginHostRpc(undefined, app);
      return disposeRoot;
    });
    const container = document.createElement("div");
    document.body.append(container);

    const path = await controller!.createRuntimePath({
      container,
      handlers: [],
      pluginId: "plugin.example",
      packageId: "package.example",
      applicationId: "00000000-0000-4000-8000-000000000001",
      activationId: "activation.example",
      ownerScopeKind: "workspace",
      userId: "user.example",
      deviceId: "device.example",
      workspaceId: "00000000-0000-4000-8000-000000000002",
      bundleHash: "bundle-hash-1",
      manifestHash: "manifest-hash-1",
      capabilityId: "capability-1",
      capabilityGrantId: "capability-grant-1",
      stateHeadHash: "state-head-1",
      consentHeadHash: "consent-head-1",
      frameGeneration: 1,
      bootNonce: "boot-parent-one",
      sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/parent-session-one",
      sandboxDocumentSessionLoader,
      consentEpoch: 1,
      permissions: ["ui:workspace_tile", "document:read:workspace"],
      documentScope: { workspaceReadAllowed: true },
      validateSession: () => null,
      auditSink,
      title: "Runtime Plugin",
    });
    const mainPort = connectIframe(controller!.router, path.runtime.iframe);

    mainPort.postMessage(
      runtimePathRequestEnvelope({
        request_id: "workspace-tile-register",
        request_nonce: "workspace-tile-register-nonce",
        operation: "ui.workspace.register_tile",
        payload: {
          surface: "workspace_tile",
          local_id: "board",
          tile_id: "board",
          title: "Board",
          scope: "workspace",
        },
      }),
    );
    expect(await waitForPortMessage(mainPort)).toMatchObject({ kind: "response" });
    mainPort.postMessage(
      runtimePathRequestEnvelope({
        request_id: "workspace-tile-action-register",
        request_nonce: "workspace-tile-action-register-nonce",
        operation: "ui.workspace.register_tile_action",
        payload: {
          surface: "workspace_tile_action",
          local_id: "board.refresh",
          tile_ref: { kind: "local_tile", local_id: "board" },
          action_id: "refresh",
          title: "Refresh",
          placement: "refresh",
          document_query: { scope: "workspace", max_documents: 2, max_bytes: 64 },
        },
      }),
    );
    expect(await waitForPortMessage(mainPort)).toMatchObject({ kind: "response" });

    const tile = capturedTile as WorkspaceTileConfig | null;
    if (!tile) throw new Error("workspace_tile_not_registered");
    const tileAction = tile.actions?.()?.[0];
    if (!tileAction) throw new Error("workspace_tile_action_not_registered");

    const tileContainer = document.createElement("div");
    document.body.append(tileContainer);
    tile.render(tileContainer, {
      tileInstanceId: "tile-instance-denied",
      action: {
        actionId: "tile-action-denied",
        tileId: tile.id,
        tileInstanceId: "tile-instance-denied",
        kind: "tile_action",
        tileActionId: tileAction.actionId,
        documentQuery: tileAction.documentQuery,
        issuedAtMs: Date.now(),
      },
    });
    const uiIframe = await waitForIframe(tileContainer);
    const uiPort = connectIframe(controller!.router, uiIframe);
    await expect(waitForNoPortMessage(uiPort)).resolves.toBeUndefined();
    expect(auditSink).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "plugin.ui.invocation.accepted",
        operation: "ui.workspace_tile.action",
        payloadKind: "ui.workspace_tile_action",
        requestId: "tile-action-denied",
        executionContextId: null,
      }),
    );

    path.destroy("test_destroy");
    tileContainer.remove();
    container.remove();
    dispose();
  });

  it("prioritizes document query contexts for document-scoped workspace tile actions", async () => {
    let controller: PluginHostRuntimeController;
    let capturedTile: WorkspaceTileConfig | null = null;
    const releaseDocument = vi.fn();
    const getDocumentById = vi.fn(async (documentId: string) => {
      const documents = {
        "doc-one": { id: "doc-one", title: "One", text: "alpha" },
        "doc-two": { id: "doc-two", title: "Two", text: "beta" },
        "doc-three": { id: "doc-three", title: "Three", text: "gamma" },
      } as const;
      const document = documents[documentId as keyof typeof documents];
      return document ? { ...document, release: releaseDocument } : null;
    });
    const app = createTestApp({
      documents: {
        getActiveDocument: () => null,
        getSelectedDocuments: () => [],
        queryWorkspaceDocuments: () => [],
        getDocumentList: () => [
          { id: "doc-one", title: "One", docType: "document", archivedAt: null },
          { id: "doc-two", title: "Two", docType: "document", archivedAt: null },
          { id: "doc-three", title: "Three", docType: "document", archivedAt: null },
        ],
        getDocumentById,
        getActiveDocumentText: () => null,
        openDocument: () => undefined,
        createDocument: async () => "document-new",
        on: () => ({}) as never,
        offref: () => undefined,
      } as unknown as App["documents"],
      workspace: {
        addCommand: (command: Command) => command,
        removeCommand: () => undefined,
        listCommands: () => [],
        addStatusBarItem: () => document.createElement("div"),
        addSidebarPanel: () => undefined,
        removeSidebarPanel: () => undefined,
        addWorkspaceTile: (tile: WorkspaceTileConfig) => {
          capturedTile = tile;
        },
        openWorkspaceTile: () => undefined,
        removeWorkspaceTile: () => {
          capturedTile = null;
        },
        getWorkspaceTiles: () => (capturedTile ? [capturedTile] : []),
        addAuxiliaryPane: () => undefined,
        removeAuxiliaryPane: () => undefined,
        getAuxiliaryPanes: () => [],
        addSettingTab: () => undefined,
        removeSettingTab: () => undefined,
        removeSurfacesByOwner: () => undefined,
      } as unknown as App["workspace"],
    });
    const sandboxDocumentSessionLoader = vi.fn(async () => ({
      sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/document-tile-ui",
      bootNonce: "boot-document-ui-one",
      frameGeneration: 2,
      frameScope: "secondary" as const,
      capabilityGrantId: "capability-grant-1",
    }));
    const dispose = createRoot((disposeRoot) => {
      controller = usePluginHostRpc(undefined, app);
      return disposeRoot;
    });
    const container = document.createElement("div");
    document.body.append(container);

    const path = await controller!.createRuntimePath({
      container,
      handlers: [],
      pluginId: "plugin.example",
      packageId: "package.example",
      applicationId: "00000000-0000-4000-8000-000000000001",
      activationId: "activation.example",
      ownerScopeKind: "workspace",
      userId: "user.example",
      deviceId: "device.example",
      workspaceId: "00000000-0000-4000-8000-000000000002",
      bundleHash: "bundle-hash-1",
      manifestHash: "manifest-hash-1",
      capabilityId: "capability-1",
      capabilityGrantId: "capability-grant-1",
      stateHeadHash: "state-head-1",
      consentHeadHash: "consent-head-1",
      frameGeneration: 1,
      bootNonce: "boot-parent-one",
      sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/parent-session-one",
      sandboxDocumentSessionLoader,
      consentEpoch: 1,
      permissions: ["ui:workspace_tile", "document:read:active", "document:read:workspace"],
      documentScope: {
        activeDocumentId: "doc-board",
        activeDocumentReadAllowed: true,
        workspaceReadAllowed: true,
      },
      validateSession: () => null,
      auditSink: () => true,
      title: "Runtime Plugin",
    });
    const mainPort = connectIframe(controller!.router, path.runtime.iframe);

    mainPort.postMessage(
      runtimePathRequestEnvelope({
        request_id: "document-tile-register",
        request_nonce: "document-tile-register-nonce",
        operation: "ui.workspace.register_tile",
        payload: {
          surface: "workspace_tile",
          local_id: "board",
          tile_id: "board",
          title: "Board",
          scope: "document",
        },
      }),
    );
    expect(await waitForPortMessage(mainPort)).toMatchObject({ kind: "response" });
    mainPort.postMessage(
      runtimePathRequestEnvelope({
        request_id: "document-tile-action-register",
        request_nonce: "document-tile-action-register-nonce",
        operation: "ui.workspace.register_tile_action",
        payload: {
          surface: "workspace_tile_action",
          local_id: "board.refresh",
          tile_ref: { kind: "local_tile", local_id: "board" },
          action_id: "refresh",
          title: "Refresh",
          placement: "refresh",
          document_query: { scope: "workspace", max_documents: 2, max_bytes: 64 },
        },
      }),
    );
    expect(await waitForPortMessage(mainPort)).toMatchObject({ kind: "response" });

    const tile = capturedTile as WorkspaceTileConfig | null;
    if (!tile) throw new Error("workspace_tile_not_registered");
    const tileAction = tile.actions?.()?.[0];
    if (!tileAction) throw new Error("workspace_tile_action_not_registered");

    const tileContainer = document.createElement("div");
    document.body.append(tileContainer);
    tile.render(tileContainer, {
      documentId: "doc-board",
      tileInstanceId: "tile-instance-document",
      action: {
        actionId: "tile-action-document",
        tileId: tile.id,
        tileInstanceId: "tile-instance-document",
        documentId: "doc-board",
        kind: "tile_action",
        tileActionId: tileAction.actionId,
        documentQuery: tileAction.documentQuery,
        issuedAtMs: Date.now(),
      },
    });
    const uiIframe = await waitForIframe(tileContainer);
    const uiPort = connectIframe(controller!.router, uiIframe);
    const renderRequest = (await waitForPortMessage(uiPort)) as PluginHostRpcRequestEnvelope;
    expect(renderRequest).toMatchObject({
      kind: "request",
      operation: "ui.workspace_tile.action",
      execution_context_id: expect.any(String),
      resource: { document_id: "doc-board", max_documents: 2, max_bytes: 64 },
      payload: {
        tile_id: "board",
        tile_instance_id: "tile-instance-document",
        document_id: "doc-board",
        action_id: "refresh",
        document_query: { scope: "workspace", max_documents: 2, max_bytes: 64 },
      },
    });
    if (typeof renderRequest.execution_context_id !== "string") {
      throw new Error("workspace_tile_execution_context_missing");
    }

    uiPort.postMessage(
      runtimePathRequestEnvelope({
        request_id: "document-tile-query-no-context",
        request_nonce: "document-tile-query-no-context-nonce",
        operation: "documents.queryWorkspaceDocuments",
        frame_generation: 2,
        resource: { max_documents: 2, max_bytes: 64 },
        payload: { limit: 2 },
      }),
    );
    expect(await waitForPortMessage(uiPort)).toMatchObject({
      kind: "error",
      request_id: "document-tile-query-no-context",
      error: { code: "execution_context_required" },
    });

    uiPort.postMessage(
      runtimePathRequestEnvelope({
        request_id: "document-tile-query",
        request_nonce: "document-tile-query-nonce",
        operation: "documents.queryWorkspaceDocuments",
        frame_generation: 2,
        execution_context_id: renderRequest.execution_context_id,
        resource: renderRequest.resource,
        payload: { limit: 2 },
      }),
    );
    expect(await waitForPortMessage(uiPort)).toMatchObject({
      kind: "response",
      request_id: "document-tile-query",
      payload: {
        documents: [
          { document_id: "doc-one", title: "One", plaintext: "alpha" },
          { document_id: "doc-two", title: "Two", plaintext: "beta" },
        ],
      },
    });
    expect(getDocumentById).toHaveBeenCalledTimes(2);
    expect(getDocumentById).not.toHaveBeenCalledWith("doc-three");

    uiPort.postMessage({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: renderRequest.request_id,
      payload: { rendered: true },
    });

    path.destroy("test_destroy");
    tileContainer.remove();
    container.remove();
    dispose();
  });

  it("issues document read contexts for normal document-scoped workspace tile render", async () => {
    let controller: PluginHostRuntimeController;
    let capturedTile: WorkspaceTileConfig | null = null;
    const releaseDocument = vi.fn();
    const getDocumentById = vi.fn(async (documentId: string) => {
      if (documentId !== "doc-marp") return null;
      return {
        id: "doc-marp",
        title: "Slides",
        text: "# Slide\n\nhello",
        release: releaseDocument,
      };
    });
    const auditSink = vi.fn(() => true);
    const app = createTestApp({
      documents: {
        getActiveDocument: () => null,
        getSelectedDocuments: () => [],
        queryWorkspaceDocuments: () => [],
        getDocumentList: () => [
          { id: "doc-marp", title: "Slides", docType: "document", archivedAt: null },
        ],
        getDocumentById,
        getActiveDocumentText: () => null,
        openDocument: () => undefined,
        createDocument: async () => "document-new",
        on: () => ({}) as never,
        offref: () => undefined,
      } as unknown as App["documents"],
      workspace: {
        addCommand: (command: Command) => command,
        removeCommand: () => undefined,
        listCommands: () => [],
        addStatusBarItem: () => document.createElement("div"),
        addSidebarPanel: () => undefined,
        removeSidebarPanel: () => undefined,
        addWorkspaceTile: (tile: WorkspaceTileConfig) => {
          capturedTile = tile;
        },
        openWorkspaceTile: () => undefined,
        removeWorkspaceTile: () => {
          capturedTile = null;
        },
        getWorkspaceTiles: () => (capturedTile ? [capturedTile] : []),
        addAuxiliaryPane: () => undefined,
        removeAuxiliaryPane: () => undefined,
        getAuxiliaryPanes: () => [],
        addSettingTab: () => undefined,
        removeSettingTab: () => undefined,
        removeSurfacesByOwner: () => undefined,
      } as unknown as App["workspace"],
    });
    const sandboxDocumentSessionLoader = vi.fn(async () => ({
      sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/document-tile-render",
      bootNonce: "boot-document-tile",
      frameGeneration: 2,
      frameScope: "secondary" as const,
      capabilityGrantId: "capability-grant-1",
    }));
    const dispose = createRoot((disposeRoot) => {
      controller = usePluginHostRpc(undefined, app);
      return disposeRoot;
    });
    const container = document.createElement("div");
    document.body.append(container);

    const path = await controller!.createRuntimePath({
      container,
      handlers: [],
      pluginId: "plugin.example",
      packageId: "package.example",
      applicationId: "00000000-0000-4000-8000-000000000001",
      activationId: "activation.example",
      ownerScopeKind: "workspace",
      userId: "user.example",
      deviceId: "device.example",
      workspaceId: "00000000-0000-4000-8000-000000000002",
      bundleHash: "bundle-hash-1",
      manifestHash: "manifest-hash-1",
      capabilityId: "capability-1",
      capabilityGrantId: "capability-grant-1",
      stateHeadHash: "state-head-1",
      consentHeadHash: "consent-head-1",
      frameGeneration: 1,
      bootNonce: "boot-parent-one",
      sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/parent-session-one",
      sandboxDocumentSessionLoader,
      consentEpoch: 1,
      permissions: ["ui:workspace_tile", "document:read:active"],
      documentScope: { activeDocumentReadAllowed: true, activeDocumentId: "doc-marp" },
      validateSession: () => null,
      auditSink,
      title: "Runtime Plugin",
    });
    const mainPort = connectIframe(controller!.router, path.runtime.iframe);

    mainPort.postMessage(
      runtimePathRequestEnvelope({
        request_id: "document-tile-register",
        request_nonce: "document-tile-register-nonce",
        operation: "ui.workspace.register_tile",
        payload: {
          surface: "workspace_tile",
          local_id: "slides",
          tile_id: "slides",
          title: "Slides",
          scope: "document",
        },
      }),
    );
    expect(await waitForPortMessage(mainPort)).toMatchObject({ kind: "response" });

    const tile = capturedTile as WorkspaceTileConfig | null;
    if (!tile) throw new Error("workspace_tile_not_registered");

    const tileContainer = document.createElement("div");
    document.body.append(tileContainer);
    tile.render(tileContainer, {
      tileInstanceId: "tile-instance-document",
      documentId: "doc-marp",
      action: {
        actionId: "document-render-action",
        tileId: tile.id,
        tileInstanceId: "tile-instance-document",
        documentId: "doc-marp",
        issuedAtMs: Date.now(),
      },
    });

    const uiIframe = await waitForIframe(tileContainer);
    const uiPort = connectIframe(controller!.router, uiIframe);
    const renderRequest = (await waitForPortMessage(uiPort)) as PluginHostRpcRequestEnvelope;
    expect(renderRequest).toMatchObject({
      kind: "request",
      operation: "ui.workspace_tile.render",
      execution_context_id: expect.any(String),
      resource: { document_id: "doc-marp" },
      payload: {
        tile_id: "slides",
        tile_instance_id: "tile-instance-document",
        document_id: "doc-marp",
      },
    });
    if (typeof renderRequest.execution_context_id !== "string") {
      throw new Error("workspace_tile_execution_context_missing");
    }
    expect(auditSink).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "plugin.ui.invocation.accepted",
        operation: "ui.workspace_tile.render",
        payloadKind: "ui.workspace_tile_render",
        plaintextScopeKind: "active_document",
        requestId: "document-render-action",
        executionContextId: null,
        resourceRef: { document_id: "doc-marp" },
        result: "allow",
      }),
    );

    uiPort.postMessage(
      runtimePathRequestEnvelope({
        request_id: "document-tile-no-context-read",
        request_nonce: "document-tile-no-context-read-nonce",
        operation: "documents.getActiveDocument",
        frame_generation: 2,
        resource: renderRequest.resource,
      }),
    );
    expect(await waitForPortMessage(uiPort)).toMatchObject({
      kind: "error",
      request_id: "document-tile-no-context-read",
      error: { code: "execution_context_required" },
    });

    uiPort.postMessage(
      runtimePathRequestEnvelope({
        request_id: "document-tile-read",
        request_nonce: "document-tile-read-nonce",
        operation: "documents.getActiveDocument",
        frame_generation: 2,
        execution_context_id: renderRequest.execution_context_id,
        resource: renderRequest.resource,
      }),
    );
    expect(await waitForPortMessage(uiPort)).toMatchObject({
      kind: "response",
      request_id: "document-tile-read",
      payload: {
        document_id: "doc-marp",
        title: "Slides",
        plaintext: "# Slide\n\nhello",
      },
    });
    expect(getDocumentById).toHaveBeenCalledWith("doc-marp");
    expect(releaseDocument).toHaveBeenCalledTimes(1);

    uiPort.postMessage({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: renderRequest.request_id,
      payload: { rendered: true },
    });

    path.destroy("test_destroy");
    tileContainer.remove();
    container.remove();
    dispose();
  });

  it("does not invoke document-scoped workspace tile render when pre-invoke audit fails", async () => {
    let controller: PluginHostRuntimeController;
    let capturedTile: WorkspaceTileConfig | null = null;
    const auditSink = vi.fn((event) => event.type !== "plugin.ui.invocation.accepted");
    const app = createTestApp({
      documents: {
        getActiveDocument: () => null,
        getSelectedDocuments: () => [],
        queryWorkspaceDocuments: () => [],
        getDocumentList: () => [
          { id: "doc-marp", title: "Slides", docType: "document", archivedAt: null },
        ],
        getDocumentById: vi.fn(async () => ({
          id: "doc-marp",
          title: "Slides",
          text: "# Slide\n\nhello",
        })),
        getActiveDocumentText: () => null,
        openDocument: () => undefined,
        createDocument: async () => "document-new",
        on: () => ({}) as never,
        offref: () => undefined,
      } as unknown as App["documents"],
      workspace: {
        addCommand: (command: Command) => command,
        removeCommand: () => undefined,
        listCommands: () => [],
        addStatusBarItem: () => document.createElement("div"),
        addSidebarPanel: () => undefined,
        removeSidebarPanel: () => undefined,
        addWorkspaceTile: (tile: WorkspaceTileConfig) => {
          capturedTile = tile;
        },
        openWorkspaceTile: () => undefined,
        removeWorkspaceTile: () => {
          capturedTile = null;
        },
        getWorkspaceTiles: () => (capturedTile ? [capturedTile] : []),
        addAuxiliaryPane: () => undefined,
        removeAuxiliaryPane: () => undefined,
        getAuxiliaryPanes: () => [],
        addSettingTab: () => undefined,
        removeSettingTab: () => undefined,
        removeSurfacesByOwner: () => undefined,
      } as unknown as App["workspace"],
    });
    const sandboxDocumentSessionLoader = vi.fn(async () => ({
      sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/document-tile-render-audit-denied",
      bootNonce: "boot-document-tile-denied",
      frameGeneration: 2,
      frameScope: "secondary" as const,
      capabilityGrantId: "capability-grant-1",
    }));
    const dispose = createRoot((disposeRoot) => {
      controller = usePluginHostRpc(undefined, app);
      return disposeRoot;
    });
    const container = document.createElement("div");
    document.body.append(container);

    const path = await controller!.createRuntimePath({
      container,
      handlers: [],
      pluginId: "plugin.example",
      packageId: "package.example",
      applicationId: "00000000-0000-4000-8000-000000000001",
      activationId: "activation.example",
      ownerScopeKind: "workspace",
      userId: "user.example",
      deviceId: "device.example",
      workspaceId: "00000000-0000-4000-8000-000000000002",
      bundleHash: "bundle-hash-1",
      manifestHash: "manifest-hash-1",
      capabilityId: "capability-1",
      capabilityGrantId: "capability-grant-1",
      stateHeadHash: "state-head-1",
      consentHeadHash: "consent-head-1",
      frameGeneration: 1,
      bootNonce: "boot-parent-one",
      sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/parent-session-one",
      sandboxDocumentSessionLoader,
      consentEpoch: 1,
      permissions: ["ui:workspace_tile", "document:read:active"],
      documentScope: { activeDocumentReadAllowed: true, activeDocumentId: "doc-marp" },
      validateSession: () => null,
      auditSink,
      title: "Runtime Plugin",
    });
    const mainPort = connectIframe(controller!.router, path.runtime.iframe);

    mainPort.postMessage(
      runtimePathRequestEnvelope({
        request_id: "document-tile-register-denied",
        request_nonce: "document-tile-register-denied-nonce",
        operation: "ui.workspace.register_tile",
        payload: {
          surface: "workspace_tile",
          local_id: "slides",
          tile_id: "slides",
          title: "Slides",
          scope: "document",
        },
      }),
    );
    expect(await waitForPortMessage(mainPort)).toMatchObject({ kind: "response" });

    const tile = capturedTile as WorkspaceTileConfig | null;
    if (!tile) throw new Error("workspace_tile_not_registered");

    const tileContainer = document.createElement("div");
    document.body.append(tileContainer);
    tile.render(tileContainer, {
      tileInstanceId: "tile-instance-document-denied",
      documentId: "doc-marp",
      action: {
        actionId: "document-render-action-denied",
        tileId: tile.id,
        tileInstanceId: "tile-instance-document-denied",
        documentId: "doc-marp",
        issuedAtMs: Date.now(),
      },
    });

    const uiIframe = await waitForIframe(tileContainer);
    const uiPort = connectIframe(controller!.router, uiIframe);
    await expect(waitForNoPortMessage(uiPort)).resolves.toBeUndefined();
    expect(auditSink).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "plugin.ui.invocation.accepted",
        operation: "ui.workspace_tile.render",
        payloadKind: "ui.workspace_tile_render",
        requestId: "document-render-action-denied",
        executionContextId: null,
        resourceRef: { document_id: "doc-marp" },
      }),
    );

    path.destroy("test_destroy");
    tileContainer.remove();
    container.remove();
    dispose();
  });

  it("mirrors plugin UI commands into the Host command surface with runtime owner metadata", async () => {
    let controller: PluginHostRuntimeController;
    const dispose = createRoot((disposeRoot) => {
      controller = usePluginHostRpc(undefined, createTestApp());
      return disposeRoot;
    });
    const container = document.createElement("div");
    document.body.append(container);

    const path = await controller!.createRuntimePath({
      container,
      handlers: [
        {
          operation: "plugin.ui.echo",
          handler: () => ({ ok: true }),
          policy: { plaintext: null },
        },
      ],
      pluginId: "plugin.example",
      packageId: "package.example",
      applicationId: "00000000-0000-4000-8000-000000000001",
      activationId: "activation.example",
      ownerScopeKind: "workspace",
      userId: "user.example",
      deviceId: "device.example",
      workspaceId: "00000000-0000-4000-8000-000000000002",
      bundleHash: "bundle-hash-1",
      manifestHash: "manifest-hash-1",
      capabilityId: "capability-1",
      capabilityGrantId: "capability-grant-1",
      ...runtimeSandboxDocumentSession("ui-command-owner-runtime"),
      consentEpoch: 1,
      permissions: ["ui:command"],
      auditSink: () => true,
      validateSession: () => null,
      title: "Runtime Plugin",
    });

    const postMessageSpy = vi.spyOn(path.runtime.session.contentWindow, "postMessage");
    controller!.router.handleWindowMessage({
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
      runtimePathRequestEnvelope({
        request_id: "ui-command-register",
        request_nonce: "ui-command-register-nonce",
        operation: "ui.command.register",
        payload: {
          surface: "command",
          local_id: "open.panel",
          title: "Open panel",
        },
      }),
    );

    expect(await waitForPortMessage(port)).toMatchObject({ kind: "response" });
    const registeredCommand = workspaceManager
      .listCommands()
      .find((command) => command.name === "Open panel");
    expect(registeredCommand?.owner).toMatchObject({
      kind: "third_party",
      pluginId: "plugin.example",
      packageId: "package.example",
      applicationId: "00000000-0000-4000-8000-000000000001",
      activationId: "activation.example",
      ownerScopeKind: "workspace",
      userId: "user.example",
      deviceId: "device.example",
      workspaceId: "00000000-0000-4000-8000-000000000002",
      capabilityGrantId: "capability-grant-1",
    });

    path.destroy("test_destroy");
    expect(
      workspaceManager.listCommands().some((command) => command.id === registeredCommand?.id),
    ).toBe(false);
    container.remove();
    dispose();
  });

  it("uses fresh server-issued sandbox sessions for UI iframe runtimes", async () => {
    let controller: PluginHostRuntimeController;
    const sandboxDocumentSessionLoader = vi.fn(async () => ({
      sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/ui-session-one",
      bootNonce: "boot-ui-one",
      frameGeneration: 2,
      frameScope: "secondary" as const,
      capabilityGrantId: "capability-grant-1",
    }));
    const dispose = createRoot((disposeRoot) => {
      controller = usePluginHostRpc(undefined, createTestApp());
      return disposeRoot;
    });
    const container = document.createElement("div");
    document.body.append(container);

    const path = await controller!.createRuntimePath({
      container,
      handlers: [
        {
          operation: "plugin.ui.echo",
          handler: () => ({ ok: true }),
          policy: { plaintext: null },
        },
      ],
      pluginId: "plugin.example",
      packageId: "package.example",
      applicationId: "00000000-0000-4000-8000-000000000001",
      activationId: "activation.example",
      ownerScopeKind: "workspace",
      userId: "user.example",
      deviceId: "device.example",
      workspaceId: "00000000-0000-4000-8000-000000000002",
      bundleHash: "bundle-hash-1",
      manifestHash: "manifest-hash-1",
      capabilityId: "capability-1",
      capabilityGrantId: "capability-grant-1",
      stateHeadHash: "state-head-1",
      consentHeadHash: "consent-head-1",
      frameGeneration: 1,
      bootNonce: "boot-parent-one",
      sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/parent-session-one",
      sandboxDocumentSessionLoader,
      consentEpoch: 1,
      permissions: ["ui:sidebar", "ui:command"],
      validateSession: () => null,
      auditSink: () => true,
      title: "Runtime Plugin",
    });
    const mainPort = connectIframe(controller!.router, path.runtime.iframe);

    mainPort.postMessage(
      runtimePathRequestEnvelope({
        request_id: "sidebar-register",
        request_nonce: "sidebar-register-nonce",
        operation: "ui.sidebar.register_panel",
        payload: {
          surface: "sidebar_panel",
          local_id: "outline",
          panel_id: "outline",
          title: "Outline",
          allowed_locations: ["right"],
        },
      }),
    );
    expect(await waitForPortMessage(mainPort)).toMatchObject({ kind: "response" });

    const panel = workspaceManager
      .getSidebarPanels()()
      .find((entry) => entry.title === "Outline");
    if (!panel?.render) throw new Error("sidebar_panel_render_missing");
    const panelContainer = document.createElement("div");
    document.body.append(panelContainer);
    panel.render(panelContainer);
    const uiIframe = await waitForIframe(panelContainer);
    expect(uiIframe.hasAttribute("srcdoc")).toBe(false);
    expect(uiIframe.getAttribute("src")).toBe(
      "/api/plugin-runtime/sandbox-documents/ui-session-one",
    );
    expect(sandboxDocumentSessionLoader).toHaveBeenCalledWith({
      workspaceId: "00000000-0000-4000-8000-000000000002",
      applicationId: "00000000-0000-4000-8000-000000000001",
      stateHeadHash: "state-head-1",
      consentHeadHash: "consent-head-1",
      capabilityGrantId: "capability-grant-1",
      frameScope: "secondary",
    });
    expect(sessionForIframe(controller!.router, uiIframe)?.frameGeneration).toBe(2);
    expect(sessionForIframe(controller!.router, uiIframe)?.capabilityGrantId).toBe(
      "capability-grant-1",
    );
    await waitForOwnerHandler(controller!.router, "plugin.ui.echo");
    const uiPort = connectIframe(controller!.router, uiIframe);

    uiPort.postMessage(
      runtimePathRequestEnvelope({
        request_id: "ui-echo",
        request_nonce: "ui-echo-nonce",
        operation: "plugin.ui.echo",
        frame_generation: 2,
        capability_grant_id: "capability-grant-1",
      }),
    );
    const uiResponse = await waitForPortMessage(uiPort);
    expect(uiResponse).toMatchObject({
      kind: "response",
      payload: { ok: true },
    });

    uiPort.postMessage(
      runtimePathRequestEnvelope({
        request_id: "ui-iframe-command-register",
        request_nonce: "ui-iframe-command-register-nonce",
        operation: "ui.command.register",
        frame_generation: 2,
        capability_grant_id: "capability-grant-1",
        payload: {
          surface: "command",
          local_id: "iframe.command",
          title: "Iframe command",
        },
      }),
    );
    expect(await waitForPortMessage(uiPort)).toMatchObject({ kind: "error" });
    const iframeCommand = workspaceManager
      .listCommands()
      .find((command) => command.name === "Iframe command");
    expect(iframeCommand).toBeUndefined();

    controller!.router.closeByCapabilityGrant("capability-grant-1", "hidden_runtime_closed");
    await waitForNoIframe(panelContainer);
    expect(
      workspaceManager.listCommands().some((command) => command.name === "Iframe command"),
    ).toBe(false);

    path.destroy("test_destroy");
    panelContainer.remove();
    container.remove();
    dispose();
  });

  it("does not mount UI iframe runtimes without a server-issued secondary sandbox session", async () => {
    let controller: PluginHostRuntimeController;
    const sandboxDocumentSessionLoader = vi.fn(async () => ({
      sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/ui-session-one",
      bootNonce: "boot-ui-one",
      frameGeneration: 2,
      frameScope: "secondary" as const,
      capabilityGrantId: "capability-grant-1",
    }));
    const dispose = createRoot((disposeRoot) => {
      controller = usePluginHostRpc(undefined, createTestApp());
      return disposeRoot;
    });
    const container = document.createElement("div");
    document.body.append(container);

    const path = await controller!.createRuntimePath({
      container,
      handlers: [],
      pluginId: "plugin.example",
      packageId: "package.example",
      applicationId: "00000000-0000-4000-8000-000000000001",
      activationId: "activation.example",
      ownerScopeKind: "workspace",
      userId: "user.example",
      deviceId: "device.example",
      workspaceId: "00000000-0000-4000-8000-000000000002",
      bundleHash: "bundle-hash-1",
      manifestHash: "manifest-hash-1",
      capabilityId: "capability-1",
      capabilityGrantId: "capability-grant-1",
      frameGeneration: 1,
      bootNonce: "boot-parent-one",
      sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/parent-session-one",
      sandboxDocumentSessionLoader,
      consentEpoch: 1,
      permissions: ["ui:sidebar"],
      validateSession: () => null,
      auditSink: () => true,
      title: "Runtime Plugin",
    });
    const mainPort = connectIframe(controller!.router, path.runtime.iframe);

    mainPort.postMessage(
      runtimePathRequestEnvelope({
        request_id: "sidebar-register",
        request_nonce: "sidebar-register-nonce",
        operation: "ui.sidebar.register_panel",
        payload: {
          surface: "sidebar_panel",
          local_id: "outline",
          panel_id: "outline",
          title: "Outline",
          allowed_locations: ["right"],
        },
      }),
    );
    expect(await waitForPortMessage(mainPort)).toMatchObject({ kind: "response" });

    const panel = workspaceManager
      .getSidebarPanels()()
      .find((entry) => entry.title === "Outline");
    if (!panel?.render) throw new Error("sidebar_panel_render_missing");
    const panelContainer = document.createElement("div");
    document.body.append(panelContainer);
    panel.render(panelContainer);

    await new Promise((resolve) => setTimeout(resolve, 5));
    expect(panelContainer.querySelector("iframe")).toBeNull();
    expect(sandboxDocumentSessionLoader).not.toHaveBeenCalled();

    path.destroy("test_destroy");
    panelContainer.remove();
    container.remove();
    dispose();
  });

  it("connects production document, renderer, and editor plaintext handlers fail-closed", async () => {
    let controller: PluginHostRuntimeController;
    const dispose = createRoot((disposeRoot) => {
      controller = usePluginHostRpc(undefined, createTestApp());
      return disposeRoot;
    });
    const container = document.createElement("div");
    document.body.append(container);

    const path = await controller!.createRuntimePath({
      container,
      handlers: [],
      pluginId: "plugin.example",
      packageId: "package.example",
      applicationId: "00000000-0000-4000-8000-000000000001",
      activationId: "activation.example",
      ownerScopeKind: "workspace",
      userId: "user.example",
      deviceId: "device.example",
      workspaceId: "00000000-0000-4000-8000-000000000002",
      bundleHash: "bundle-hash-1",
      manifestHash: "manifest-hash-1",
      capabilityId: "capability-1",
      capabilityGrantId: "capability-grant-1",
      ...runtimeSandboxDocumentSession("plaintext-fail-closed-runtime"),
      consentEpoch: 1,
      permissions: [
        "document:read:active",
        "document:read:selected",
        "plaintext:render:block:chart",
        "editor:selection:read",
      ],
      documentScope: {
        activeDocumentReadAllowed: true,
        activeDocumentId: "doc-active",
        selectedDocumentsReadAllowed: true,
        selectedDocumentIds: ["doc-active"],
      },
      rendererSlots: [{ kind: "block", type: "chart" }],
      validateSession: () => null,
      auditSink: () => true,
      title: "Runtime Plugin",
    });

    const postMessageSpy = vi.spyOn(path.runtime.session.contentWindow, "postMessage");
    controller!.router.handleWindowMessage({
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

    for (const request of [
      runtimePathRequestEnvelope({
        request_id: "document-active",
        request_nonce: "document-active-nonce",
        operation: "documents.getActiveDocument",
        resource: { document_id: "doc-active" },
      }),
      runtimePathRequestEnvelope({
        request_id: "document-selected",
        request_nonce: "document-selected-nonce",
        operation: "documents.getSelectedDocuments",
        resource: { selected_document_ids: ["doc-active"] },
      }),
      runtimePathRequestEnvelope({
        request_id: "renderer-source",
        request_nonce: "renderer-source-nonce",
        operation: "renderer.getSource",
        resource: { document_id: "doc-active", block_id: "block-one" },
      }),
      runtimePathRequestEnvelope({
        request_id: "editor-selection",
        request_nonce: "editor-selection-nonce",
        operation: "editor.getSelection",
        resource: { document_id: "doc-active", editor_id: "editor-one" },
      }),
    ]) {
      port.postMessage(request);
      expect(await waitForPortMessage(port)).toMatchObject({
        kind: "error",
        error: { code: "execution_context_required" },
      });
    }

    path.destroy("test_destroy");
    container.remove();
    dispose();
  });

  it("materializes semantic active and selected document scopes at the Host boundary", async () => {
    const activeEditor = { getValue: () => "active plaintext" };
    const selectedEditor = { getValue: () => "selected plaintext" };
    let controller: PluginHostRuntimeController;
    const dispose = createRoot((disposeRoot) => {
      controller = usePluginHostRpc(
        undefined,
        createTestApp({
          documents: {
            getActiveDocument: () => ({
              id: "doc-active",
              title: "Active",
              editor: activeEditor,
            }),
            getSelectedDocuments: () => [
              {
                id: "doc-selected",
                title: "Selected",
                editor: selectedEditor,
              },
            ],
            getDocumentById: async (documentId: string) => {
              if (documentId !== "doc-selected") return null;
              return {
                id: "doc-selected",
                title: "Selected",
                text: "selected plaintext",
                release: vi.fn(),
              };
            },
          } as unknown as App["documents"],
        }),
      );
      return disposeRoot;
    });
    const container = document.createElement("div");
    document.body.append(container);

    const path = await controller!.createRuntimePath({
      container,
      handlers: [],
      pluginId: "plugin.example",
      packageId: "package.example",
      applicationId: "00000000-0000-4000-8000-000000000001",
      activationId: "activation.example",
      ownerScopeKind: "workspace",
      userId: "user.example",
      deviceId: "device.example",
      workspaceId: "00000000-0000-4000-8000-000000000002",
      bundleHash: "bundle-hash-1",
      manifestHash: "manifest-hash-1",
      capabilityId: "capability-1",
      capabilityGrantId: "capability-grant-1",
      ...runtimeSandboxDocumentSession("semantic-document-scope-runtime"),
      consentEpoch: 1,
      permissions: ["document:read:active", "document:read:selected"],
      documentScope: {
        activeDocumentReadAllowed: true,
        selectedDocumentsReadAllowed: true,
      },
      validateSession: () => null,
      auditSink: () => true,
      title: "Runtime Plugin",
    });

    expect(path.runtime.session.documentScope).toMatchObject({
      activeDocumentReadAllowed: true,
      activeDocumentId: "doc-active",
      selectedDocumentsReadAllowed: true,
      selectedDocumentIds: ["doc-selected"],
    });

    const port = connectIframe(controller!.router, path.runtime.iframe);

    port.postMessage(
      runtimePathRequestEnvelope({
        request_id: "active-current",
        request_nonce: "active-current-nonce",
        operation: "documents.getActiveDocument",
        resource: { document_id: "doc-active" },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      error: { code: "execution_context_required" },
    });

    port.postMessage(
      runtimePathRequestEnvelope({
        request_id: "active-stale",
        request_nonce: "active-stale-nonce",
        operation: "documents.getActiveDocument",
        resource: { document_id: "doc-stale" },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      error: { code: "document_scope_denied" },
    });

    port.postMessage(
      runtimePathRequestEnvelope({
        request_id: "selected-current",
        request_nonce: "selected-current-nonce",
        operation: "documents.getSelectedDocuments",
        resource: { selected_document_ids: ["doc-selected"] },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      error: { code: "execution_context_required" },
    });

    port.postMessage(
      runtimePathRequestEnvelope({
        request_id: "selected-stale",
        request_nonce: "selected-stale-nonce",
        operation: "documents.getSelectedDocuments",
        resource: { selected_document_ids: ["doc-stale"] },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      error: { code: "document_scope_denied" },
    });

    path.destroy("test_destroy");
    container.remove();
    dispose();
  });

  it("closes old-workspace plugin Host RPC sessions when the app workspace changes", async () => {
    let setWorkspaceId: Setter<string>;
    const dispose = createRoot((disposeRoot) => {
      const [workspaceId, setCurrentWorkspaceId] = createSignal("workspace-alpha");
      setWorkspaceId = setCurrentWorkspaceId;
      usePluginHostRpc(workspaceId, createTestApp());
      return disposeRoot;
    });
    await Promise.resolve();

    const router = getPluginHostMessageRouter();
    const oldWorkspaceSession = createConnectedSession(
      router,
      "workspace-alpha",
      "00000000-0000-4000-8000-000000000101",
    );
    const nextWorkspaceSession = createConnectedSession(
      router,
      "workspace-beta",
      "00000000-0000-4000-8000-000000000102",
    );

    expect(oldWorkspaceSession.connected).toBe(true);
    expect(nextWorkspaceSession.connected).toBe(true);
    workspaceManager.addCommand({
      id: "old-workspace-plugin-command",
      name: "Old workspace plugin command",
      owner: thirdPartySurfaceOwner("workspace-alpha", "00000000-0000-4000-8000-000000000101"),
    });
    workspaceManager.addCommand({
      id: "next-workspace-plugin-command",
      name: "Next workspace plugin command",
      owner: thirdPartySurfaceOwner("workspace-beta", "00000000-0000-4000-8000-000000000102"),
    });

    setWorkspaceId!("workspace-beta");
    await Promise.resolve();

    expect(oldWorkspaceSession.connected).toBe(false);
    expect(nextWorkspaceSession.connected).toBe(true);
    expect(
      workspaceManager
        .listCommands()
        .some((command) => command.id === "old-workspace-plugin-command"),
    ).toBe(false);
    expect(
      workspaceManager
        .listCommands()
        .some((command) => command.id === "next-workspace-plugin-command"),
    ).toBe(true);
    dispose();
  });
});

function thirdPartySurfaceOwner(workspaceId: string, applicationId: string): WorkspaceSurfaceOwner {
  return {
    kind: "third_party",
    pluginId: "plugin.example",
    packageId: "package.example",
    applicationId,
    activationId: "activation.example",
    ownerScopeKind: "workspace",
    workspaceId,
    userId: "user.example",
    deviceId: "device.example",
    bundleHash: "bundle-hash-1",
    manifestHash: "manifest-hash-1",
    frameGeneration: 1,
    consentEpoch: 1,
    capabilityGrantId: `capability-grant-${applicationId}`,
  };
}

function runtimePathRequestEnvelope(
  overrides: Partial<PluginHostRpcRequestEnvelope> = {},
): PluginHostRpcRequestEnvelope {
  return {
    protocol: PLUGIN_HOST_RPC_PROTOCOL,
    version: PLUGIN_HOST_RPC_VERSION,
    kind: "request",
    request_id: "runtime-path-request",
    request_nonce: "runtime-path-nonce",
    plugin_id: "plugin.example",
    package_id: "package.example",
    application_id: "00000000-0000-4000-8000-000000000001",
    activation_id: "activation.example",
    workspace_id: "00000000-0000-4000-8000-000000000002",
    bundle_hash: "bundle-hash-1",
    manifest_hash: "manifest-hash-1",
    capability_id: "capability-1",
    capability_grant_id: "capability-grant-1",
    consent_epoch: 1,
    frame_generation: 1,
    operation: "plugin.ping",
    ...overrides,
    owner_scope_kind: overrides.owner_scope_kind ?? "workspace",
    user_id: overrides.user_id ?? "user.example",
    device_id: overrides.device_id ?? "device.example",
  };
}

function connectIframe(router: PluginHostMessageRouter, iframe: HTMLIFrameElement): MessagePort {
  const session = sessionForIframe(router, iframe);
  expect(session).toBeDefined();
  const postMessageSpy = vi.spyOn(session!.contentWindow, "postMessage");
  router.handleWindowMessage({
    data: {
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "boot-ready",
    },
    source: session?.contentWindow,
  } as unknown as MessageEvent);
  const postMessageCalls = postMessageSpy.mock.calls as unknown as [
    unknown,
    string,
    Transferable[],
  ][];
  const port = postMessageCalls[0]?.[2]?.[0] as MessagePort | undefined;
  assertMessagePort(port);
  port.start();
  acknowledgeBoot(session!);
  return port;
}

async function waitForIframe(container: HTMLElement): Promise<HTMLIFrameElement> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const iframe = container.querySelector("iframe");
    if (iframe instanceof HTMLIFrameElement && iframe.hasAttribute("src")) return iframe;
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  const iframe = container.querySelector("iframe");
  expect(iframe).toBeInstanceOf(HTMLIFrameElement);
  return iframe as HTMLIFrameElement;
}

async function waitForNoIframe(container: HTMLElement): Promise<void> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (!container.querySelector("iframe")) return;
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  expect(container.querySelector("iframe")).toBeNull();
}

async function waitForOwnerHandler(
  router: PluginHostMessageRouter,
  operation: string,
): Promise<void> {
  const ownerHandlers = (router as unknown as { ownerHandlers: Map<string, unknown> })
    .ownerHandlers;
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (Array.from(ownerHandlers.keys()).some((key) => key.includes(operation))) return;
    await new Promise((resolve) => setTimeout(resolve, 1));
  }
  expect(Array.from(ownerHandlers.keys()).some((key) => key.includes(operation))).toBe(true);
}

function sessionForIframe(router: PluginHostMessageRouter, iframe: HTMLIFrameElement) {
  return Array.from(
    (
      router as unknown as {
        sessionsById: Map<
          string,
          {
            bootNonce: string;
            frameGeneration: number;
            capabilityGrantId: string;
            contentWindow: Window;
            frameElement: unknown;
          }
        >;
      }
    ).sessionsById.values(),
  ).find((session) => session.frameElement === iframe);
}

function networkRequestEnvelope(
  overrides: Partial<PluginHostRpcRequestEnvelope> = {},
): PluginHostRpcRequestEnvelope {
  return runtimePathRequestEnvelope({
    request_id: "network-request",
    request_nonce: "network-nonce",
    operation: "app.network.fetch",
    payload: {
      endpoint_id: "unknown",
      route: "direct",
      method: "GET",
    },
    ...overrides,
  });
}

function runtimeAuditEvent(workspaceId: string) {
  return {
    protocol: "refmd.security-audit-event",
    version: 1,
    event_id: "audit-event-one",
    class: "security_runtime",
    type: "plugin.sandbox.loaded",
    actor: {
      user_id: "user-one",
      device_id: "device-one",
      session_id: "session-one",
      principal_kind: "user",
      principal_id: "user-one",
    },
    pluginId: "plugin.example",
    packageId: "package.example",
    applicationId: "application-one",
    activationId: "activation.example",
    ownerScopeKind: "workspace",
    capabilityGrantId: "capability-grant-one",
    consentEpoch: 1,
    frameGeneration: 1,
    workspaceId,
    bundleHash: "bundle-hash",
    manifestHash: "manifest-hash",
    capabilityId: "capability-one",
    requestId: null,
    executionContextId: null,
    contextKind: null,
    payloadKind: "unknown",
    plaintextScopeKind: "none",
    plaintextBytes: 0,
    operation: "plugin.sandbox.load",
    resourceRef: null,
    result: "allow",
    scope: {
      workspace_id: workspaceId,
      document_id: null,
      share_id: null,
    },
    resource: {
      kind: "plugin",
      id: "plugin.example",
      version_hash: "bundle-hash",
    },
    action: {
      operation: "plugin.sandbox.load",
      result: "completed",
      reason_code: null,
    },
    sensitivity: {
      plaintext_scope_kind: "none",
      plaintext_bytes: 0,
      egress_bytes: 0,
      storage_bytes: 0,
    },
    correlation: {
      request_id: null,
      capability_id: "capability-one",
      execution_context_id: null,
      authority_event_ref: null,
    },
    created_at: "2026-05-24T00:00:00.000Z",
  } as const;
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

function waitForNoPortMessage(port: MessagePort, timeoutMs = 100): Promise<void> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup();
      resolve();
    }, timeoutMs);
    const cleanup = () => {
      clearTimeout(timeout);
      port.removeEventListener("message", listener as EventListener);
    };
    const listener = (event: MessageEvent) => {
      if (isBootContextMessage(event.data)) return;
      cleanup();
      reject(new Error(`unexpected_port_message:${String(event.data)}`));
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
