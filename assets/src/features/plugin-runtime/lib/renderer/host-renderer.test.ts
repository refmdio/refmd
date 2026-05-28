import { describe, expect, it } from "vitest";
import {
  PLUGIN_HOST_RPC_PROTOCOL,
  PLUGIN_HOST_RPC_VERSION,
  PluginHostMessageRouter,
  type PluginHostFrameWindow,
  type PluginHostRpcRequestEnvelope,
  type PluginHostRpcResponseEnvelope,
} from "../host-rpc/host-rpc";
import {
  createPluginRendererSourceStore,
  issuePluginRendererSource,
  notifyPluginRendererResize,
  notifyPluginRendererTheme,
  registerPluginHostRendererHandlers,
  requestPluginRendererRender,
} from "../renderer/host-renderer";
import type { PluginAuditEvent } from "../capability/capability-enforcement";

class FakeFrameWindow implements PluginHostFrameWindow {
  readonly messages: { message: unknown; targetOrigin: string; transfer: Transferable[] }[] = [];

  postMessage(message: unknown, targetOrigin: string, transfer: Transferable[] = []): void {
    this.messages.push({ message, targetOrigin, transfer });
  }
}

function createIdFactory(): () => string {
  let nextId = 0;
  return () => `renderer-test-id-${++nextId}`;
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

function createRouterWithRenderer(store = createPluginRendererSourceStore()): {
  router: PluginHostMessageRouter;
  store: ReturnType<typeof createPluginRendererSourceStore>;
} {
  const router = new PluginHostMessageRouter({
    windowTarget: { addEventListener() {}, removeEventListener() {} },
    idFactory: createIdFactory(),
  });
  registerPluginHostRendererHandlers(router, {
    slots: [{ kind: "block", type: "mermaid" }],
    sourceStore: store,
    themeSnapshot: () => ({
      colorScheme: "dark",
      foreground: "#ffffff",
      background: "#000000",
      accent: "#66ccff",
    }),
  });
  return { router, store };
}

function boot(
  router: PluginHostMessageRouter,
  auditEvents: PluginAuditEvent[] = [],
  permissions: Parameters<PluginHostMessageRouter["createSession"]>[0]["permissions"] = [
    "plaintext:render:block:mermaid",
  ],
) {
  const frame = new FakeFrameWindow();
  const session = router.createSession({
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
    request_id: "renderer-request",
    request_nonce: `renderer-nonce-${Math.random()}`,
    plugin_id: "plugin.example",
    package_id: "package.example",
    application_id: "00000000-0000-4000-8000-000000000001",
    activation_id: "activation.example",
    owner_scope_kind: "workspace",
    user_id: "user.example",
    device_id: "device.example",
    workspace_id: "00000000-0000-4000-8000-000000000002",
    bundle_hash: "bundle-hash-1",
    manifest_hash: "manifest-hash-1",
    capability_id: "capability-1",
    capability_grant_id: "capability-grant-1",
    consent_epoch: 3,
    frame_generation: 7,
    operation: "renderer.getSource",
    ...overrides,
  };
}

function responseEnvelope(
  requestId: string,
  payload: unknown = { ok: true },
): PluginHostRpcResponseEnvelope {
  return {
    protocol: PLUGIN_HOST_RPC_PROTOCOL,
    version: PLUGIN_HOST_RPC_VERSION,
    kind: "response",
    request_id: requestId,
    payload,
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

describe("plugin Host RPC renderer surface", () => {
  it("delivers block renderer source through typed plaintext execution context", async () => {
    const auditEvents: PluginAuditEvent[] = [];
    const { router, store } = createRouterWithRenderer();
    const { session, port } = boot(router, auditEvents);
    const source = issuePluginRendererSource({
      session,
      store,
      slot: { kind: "block", type: "mermaid" },
      documentId: "document-1",
      blockId: "block-1",
      source: "graph TD; A-->B",
      maxBytes: 512,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "renderer-source",
        request_nonce: "renderer-source-nonce",
        execution_context_id: source.executionContextId,
        resource: { document_id: "document-1", block_id: "block-1", max_bytes: 512 },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      request_id: "renderer-source",
      payload: {
        kind: "block",
        type: "mermaid",
        document_id: "document-1",
        block_id: "block-1",
        source: "graph TD; A-->B",
        theme: {
          colorScheme: "dark",
        },
      },
    });
    expect(auditEvents.at(-1)).toMatchObject({
      type: "plugin.plaintext_payload.delivered",
      operation: "renderer.getSource",
      contextKind: "renderer_invocation",
      plaintextScopeKind: "block",
    });
  });

  it("rejects renderer source access without the matching slot capability", async () => {
    const auditEvents: PluginAuditEvent[] = [];
    const { router, store } = createRouterWithRenderer();
    const { session, port } = boot(router, auditEvents, ["plaintext:render:block:chart"]);
    const source = issuePluginRendererSource({
      session,
      store,
      slot: { kind: "block", type: "mermaid" },
      documentId: "document-1",
      blockId: "block-1",
      source: "graph TD; A-->B",
      maxBytes: 512,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "renderer-denied",
        request_nonce: "renderer-denied-nonce",
        execution_context_id: source.executionContextId,
        resource: { document_id: "document-1", block_id: "block-1", max_bytes: 512 },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      request_id: "renderer-denied",
      error: { code: "permission_denied" },
    });
  });

  it("rejects arbitrary full-document markdown renderer slot registration", () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
    });

    expect(() =>
      registerPluginHostRendererHandlers(router, {
        slots: [{ kind: "block", type: "markdown" }],
        sourceStore: createPluginRendererSourceStore(),
      }),
    ).toThrowError(
      expect.objectContaining({
        code: "renderer_slot_invalid",
      }),
    );

    expect(() =>
      registerPluginHostRendererHandlers(router, {
        slots: [{ kind: "inline", type: "badge" }],
        sourceStore: createPluginRendererSourceStore(),
      }),
    ).toThrowError(
      expect.objectContaining({
        code: "renderer_slot_invalid",
      }),
    );
  });

  it("delivers every declared renderer slot instead of only the first one", async () => {
    const store = createPluginRendererSourceStore();
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    registerPluginHostRendererHandlers(router, {
      slots: [
        { kind: "block", type: "mermaid" },
        { kind: "inline", type: "code" },
      ],
      sourceStore: store,
    });
    const { session, port } = boot(
      router,
      [],
      ["plaintext:render:block:mermaid", "plaintext:render:inline:code"],
    );
    const inlineSource = issuePluginRendererSource({
      session,
      store,
      slot: { kind: "inline", type: "code" },
      documentId: "document-1",
      blockId: "inline-1",
      source: "OK",
      maxBytes: 128,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "renderer-inline-source",
        request_nonce: "renderer-inline-source-nonce",
        execution_context_id: inlineSource.executionContextId,
        resource: { document_id: "document-1", block_id: "inline-1", max_bytes: 128 },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      request_id: "renderer-inline-source",
      payload: {
        kind: "inline",
        type: "code",
        document_id: "document-1",
        source: "OK",
      },
    });
  });

  it("accepts bounded height reports without exposing a Host DOM node", async () => {
    const heightChanges: number[] = [];
    const { router, store } = createRouterWithRenderer();
    const { session, port } = boot(router);
    const source = issuePluginRendererSource({
      session,
      store,
      slot: { kind: "block", type: "mermaid" },
      documentId: "document-1",
      blockId: "block-1",
      source: "graph TD; A-->B",
      maxBytes: 512,
      onHeightChange: (height) => heightChanges.push(height),
    });

    port.postMessage(
      requestEnvelope({
        request_id: "renderer-height",
        request_nonce: "renderer-height-nonce",
        operation: "renderer.setHeight",
        payload: {
          execution_context_id: source.executionContextId,
          height: 240,
        },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      request_id: "renderer-height",
      payload: { height: 240 },
    });
    expect(heightChanges).toEqual([240]);
  });

  it("sends resize and theme notifications as Host-to-plugin messages", async () => {
    const { router, store } = createRouterWithRenderer();
    const { session, port } = boot(router);
    const source = issuePluginRendererSource({
      session,
      store,
      slot: { kind: "block", type: "mermaid" },
      documentId: "document-1",
      blockId: "block-1",
      source: "graph TD; A-->B",
      maxBytes: 512,
    });

    const resizeRequest = notifyPluginRendererResize(session, source, { width: 640, height: 320 });
    const resizeEnvelope = await waitForPortMessage(port);
    expect(resizeEnvelope).toMatchObject({
      kind: "request",
      operation: "renderer.resize",
      payload: {
        execution_context_id: source.executionContextId,
        width: 640,
        height: 320,
      },
    });
    port.postMessage(responseEnvelope((resizeEnvelope as PluginHostRpcRequestEnvelope).request_id));
    await expect(resizeRequest).resolves.toEqual({ ok: true });

    const themeRequest = notifyPluginRendererTheme(session, source, {
      colorScheme: "light",
      foreground: "#111111",
      background: "#ffffff",
      accent: "#0066cc",
    });
    const themeEnvelope = await waitForPortMessage(port);
    expect(themeEnvelope).toMatchObject({
      kind: "request",
      operation: "renderer.theme",
      payload: {
        execution_context_id: source.executionContextId,
        theme: {
          colorScheme: "light",
          foreground: "#111111",
          background: "#ffffff",
          accent: "#0066cc",
        },
      },
    });
    port.postMessage(responseEnvelope((themeEnvelope as PluginHostRpcRequestEnvelope).request_id));
    await expect(themeRequest).resolves.toEqual({ ok: true });
  });

  it("sends renderer render requests with the source byte bound resource", async () => {
    const { router, store } = createRouterWithRenderer();
    const { session, port } = boot(router);
    const source = issuePluginRendererSource({
      session,
      store,
      slot: { kind: "block", type: "mermaid" },
      documentId: "document-1",
      blockId: "block-1",
      source: "graph TD; A-->B",
      maxBytes: 512,
    });

    const renderRequest = requestPluginRendererRender(
      session,
      source,
      { kind: "block", type: "mermaid" },
      "document-1",
      "block-1",
    );
    const renderEnvelope = await waitForPortMessage(port);
    expect(renderEnvelope).toMatchObject({
      kind: "request",
      operation: "renderer.render",
      payload: {
        execution_context_id: source.executionContextId,
        kind: "block",
        type: "mermaid",
        document_id: "document-1",
        block_id: "block-1",
        max_bytes: 512,
      },
      resource: { document_id: "document-1", block_id: "block-1", max_bytes: 512 },
    });
    port.postMessage(responseEnvelope((renderEnvelope as PluginHostRpcRequestEnvelope).request_id));
    await expect(renderRequest).resolves.toEqual({ ok: true });
  });
});
