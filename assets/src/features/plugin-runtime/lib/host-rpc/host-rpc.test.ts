import { describe, expect, it, vi } from "vite-plus/test";
import {
  PLUGIN_HOST_RPC_DEFAULT_TIMEOUT_MS,
  PLUGIN_HOST_RPC_PROTOCOL,
  PLUGIN_HOST_RPC_VERSION,
  PluginHostMessageRouter,
  PluginHostRpcError,
  type PluginHostFrameLifecycleTarget,
  type PluginHostFrameWindow,
  type PluginHostRpcRequestEnvelope,
} from "../host-rpc/host-rpc";
import { mergeDefaultRuntimeHandlers } from "./document-handlers";
import {
  PLUGIN_EXECUTION_CONTEXT_MAX_TTL_MS,
  type PluginAuditEvent,
  type PluginExecutionContextIssueOptions,
  type PluginHostRpcOperationPolicy,
} from "../capability/capability-enforcement";
import hostRpcSource from "./host-rpc.ts?raw";
import pluginHostRpcSource from "./use-host-rpc.ts?raw";

const NON_PLAINTEXT_RPC_POLICY: PluginHostRpcOperationPolicy = { plaintext: null };
const ENCRYPTED_DOCUMENT_WRITE_POLICY: PluginHostRpcOperationPolicy = {
  requiredPermissions: ["document:write"],
  documentAccess: "allowed_document",
  plaintext: null,
  documentWrite: {
    operation: "document.write",
    sink: "encrypted_document_body",
    maxBytes: 64,
    rateLimit: { windowMs: 60_000, maxRequests: 2 },
    highRiskConsent: "required",
  },
};

class FakeFrameWindow implements PluginHostFrameWindow {
  readonly messages: { message: unknown; targetOrigin: string; transfer: Transferable[] }[] = [];

  postMessage(message: unknown, targetOrigin: string, transfer: Transferable[] = []): void {
    this.messages.push({ message, targetOrigin, transfer });
  }
}

class FakeFrameLifecycleTarget implements PluginHostFrameLifecycleTarget {
  private readonly listeners = new Map<"load" | "error" | "unload", Set<EventListener>>();
  removeCount = 0;

  addEventListener(type: "load" | "error" | "unload", listener: EventListener): void {
    const listeners = this.listeners.get(type) ?? new Set<EventListener>();
    listeners.add(listener);
    this.listeners.set(type, listeners);
  }

  removeEventListener(type: "load" | "error" | "unload", listener: EventListener): void {
    this.listeners.get(type)?.delete(listener);
  }

  dispatch(type: "load" | "error" | "unload"): void {
    for (const listener of this.listeners.get(type) ?? []) {
      listener(new Event(type));
    }
  }

  listenerCount(type: "load" | "error" | "unload"): number {
    return this.listeners.get(type)?.size ?? 0;
  }

  remove(): void {
    this.removeCount += 1;
  }
}

class FakeDomFrameLifecycleTarget extends FakeFrameLifecycleTarget {
  src: string | null = null;

  getAttribute(name: "src"): string | null {
    return name === "src" ? this.src : null;
  }
}

class FakeWindowTarget {
  addCount = 0;
  removeCount = 0;

  addEventListener(type: string): void {
    if (type === "message") this.addCount += 1;
  }

  removeEventListener(type: string): void {
    if (type === "message") this.removeCount += 1;
  }
}

function createIdFactory(): () => string {
  let nextId = 0;
  return () => `test-id-${++nextId}`;
}

function fakeMessageEvent(data: unknown, source: FakeFrameWindow, origin: string): MessageEvent {
  return { data, source, origin } as unknown as MessageEvent;
}

function assertMessagePort(port: MessagePort | undefined): asserts port is MessagePort {
  expect(port).toBeInstanceOf(MessagePort);
}

function boot(router: PluginHostMessageRouter, frame: FakeFrameWindow) {
  const session = router.createSession({
    pluginId: "plugin.example",
    packageId: "package.example",
    applicationId: "00000000-0000-4000-8000-000000000001",
    activationId: "activation.example",
    ownerScopeKind: "workspace",
    workspaceId: "00000000-0000-4000-8000-000000000002",
    userId: "user.example",
    deviceId: "device.example",
    bundleHash: "bundle-hash-1",
    manifestHash: "manifest-hash-1",
    capabilityId: "capability-1",
    capabilityGrantId: "capability-grant-1",
    consentEpoch: 3,
    frameGeneration: 7,
    contentWindow: frame,
  });

  const handled = router.handleWindowMessage(
    fakeMessageEvent(
      {
        protocol: PLUGIN_HOST_RPC_PROTOCOL,
        version: PLUGIN_HOST_RPC_VERSION,
        kind: "boot-ready",
      },
      frame,
      "null",
    ),
  );

  expect(handled).toBe(true);
  expect(session.connected).toBe(false);
  expect(frame.messages).toHaveLength(1);
  expect(frame.messages[0]?.targetOrigin).toBe("*");
  expect(frame.messages[0]?.message).toEqual({
    protocol: PLUGIN_HOST_RPC_PROTOCOL,
    version: PLUGIN_HOST_RPC_VERSION,
    kind: "boot-port",
    frame_generation: 7,
  });
  expect(JSON.stringify(frame.messages[0]?.message)).not.toContain("capability");
  expect(JSON.stringify(frame.messages[0]?.message)).not.toContain("runtime_context");

  const port = frame.messages[0]?.transfer[0] as MessagePort | undefined;
  assertMessagePort(port);
  port.start();
  acknowledgeBoot(session);
  expect(session.connected).toBe(true);

  return { session, port };
}

function createSessionAndBoot(
  router: PluginHostMessageRouter,
  frame: FakeFrameWindow,
  overrides: Partial<Parameters<PluginHostMessageRouter["createSession"]>[0]>,
) {
  const session = router.createSession({
    pluginId: "plugin.example",
    packageId: "package.example",
    applicationId: "00000000-0000-4000-8000-000000000001",
    activationId: "activation.example",
    workspaceId: "00000000-0000-4000-8000-000000000002",
    bundleHash: "bundle-hash-1",
    manifestHash: "manifest-hash-1",
    capabilityId: "capability-1",
    capabilityGrantId: "capability-grant-1",
    consentEpoch: 3,
    frameGeneration: 7,
    contentWindow: frame,
    ...overrides,
    ownerScopeKind: overrides.ownerScopeKind ?? "workspace",
    userId: overrides.userId ?? "user.example",
    deviceId: overrides.deviceId ?? "device.example",
  });

  const handled = router.handleWindowMessage(
    fakeMessageEvent(
      {
        protocol: PLUGIN_HOST_RPC_PROTOCOL,
        version: PLUGIN_HOST_RPC_VERSION,
        kind: "boot-ready",
      },
      frame,
      "null",
    ),
  );

  expect(handled).toBe(true);
  const port = frame.messages[0]?.transfer[0] as MessagePort | undefined;
  assertMessagePort(port);
  port.start();
  acknowledgeBoot(session);
  expect(session.connected).toBe(true);
  return { session, port };
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

function bootSessionWithOverrides(
  router: PluginHostMessageRouter,
  overrides: Partial<Parameters<PluginHostMessageRouter["createSession"]>[0]>,
) {
  return createSessionAndBoot(router, new FakeFrameWindow(), overrides);
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
    plugin_id: "plugin.example",
    package_id: "package.example",
    application_id: "00000000-0000-4000-8000-000000000001",
    activation_id: "activation.example",
    workspace_id: "00000000-0000-4000-8000-000000000002",
    bundle_hash: "bundle-hash-1",
    manifest_hash: "manifest-hash-1",
    capability_id: "capability-1",
    capability_grant_id: "capability-grant-1",
    consent_epoch: 3,
    frame_generation: 7,
    operation: "echo",
    payload: { value: 1 },
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

function waitForBootContextMessage(port: MessagePort): Promise<unknown> {
  return new Promise((resolve) => {
    const listener = (event: MessageEvent) => {
      if (!isBootContextMessage(event.data)) return;
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

function waitForPortMessages(port: MessagePort, count: number): Promise<unknown[]> {
  return new Promise((resolve) => {
    const messages: unknown[] = [];
    const listener = (event: MessageEvent) => {
      if (isBootContextMessage(event.data)) return;
      messages.push(event.data);
      if (messages.length < count) return;

      port.removeEventListener("message", listener as EventListener);
      resolve(messages);
    };
    port.addEventListener("message", listener as EventListener);
    port.start();
  });
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

describe("PluginHostMessageRouter", () => {
  it("uses the shared bounded default timeout for Host RPC sessions", () => {
    expect(PLUGIN_HOST_RPC_DEFAULT_TIMEOUT_MS).toBe(120_000);
    expect(hostRpcSource).toContain("options.timeoutMs ?? PLUGIN_HOST_RPC_DEFAULT_TIMEOUT_MS");
  });

  it("keeps workspace tile action contexts wired for selected document reads", () => {
    expect(pluginHostRpcSource).toContain('permissions.has("document:read:selected")');
    expect(pluginHostRpcSource).toContain('"selected_documents"');
    expect(pluginHostRpcSource).toContain("selected_document_ids: [options.documentId]");
  });

  it("sends plugin-facing workspace tile ids in render payloads", () => {
    expect(pluginHostRpcSource).toContain(
      "tile_id: mountOptions.resource?.tileId ?? mountOptions.id",
    );
  });

  it("transfers capability context only after authenticated boot ack", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const frame = new FakeFrameWindow();

    const { port } = boot(router, frame);

    expect(frame.messages).toHaveLength(1);
    expect(frame.messages[0]?.targetOrigin).toBe("*");
    expect(frame.messages[0]?.message).toEqual({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "boot-port",
      frame_generation: 7,
    });
    expect(JSON.stringify(frame.messages[0]?.message)).not.toContain("capability");
    expect(JSON.stringify(frame.messages[0]?.message)).not.toContain("runtime_context");

    await expect(waitForBootContextMessage(port)).resolves.toMatchObject({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "boot-context",
      frame_generation: 7,
      runtime_context: {
        plugin_id: "plugin.example",
        package_id: "package.example",
        application_id: "00000000-0000-4000-8000-000000000001",
        activation_id: "activation.example",
        owner_scope_kind: "workspace",
        workspace_id: "00000000-0000-4000-8000-000000000002",
        user_id: "user.example",
        device_id: "device.example",
        bundle_hash: "bundle-hash-1",
        manifest_hash: "manifest-hash-1",
        capability_id: "capability-1",
        capability_grant_id: "capability-grant-1",
        consent_epoch: 3,
        frame_scope: "primary",
      },
    });
  });

  it("notifies sandbox lifecycle only after authenticated boot ack", () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const frame = new FakeFrameWindow();
    const session = router.createSession({
      pluginId: "plugin.example",
      packageId: "package.example",
      applicationId: "00000000-0000-4000-8000-000000000001",
      activationId: "activation.example",
      ownerScopeKind: "workspace",
      workspaceId: "00000000-0000-4000-8000-000000000002",
      userId: "user.example",
      deviceId: "device.example",
      bundleHash: "bundle-hash-1",
      manifestHash: "manifest-hash-1",
      capabilityId: "capability-1",
      capabilityGrantId: "capability-grant-1",
      consentEpoch: 3,
      frameGeneration: 7,
      contentWindow: frame,
    });
    const authenticated = vi.fn();
    session.onBootAuthenticated(authenticated);

    expect(
      router.handleWindowMessage(
        fakeMessageEvent(
          {
            protocol: PLUGIN_HOST_RPC_PROTOCOL,
            version: PLUGIN_HOST_RPC_VERSION,
            kind: "boot-ready",
          },
          frame,
          "null",
        ),
      ),
    ).toBe(true);
    expect(authenticated).not.toHaveBeenCalled();

    acknowledgeBoot(session);
    expect(authenticated).toHaveBeenCalledTimes(1);
  });

  it("requires an explicit policy for plugin-originated Host RPC handlers", () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });

    expect(() => {
      // @ts-expect-error runtime guard is intentional for JavaScript callers.
      router.registerHandler("echo", () => "ok");
    }).toThrow(
      expect.objectContaining({
        code: "operation_policy_required",
      } satisfies Partial<PluginHostRpcError>),
    );
  });

  it("binds owner-registered handlers to the matching session owner", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const ownerA = {
      pluginId: "plugin.example",
      packageId: "package.example",
      workspaceId: "00000000-0000-4000-8000-000000000002",
      applicationId: "00000000-0000-4000-8000-000000000001",
      activationId: "activation.example",
      ownerScopeKind: "workspace",
      userId: "user.example",
      deviceId: "device.example",
      bundleHash: "bundle-hash-1",
      manifestHash: "manifest-hash-1",
      frameGeneration: 7,
      consentEpoch: 3,
      capabilityGrantId: "capability-grant-1",
    };
    const ownerB = {
      ...ownerA,
      applicationId: "00000000-0000-4000-8000-000000000101",
      activationId: "activation.example",
      capabilityGrantId: "capability-grant-2",
    };
    const ownerUpdatedBundle = {
      ...ownerA,
      bundleHash: "bundle-hash-2",
    };
    const unregisterA = router.registerOwnerHandler(
      ownerA,
      "owner.echo",
      () => ({ owner: "a" }),
      NON_PLAINTEXT_RPC_POLICY,
    );
    const unregisterB = router.registerOwnerHandler(
      ownerB,
      "owner.echo",
      () => ({ owner: "b" }),
      NON_PLAINTEXT_RPC_POLICY,
    );
    const unregisterAOnly = router.registerOwnerHandler(
      ownerA,
      "owner.aOnly",
      () => ({ owner: "a-only" }),
      NON_PLAINTEXT_RPC_POLICY,
    );
    const unregisterUpdatedBundle = router.registerOwnerHandler(
      ownerUpdatedBundle,
      "owner.echo",
      () => ({ owner: "updated-bundle" }),
      NON_PLAINTEXT_RPC_POLICY,
    );

    expect(() => {
      router.registerOwnerHandler(
        ownerA,
        "owner.echo",
        () => ({ owner: "duplicate" }),
        NON_PLAINTEXT_RPC_POLICY,
      );
    }).toThrow(
      expect.objectContaining({
        code: "duplicate_operation",
      } satisfies Partial<PluginHostRpcError>),
    );

    const sessionA = bootSessionWithOverrides(router, {});
    const sessionB = bootSessionWithOverrides(router, {
      applicationId: ownerB.applicationId,
      activationId: "activation.example",
      capabilityGrantId: ownerB.capabilityGrantId,
    });
    const sessionUpdatedBundle = bootSessionWithOverrides(router, {
      bundleHash: ownerUpdatedBundle.bundleHash,
    });
    const sessionSecondaryFrame = bootSessionWithOverrides(router, {
      frameScope: "secondary",
    });

    sessionA.port.postMessage(requestEnvelope({ operation: "owner.echo" }));
    expect(await waitForPortMessage(sessionA.port)).toMatchObject({
      kind: "response",
      payload: { owner: "a" },
    });

    sessionB.port.postMessage(
      requestEnvelope({
        request_id: "request-b",
        request_nonce: "nonce-b",
        operation: "owner.echo",
        application_id: ownerB.applicationId,
        activation_id: "activation.example",
        capability_grant_id: ownerB.capabilityGrantId,
      }),
    );
    expect(await waitForPortMessage(sessionB.port)).toMatchObject({
      kind: "response",
      request_id: "request-b",
      payload: { owner: "b" },
    });

    sessionUpdatedBundle.port.postMessage(
      requestEnvelope({
        request_id: "request-updated-bundle",
        request_nonce: "nonce-updated-bundle",
        bundle_hash: ownerUpdatedBundle.bundleHash,
        operation: "owner.echo",
      }),
    );
    expect(await waitForPortMessage(sessionUpdatedBundle.port)).toMatchObject({
      kind: "response",
      request_id: "request-updated-bundle",
      payload: { owner: "updated-bundle" },
    });

    sessionSecondaryFrame.port.postMessage(
      requestEnvelope({
        request_id: "request-secondary-frame-denied",
        request_nonce: "nonce-secondary-frame-denied",
        operation: "owner.echo",
      }),
    );
    expect(await waitForPortMessage(sessionSecondaryFrame.port)).toMatchObject({
      kind: "error",
      request_id: "request-secondary-frame-denied",
      error: { code: "unknown_operation" },
    });

    sessionB.port.postMessage(
      requestEnvelope({
        request_id: "request-b-denied",
        request_nonce: "nonce-b-denied",
        operation: "owner.aOnly",
        application_id: ownerB.applicationId,
        activation_id: "activation.example",
        capability_grant_id: ownerB.capabilityGrantId,
      }),
    );
    expect(await waitForPortMessage(sessionB.port)).toMatchObject({
      kind: "error",
      request_id: "request-b-denied",
      error: { code: "unknown_operation" },
    });

    sessionB.session.close("test_done");
    sessionSecondaryFrame.session.close("test_done");
    sessionUpdatedBundle.session.close("test_done");
    sessionA.session.close("test_done");
    unregisterUpdatedBundle();
    unregisterAOnly();
    unregisterB();
    unregisterA();
  });

  it("audits known plaintext RPC attempts when no handler is registered", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const auditEvents: PluginAuditEvent[] = [];
    const { port } = bootSessionWithOverrides(router, {
      auditSink(event) {
        auditEvents.push(event);
        return true;
      },
    });

    port.postMessage(
      requestEnvelope({
        request_id: "unknown-plaintext",
        request_nonce: "unknown-plaintext-nonce",
        operation: "documents.getActiveDocument",
        resource: { document_id: "doc-1", max_bytes: 128 },
      }),
    );

    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      request_id: "unknown-plaintext",
      error: { code: "unknown_operation" },
    });
    expect(auditEvents).toHaveLength(1);
    expect(auditEvents[0]).toMatchObject({
      type: "plugin.plaintext_payload.denied",
      operation: "documents.getActiveDocument",
      requestId: "unknown-plaintext",
      payloadKind: "unknown",
      plaintextScopeKind: "active_document",
      plaintextBytes: 128,
      result: "deny",
      reasonCode: "unknown_operation",
      action: {
        operation: "documents.getActiveDocument",
        result: "denied",
        reason_code: "unknown_operation",
      },
      correlation: {
        request_id: "unknown-plaintext",
        execution_context_id: null,
      },
    });
  });

  it("fails closed when unknown known-plaintext RPC attempts cannot be audited", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const { port } = bootSessionWithOverrides(router, {});

    port.postMessage(
      requestEnvelope({
        request_id: "unknown-plaintext-auditless",
        request_nonce: "unknown-plaintext-auditless-nonce",
        operation: "documents.getActiveDocument",
        resource: { document_id: "doc-1" },
      }),
    );

    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      request_id: "unknown-plaintext-auditless",
      error: { code: "audit_sink_unavailable" },
    });
  });

  it("rejects handler policies without explicit plaintext classification", () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });

    expect(() => {
      // @ts-expect-error runtime guard is intentional for JavaScript callers.
      router.registerHandler("custom.operation", () => ({ value: "ok" }), {});
    }).toThrow(
      expect.objectContaining({
        code: "operation_plaintext_classification_required",
      } satisfies Partial<PluginHostRpcError>),
    );

    expect(() => {
      // @ts-expect-error runtime guard is intentional for JavaScript callers.
      router.registerHandler("documents.getActiveDocument", () => ({ plaintext: "content" }), {});
    }).toThrow(
      expect.objectContaining({
        code: "operation_plaintext_classification_required",
      } satisfies Partial<PluginHostRpcError>),
    );
  });

  it("rejects third-party Host RPC handlers for server-visible metadata writes", () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });

    expect(() => {
      router.registerHandler("documents.writeLinkText", () => ({ ok: true }), {
        requiredPermissions: ["document:write"],
        documentAccess: "allowed_document",
        plaintext: null,
        documentWrite: {
          operation: "document.write",
          sink: "encrypted_document_body",
          maxBytes: 64,
          rateLimit: { windowMs: 60_000, maxRequests: 2 },
          highRiskConsent: "required",
        },
      });
    }).toThrow(
      expect.objectContaining({
        code: "server_visible_metadata_sink_forbidden",
      } satisfies Partial<PluginHostRpcError>),
    );

    expect(() => {
      router.registerHandler("documents.applyEncryptedUpdate", () => ({ ok: true }), {
        requiredPermissions: ["document:write"],
        documentAccess: "allowed_document",
        plaintext: null,
        documentWrite: {
          operation: "document.write",
          sink: "server_visible_metadata" as never,
          maxBytes: 64,
          rateLimit: { windowMs: 60_000, maxRequests: 2 },
          highRiskConsent: "required",
        },
      });
    }).toThrow(
      expect.objectContaining({
        code: "server_visible_metadata_sink_forbidden",
      } satisfies Partial<PluginHostRpcError>),
    );
  });

  it("rejects known plaintext handlers classified as non-plaintext", () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });

    expect(() => {
      router.registerHandler(
        "documents.getActiveDocument",
        () => ({ plaintext: "content" }),
        NON_PLAINTEXT_RPC_POLICY,
      );
    }).toThrow(
      expect.objectContaining({
        code: "plaintext_policy_required",
      } satisfies Partial<PluginHostRpcError>),
    );

    expect(() => {
      router.registerHandler(
        "documents.queryWorkspaceDocuments",
        () => ({ plaintext: ["content"] }),
        NON_PLAINTEXT_RPC_POLICY,
      );
    }).toThrow(
      expect.objectContaining({
        code: "plaintext_policy_required",
      } satisfies Partial<PluginHostRpcError>),
    );
  });

  it("allows encrypted document write only within scope, size, rate, and consent bounds", async () => {
    const auditEvents: PluginAuditEvent[] = [];
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    router.registerHandler(
      "documents.applyEncryptedUpdate",
      () => ({ ok: true }),
      ENCRYPTED_DOCUMENT_WRITE_POLICY,
    );

    const { port } = bootSessionWithOverrides(router, {
      permissions: ["document:write", "document:read:active"],
      highRiskConsents: ["plaintext_document_write"],
      documentScope: { activeDocumentId: "doc-1", allowedDocumentIds: ["doc-1"] },
      auditSink(event) {
        auditEvents.push(event);
        return true;
      },
    });

    port.postMessage(
      requestEnvelope({
        operation: "documents.applyEncryptedUpdate",
        resource: { document_id: "doc-1", max_bytes: 64 },
        payload: { encrypted_update: "a".repeat(8) },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "response",
      payload: { ok: true },
    });
    expect(auditEvents).toContainEqual(
      expect.objectContaining({
        type: "plugin.document_write.requested",
        operation: "documents.applyEncryptedUpdate",
        payloadKind: "document.write",
        resourceRef: expect.objectContaining({ document_id: "doc-1" }),
        result: "allow",
        resource: expect.objectContaining({ kind: "document", id: "doc-1" }),
      }),
    );

    port.postMessage(
      requestEnvelope({
        request_id: "oversized-write",
        request_nonce: "nonce-oversized-write",
        operation: "documents.applyEncryptedUpdate",
        resource: { document_id: "doc-1", max_bytes: 12 },
        payload: { encrypted_update: "a".repeat(64) },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      request_id: "oversized-write",
      error: { code: "document_write_payload_too_large" },
    });

    port.postMessage(
      requestEnvelope({
        request_id: "second-write",
        request_nonce: "nonce-second-write",
        operation: "documents.applyEncryptedUpdate",
        resource: { document_id: "doc-1", max_bytes: 64 },
        payload: { encrypted_update: "b" },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({ kind: "response" });

    port.postMessage(
      requestEnvelope({
        request_id: "rate-limited-write",
        request_nonce: "nonce-rate-limited-write",
        operation: "documents.applyEncryptedUpdate",
        resource: { document_id: "doc-1", max_bytes: 64 },
        payload: { encrypted_update: "c" },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      request_id: "rate-limited-write",
      error: { code: "document_write_rate_limited" },
    });
  });

  it("fails closed when document write audit cannot be recorded", async () => {
    const called = vi.fn();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    router.registerHandler(
      "documents.applyEncryptedUpdate",
      () => {
        called();
        return { ok: true };
      },
      ENCRYPTED_DOCUMENT_WRITE_POLICY,
    );

    const { port } = bootSessionWithOverrides(router, {
      permissions: ["document:write", "document:read:active"],
      highRiskConsents: ["plaintext_document_write"],
      documentScope: { activeDocumentId: "doc-1", allowedDocumentIds: ["doc-1"] },
    });

    port.postMessage(
      requestEnvelope({
        operation: "documents.applyEncryptedUpdate",
        resource: { document_id: "doc-1", max_bytes: 64 },
        payload: { encrypted_update: "a".repeat(8) },
      }),
    );

    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      error: { code: "document_write_audit_unavailable" },
    });
    expect(called).not.toHaveBeenCalled();
  });

  it("requires high-risk consent when plaintext read and document write are combined", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    router.registerHandler(
      "documents.applyEncryptedUpdate",
      () => ({ ok: true }),
      ENCRYPTED_DOCUMENT_WRITE_POLICY,
    );

    const { port } = bootSessionWithOverrides(router, {
      permissions: ["document:write", "document:read:active"],
      documentScope: { activeDocumentId: "doc-1", allowedDocumentIds: ["doc-1"] },
    });

    port.postMessage(
      requestEnvelope({
        operation: "documents.applyEncryptedUpdate",
        resource: { document_id: "doc-1", max_bytes: 64 },
        payload: { encrypted_update: "a" },
      }),
    );

    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      error: { code: "high_risk_consent_required" },
    });
  });

  it("requires exact typed plaintext policy for renderer and editor context RPC", () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });

    expect(() => {
      router.registerHandler("renderer.getSource", () => ({ source: "graph" }), {
        requiredPermissions: ["plaintext:render:block:chart"],
        plaintext: {
          operation: "plaintext.read",
          requiredPermission: "plaintext:render:block:mermaid",
          allowedContextKinds: ["renderer_invocation"],
          allowedPlaintextScopes: ["block"],
          audit: "required",
        },
      });
    }).toThrow(
      expect.objectContaining({
        code: "plaintext_capability_required",
      } satisfies Partial<PluginHostRpcError>),
    );

    expect(() => {
      router.registerHandler("editor.getContext", () => ({ context: "nearby text" }), {
        requiredPermissions: ["editor:context:read"],
        documentAccess: "allowed_document",
        plaintext: {
          operation: "plaintext.read",
          requiredPermission: "editor:context:read",
          allowedContextKinds: ["editor_suggestion"],
          allowedPlaintextScopes: ["active_document"],
          audit: "required",
        },
      });
    }).toThrow(
      expect.objectContaining({
        code: "plaintext_scope_denied",
      } satisfies Partial<PluginHostRpcError>),
    );
  });

  it("rejects known plaintext RPC policies with broadened context or scope", () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });

    expect(() => {
      router.registerHandler("documents.getActiveDocument", () => ({ plaintext: "content" }), {
        requiredPermissions: ["document:read:active"],
        documentAccess: "active_document",
        plaintext: {
          operation: "plaintext.read",
          requiredPermission: "document:read:active",
          allowedContextKinds: ["renderer_invocation"],
          allowedPlaintextScopes: ["active_document"],
          audit: "required",
        },
      });
    }).toThrow(
      expect.objectContaining({
        code: "plaintext_context_denied",
      } satisfies Partial<PluginHostRpcError>),
    );

    expect(() => {
      router.registerHandler("documents.getActiveDocument", () => ({ plaintext: "content" }), {
        requiredPermissions: ["document:read:active"],
        documentAccess: "active_document",
        plaintext: {
          operation: "plaintext.read",
          requiredPermission: "document:read:active",
          allowedContextKinds: ["user_command"],
          allowedPlaintextScopes: ["active_document", "workspace"],
          audit: "required",
        },
      });
    }).toThrow(
      expect.objectContaining({
        code: "plaintext_scope_denied",
      } satisfies Partial<PluginHostRpcError>),
    );

    expect(() => {
      router.registerHandler("renderer.getSource", () => ({ source: "graph" }), {
        requiredPermissions: ["plaintext:render:block:mermaid"],
        documentAccess: "allowed_document",
        plaintext: {
          operation: "plaintext.read",
          requiredPermission: "plaintext:render:block:mermaid",
          allowedContextKinds: ["user_command"],
          allowedPlaintextScopes: ["block"],
          audit: "required",
        },
      });
    }).toThrow(
      expect.objectContaining({
        code: "plaintext_context_denied",
      } satisfies Partial<PluginHostRpcError>),
    );

    expect(() => {
      router.registerHandler("renderer.getSource", () => ({ source: "graph" }), {
        requiredPermissions: ["plaintext:render:block:mermaid"],
        documentAccess: "allowed_document",
        plaintext: {
          operation: "plaintext.read",
          requiredPermission: "plaintext:render:block:mermaid",
          allowedContextKinds: ["renderer_invocation"],
          allowedPlaintextScopes: ["block", "inline"],
          audit: "required",
        },
      });
    }).toThrow(
      expect.objectContaining({
        code: "plaintext_scope_denied",
      } satisfies Partial<PluginHostRpcError>),
    );

    expect(() => {
      router.registerHandler("formatter.getInput", () => ({ plaintext: "workspace" }), {
        requiredPermissions: ["document:read:workspace"],
        documentAccess: "workspace_documents",
        plaintext: {
          operation: "plaintext.read",
          requiredPermission: "document:read:workspace",
          allowedContextKinds: ["formatter"],
          allowedPlaintextScopes: ["workspace"],
          audit: "required",
        },
      });
    }).toThrow(
      expect.objectContaining({
        code: "plaintext_operation_policy_mismatch",
      } satisfies Partial<PluginHostRpcError>),
    );

    const unregisterFormatterContext = router.registerHandler(
      "formatter.getInput",
      () => ({ context: "nearby text" }),
      {
        requiredPermissions: ["editor:context:read"],
        documentAccess: "allowed_document",
        plaintext: {
          operation: "plaintext.read",
          requiredPermission: "editor:context:read",
          allowedContextKinds: ["formatter"],
          allowedPlaintextScopes: ["editor_context"],
          audit: "required",
        },
      },
    );
    unregisterFormatterContext();
  });

  it("requires document access for typed renderer and editor plaintext policies", () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });

    expect(() => {
      router.registerHandler("renderer.getSource", () => ({ source: "graph" }), {
        requiredPermissions: ["plaintext:render:block:mermaid"],
        plaintext: {
          operation: "plaintext.read",
          requiredPermission: "plaintext:render:block:mermaid",
          allowedContextKinds: ["renderer_invocation"],
          allowedPlaintextScopes: ["block"],
          audit: "required",
        },
      });
    }).toThrow(
      expect.objectContaining({
        code: "document_scope_policy_required",
      } satisfies Partial<PluginHostRpcError>),
    );

    expect(() => {
      router.registerHandler("editor.getContext", () => ({ context: "nearby text" }), {
        requiredPermissions: ["editor:context:read"],
        plaintext: {
          operation: "plaintext.read",
          requiredPermission: "editor:context:read",
          allowedContextKinds: ["editor_suggestion"],
          allowedPlaintextScopes: ["editor_context"],
          audit: "required",
        },
      });
    }).toThrow(
      expect.objectContaining({
        code: "document_scope_policy_required",
      } satisfies Partial<PluginHostRpcError>),
    );

    expect(() => {
      router.registerHandler("formatter.getInput", () => ({ context: "nearby text" }), {
        requiredPermissions: ["editor:context:read"],
        plaintext: {
          operation: "plaintext.read",
          requiredPermission: "editor:context:read",
          allowedContextKinds: ["formatter"],
          allowedPlaintextScopes: ["editor_context"],
          audit: "required",
        },
      });
    }).toThrow(
      expect.objectContaining({
        code: "document_scope_policy_required",
      } satisfies Partial<PluginHostRpcError>),
    );
  });

  it("requires matching document access for document plaintext policies", () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });

    expect(() => {
      router.registerHandler("documents.getActiveDocument", () => ({ plaintext: "content" }), {
        requiredPermissions: ["document:read:active"],
        plaintext: {
          operation: "plaintext.read",
          requiredPermission: "document:read:active",
          allowedContextKinds: ["user_command"],
          allowedPlaintextScopes: ["active_document"],
          audit: "required",
        },
      });
    }).toThrow(
      expect.objectContaining({
        code: "document_scope_policy_required",
      } satisfies Partial<PluginHostRpcError>),
    );

    expect(() => {
      router.registerHandler("documents.queryWorkspaceDocuments", () => ({ plaintext: [] }), {
        requiredPermissions: ["document:read:workspace"],
        documentAccess: "active_document",
        plaintext: {
          operation: "plaintext.read",
          requiredPermission: "document:read:workspace",
          allowedContextKinds: ["user_command"],
          allowedPlaintextScopes: ["workspace"],
          audit: "required",
        },
      });
    }).toThrow(
      expect.objectContaining({
        code: "document_scope_policy_required",
      } satisfies Partial<PluginHostRpcError>),
    );

    expect(() => {
      router.registerHandler("documents.queryWorkspaceDocuments", () => ({ plaintext: [] }), {
        requiredPermissions: ["document:read:workspace"],
        documentAccess: "workspace_documents",
        plaintext: {
          operation: "plaintext.read",
          requiredPermission: "document:read:workspace",
          allowedContextKinds: ["user_command", "scheduled_task"],
          allowedPlaintextScopes: ["workspace"],
          audit: "required",
        },
      });
    }).toThrow(
      expect.objectContaining({
        code: "plaintext_context_denied",
      } satisfies Partial<PluginHostRpcError>),
    );
  });

  it("does not include scheduled workspace reads in default document handlers", () => {
    const handlers = mergeDefaultRuntimeHandlers([], {
      addCommand() {},
      removeCommand() {},
      addStatusBarItem() {
        return document.createElement("div");
      },
      addSidebarPanel() {},
      removeSidebarPanel() {},
      addWorkspaceTile() {},
      removeWorkspaceTile() {},
      addSettingTab() {
        return document.createElement("div");
      },
      removeSettingTab() {},
      activeDocument() {
        return null;
      },
      activeEditor() {
        return null;
      },
      activeEditorEntry() {
        return null;
      },
      documentList() {
        return [];
      },
      async getDocumentById() {
        return null;
      },
      notifyDocumentChange() {},
    });

    const handler = handlers.find(
      (candidate) => candidate.operation === "documents.queryWorkspaceDocuments",
    );

    expect(handler?.policy.plaintext?.allowedContextKinds).toEqual(["user_command"]);
  });

  it("rejects workspace document query contexts without document and byte limits", () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const { session } = bootSessionWithOverrides(router, {
      permissions: ["document:read:workspace"],
      documentScope: { workspaceReadAllowed: true },
      auditSink: () => true,
    });
    const baseContext = {
      kind: "user_command" as const,
      hostInvocation: { kind: "command" as const, userGesture: true },
      plaintextScope: { kind: "workspace" as const, maxBytes: 128 },
      allowedOperations: ["plaintext.read"] as const,
      expiresAtMs: Date.now() + 60_000,
    };

    expect(() =>
      session.issueExecutionContext({
        ...baseContext,
        resource: { max_bytes: 128 },
      }),
    ).toThrow(
      expect.objectContaining({
        code: "execution_context_resource_required",
      } satisfies Partial<PluginHostRpcError>),
    );
    expect(() =>
      session.issueExecutionContext({
        ...baseContext,
        resource: { max_documents: 1 },
      }),
    ).toThrow(
      expect.objectContaining({
        code: "execution_context_resource_required",
      } satisfies Partial<PluginHostRpcError>),
    );
  });

  it("rejects workspace document query requests without an execution context before handler delivery", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    let called = 0;
    router.registerHandler(
      "documents.queryWorkspaceDocuments",
      () => {
        called += 1;
        return { documents: [] };
      },
      {
        requiredPermissions: ["document:read:workspace"],
        documentAccess: "workspace_documents",
        plaintext: {
          operation: "plaintext.read",
          requiredPermission: "document:read:workspace",
          allowedContextKinds: ["user_command"],
          allowedPlaintextScopes: ["workspace"],
          audit: "required",
        },
      },
    );
    const auditEvents: unknown[] = [];
    const { port } = bootSessionWithOverrides(router, {
      permissions: ["document:read:workspace"],
      documentScope: { workspaceReadAllowed: true },
      auditSink: (event) => {
        auditEvents.push(event);
        return true;
      },
    });

    port.postMessage(
      requestEnvelope({
        request_id: "workspace-query-no-context",
        request_nonce: "workspace-query-no-context-nonce",
        operation: "documents.queryWorkspaceDocuments",
      }),
    );

    expect(await waitForPortMessage(port)).toEqual({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "error",
      request_id: "workspace-query-no-context",
      error: {
        code: "execution_context_required",
        message: "plaintext RPC requires a Host-issued execution context",
      },
    });
    expect(called).toBe(0);
    expect(auditEvents.at(-1)).toMatchObject({
      type: "plugin.plaintext_payload.denied",
      requestId: "workspace-query-no-context",
      payloadKind: "plaintext.read",
      plaintextScopeKind: "workspace",
      result: "deny",
      reasonCode: "execution_context_required",
      action: {
        operation: "documents.queryWorkspaceDocuments",
        result: "denied",
        reason_code: "execution_context_required",
      },
    });
  });

  it("rejects workspace document query requests without document and byte limits", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    router.registerHandler("documents.queryWorkspaceDocuments", () => ({ documents: [] }), {
      requiredPermissions: ["document:read:workspace"],
      documentAccess: "workspace_documents",
      plaintext: {
        operation: "plaintext.read",
        requiredPermission: "document:read:workspace",
        allowedContextKinds: ["user_command"],
        allowedPlaintextScopes: ["workspace"],
        audit: "required",
      },
    });
    const { session, port } = bootSessionWithOverrides(router, {
      permissions: ["document:read:workspace"],
      documentScope: { workspaceReadAllowed: true },
      auditSink: () => true,
    });

    const missingByteLimit = session.issueExecutionContext({
      kind: "user_command",
      hostInvocation: { kind: "command", userGesture: true },
      resource: { max_documents: 1, max_bytes: 128 },
      plaintextScope: { kind: "workspace", maxBytes: 128 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
    });
    port.postMessage(
      requestEnvelope({
        request_id: "workspace-query-missing-byte-limit",
        request_nonce: "workspace-query-missing-byte-limit-nonce",
        operation: "documents.queryWorkspaceDocuments",
        execution_context_id: missingByteLimit.execution_context_id,
        resource: { max_documents: 1 },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      request_id: "workspace-query-missing-byte-limit",
      error: {
        code: "plaintext_scope_denied",
      },
    });

    const missingDocumentLimit = session.issueExecutionContext({
      kind: "user_command",
      hostInvocation: { kind: "command", userGesture: true },
      resource: { max_documents: 1, max_bytes: 128 },
      plaintextScope: { kind: "workspace", maxBytes: 128 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
    });
    port.postMessage(
      requestEnvelope({
        request_id: "workspace-query-missing-document-limit",
        request_nonce: "workspace-query-missing-document-limit-nonce",
        operation: "documents.queryWorkspaceDocuments",
        execution_context_id: missingDocumentLimit.execution_context_id,
        resource: { max_bytes: 128 },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      request_id: "workspace-query-missing-document-limit",
      error: {
        code: "plaintext_scope_denied",
      },
    });
  });

  it("fails closed in the default workspace document query handler without explicit limits", async () => {
    const handlers = mergeDefaultRuntimeHandlers([], {
      addCommand() {},
      removeCommand() {},
      addStatusBarItem() {
        return document.createElement("div");
      },
      addSidebarPanel() {},
      removeSidebarPanel() {},
      addWorkspaceTile() {},
      removeWorkspaceTile() {},
      addSettingTab() {
        return document.createElement("div");
      },
      removeSettingTab() {},
      activeDocument() {
        return null;
      },
      activeEditor() {
        return null;
      },
      activeEditorEntry() {
        return null;
      },
      documentList() {
        return [];
      },
      async getDocumentById() {
        return null;
      },
      notifyDocumentChange() {},
    });
    const handler = handlers.find(
      (candidate) => candidate.operation === "documents.queryWorkspaceDocuments",
    );
    if (!handler) throw new Error("workspace_query_handler_missing");

    await expect(
      handler.handler(
        {} as never,
        {
          payload: {},
          resource: { max_documents: 1 },
        } as never,
      ),
    ).rejects.toMatchObject({ code: "invalid_plaintext_byte_limit" });
    await expect(
      handler.handler(
        {} as never,
        {
          payload: {},
          resource: { max_bytes: 128 },
        } as never,
      ),
    ).rejects.toMatchObject({ code: "invalid_document_limit" });
  });

  it("rejects scheduled workspace document query requests", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    router.registerHandler("documents.queryWorkspaceDocuments", () => ({ documents: [] }), {
      requiredPermissions: ["document:read:workspace"],
      documentAccess: "workspace_documents",
      plaintext: {
        operation: "plaintext.read",
        requiredPermission: "document:read:workspace",
        allowedContextKinds: ["user_command"],
        allowedPlaintextScopes: ["workspace"],
        audit: "required",
      },
    });
    const { session, port } = bootSessionWithOverrides(router, {
      permissions: ["document:read:workspace"],
      documentScope: { workspaceReadAllowed: true },
      auditSink: () => true,
    });

    const scheduled = session.issueExecutionContext({
      kind: "scheduled_task",
      hostInvocation: { kind: "scheduled_policy", userGesture: false },
      resource: { max_documents: 1, max_bytes: 128 },
      plaintextScope: { kind: "workspace", maxBytes: 128 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "scheduled-workspace-query",
        request_nonce: "scheduled-workspace-query-nonce",
        operation: "documents.queryWorkspaceDocuments",
        execution_context_id: scheduled.execution_context_id,
        resource: { max_documents: 1, max_bytes: 128 },
      }),
    );

    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      request_id: "scheduled-workspace-query",
      error: {
        code: "scheduled_context_reserved",
      },
    });
  });

  it("rejects malformed plaintext policies without required audit mode", () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });

    expect(() => {
      router.registerHandler("documents.getActiveDocument", () => ({ plaintext: "content" }), {
        requiredPermissions: ["document:read:active"],
        plaintext: {
          operation: "plaintext.read",
          requiredPermission: "document:read:active",
          allowedContextKinds: ["user_command"],
          allowedPlaintextScopes: ["active_document"],
        },
      } as unknown as PluginHostRpcOperationPolicy);
    }).toThrow(
      expect.objectContaining({
        code: "plaintext_audit_required",
      } satisfies Partial<PluginHostRpcError>),
    );
  });

  it("boots only the iframe contentWindow that owns the one-time boot nonce", () => {
    const frame = new FakeFrameWindow();
    const attacker = new FakeFrameWindow();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
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
      contentWindow: frame,
    });

    const attackerHandled = router.handleWindowMessage(
      fakeMessageEvent(
        {
          protocol: PLUGIN_HOST_RPC_PROTOCOL,
          version: PLUGIN_HOST_RPC_VERSION,
          kind: "boot-ready",
        },
        attacker,
        "https://attacker.example",
      ),
    );

    expect(attackerHandled).toBe(false);
    expect(frame.messages).toHaveLength(0);
    expect(session.connected).toBe(false);

    const ownerHandled = router.handleWindowMessage(
      fakeMessageEvent(
        {
          protocol: PLUGIN_HOST_RPC_PROTOCOL,
          version: PLUGIN_HOST_RPC_VERSION,
          kind: "boot-ready",
        },
        frame,
        "https://unexpected.example",
      ),
    );

    expect(ownerHandled).toBe(true);
    expect(frame.messages).toHaveLength(1);
    expect(session.connected).toBe(false);

    const replayHandled = router.handleWindowMessage(
      fakeMessageEvent(
        {
          protocol: PLUGIN_HOST_RPC_PROTOCOL,
          version: PLUGIN_HOST_RPC_VERSION,
          kind: "boot-ready",
        },
        frame,
        "null",
      ),
    );

    expect(replayHandled).toBe(true);
    expect(frame.messages).toHaveLength(1);
    expect(session.connected).toBe(false);
  });

  it("requires host-issued capability identity at session creation", () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });

    expect(() =>
      router.createSession({
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
        consentEpoch: 3,
        contentWindow: new FakeFrameWindow(),
      } as unknown as Parameters<PluginHostMessageRouter["createSession"]>[0]),
    ).toThrow(
      expect.objectContaining({
        name: "PluginHostRpcError",
        code: "plugin_runtime_capability_grant_required",
      }),
    );

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
      contentWindow: new FakeFrameWindow(),
    });

    expect(session.capabilityId).toBe("capability-1");
    expect(session.capabilityGrantId).toBe("capability-grant-1");
  });

  it("closes a known plugin frame that sends a non-boot window message before boot", () => {
    const frame = new FakeFrameWindow();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
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
      contentWindow: frame,
    });

    const handled = router.handleWindowMessage(
      fakeMessageEvent(
        {
          protocol: PLUGIN_HOST_RPC_PROTOCOL,
          version: PLUGIN_HOST_RPC_VERSION,
          kind: "unexpected",
        },
        frame,
        "null",
      ),
    );

    expect(handled).toBe(true);
    expect(session.connected).toBe(false);
    expect(frame.messages).toHaveLength(0);
  });

  it("requires the transferred port to acknowledge the host-issued boot nonce", () => {
    const frame = new FakeFrameWindow();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
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
    });

    const handled = router.handleWindowMessage(
      fakeMessageEvent(
        {
          protocol: PLUGIN_HOST_RPC_PROTOCOL,
          version: PLUGIN_HOST_RPC_VERSION,
          kind: "boot-ready",
        },
        frame,
        "null",
      ),
    );

    expect(handled).toBe(true);
    expect(session.connected).toBe(false);
    void (
      session as unknown as {
        handlePortMessage(message: unknown): Promise<void>;
      }
    ).handlePortMessage({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "boot-ack",
      boot_nonce: "wrong-boot-nonce",
      frame_generation: 7,
    });

    expect(session.connected).toBe(false);
    expect(() =>
      session.issueExecutionContext({
        kind: "scheduled_task",
        hostInvocation: { kind: "scheduled_policy", userGesture: false },
        plaintextScope: { kind: "workspace", maxBytes: 128 },
        allowedOperations: ["plaintext.read"],
        expiresAtMs: Date.now() + 1_000,
      }),
    ).toThrow(
      expect.objectContaining({
        code: "session_not_connected",
      }),
    );
  });

  it("handles plugin requests over the transferred MessagePort", async () => {
    const frame = new FakeFrameWindow();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    router.registerHandler(
      "echo",
      (context, request) => ({
        context,
        payload: request.payload,
      }),
      NON_PLAINTEXT_RPC_POLICY,
    );
    const { session, port } = boot(router, frame);

    port.postMessage(requestEnvelope());
    const response = await waitForPortMessage(port);

    expect(response).toEqual({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: "request-1",
      payload: {
        context: {
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
          frameScope: "primary",
          sessionId: session.sessionId,
          auditActor: {
            user_id: null,
            device_id: null,
            session_id: session.sessionId,
            principal_kind: "system",
            principal_id: null,
          },
        },
        payload: { value: 1 },
      },
    });
  });

  it("returns a timeout error when a plugin-originated Host handler does not settle", async () => {
    const frame = new FakeFrameWindow();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      timeoutMs: 10,
      validateSession: () => null,
    });
    router.registerHandler("slow", () => new Promise(() => {}), NON_PLAINTEXT_RPC_POLICY);
    const { port } = boot(router, frame);

    port.postMessage(requestEnvelope({ operation: "slow" }));

    expect(await waitForPortMessage(port)).toEqual({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "error",
      request_id: "request-1",
      error: {
        code: "timeout",
        message: "plugin Host RPC handler timed out: slow",
      },
    });
  });

  it("enforces policy, execution context, byte limit, and audit for Host-to-plugin plaintext delivery", async () => {
    const frame = new FakeFrameWindow();
    const auditEvents: PluginAuditEvent[] = [];
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const { session, port } = createSessionAndBoot(router, frame, {
      permissions: ["plaintext:render:block:mermaid"],
      documentScope: { allowedDocumentIds: ["doc-1"] },
      auditSink(event) {
        auditEvents.push(event);
        return true;
      },
    });
    const rendererPolicy: PluginHostRpcOperationPolicy = {
      requiredPermissions: ["plaintext:render:block:mermaid"],
      documentAccess: "allowed_document",
      plaintext: {
        operation: "plaintext.read",
        requiredPermission: "plaintext:render:block:mermaid",
        allowedContextKinds: ["renderer_invocation"],
        allowedPlaintextScopes: ["block"],
        audit: "required",
      },
    };
    const resource = { document_id: "doc-1", block_id: "block-1", max_bytes: 64 };

    await expect(session.request("renderer.render", { source: "graph" })).rejects.toMatchObject({
      code: "operation_policy_required",
    } satisfies Partial<PluginHostRpcError>);

    await expect(
      session.request("renderer.render", { source: "graph" }, resource, undefined, {
        policy: rendererPolicy,
      }),
    ).rejects.toMatchObject({
      code: "execution_context_required",
    } satisfies Partial<PluginHostRpcError>);
    expect(auditEvents.at(-1)).toMatchObject({
      type: "plugin.plaintext_payload.denied",
      reasonCode: "execution_context_required",
    });

    const handle = session.issueExecutionContext({
      kind: "renderer_invocation",
      hostInvocation: { kind: "renderer_slot", userGesture: false },
      resource: { document_id: "doc-1", block_id: "block-1" },
      plaintextScope: { kind: "block", maxBytes: 64 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
    });
    const request = session.request("renderer.render", { source: "graph" }, resource, undefined, {
      policy: rendererPolicy,
      executionContextId: handle.execution_context_id,
    });
    const envelope = await waitForPortMessage(port);

    expect(envelope).toMatchObject({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "request",
      operation: "renderer.render",
      execution_context_id: handle.execution_context_id,
      resource,
      payload: { source: "graph" },
    });
    expect(auditEvents.at(-1)).toMatchObject({
      type: "plugin.plaintext_payload.delivered",
      result: "allow",
      executionContextId: handle.execution_context_id,
      plaintextBytes: 5,
      sensitivity: { plaintext_bytes: 5 },
    });

    if (typeof envelope === "object" && envelope && "request_id" in envelope) {
      port.postMessage({
        protocol: PLUGIN_HOST_RPC_PROTOCOL,
        version: PLUGIN_HOST_RPC_VERSION,
        kind: "response",
        request_id: envelope.request_id,
        payload: { rendered: true },
      });
    }
    await expect(request).resolves.toEqual({ rendered: true });

    const tooSmall = session.issueExecutionContext({
      kind: "renderer_invocation",
      hostInvocation: { kind: "renderer_slot", userGesture: false },
      resource: { document_id: "doc-1", block_id: "block-1" },
      plaintextScope: { kind: "block", maxBytes: 4 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
    });
    await expect(
      session.request(
        "renderer.render",
        { source: "graph" },
        { document_id: "doc-1", block_id: "block-1", max_bytes: 4 },
        undefined,
        {
          policy: rendererPolicy,
          executionContextId: tooSmall.execution_context_id,
        },
      ),
    ).rejects.toMatchObject({
      code: "plaintext_payload_too_large",
    } satisfies Partial<PluginHostRpcError>);
    expect(auditEvents.at(-1)).toMatchObject({
      type: "plugin.plaintext_payload.denied",
      reasonCode: "plaintext_payload_too_large",
      plaintextBytes: 5,
    });
  });

  it("does not treat semantic active or selected document flags as concrete document access", () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });

    const { session: semanticSession } = bootSessionWithOverrides(router, {
      permissions: ["document:read:active", "document:read:selected"],
      documentScope: {
        activeDocumentReadAllowed: true,
        selectedDocumentsReadAllowed: true,
      },
    });

    expect(semanticSession.allowsDocument("doc-1")).toBe(false);

    const { session: concreteSession } = bootSessionWithOverrides(router, {
      permissions: ["document:read:active", "document:read:selected"],
      documentScope: {
        activeDocumentReadAllowed: true,
        activeDocumentId: "doc-1",
        selectedDocumentsReadAllowed: true,
        selectedDocumentIds: ["doc-2"],
      },
    });

    expect(concreteSession.allowsDocument("doc-1")).toBe(true);
    expect(concreteSession.allowsDocument("doc-2")).toBe(true);
    expect(concreteSession.allowsDocument("doc-3")).toBe(false);
  });

  it("authorizes semantic active document scope against the current provider value", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    let activeDocumentId = "doc-start";
    let called = 0;
    router.registerHandler(
      "documents.getActiveDocument",
      () => {
        called += 1;
        return { plaintext: "provider active content" };
      },
      {
        requiredPermissions: ["document:read:active"],
        documentAccess: "active_document",
        plaintext: {
          operation: "plaintext.read",
          requiredPermission: "document:read:active",
          allowedContextKinds: ["user_command"],
          allowedPlaintextScopes: ["active_document"],
          audit: "required",
        },
      },
    );

    const { session, port } = bootSessionWithOverrides(router, {
      permissions: ["document:read:active"],
      documentScope: {
        activeDocumentReadAllowed: true,
        activeDocumentId: "doc-start",
      },
      documentScopeProvider: () => ({
        activeDocumentReadAllowed: true,
        activeDocumentId,
      }),
      auditSink: () => true,
    });

    expect(session.allowsDocument("doc-start")).toBe(true);
    activeDocumentId = "doc-current";
    expect(session.allowsDocument("doc-start")).toBe(false);
    expect(session.allowsDocument("doc-current")).toBe(true);

    const handle = session.issueExecutionContext({
      kind: "user_command",
      hostInvocation: { kind: "command", userGesture: true },
      resource: { document_id: "doc-current" },
      plaintextScope: { kind: "active_document", maxBytes: 128 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
      singleUse: true,
    });

    port.postMessage(
      requestEnvelope({
        operation: "documents.getActiveDocument",
        execution_context_id: handle.execution_context_id,
        resource: { document_id: "doc-current", max_bytes: 128 },
      }),
    );

    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "response",
      payload: { plaintext: "provider active content" },
    });
    expect(called).toBe(1);
  });

  it("allows Host UI text refresh contexts to read the active document", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    for (const handler of mergeDefaultRuntimeHandlers([], {
      addCommand() {},
      removeCommand() {},
      addStatusBarItem() {
        return document.createElement("div");
      },
      addSidebarPanel() {},
      removeSidebarPanel() {},
      addWorkspaceTile() {},
      removeWorkspaceTile() {},
      addSettingTab() {
        return document.createElement("div");
      },
      removeSettingTab() {},
      activeDocument() {
        return {
          id: "doc-active",
          title: "Active",
          editor: { getValue: () => "active plaintext" },
        };
      },
      activeEditor() {
        return null;
      },
      activeEditorEntry() {
        return null;
      },
      documentList() {
        return [];
      },
      async getDocumentById() {
        return null;
      },
      notifyDocumentChange() {},
    })) {
      router.registerHandler(handler.operation, handler.handler, handler.policy);
    }
    const { session, port } = bootSessionWithOverrides(router, {
      permissions: ["document:read:active"],
      documentScope: {
        activeDocumentReadAllowed: true,
        activeDocumentId: "doc-active",
      },
      auditSink: () => true,
    });
    const handle = session.issueExecutionContext({
      kind: "ui_text_refresh",
      hostInvocation: { kind: "ui_text_refresh", userGesture: false },
      resource: { document_id: "doc-active" },
      plaintextScope: { kind: "active_document", maxBytes: 128 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
      singleUse: true,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "status-refresh-active-doc",
        request_nonce: "status-refresh-active-doc-nonce",
        operation: "documents.getActiveDocument",
        execution_context_id: handle.execution_context_id,
        resource: { document_id: "doc-active", max_bytes: 128 },
      }),
    );

    expect(await waitForPortMessage(port)).toEqual({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: "status-refresh-active-doc",
      payload: {
        document_id: "doc-active",
        title: "Active",
        plaintext: "active plaintext",
      },
    });
  });

  it("reads a context-bound active document for workspace tile actions after focus moves", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const release = vi.fn();
    for (const handler of mergeDefaultRuntimeHandlers([], {
      addCommand() {},
      removeCommand() {},
      addStatusBarItem() {
        return document.createElement("div");
      },
      addSidebarPanel() {},
      removeSidebarPanel() {},
      addWorkspaceTile() {},
      removeWorkspaceTile() {},
      addSettingTab() {
        return document.createElement("div");
      },
      removeSettingTab() {},
      activeDocument() {
        return {
          id: "doc-focused",
          title: "Focused",
          editor: { getValue: () => "focused plaintext" },
        };
      },
      activeEditor() {
        return null;
      },
      activeEditorEntry() {
        return null;
      },
      documentList() {
        return [];
      },
      async getDocumentById(documentId) {
        if (documentId !== "doc-panel") return null;
        return {
          id: "doc-panel",
          title: "Panel",
          text: "panel plaintext",
          release,
        };
      },
      notifyDocumentChange() {},
    })) {
      router.registerHandler(handler.operation, handler.handler, handler.policy);
    }
    const { session, port } = bootSessionWithOverrides(router, {
      permissions: ["document:read:active"],
      documentScope: {
        activeDocumentReadAllowed: true,
        activeDocumentId: "doc-focused",
      },
      auditSink: () => true,
    });
    const handle = session.issueExecutionContext({
      kind: "ui_action",
      hostInvocation: { kind: "host_action_token", userGesture: true, tokenId: "panel-action" },
      resource: { document_id: "doc-panel" },
      plaintextScope: { kind: "active_document", maxBytes: 128 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "panel-action-active-doc",
        request_nonce: "panel-action-active-doc-nonce",
        operation: "documents.getActiveDocument",
        execution_context_id: handle.execution_context_id,
        resource: { document_id: "doc-panel", max_bytes: 128 },
      }),
    );

    expect(await waitForPortMessage(port)).toEqual({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: "panel-action-active-doc",
      payload: {
        document_id: "doc-panel",
        title: "Panel",
        plaintext: "panel plaintext",
      },
    });
    expect(release).toHaveBeenCalledOnce();
  });

  it("reads a context-bound selected document for workspace tile actions", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const release = vi.fn();
    for (const handler of mergeDefaultRuntimeHandlers([], {
      addCommand() {},
      removeCommand() {},
      addStatusBarItem() {
        return document.createElement("div");
      },
      addSidebarPanel() {},
      removeSidebarPanel() {},
      addWorkspaceTile() {},
      removeWorkspaceTile() {},
      addSettingTab() {
        return document.createElement("div");
      },
      removeSettingTab() {},
      activeDocument() {
        return null;
      },
      activeEditor() {
        return null;
      },
      activeEditorEntry() {
        return null;
      },
      documentList() {
        return [];
      },
      async getDocumentById(documentId) {
        if (documentId !== "doc-panel") return null;
        return {
          id: "doc-panel",
          title: "Panel",
          text: "panel plaintext",
          release,
        };
      },
      notifyDocumentChange() {},
    })) {
      router.registerHandler(handler.operation, handler.handler, handler.policy);
    }
    const { session, port } = bootSessionWithOverrides(router, {
      permissions: ["document:read:selected"],
      documentScope: {
        selectedDocumentsReadAllowed: true,
      },
      auditSink: () => true,
    });
    const handle = session.issueExecutionContext({
      kind: "ui_action",
      hostInvocation: { kind: "host_action_token", userGesture: true, tokenId: "panel-action" },
      resource: { selected_document_ids: ["doc-panel"] },
      plaintextScope: { kind: "selected_documents", maxBytes: 128 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "panel-action-selected-doc",
        request_nonce: "panel-action-selected-doc-nonce",
        operation: "documents.getSelectedDocuments",
        execution_context_id: handle.execution_context_id,
        resource: { selected_document_ids: ["doc-panel"], max_bytes: 128 },
      }),
    );

    expect(await waitForPortMessage(port)).toEqual({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: "panel-action-selected-doc",
      payload: {
        documents: [
          {
            document_id: "doc-panel",
            title: "Panel",
            plaintext: "panel plaintext",
          },
        ],
      },
    });
    expect(release).toHaveBeenCalledOnce();
  });

  it("keeps command execution contexts available after non-plaintext Host delivery", async () => {
    const frame = new FakeFrameWindow();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const activeDocumentPolicy: PluginHostRpcOperationPolicy = {
      requiredPermissions: ["document:read:active"],
      documentAccess: "active_document",
      plaintext: {
        operation: "plaintext.read",
        requiredPermission: "document:read:active",
        allowedContextKinds: ["user_command"],
        allowedPlaintextScopes: ["active_document"],
        audit: "required",
      },
    };
    router.registerHandler(
      "documents.getActiveDocument",
      () => ({ plaintext: "content" }),
      activeDocumentPolicy,
    );
    const { session, port } = createSessionAndBoot(router, frame, {
      permissions: ["document:read:active"],
      documentScope: { activeDocumentId: "doc-1" },
      auditSink: () => true,
    });
    const handle = session.issueExecutionContext({
      kind: "user_command",
      hostInvocation: { kind: "command", userGesture: true },
      resource: { document_id: "doc-1" },
      plaintextScope: { kind: "active_document", maxBytes: 64 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
      singleUse: true,
    });

    const delivery = session.request(
      "ui.command.invoke",
      { command_id: "open-active-document" },
      undefined,
      undefined,
      {
        policy: NON_PLAINTEXT_RPC_POLICY,
        executionContextId: handle.execution_context_id,
      },
    );
    const deliveryEnvelope = await waitForPortMessage(port);
    expect(deliveryEnvelope).toMatchObject({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "request",
      operation: "ui.command.invoke",
      execution_context_id: handle.execution_context_id,
      payload: { command_id: "open-active-document" },
    });
    if (
      typeof deliveryEnvelope === "object" &&
      deliveryEnvelope &&
      "request_id" in deliveryEnvelope
    ) {
      port.postMessage({
        protocol: PLUGIN_HOST_RPC_PROTOCOL,
        version: PLUGIN_HOST_RPC_VERSION,
        kind: "response",
        request_id: deliveryEnvelope.request_id,
        payload: { ok: true },
      });
    }
    await expect(delivery).resolves.toEqual({ ok: true });

    port.postMessage(
      requestEnvelope({
        request_id: "request-command-context",
        request_nonce: "nonce-command-context",
        operation: "documents.getActiveDocument",
        execution_context_id: handle.execution_context_id,
        resource: { document_id: "doc-1", max_bytes: 64 },
      }),
    );
    expect(await waitForPortMessage(port)).toEqual({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: "request-command-context",
      payload: { plaintext: "content" },
    });

    port.postMessage(
      requestEnvelope({
        request_id: "request-command-context-consumed",
        request_nonce: "nonce-command-context-consumed",
        operation: "documents.getActiveDocument",
        execution_context_id: handle.execution_context_id,
        resource: { document_id: "doc-1", max_bytes: 64 },
      }),
    );
    expect(await waitForPortMessage(port)).toEqual({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "error",
      request_id: "request-command-context-consumed",
      error: {
        code: "execution_context_consumed",
        message: "execution context was already consumed",
      },
    });
  });

  it("rejects requests that do not match the bound owner identity, capability, or frame generation", async () => {
    const frame = new FakeFrameWindow();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    let called = false;
    router.registerHandler(
      "echo",
      () => {
        called = true;
      },
      NON_PLAINTEXT_RPC_POLICY,
    );
    const { port } = boot(router, frame);

    port.postMessage(requestEnvelope({ capability_id: "wrong-capability" }));
    const capabilityError = await waitForPortMessage(port);

    expect(capabilityError).toEqual({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "error",
      request_id: "request-1",
      error: {
        code: "capability_mismatch",
        message: "capability_id does not match session",
      },
    });
    expect(called).toBe(false);

    port.postMessage(
      requestEnvelope({
        request_id: "request-2",
        request_nonce: "nonce-2",
        consent_epoch: 2,
      }),
    );
    const consentError = await waitForPortMessage(port);

    expect(consentError).toEqual({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "error",
      request_id: "request-2",
      error: {
        code: "consent_epoch_mismatch",
        message: "consent_epoch does not match session",
      },
    });
    expect(called).toBe(false);

    port.postMessage(
      requestEnvelope({
        request_id: "request-3",
        request_nonce: "nonce-3",
        capability_grant_id: "stale-grant",
      }),
    );
    const grantError = await waitForPortMessage(port);

    expect(grantError).toEqual({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "error",
      request_id: "request-3",
      error: {
        code: "capability_grant_mismatch",
        message: "capability_grant_id does not match session",
      },
    });
    expect(called).toBe(false);

    port.postMessage(
      requestEnvelope({
        request_id: "request-4",
        request_nonce: "nonce-4",
        manifest_hash: "wrong-manifest",
      }),
    );
    const manifestError = await waitForPortMessage(port);

    expect(manifestError).toEqual({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "error",
      request_id: "request-4",
      error: {
        code: "manifest_mismatch",
        message: "manifest_hash does not match session",
      },
    });
    expect(called).toBe(false);

    port.postMessage(
      requestEnvelope({
        request_id: "request-5",
        request_nonce: "nonce-5",
        frame_generation: 8,
      }),
    );
    const frameError = await waitForPortMessage(port);

    expect(frameError).toEqual({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "error",
      request_id: "request-5",
      error: {
        code: "frame_generation_mismatch",
        message: "frame_generation does not match session",
      },
    });
    expect(called).toBe(false);
  });

  it("fails closed when the session freshness validator rejects a request", async () => {
    const frame = new FakeFrameWindow();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => ({
        code: "consent_stale",
        message: "consent epoch is no longer current",
      }),
    });
    let called = false;
    router.registerHandler(
      "echo",
      () => {
        called = true;
      },
      NON_PLAINTEXT_RPC_POLICY,
    );
    const { port } = boot(router, frame);

    port.postMessage(requestEnvelope());
    const response = await waitForPortMessage(port);

    expect(response).toEqual({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "error",
      request_id: "request-1",
      error: {
        code: "consent_stale",
        message: "consent epoch is no longer current",
      },
    });
    expect(called).toBe(false);
  });

  it("enforces handler permissions, document scope, execution context, and plaintext audit before dispatch", async () => {
    const frame = new FakeFrameWindow();
    const auditEvents: PluginAuditEvent[] = [];
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
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
    let called = 0;
    const auditActor = {
      user_id: "00000000-0000-4000-8000-000000000201",
      device_id: "00000000-0000-4000-8000-000000000202",
      session_id: "00000000-0000-4000-8000-000000000203",
      principal_kind: "user" as const,
      principal_id: "00000000-0000-4000-8000-000000000201",
    };
    router.registerHandler(
      "documents.getActiveDocument",
      () => {
        called += 1;
        return { plaintext: "content" };
      },
      activeDocumentPolicy,
    );
    const { session, port } = createSessionAndBoot(router, frame, {
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
      permissions: ["document:read:active"],
      documentScope: { activeDocumentId: "doc-1" },
      auditActor,
      auditSink: (event) => {
        auditEvents.push(event);
        return true;
      },
    });

    port.postMessage(
      requestEnvelope({
        request_id: "request-no-context",
        request_nonce: "nonce-no-context",
        operation: "documents.getActiveDocument",
        resource: { document_id: "doc-1", max_bytes: 256 },
      }),
    );
    expect(await waitForPortMessage(port)).toEqual({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "error",
      request_id: "request-no-context",
      error: {
        code: "execution_context_required",
        message: "plaintext RPC requires a Host-issued execution context",
      },
    });
    expect(called).toBe(0);
    expect(auditEvents.at(-1)).toMatchObject({
      protocol: "refmd.security-audit-event",
      version: 1,
      event_id: expect.any(String),
      class: "security_runtime",
      actor: auditActor,
      type: "plugin.plaintext_payload.denied",
      requestId: "request-no-context",
      payloadKind: "plaintext.read",
      plaintextScopeKind: "active_document",
      plaintextBytes: 256,
      contextKind: null,
      result: "deny",
      reasonCode: "execution_context_required",
      action: {
        operation: "documents.getActiveDocument",
        result: "denied",
        reason_code: "execution_context_required",
      },
      sensitivity: {
        plaintext_scope_kind: "active_document",
        plaintext_bytes: 256,
      },
      resource: {
        kind: "plugin",
        id: "plugin.example",
        version_hash: "bundle-hash-1",
      },
      correlation: {
        request_id: "request-no-context",
        capability_id: "capability-1",
        execution_context_id: null,
      },
      created_at: expect.any(String),
    });
    expect(session.sessionId).not.toBe(auditActor.session_id);
    expect(auditEvents.at(-1)).not.toHaveProperty("plaintext");
    expect(auditEvents.at(-1)).not.toHaveProperty("payload");
    expect(auditEvents.at(-1)).not.toHaveProperty("auditResource");

    const handle = session.issueExecutionContext({
      kind: "user_command",
      hostInvocation: { kind: "command", userGesture: true },
      resource: { document_id: "doc-1" },
      plaintextScope: { kind: "active_document", maxBytes: 512 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
      singleUse: true,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "request-wrong-doc",
        request_nonce: "nonce-wrong-doc",
        operation: "documents.getActiveDocument",
        execution_context_id: handle.execution_context_id,
        resource: { document_id: "doc-2", max_bytes: 256 },
      }),
    );
    expect(await waitForPortMessage(port)).toEqual({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "error",
      request_id: "request-wrong-doc",
      error: {
        code: "document_scope_denied",
        message: "requested document is not the active document",
      },
    });
    expect(called).toBe(0);
    expect(auditEvents.at(-1)).toMatchObject({
      type: "plugin.plaintext_payload.denied",
      requestId: "request-wrong-doc",
      executionContextId: handle.execution_context_id,
      contextKind: "user_command",
      plaintextScopeKind: "active_document",
      plaintextBytes: 256,
      result: "deny",
      reasonCode: "document_scope_denied",
      correlation: {
        request_id: "request-wrong-doc",
        execution_context_id: handle.execution_context_id,
      },
    });

    port.postMessage(
      requestEnvelope({
        request_id: "request-ok",
        request_nonce: "nonce-ok",
        operation: "documents.getActiveDocument",
        execution_context_id: handle.execution_context_id,
        resource: { document_id: "doc-1", max_bytes: 256 },
      }),
    );
    expect(await waitForPortMessage(port)).toEqual({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: "request-ok",
      payload: { plaintext: "content" },
    });
    expect(called).toBe(1);
    expect(auditEvents.at(-1)).toMatchObject({
      type: "plugin.plaintext_payload.delivered",
      result: "allow",
      requestId: "request-ok",
      executionContextId: handle.execution_context_id,
      contextKind: "user_command",
      payloadKind: "plaintext.read",
      plaintextScopeKind: "active_document",
      plaintextBytes: 7,
      action: {
        operation: "documents.getActiveDocument",
        result: "allowed",
        reason_code: null,
      },
      actor: auditActor,
      sensitivity: {
        plaintext_scope_kind: "active_document",
        plaintext_bytes: 7,
        egress_bytes: 0,
        storage_bytes: 0,
      },
      correlation: {
        request_id: "request-ok",
        capability_id: "capability-1",
        execution_context_id: handle.execution_context_id,
      },
    });
    expect(auditEvents.at(-1)).not.toHaveProperty("plaintext");

    port.postMessage(
      requestEnvelope({
        request_id: "request-consumed",
        request_nonce: "nonce-consumed",
        operation: "documents.getActiveDocument",
        execution_context_id: handle.execution_context_id,
        resource: { document_id: "doc-1", max_bytes: 256 },
      }),
    );
    expect(await waitForPortMessage(port)).toEqual({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "error",
      request_id: "request-consumed",
      error: {
        code: "execution_context_consumed",
        message: "execution context was already consumed",
      },
    });
    expect(called).toBe(1);
  });

  it("consumes a single-use execution context before concurrent plaintext dispatch", async () => {
    const frame = new FakeFrameWindow();
    const firstHandler = deferred<{ plaintext: string }>();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const activeDocumentPolicy: PluginHostRpcOperationPolicy = {
      requiredPermissions: ["document:read:active"],
      documentAccess: "active_document",
      plaintext: {
        operation: "plaintext.read",
        requiredPermission: "document:read:active",
        allowedContextKinds: ["user_command"],
        allowedPlaintextScopes: ["active_document"],
        audit: "required",
      },
    };
    let called = 0;
    router.registerHandler(
      "documents.getActiveDocument",
      () => {
        called += 1;
        return firstHandler.promise;
      },
      activeDocumentPolicy,
    );
    const { session, port } = createSessionAndBoot(router, frame, {
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
      permissions: ["document:read:active"],
      documentScope: { activeDocumentId: "doc-1" },
      auditSink: () => true,
    });
    const handle = session.issueExecutionContext({
      kind: "user_command",
      hostInvocation: { kind: "command", userGesture: true },
      resource: { document_id: "doc-1" },
      plaintextScope: { kind: "active_document", maxBytes: 512 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
      singleUse: true,
    });

    const messages = waitForPortMessages(port, 2);
    port.postMessage(
      requestEnvelope({
        request_id: "request-first",
        request_nonce: "nonce-first",
        operation: "documents.getActiveDocument",
        execution_context_id: handle.execution_context_id,
        resource: { document_id: "doc-1", max_bytes: 256 },
      }),
    );
    await vi.waitFor(() => expect(called).toBe(1));

    port.postMessage(
      requestEnvelope({
        request_id: "request-second",
        request_nonce: "nonce-second",
        operation: "documents.getActiveDocument",
        execution_context_id: handle.execution_context_id,
        resource: { document_id: "doc-1", max_bytes: 256 },
      }),
    );

    firstHandler.resolve({ plaintext: "content" });

    const observedMessages = await messages;
    expect(
      observedMessages.find(
        (message) =>
          typeof message === "object" &&
          message !== null &&
          "kind" in message &&
          message.kind === "error" &&
          "request_id" in message &&
          message.request_id === "request-second",
      ),
    ).toMatchObject({
      kind: "error",
      request_id: "request-second",
      error: { code: "execution_context_consumed" },
    });
    expect(
      observedMessages.find(
        (message) =>
          typeof message === "object" &&
          message !== null &&
          "kind" in message &&
          message.kind === "response" &&
          "request_id" in message &&
          message.request_id === "request-first",
      ),
    ).toMatchObject({
      kind: "response",
      request_id: "request-first",
      payload: { plaintext: "content" },
    });
    expect(called).toBe(1);
  });

  it("keeps a single-use execution context available when plaintext delivery finalization fails", async () => {
    const frame = new FakeFrameWindow();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const activeDocumentPolicy: PluginHostRpcOperationPolicy = {
      requiredPermissions: ["document:read:active"],
      documentAccess: "active_document",
      plaintext: {
        operation: "plaintext.read",
        requiredPermission: "document:read:active",
        allowedContextKinds: ["user_command"],
        allowedPlaintextScopes: ["active_document"],
        audit: "required",
      },
    };
    let called = 0;
    router.registerHandler(
      "documents.getActiveDocument",
      () => {
        called += 1;
        return { plaintext: called === 1 ? "content too large" : "ok" };
      },
      activeDocumentPolicy,
    );
    const { session, port } = createSessionAndBoot(router, frame, {
      permissions: ["document:read:active"],
      documentScope: { activeDocumentId: "doc-1" },
      auditSink: () => true,
    });
    const handle = session.issueExecutionContext({
      kind: "user_command",
      hostInvocation: { kind: "command", userGesture: true },
      resource: { document_id: "doc-1", max_bytes: 8 },
      plaintextScope: { kind: "active_document", maxBytes: 8 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
      singleUse: true,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "request-too-large",
        request_nonce: "nonce-too-large",
        operation: "documents.getActiveDocument",
        execution_context_id: handle.execution_context_id,
        resource: { document_id: "doc-1", max_bytes: 8 },
      }),
    );
    expect(await waitForPortMessage(port)).toEqual({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "error",
      request_id: "request-too-large",
      error: {
        code: "plaintext_payload_too_large",
        message: "plaintext RPC response exceeds the execution context byte limit",
      },
    });

    port.postMessage(
      requestEnvelope({
        request_id: "request-retry",
        request_nonce: "nonce-retry",
        operation: "documents.getActiveDocument",
        execution_context_id: handle.execution_context_id,
        resource: { document_id: "doc-1", max_bytes: 8 },
      }),
    );
    expect(await waitForPortMessage(port)).toEqual({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: "request-retry",
      payload: { plaintext: "ok" },
    });

    port.postMessage(
      requestEnvelope({
        request_id: "request-consumed-after-retry",
        request_nonce: "nonce-consumed-after-retry",
        operation: "documents.getActiveDocument",
        execution_context_id: handle.execution_context_id,
        resource: { document_id: "doc-1", max_bytes: 8 },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      request_id: "request-consumed-after-retry",
      error: { code: "execution_context_consumed" },
    });
    expect(called).toBe(2);
  });

  it("binds selection plaintext execution contexts to the Host selection range", async () => {
    const frame = new FakeFrameWindow();
    const auditEvents: PluginAuditEvent[] = [];
    let called = 0;
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    router.registerHandler(
      "editor.getSelection",
      () => {
        called += 1;
        return { text: "hello" };
      },
      {
        requiredPermissions: ["editor:selection:read"],
        documentAccess: "allowed_document",
        plaintext: {
          operation: "plaintext.read",
          requiredPermission: "editor:selection:read",
          allowedContextKinds: ["user_command"],
          allowedPlaintextScopes: ["selection"],
          audit: "required",
        },
      },
    );
    const { session, port } = createSessionAndBoot(router, frame, {
      permissions: ["editor:selection:read"],
      documentScope: { allowedDocumentIds: ["doc-1"] },
      auditSink(event) {
        auditEvents.push(event);
        return true;
      },
    });
    const handle = session.issueExecutionContext({
      kind: "user_command",
      hostInvocation: { kind: "command", userGesture: true },
      resource: {
        document_id: "doc-1",
        editor_id: "editor-1",
        selection_range: { anchor: 4, head: 9 },
      },
      plaintextScope: { kind: "selection", maxBytes: 32 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "selection-ok",
        request_nonce: "selection-ok-nonce",
        operation: "editor.getSelection",
        execution_context_id: handle.execution_context_id,
        resource: {
          document_id: "doc-1",
          editor_id: "editor-1",
          selection_range: { anchor: 4, head: 9 },
          max_bytes: 32,
        },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "response",
      request_id: "selection-ok",
      payload: { text: "hello" },
    });
    expect(auditEvents.at(-1)).toMatchObject({
      type: "plugin.plaintext_payload.delivered",
      operation: "editor.getSelection",
      plaintextScopeKind: "selection",
    });

    port.postMessage(
      requestEnvelope({
        request_id: "selection-range-mismatch",
        request_nonce: "selection-range-mismatch-nonce",
        operation: "editor.getSelection",
        execution_context_id: handle.execution_context_id,
        resource: {
          document_id: "doc-1",
          editor_id: "editor-1",
          selection_range: { anchor: 5, head: 9 },
          max_bytes: 32,
        },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      request_id: "selection-range-mismatch",
      error: {
        code: "execution_context_resource_mismatch",
      },
    });
    expect(called).toBe(1);
  });

  it("binds editor context plaintext execution contexts to the Host context range", async () => {
    const frame = new FakeFrameWindow();
    const auditEvents: PluginAuditEvent[] = [];
    let called = 0;
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    router.registerHandler(
      "editor.getContext",
      () => {
        called += 1;
        return { context: "nearby text" };
      },
      {
        requiredPermissions: ["editor:context:read"],
        documentAccess: "allowed_document",
        plaintext: {
          operation: "plaintext.read",
          requiredPermission: "editor:context:read",
          allowedContextKinds: ["editor_suggestion"],
          allowedPlaintextScopes: ["editor_context"],
          audit: "required",
        },
      },
    );
    const { session, port } = createSessionAndBoot(router, frame, {
      permissions: ["editor:context:read"],
      documentScope: { allowedDocumentIds: ["doc-1"] },
      auditSink(event) {
        auditEvents.push(event);
        return true;
      },
    });
    const handle = session.issueExecutionContext({
      kind: "editor_suggestion",
      hostInvocation: { kind: "editor_suggestion_provider", userGesture: false },
      resource: {
        document_id: "doc-1",
        editor_id: "editor-1",
        context_range: { anchor: 10, head: 40 },
      },
      plaintextScope: { kind: "editor_context", maxBytes: 128 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "context-ok",
        request_nonce: "context-ok-nonce",
        operation: "editor.getContext",
        execution_context_id: handle.execution_context_id,
        resource: {
          document_id: "doc-1",
          editor_id: "editor-1",
          context_range: { anchor: 10, head: 40 },
          max_bytes: 128,
        },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "response",
      request_id: "context-ok",
      payload: { context: "nearby text" },
    });
    expect(auditEvents.at(-1)).toMatchObject({
      type: "plugin.plaintext_payload.delivered",
      operation: "editor.getContext",
      plaintextScopeKind: "editor_context",
    });

    port.postMessage(
      requestEnvelope({
        request_id: "context-range-mismatch",
        request_nonce: "context-range-mismatch-nonce",
        operation: "editor.getContext",
        execution_context_id: handle.execution_context_id,
        resource: {
          document_id: "doc-1",
          editor_id: "editor-1",
          context_range: { anchor: 11, head: 40 },
          max_bytes: 128,
        },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      request_id: "context-range-mismatch",
      error: {
        code: "execution_context_resource_mismatch",
      },
    });
    expect(called).toBe(1);
  });

  it("rejects in-flight plaintext delivery when the execution context expires before handler completion", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(1_000);
    const frame = new FakeFrameWindow();
    const auditEvents: PluginAuditEvent[] = [];
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const activeDocumentPolicy: PluginHostRpcOperationPolicy = {
      requiredPermissions: ["document:read:active"],
      documentAccess: "active_document",
      plaintext: {
        operation: "plaintext.read",
        requiredPermission: "document:read:active",
        allowedContextKinds: ["user_command"],
        allowedPlaintextScopes: ["active_document"],
        audit: "required",
      },
    };
    let resolveHandler!: (payload: unknown) => void;
    let markHandlerStarted!: () => void;
    const handlerStarted = new Promise<void>((resolve) => {
      markHandlerStarted = resolve;
    });
    router.registerHandler(
      "documents.getActiveDocument",
      () => {
        markHandlerStarted();
        return new Promise((resolve) => {
          resolveHandler = resolve;
        });
      },
      activeDocumentPolicy,
    );
    const { session, port } = createSessionAndBoot(router, frame, {
      permissions: ["document:read:active"],
      documentScope: { activeDocumentId: "doc-1" },
      auditSink(event) {
        auditEvents.push(event);
        return true;
      },
    });
    const handle = session.issueExecutionContext({
      kind: "user_command",
      hostInvocation: { kind: "command", userGesture: true },
      resource: { document_id: "doc-1" },
      plaintextScope: { kind: "active_document", maxBytes: 512 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: 1_500,
    });

    try {
      const response = waitForPortMessage(port);
      port.postMessage(
        requestEnvelope({
          request_id: "request-expired-after-dispatch",
          request_nonce: "nonce-expired-after-dispatch",
          operation: "documents.getActiveDocument",
          execution_context_id: handle.execution_context_id,
          resource: { document_id: "doc-1", max_bytes: 256 },
        }),
      );
      await handlerStarted;
      vi.setSystemTime(1_600);
      resolveHandler({ plaintext: "content" });

      expect(await response).toEqual({
        protocol: PLUGIN_HOST_RPC_PROTOCOL,
        version: PLUGIN_HOST_RPC_VERSION,
        kind: "error",
        request_id: "request-expired-after-dispatch",
        error: {
          code: "execution_context_expired",
          message: "execution context has expired",
        },
      });
      expect(auditEvents.at(-1)).toMatchObject({
        type: "plugin.plaintext_payload.denied",
        requestId: "request-expired-after-dispatch",
        executionContextId: handle.execution_context_id,
        reasonCode: "execution_context_expired",
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("rejects plaintext RPC when permission, context kind, byte scope, or audit sink is missing", async () => {
    const activeDocumentPolicy: PluginHostRpcOperationPolicy = {
      requiredPermissions: ["document:read:active"],
      documentAccess: "active_document",
      plaintext: {
        operation: "plaintext.read",
        requiredPermission: "document:read:active",
        allowedContextKinds: ["user_command"],
        allowedPlaintextScopes: ["active_document"],
        audit: "required",
      },
    };

    const missingFreshnessValidatorFrame = new FakeFrameWindow();
    const missingFreshnessValidatorAuditEvents: PluginAuditEvent[] = [];
    const missingFreshnessValidatorRouter = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
    });
    let missingFreshnessValidatorCalled = false;
    missingFreshnessValidatorRouter.registerHandler(
      "documents.getActiveDocument",
      () => {
        missingFreshnessValidatorCalled = true;
        return "nope";
      },
      activeDocumentPolicy,
    );
    const { port: missingFreshnessValidatorPort } = createSessionAndBoot(
      missingFreshnessValidatorRouter,
      missingFreshnessValidatorFrame,
      {
        permissions: ["document:read:active"],
        documentScope: { activeDocumentId: "doc-1" },
        auditSink(event) {
          missingFreshnessValidatorAuditEvents.push(event);
          return true;
        },
      },
    );

    missingFreshnessValidatorPort.postMessage(
      requestEnvelope({
        request_id: "missing-freshness-validator",
        request_nonce: "missing-freshness-validator-nonce",
        operation: "documents.getActiveDocument",
        resource: { document_id: "doc-1" },
      }),
    );
    expect(await waitForPortMessage(missingFreshnessValidatorPort)).toMatchObject({
      kind: "error",
      request_id: "missing-freshness-validator",
      error: {
        code: "session_freshness_validator_required",
      },
    });
    expect(missingFreshnessValidatorCalled).toBe(false);
    expect(missingFreshnessValidatorAuditEvents).toHaveLength(1);
    expect(missingFreshnessValidatorAuditEvents[0]).toMatchObject({
      type: "plugin.plaintext_payload.denied",
      requestId: "missing-freshness-validator",
      reasonCode: "session_freshness_validator_required",
    });

    const missingPlaintextCapabilityRouter = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    expect(() => {
      missingPlaintextCapabilityRouter.registerHandler(
        "documents.getActiveDocument",
        () => "nope",
        {
          requiredPermissions: ["ui:panel"],
          documentAccess: "active_document",
          plaintext: {
            operation: "plaintext.read",
            requiredPermission: "document:read:active",
            allowedContextKinds: ["user_command"],
            allowedPlaintextScopes: ["active_document"],
            audit: "required",
          },
        },
      );
    }).toThrow(
      expect.objectContaining({
        code: "plaintext_capability_required",
      } satisfies Partial<PluginHostRpcError>),
    );

    const missingPermissionFrame = new FakeFrameWindow();
    const missingPermissionAuditEvents: PluginAuditEvent[] = [];
    const missingPermissionRouter = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    missingPermissionRouter.registerHandler(
      "documents.getActiveDocument",
      () => "nope",
      activeDocumentPolicy,
    );
    const { port: missingPermissionPort } = createSessionAndBoot(
      missingPermissionRouter,
      missingPermissionFrame,
      {
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
        contentWindow: missingPermissionFrame,
        documentScope: { activeDocumentId: "doc-1" },
        auditSink(event) {
          missingPermissionAuditEvents.push(event);
          return true;
        },
      },
    );

    missingPermissionPort.postMessage(
      requestEnvelope({
        operation: "documents.getActiveDocument",
        resource: { document_id: "doc-1" },
      }),
    );
    expect(await waitForPortMessage(missingPermissionPort)).toMatchObject({
      kind: "error",
      error: {
        code: "permission_denied",
      },
    });
    expect(missingPermissionAuditEvents).toHaveLength(1);
    expect(missingPermissionAuditEvents[0]).toMatchObject({
      type: "plugin.plaintext_payload.denied",
      requestId: "request-1",
      executionContextId: null,
      contextKind: null,
      plaintextScopeKind: "active_document",
      plaintextBytes: 0,
      result: "deny",
      reasonCode: "permission_denied",
    });

    const auditlessPermissionFrame = new FakeFrameWindow();
    const auditlessPermissionRouter = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    auditlessPermissionRouter.registerHandler(
      "documents.getActiveDocument",
      () => "nope",
      activeDocumentPolicy,
    );
    const { port: auditlessPermissionPort } = createSessionAndBoot(
      auditlessPermissionRouter,
      auditlessPermissionFrame,
      {
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
        contentWindow: auditlessPermissionFrame,
        documentScope: { activeDocumentId: "doc-1" },
      },
    );

    auditlessPermissionPort.postMessage(
      requestEnvelope({
        request_id: "auditless-permission",
        request_nonce: "auditless-permission-nonce",
        operation: "documents.getActiveDocument",
        resource: { document_id: "doc-1" },
      }),
    );
    expect(await waitForPortMessage(auditlessPermissionPort)).toMatchObject({
      kind: "error",
      request_id: "auditless-permission",
      error: {
        code: "audit_sink_unavailable",
      },
    });

    const frame = new FakeFrameWindow();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    router.registerHandler("documents.getActiveDocument", () => "ok", activeDocumentPolicy);
    const { session, port } = createSessionAndBoot(router, frame, {
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
      permissions: ["document:read:active"],
      documentScope: { activeDocumentId: "doc-1" },
      auditSink: () => true,
    });

    expect(() =>
      session.issueExecutionContext({
        kind: "user_command",
        hostInvocation: { kind: "command", userGesture: true },
        plaintextScope: { kind: "active_document", maxBytes: 64 },
        allowedOperations: ["plaintext.read"],
        expiresAtMs: Date.now() + 60_000,
      }),
    ).toThrowError(PluginHostRpcError);
    expect(() =>
      session.issueExecutionContext({
        kind: "user_command",
        resource: { document_id: "doc-1" },
        plaintextScope: { kind: "active_document", maxBytes: 64 },
        allowedOperations: ["plaintext.read"],
        expiresAtMs: Date.now() + 60_000,
      } as unknown as PluginExecutionContextIssueOptions),
    ).toThrow(
      expect.objectContaining({
        code: "host_invocation_required",
      } satisfies Partial<PluginHostRpcError>),
    );
    expect(() =>
      session.issueExecutionContext({
        kind: "ui_action",
        resource: { document_id: "doc-1" },
        plaintextScope: { kind: "active_document", maxBytes: 64 },
        hostInvocation: { kind: "command", userGesture: true },
        allowedOperations: ["plaintext.read"],
        expiresAtMs: Date.now() + 60_000,
      }),
    ).toThrow(
      expect.objectContaining({
        code: "host_invocation_denied",
      } satisfies Partial<PluginHostRpcError>),
    );
    expect(() =>
      session.issueExecutionContext({
        kind: "renderer_invocation",
        hostInvocation: { kind: "renderer_slot", userGesture: false },
        resource: { document_id: "doc-1" },
        plaintextScope: { kind: "block", maxBytes: 64 },
        allowedOperations: ["plaintext.read"],
        expiresAtMs: Date.now() + 60_000,
      }),
    ).toThrowError("renderer plaintext context requires document_id and block_id");
    expect(() =>
      session.issueExecutionContext({
        kind: "user_command",
        hostInvocation: { kind: "command", userGesture: true },
        resource: { document_id: "doc-1", editor_id: "editor-1" },
        plaintextScope: { kind: "selection", maxBytes: 64 },
        allowedOperations: ["plaintext.read"],
        expiresAtMs: Date.now() + 60_000,
      }),
    ).toThrowError(
      "selection plaintext context requires editor_id or document selection resource and selection_range",
    );
    expect(() =>
      session.issueExecutionContext({
        kind: "editor_suggestion",
        hostInvocation: { kind: "editor_suggestion_provider", userGesture: false },
        resource: { document_id: "doc-1", editor_id: "editor-1" },
        plaintextScope: { kind: "editor_context", maxBytes: 64 },
        allowedOperations: ["plaintext.read"],
        expiresAtMs: Date.now() + 60_000,
      }),
    ).toThrowError(
      "editor context plaintext context requires editor_id or document_id and context_range",
    );
    expect(() =>
      session.issueExecutionContext({
        kind: "user_command",
        hostInvocation: { kind: "command", userGesture: true },
        resource: { document_id: "doc-1" },
        plaintextScope: { kind: "active_document", maxBytes: 64 },
        allowedOperations: ["plaintext.read"],
        expiresAtMs: Date.now() - 1,
      }),
    ).toThrow(
      expect.objectContaining({
        code: "execution_context_expired",
      } satisfies Partial<PluginHostRpcError>),
    );
    expect(() =>
      session.issueExecutionContext({
        kind: "user_command",
        hostInvocation: { kind: "command", userGesture: true },
        resource: { document_id: "doc-1" },
        plaintextScope: { kind: "active_document", maxBytes: 64 },
        allowedOperations: ["plaintext.read"],
        expiresAtMs: Number.POSITIVE_INFINITY,
      }),
    ).toThrow(
      expect.objectContaining({
        code: "invalid_execution_context_expiration",
      } satisfies Partial<PluginHostRpcError>),
    );
    expect(() =>
      session.issueExecutionContext({
        kind: "user_command",
        hostInvocation: { kind: "command", userGesture: true },
        resource: { document_id: "doc-1" },
        plaintextScope: { kind: "active_document", maxBytes: 64 },
        allowedOperations: ["plaintext.read"],
        expiresAtMs: Date.now() + PLUGIN_EXECUTION_CONTEXT_MAX_TTL_MS + 60_000,
      }),
    ).toThrow(
      expect.objectContaining({
        code: "execution_context_ttl_too_long",
      } satisfies Partial<PluginHostRpcError>),
    );
    expect(() =>
      session.issueExecutionContext({
        kind: "user_command",
        hostInvocation: { kind: "command", userGesture: true },
        resource: { document_id: "doc-1" },
        plaintextScope: { kind: "active_document", maxBytes: Number.NaN },
        allowedOperations: ["plaintext.read"],
        expiresAtMs: Date.now() + 60_000,
      }),
    ).toThrow(
      expect.objectContaining({
        code: "invalid_plaintext_byte_limit",
      } satisfies Partial<PluginHostRpcError>),
    );

    const wrongKind = session.issueExecutionContext({
      kind: "renderer_invocation",
      hostInvocation: { kind: "renderer_slot", userGesture: false },
      resource: { document_id: "doc-1" },
      plaintextScope: { kind: "active_document", maxBytes: 64 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "wrong-kind",
        request_nonce: "wrong-kind-nonce",
        operation: "documents.getActiveDocument",
        execution_context_id: wrongKind.execution_context_id,
        resource: { document_id: "doc-1", max_bytes: 32 },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      request_id: "wrong-kind",
      error: {
        code: "execution_context_kind_denied",
      },
    });

    const tooSmall = session.issueExecutionContext({
      kind: "user_command",
      hostInvocation: { kind: "command", userGesture: true },
      resource: { document_id: "doc-1" },
      plaintextScope: { kind: "active_document", maxBytes: 16 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "too-large",
        request_nonce: "too-large-nonce",
        operation: "documents.getActiveDocument",
        execution_context_id: tooSmall.execution_context_id,
        resource: { document_id: "doc-1", max_bytes: 32 },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      request_id: "too-large",
      error: {
        code: "plaintext_scope_denied",
      },
    });

    const invalidRequestLimit = session.issueExecutionContext({
      kind: "user_command",
      hostInvocation: { kind: "command", userGesture: true },
      resource: { document_id: "doc-1" },
      plaintextScope: { kind: "active_document", maxBytes: 64 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "invalid-request-limit",
        request_nonce: "invalid-request-limit-nonce",
        operation: "documents.getActiveDocument",
        execution_context_id: invalidRequestLimit.execution_context_id,
        resource: { document_id: "doc-1", max_bytes: Number.NaN },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      request_id: "invalid-request-limit",
      error: {
        code: "invalid_plaintext_byte_limit",
      },
    });

    const auditlessFrame = new FakeFrameWindow();
    const auditlessRouter = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    auditlessRouter.registerHandler(
      "documents.getActiveDocument",
      () => "ok",
      activeDocumentPolicy,
    );
    const { session: auditlessSession, port: auditlessPort } = createSessionAndBoot(
      auditlessRouter,
      auditlessFrame,
      {
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
        contentWindow: auditlessFrame,
        permissions: ["document:read:active"],
        documentScope: { activeDocumentId: "doc-1" },
      },
    );

    auditlessPort.postMessage(
      requestEnvelope({
        request_id: "auditless-denied",
        request_nonce: "auditless-denied-nonce",
        operation: "documents.getActiveDocument",
        resource: { document_id: "doc-1", max_bytes: 32 },
      }),
    );
    expect(await waitForPortMessage(auditlessPort)).toMatchObject({
      kind: "error",
      request_id: "auditless-denied",
      error: {
        code: "audit_sink_unavailable",
      },
    });

    const auditlessContext = auditlessSession.issueExecutionContext({
      kind: "user_command",
      hostInvocation: { kind: "command", userGesture: true },
      resource: { document_id: "doc-1" },
      plaintextScope: { kind: "active_document", maxBytes: 64 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
    });

    auditlessPort.postMessage(
      requestEnvelope({
        request_id: "auditless",
        request_nonce: "auditless-nonce",
        operation: "documents.getActiveDocument",
        execution_context_id: auditlessContext.execution_context_id,
        resource: { document_id: "doc-1", max_bytes: 32 },
      }),
    );
    expect(await waitForPortMessage(auditlessPort)).toMatchObject({
      kind: "error",
      request_id: "auditless",
      error: {
        code: "audit_sink_unavailable",
      },
    });
  });

  it("checks actual plaintext response bytes before delivery and audits delivered bytes", async () => {
    const activeDocumentPolicy: PluginHostRpcOperationPolicy = {
      requiredPermissions: ["document:read:active"],
      documentAccess: "active_document",
      plaintext: {
        operation: "plaintext.read",
        requiredPermission: "document:read:active",
        allowedContextKinds: ["user_command"],
        allowedPlaintextScopes: ["active_document"],
        audit: "required",
      },
    };

    const frame = new FakeFrameWindow();
    const auditEvents: PluginAuditEvent[] = [];
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    router.registerHandler(
      "documents.getActiveDocument",
      () => ({ plaintext: "content" }),
      activeDocumentPolicy,
    );
    const { session, port } = createSessionAndBoot(router, frame, {
      permissions: ["document:read:active"],
      documentScope: { activeDocumentId: "doc-1" },
      auditSink(event) {
        auditEvents.push(event);
        return true;
      },
    });

    const withinLimit = session.issueExecutionContext({
      kind: "user_command",
      hostInvocation: { kind: "command", userGesture: true },
      resource: { document_id: "doc-1" },
      plaintextScope: { kind: "active_document", maxBytes: 7 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "omitted-max-ok",
        request_nonce: "omitted-max-ok-nonce",
        operation: "documents.getActiveDocument",
        execution_context_id: withinLimit.execution_context_id,
        resource: { document_id: "doc-1" },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "response",
      request_id: "omitted-max-ok",
      payload: { plaintext: "content" },
    });
    expect(auditEvents.at(-1)).toMatchObject({
      type: "plugin.plaintext_payload.delivered",
      requestId: "omitted-max-ok",
      plaintextBytes: 7,
      sensitivity: { plaintext_bytes: 7 },
    });

    const tooSmall = session.issueExecutionContext({
      kind: "user_command",
      hostInvocation: { kind: "command", userGesture: true },
      resource: { document_id: "doc-1" },
      plaintextScope: { kind: "active_document", maxBytes: 6 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "omitted-max-too-large",
        request_nonce: "omitted-max-too-large-nonce",
        operation: "documents.getActiveDocument",
        execution_context_id: tooSmall.execution_context_id,
        resource: { document_id: "doc-1" },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      request_id: "omitted-max-too-large",
      error: {
        code: "plaintext_payload_too_large",
      },
    });
    expect(auditEvents.at(-1)).toMatchObject({
      type: "plugin.plaintext_payload.denied",
      requestId: "omitted-max-too-large",
      plaintextBytes: 7,
      result: "deny",
      reasonCode: "plaintext_payload_too_large",
      sensitivity: { plaintext_bytes: 7 },
    });

    const lowerRequestLimit = session.issueExecutionContext({
      kind: "user_command",
      hostInvocation: { kind: "command", userGesture: true },
      resource: { document_id: "doc-1" },
      plaintextScope: { kind: "active_document", maxBytes: 32 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "request-max-too-small",
        request_nonce: "request-max-too-small-nonce",
        operation: "documents.getActiveDocument",
        execution_context_id: lowerRequestLimit.execution_context_id,
        resource: { document_id: "doc-1", max_bytes: 6 },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      request_id: "request-max-too-small",
      error: {
        code: "plaintext_payload_too_large",
      },
    });

    const invalidDeliveryLimit = session.issueExecutionContext({
      kind: "user_command",
      hostInvocation: { kind: "command", userGesture: true },
      resource: { document_id: "doc-1" },
      plaintextScope: { kind: "active_document", maxBytes: 32 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "request-max-infinite",
        request_nonce: "request-max-infinite-nonce",
        operation: "documents.getActiveDocument",
        execution_context_id: invalidDeliveryLimit.execution_context_id,
        resource: { document_id: "doc-1", max_bytes: Number.POSITIVE_INFINITY },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      request_id: "request-max-infinite",
      error: {
        code: "invalid_plaintext_byte_limit",
      },
    });
  });

  it("checks binary plaintext response bytes before delivery and audits delivered bytes", async () => {
    const activeDocumentPolicy: PluginHostRpcOperationPolicy = {
      requiredPermissions: ["document:read:active"],
      documentAccess: "active_document",
      plaintext: {
        operation: "plaintext.read",
        requiredPermission: "document:read:active",
        allowedContextKinds: ["user_command"],
        allowedPlaintextScopes: ["active_document"],
        audit: "required",
      },
    };

    const frame = new FakeFrameWindow();
    const auditEvents: PluginAuditEvent[] = [];
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    router.registerHandler(
      "documents.getActiveDocument",
      () => ({
        body: new Uint8Array([1, 2, 3, 4, 5]),
        nested: { tail: new ArrayBuffer(2) },
      }),
      activeDocumentPolicy,
    );
    const { session, port } = createSessionAndBoot(router, frame, {
      permissions: ["document:read:active"],
      documentScope: { activeDocumentId: "doc-1" },
      auditSink(event) {
        auditEvents.push(event);
        return true;
      },
    });

    const withinLimit = session.issueExecutionContext({
      kind: "user_command",
      hostInvocation: { kind: "command", userGesture: true },
      resource: { document_id: "doc-1" },
      plaintextScope: { kind: "active_document", maxBytes: 7 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "binary-ok",
        request_nonce: "binary-ok-nonce",
        operation: "documents.getActiveDocument",
        execution_context_id: withinLimit.execution_context_id,
        resource: { document_id: "doc-1" },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "response",
      request_id: "binary-ok",
    });
    expect(auditEvents.at(-1)).toMatchObject({
      type: "plugin.plaintext_payload.delivered",
      requestId: "binary-ok",
      plaintextBytes: 7,
      sensitivity: { plaintext_bytes: 7 },
    });

    const tooSmall = session.issueExecutionContext({
      kind: "user_command",
      hostInvocation: { kind: "command", userGesture: true },
      resource: { document_id: "doc-1" },
      plaintextScope: { kind: "active_document", maxBytes: 6 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "binary-too-large",
        request_nonce: "binary-too-large-nonce",
        operation: "documents.getActiveDocument",
        execution_context_id: tooSmall.execution_context_id,
        resource: { document_id: "doc-1" },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      request_id: "binary-too-large",
      error: {
        code: "plaintext_payload_too_large",
      },
    });
    expect(auditEvents.at(-1)).toMatchObject({
      type: "plugin.plaintext_payload.denied",
      requestId: "binary-too-large",
      plaintextBytes: 7,
      result: "deny",
      reasonCode: "plaintext_payload_too_large",
      sensitivity: { plaintext_bytes: 7 },
    });
  });

  it("treats renderer plaintext source as typed plaintext capability and rejects scheduled contexts", async () => {
    const frame = new FakeFrameWindow();
    const auditEvents: PluginAuditEvent[] = [];
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    router.registerHandler("renderer.getSource", () => ({ source: "graph TD; A-->B" }), {
      requiredPermissions: ["plaintext:render:block:mermaid"],
      documentAccess: "allowed_document",
      plaintext: {
        operation: "plaintext.read",
        requiredPermission: "plaintext:render:block:mermaid",
        allowedContextKinds: ["renderer_invocation"],
        allowedPlaintextScopes: ["block"],
        audit: "required",
      },
    });
    const { session, port } = createSessionAndBoot(router, frame, {
      permissions: ["plaintext:render:block:mermaid"],
      documentScope: { allowedDocumentIds: ["doc-1"] },
      auditSink: (event) => {
        auditEvents.push(event);
        return true;
      },
    });

    const scheduled = session.issueExecutionContext({
      kind: "scheduled_task",
      hostInvocation: { kind: "scheduled_policy", userGesture: false },
      resource: { document_id: "doc-1", block_id: "block-1" },
      plaintextScope: { kind: "block", maxBytes: 128 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "scheduled-renderer",
        request_nonce: "scheduled-renderer-nonce",
        operation: "renderer.getSource",
        execution_context_id: scheduled.execution_context_id,
        resource: { document_id: "doc-1", block_id: "block-1", max_bytes: 64 },
      }),
    );
    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      request_id: "scheduled-renderer",
      error: {
        code: "scheduled_context_reserved",
      },
    });

    const rendererContext = session.issueExecutionContext({
      kind: "renderer_invocation",
      hostInvocation: { kind: "renderer_slot", userGesture: false },
      resource: { document_id: "doc-1", block_id: "block-1" },
      plaintextScope: { kind: "block", maxBytes: 128 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "renderer-ok",
        request_nonce: "renderer-ok-nonce",
        operation: "renderer.getSource",
        execution_context_id: rendererContext.execution_context_id,
        resource: { document_id: "doc-1", block_id: "block-1", max_bytes: 64 },
      }),
    );
    expect(await waitForPortMessage(port)).toEqual({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: "renderer-ok",
      payload: { source: "graph TD; A-->B" },
    });
    expect(auditEvents.at(-1)).toMatchObject({
      type: "plugin.plaintext_payload.delivered",
      operation: "renderer.getSource",
      executionContextId: rendererContext.execution_context_id,
      contextKind: "renderer_invocation",
      payloadKind: "plaintext.read",
      plaintextScopeKind: "block",
      plaintextBytes: 15,
    });
  });

  it("does not allow one renderer plaintext type to authorize another renderer type", async () => {
    const frame = new FakeFrameWindow();
    const auditEvents: PluginAuditEvent[] = [];
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    router.registerHandler("renderer.getSource", () => ({ source: "chart data" }), {
      requiredPermissions: ["plaintext:render:block:chart"],
      documentAccess: "allowed_document",
      plaintext: {
        operation: "plaintext.read",
        requiredPermission: "plaintext:render:block:chart",
        allowedContextKinds: ["renderer_invocation"],
        allowedPlaintextScopes: ["block"],
        audit: "required",
      },
    });
    const { session, port } = createSessionAndBoot(router, frame, {
      permissions: ["plaintext:render:block:mermaid"],
      documentScope: { allowedDocumentIds: ["doc-1"] },
      auditSink: (event) => {
        auditEvents.push(event);
        return true;
      },
    });
    const context = session.issueExecutionContext({
      kind: "renderer_invocation",
      hostInvocation: { kind: "renderer_slot", userGesture: false },
      resource: { document_id: "doc-1", block_id: "block-1" },
      plaintextScope: { kind: "block", maxBytes: 128 },
      allowedOperations: ["plaintext.read"],
      expiresAtMs: Date.now() + 60_000,
      singleUse: true,
    });

    port.postMessage(
      requestEnvelope({
        request_id: "renderer-type-mismatch",
        request_nonce: "renderer-type-mismatch-nonce",
        operation: "renderer.getSource",
        execution_context_id: context.execution_context_id,
        resource: { document_id: "doc-1", block_id: "block-1", max_bytes: 64 },
      }),
    );

    expect(await waitForPortMessage(port)).toMatchObject({
      kind: "error",
      request_id: "renderer-type-mismatch",
      error: { code: "permission_denied" },
    });
    expect(auditEvents.at(-1)).toMatchObject({
      type: "plugin.plaintext_payload.denied",
      reasonCode: "permission_denied",
    });
  });

  it("audits plaintext owner identity and freshness denials before dispatch", async () => {
    const activeDocumentPolicy: PluginHostRpcOperationPolicy = {
      requiredPermissions: ["document:read:active"],
      documentAccess: "active_document",
      plaintext: {
        operation: "plaintext.read",
        requiredPermission: "document:read:active",
        allowedContextKinds: ["user_command"],
        allowedPlaintextScopes: ["active_document"],
        audit: "required",
      },
    };
    const identityAuditEvents: PluginAuditEvent[] = [];
    const identityFrame = new FakeFrameWindow();
    const identityRouter = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    identityRouter.registerHandler(
      "documents.getActiveDocument",
      () => "nope",
      activeDocumentPolicy,
    );
    const { port: identityPort } = createSessionAndBoot(identityRouter, identityFrame, {
      permissions: ["document:read:active"],
      documentScope: { activeDocumentId: "doc-1" },
      auditSink(event) {
        identityAuditEvents.push(event);
        return true;
      },
    });

    identityPort.postMessage(
      requestEnvelope({
        request_id: "wrong-plugin",
        request_nonce: "wrong-plugin-nonce",
        operation: "documents.getActiveDocument",
        plugin_id: "attacker.plugin",
        resource: { document_id: "doc-1" },
      }),
    );
    expect(await waitForPortMessage(identityPort)).toMatchObject({
      kind: "error",
      request_id: "wrong-plugin",
      error: { code: "plugin_mismatch" },
    });
    expect(identityAuditEvents).toHaveLength(1);
    expect(identityAuditEvents[0]).toMatchObject({
      type: "plugin.plaintext_payload.denied",
      pluginId: "plugin.example",
      packageId: "package.example",
      requestId: "wrong-plugin",
      executionContextId: null,
      plaintextScopeKind: "active_document",
      plaintextBytes: 0,
      result: "deny",
      reasonCode: "plugin_mismatch",
    });

    const freshnessAuditEvents: PluginAuditEvent[] = [];
    const freshnessFrame = new FakeFrameWindow();
    const freshnessRouter = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => ({
        code: "consent_stale",
        message: "consent epoch is no longer current",
      }),
    });
    freshnessRouter.registerHandler(
      "documents.getActiveDocument",
      () => "nope",
      activeDocumentPolicy,
    );
    const { port: freshnessPort } = createSessionAndBoot(freshnessRouter, freshnessFrame, {
      permissions: ["document:read:active"],
      documentScope: { activeDocumentId: "doc-1" },
      auditSink(event) {
        freshnessAuditEvents.push(event);
        return true;
      },
    });

    freshnessPort.postMessage(
      requestEnvelope({
        request_id: "stale-consent",
        request_nonce: "stale-consent-nonce",
        operation: "documents.getActiveDocument",
        resource: { document_id: "doc-1" },
      }),
    );
    expect(await waitForPortMessage(freshnessPort)).toMatchObject({
      kind: "error",
      request_id: "stale-consent",
      error: { code: "consent_stale" },
    });
    expect(freshnessAuditEvents).toHaveLength(1);
    expect(freshnessAuditEvents[0]).toMatchObject({
      type: "plugin.plaintext_payload.denied",
      requestId: "stale-consent",
      plaintextScopeKind: "active_document",
      result: "deny",
      reasonCode: "consent_stale",
    });

    const auditlessFrame = new FakeFrameWindow();
    const auditlessRouter = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    auditlessRouter.registerHandler(
      "documents.getActiveDocument",
      () => "nope",
      activeDocumentPolicy,
    );
    const { port: auditlessPort } = createSessionAndBoot(auditlessRouter, auditlessFrame, {
      permissions: ["document:read:active"],
      documentScope: { activeDocumentId: "doc-1" },
    });

    auditlessPort.postMessage(
      requestEnvelope({
        request_id: "auditless-identity",
        request_nonce: "auditless-identity-nonce",
        operation: "documents.getActiveDocument",
        bundle_hash: "wrong-bundle",
        resource: { document_id: "doc-1" },
      }),
    );
    expect(await waitForPortMessage(auditlessPort)).toMatchObject({
      kind: "error",
      request_id: "auditless-identity",
      error: { code: "audit_sink_unavailable" },
    });
  });

  it("rejects dangerous plaintext read and server-synced plugin storage write grants at session creation", () => {
    const frame = new FakeFrameWindow();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });

    expect(() =>
      router.createSession({
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
        permissions: ["document:read:active", "storage:write:workspace"],
      }),
    ).toThrow(
      expect.objectContaining({
        name: "PluginHostRpcError",
        code: "dangerous_permission_combination",
      } satisfies Partial<PluginHostRpcError>),
    );
  });

  it("rejects replayed request nonces per port", async () => {
    const frame = new FakeFrameWindow();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    router.registerHandler("echo", () => "ok", NON_PLAINTEXT_RPC_POLICY);
    const { port } = boot(router, frame);

    port.postMessage(requestEnvelope());
    expect(await waitForPortMessage(port)).toMatchObject({ kind: "response" });

    port.postMessage(requestEnvelope({ request_id: "request-2" }));
    expect(await waitForPortMessage(port)).toEqual({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "error",
      request_id: "request-2",
      error: {
        code: "replayed_request_nonce",
        message: "request_nonce was already used on this port",
      },
    });
  });

  it("times out host initiated requests when the plugin does not respond", async () => {
    const frame = new FakeFrameWindow();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      timeoutMs: 5,
      validateSession: () => null,
    });
    const { session } = boot(router, frame);

    await expect(
      session.request("plugin.noop", undefined, undefined, undefined, {
        policy: NON_PLAINTEXT_RPC_POLICY,
      }),
    ).rejects.toMatchObject({
      name: "PluginHostRpcError",
      code: "timeout",
    } satisfies Partial<PluginHostRpcError>);
  });

  it("closes sessions and rejects pending host initiated requests on application teardown", async () => {
    const frame = new FakeFrameWindow();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const { session } = boot(router, frame);

    const request = session.request("plugin.noop", undefined, undefined, undefined, {
      policy: NON_PLAINTEXT_RPC_POLICY,
    });
    router.closeByApplication("00000000-0000-4000-8000-000000000001", "consent_revoked");

    expect(session.connected).toBe(false);
    await expect(request).rejects.toMatchObject({
      name: "PluginHostRpcError",
      code: "session_closed",
      message: "consent_revoked",
    } satisfies Partial<PluginHostRpcError>);
  });

  it("notifies the sandbox lifecycle before closing a connected port", async () => {
    const frame = new FakeFrameWindow();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const { session, port } = boot(router, frame);

    const lifecycle = waitForPortMessage(port);

    session.close("consent_revoked");

    await expect(lifecycle).resolves.toEqual({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "host-lifecycle",
      lifecycle: "close",
      reason: "consent_revoked",
    });
  });

  it("closes matching sessions for targeted plugin lifecycle invalidation hooks", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const alpha = bootSessionWithOverrides(router, {
      applicationId: "00000000-0000-4000-8000-000000000101",
      activationId: "activation.example",
      ownerScopeKind: "workspace",
      userId: "user.example",
      deviceId: "device.example",
      workspaceId: "workspace-alpha",
      bundleHash: "bundle-alpha",
      manifestHash: "manifest-alpha",
      capabilityGrantId: "grant-alpha",
      documentScope: { allowedDocumentIds: ["doc-alpha"] },
    });
    const beta = bootSessionWithOverrides(router, {
      applicationId: "00000000-0000-4000-8000-000000000102",
      activationId: "activation.example",
      ownerScopeKind: "workspace",
      userId: "user.example",
      deviceId: "device.example",
      workspaceId: "workspace-beta",
      bundleHash: "bundle-beta",
      manifestHash: "manifest-beta",
      capabilityGrantId: "grant-beta",
      documentScope: { allowedDocumentIds: ["doc-beta"] },
    });

    const alphaRequest = alpha.session.request("plugin.noop", undefined, undefined, undefined, {
      policy: NON_PLAINTEXT_RPC_POLICY,
    });
    router.closeByWorkspace("workspace-alpha", "workspace_left");

    expect(alpha.session.connected).toBe(false);
    expect(beta.session.connected).toBe(true);
    await expect(alphaRequest).rejects.toMatchObject({
      code: "session_closed",
      message: "workspace_left",
    } satisfies Partial<PluginHostRpcError>);

    const betaRequest = beta.session.request("plugin.noop", undefined, undefined, undefined, {
      policy: NON_PLAINTEXT_RPC_POLICY,
    });
    router.closeByCapabilityGrant("grant-beta", "consent_revoked");

    expect(beta.session.connected).toBe(false);
    await expect(betaRequest).rejects.toMatchObject({
      code: "session_closed",
      message: "consent_revoked",
    } satisfies Partial<PluginHostRpcError>);

    const bundleSession = bootSessionWithOverrides(router, {
      workspaceId: "workspace-bundle",
      bundleHash: "bundle-old",
      manifestHash: "manifest-old",
    });
    router.closeByBundle("workspace-bundle", "bundle-old", "bundle_updated");
    expect(bundleSession.session.connected).toBe(false);

    const documentSession = bootSessionWithOverrides(router, {
      documentScope: { allowedDocumentIds: ["doc-revoked"] },
    });
    router.closeByDocumentAccess("doc-revoked", "document_access_lost");
    expect(documentSession.session.connected).toBe(false);

    const workspaceDocumentSession = bootSessionWithOverrides(router, {
      documentScope: { workspaceReadAllowed: true },
    });
    router.closeByDocumentAccess("doc-workspace", "workspace_document_access_lost");
    expect(workspaceDocumentSession.session.connected).toBe(false);
  });

  it("closes all sessions and rejects pending host initiated requests on router teardown", async () => {
    const frame = new FakeFrameWindow();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const { session } = boot(router, frame);

    const request = session.request("plugin.noop", undefined, undefined, undefined, {
      policy: NON_PLAINTEXT_RPC_POLICY,
    });
    router.closeAll("workspace_left");

    expect(session.connected).toBe(false);
    await expect(request).rejects.toMatchObject({
      name: "PluginHostRpcError",
      code: "session_closed",
      message: "workspace_left",
    } satisfies Partial<PluginHostRpcError>);
  });

  it("closes the port when a connected iframe loads again after navigation", async () => {
    const frame = new FakeFrameWindow();
    const frameElement = new FakeFrameLifecycleTarget();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
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
      frameElement,
      expectsInitialFrameLoad: true,
    });

    expect(frameElement.listenerCount("load")).toBe(1);

    frameElement.dispatch("load");
    expect(session.connected).toBe(false);

    router.handleWindowMessage(
      fakeMessageEvent(
        {
          protocol: PLUGIN_HOST_RPC_PROTOCOL,
          version: PLUGIN_HOST_RPC_VERSION,
          kind: "boot-ready",
        },
        frame,
        "null",
      ),
    );
    acknowledgeBoot(session);
    expect(session.connected).toBe(true);

    const request = session.request("plugin.noop", undefined, undefined, undefined, {
      policy: NON_PLAINTEXT_RPC_POLICY,
    });
    frameElement.dispatch("load");

    expect(session.connected).toBe(false);
    expect(frameElement.listenerCount("load")).toBe(0);
    expect(frameElement.removeCount).toBe(1);
    await expect(request).rejects.toMatchObject({
      name: "PluginHostRpcError",
      code: "session_closed",
      message: "frame_navigation",
    } satisfies Partial<PluginHostRpcError>);
  });

  it("closes the boot port when an authenticating iframe loads again before boot acknowledgement", async () => {
    const frame = new FakeFrameWindow();
    const frameElement = new FakeFrameLifecycleTarget();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
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
      frameElement,
      expectsInitialFrameLoad: true,
    });
    const closeReasons: string[] = [];
    session.onClose((reason) => closeReasons.push(reason));

    frameElement.dispatch("load");
    expect(session.closed).toBe(false);

    const handled = router.handleWindowMessage(
      fakeMessageEvent(
        {
          protocol: PLUGIN_HOST_RPC_PROTOCOL,
          version: PLUGIN_HOST_RPC_VERSION,
          kind: "boot-ready",
        },
        frame,
        "null",
      ),
    );
    expect(handled).toBe(true);
    expect(session.connected).toBe(false);
    expect(session.closed).toBe(false);

    frameElement.dispatch("load");

    expect(session.connected).toBe(false);
    expect(session.closed).toBe(true);
    expect(closeReasons).toEqual(["frame_navigation"]);
    expect(frameElement.listenerCount("load")).toBe(0);
    expect(frameElement.listenerCount("error")).toBe(0);
    expect(frameElement.listenerCount("unload")).toBe(0);
    expect(frameElement.removeCount).toBe(1);
    acknowledgeBoot(session);
    expect(session.connected).toBe(false);
  });

  it("does not consume the expected sandbox document load on a src-less bootstrap iframe load", async () => {
    const frame = new FakeFrameWindow();
    const frameElement = new FakeDomFrameLifecycleTarget();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
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
      frameElement,
      expectsInitialFrameLoad: true,
    });

    frameElement.dispatch("load");
    expect(session.closed).toBe(false);

    const handled = router.handleWindowMessage(
      fakeMessageEvent(
        {
          protocol: PLUGIN_HOST_RPC_PROTOCOL,
          version: PLUGIN_HOST_RPC_VERSION,
          kind: "boot-ready",
        },
        frame,
        "null",
      ),
    );
    expect(handled).toBe(true);

    frameElement.src = "/api/plugin-runtime/sandbox-documents/session-one";
    frameElement.dispatch("load");
    expect(session.closed).toBe(false);

    frameElement.dispatch("load");
    expect(session.closed).toBe(true);
    expect(frameElement.removeCount).toBe(1);
  });

  it("ignores bootstrap iframe unload while the expected sandbox document load is pending", async () => {
    const frame = new FakeFrameWindow();
    const frameElement = new FakeDomFrameLifecycleTarget();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
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
      frameElement,
      expectsInitialFrameLoad: true,
    });
    const handled = router.handleWindowMessage(
      fakeMessageEvent(
        {
          protocol: PLUGIN_HOST_RPC_PROTOCOL,
          version: PLUGIN_HOST_RPC_VERSION,
          kind: "boot-ready",
        },
        frame,
        "null",
      ),
    );
    expect(handled).toBe(true);

    frameElement.src = "/api/plugin-runtime/sandbox-documents/session-one";
    frameElement.dispatch("unload");
    expect(session.closed).toBe(false);

    frameElement.dispatch("load");
    expect(session.closed).toBe(false);

    frameElement.dispatch("unload");
    expect(session.closed).toBe(true);
    expect(frameElement.removeCount).toBe(1);
  });

  it("ignores bootstrap iframe error while the expected sandbox document load is pending", async () => {
    const frame = new FakeFrameWindow();
    const frameElement = new FakeDomFrameLifecycleTarget();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
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
      frameElement,
      expectsInitialFrameLoad: true,
    });
    const handled = router.handleWindowMessage(
      fakeMessageEvent(
        {
          protocol: PLUGIN_HOST_RPC_PROTOCOL,
          version: PLUGIN_HOST_RPC_VERSION,
          kind: "boot-ready",
        },
        frame,
        "null",
      ),
    );
    expect(handled).toBe(true);

    frameElement.src = "/api/plugin-runtime/sandbox-documents/session-one";
    frameElement.dispatch("error");
    expect(session.closed).toBe(false);

    frameElement.dispatch("load");
    expect(session.closed).toBe(false);

    frameElement.dispatch("error");
    expect(session.closed).toBe(true);
    expect(frameElement.removeCount).toBe(1);
  });

  it("closes the boot port when an unexpected iframe load happens after connection", async () => {
    const frame = new FakeFrameWindow();
    const frameElement = new FakeFrameLifecycleTarget();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
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
      frameElement,
    });

    router.handleWindowMessage(
      fakeMessageEvent(
        {
          protocol: PLUGIN_HOST_RPC_PROTOCOL,
          version: PLUGIN_HOST_RPC_VERSION,
          kind: "boot-ready",
        },
        frame,
        "null",
      ),
    );
    acknowledgeBoot(session);
    expect(session.connected).toBe(true);

    const request = session.request("plugin.noop", undefined, undefined, undefined, {
      policy: NON_PLAINTEXT_RPC_POLICY,
    });
    frameElement.dispatch("load");

    expect(session.connected).toBe(false);
    expect(frameElement.removeCount).toBe(1);
    await expect(request).rejects.toMatchObject({
      name: "PluginHostRpcError",
      code: "session_closed",
      message: "frame_navigation",
    } satisfies Partial<PluginHostRpcError>);
  });

  it("closes the port when a connected iframe unloads", async () => {
    const frame = new FakeFrameWindow();
    const frameElement = new FakeFrameLifecycleTarget();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
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
      frameElement,
    });

    router.handleWindowMessage(
      fakeMessageEvent(
        {
          protocol: PLUGIN_HOST_RPC_PROTOCOL,
          version: PLUGIN_HOST_RPC_VERSION,
          kind: "boot-ready",
        },
        frame,
        "null",
      ),
    );
    acknowledgeBoot(session);
    expect(session.connected).toBe(true);
    expect(frameElement.listenerCount("load")).toBe(1);
    expect(frameElement.listenerCount("error")).toBe(1);
    expect(frameElement.listenerCount("unload")).toBe(1);

    const request = session.request("plugin.noop", undefined, undefined, undefined, {
      policy: NON_PLAINTEXT_RPC_POLICY,
    });
    frameElement.dispatch("unload");

    expect(session.connected).toBe(false);
    expect(frameElement.listenerCount("load")).toBe(0);
    expect(frameElement.listenerCount("error")).toBe(0);
    expect(frameElement.listenerCount("unload")).toBe(0);
    expect(frameElement.removeCount).toBe(1);
    await expect(request).rejects.toMatchObject({
      name: "PluginHostRpcError",
      code: "session_closed",
      message: "frame_navigation",
    } satisfies Partial<PluginHostRpcError>);
  });

  it("ignores the expected initial iframe load when it happens after connection", async () => {
    const frame = new FakeFrameWindow();
    const frameElement = new FakeFrameLifecycleTarget();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
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
      frameElement,
      expectsInitialFrameLoad: true,
    });

    router.handleWindowMessage(
      fakeMessageEvent(
        {
          protocol: PLUGIN_HOST_RPC_PROTOCOL,
          version: PLUGIN_HOST_RPC_VERSION,
          kind: "boot-ready",
        },
        frame,
        "null",
      ),
    );

    acknowledgeBoot(session);
    expect(session.connected).toBe(true);

    frameElement.dispatch("load");
    expect(session.connected).toBe(true);
    expect(frameElement.removeCount).toBe(0);

    const request = session.request("plugin.noop", undefined, undefined, undefined, {
      policy: NON_PLAINTEXT_RPC_POLICY,
    });
    frameElement.dispatch("load");

    expect(session.connected).toBe(false);
    expect(frameElement.removeCount).toBe(1);
    await expect(request).rejects.toMatchObject({
      name: "PluginHostRpcError",
      code: "session_closed",
      message: "frame_navigation",
    } satisfies Partial<PluginHostRpcError>);
  });

  it("closes a plugin session when its iframe sends a non-boot window message", async () => {
    const frame = new FakeFrameWindow();
    const auxiliaryHandler = vi.fn(() => true);
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    router.registerWindowMessageHandler(auxiliaryHandler);
    const { session } = boot(router, frame);

    const request = session.request("plugin.noop", undefined, undefined, undefined, {
      policy: NON_PLAINTEXT_RPC_POLICY,
    });
    const handled = router.handleWindowMessage(
      fakeMessageEvent({ type: "unexpected" }, frame, "null"),
    );

    expect(handled).toBe(true);
    expect(auxiliaryHandler).not.toHaveBeenCalled();
    expect(session.connected).toBe(false);
    await expect(request).rejects.toMatchObject({
      name: "PluginHostRpcError",
      code: "session_closed",
      message: "unexpected_window_message",
    } satisfies Partial<PluginHostRpcError>);
  });

  it("routes auxiliary window messages from unknown sources through the central router", () => {
    const source = new FakeFrameWindow();
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    const handler = vi.fn((event: MessageEvent) => {
      return (
        event.source === (source as unknown as MessageEventSource) &&
        event.data?.type === "auxiliary-window-message"
      );
    });
    const unregister = router.registerWindowMessageHandler(handler);

    expect(
      router.handleWindowMessage(
        fakeMessageEvent({ type: "auxiliary-window-message" }, source, "null"),
      ),
    ).toBe(true);
    expect(handler).toHaveBeenCalledTimes(1);

    unregister();

    expect(
      router.handleWindowMessage(
        fakeMessageEvent({ type: "auxiliary-window-message" }, source, "null"),
      ),
    ).toBe(false);
  });

  it("registers one parent window message listener through the central router", () => {
    const windowTarget = new FakeWindowTarget();
    const router = new PluginHostMessageRouter({
      windowTarget,
      idFactory: createIdFactory(),
    });

    router.start();
    router.start();
    router.stop();
    router.stop();

    expect(windowTarget.addCount).toBe(1);
    expect(windowTarget.removeCount).toBe(1);
  });

  it("closes sessions when the central router is stopped", async () => {
    const frame = new FakeFrameWindow();
    const router = new PluginHostMessageRouter({
      windowTarget: new FakeWindowTarget(),
      idFactory: createIdFactory(),
      validateSession: () => null,
    });
    router.start();
    const { session } = boot(router, frame);

    const request = session.request("plugin.noop", undefined, undefined, undefined, {
      policy: NON_PLAINTEXT_RPC_POLICY,
    });
    router.stop("workspace_left");

    expect(session.connected).toBe(false);
    await expect(request).rejects.toMatchObject({
      name: "PluginHostRpcError",
      code: "session_closed",
      message: "workspace_left",
    } satisfies Partial<PluginHostRpcError>);
  });
});
