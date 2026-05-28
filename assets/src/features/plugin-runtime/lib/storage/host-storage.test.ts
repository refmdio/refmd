import { afterEach, describe, expect, it, vi } from "vitest";
import { runBeforeSessionCleanup } from "@/shared/lib/auth/session-cleanup";
import { deletePluginRuntimePins } from "@/shared/lib/crypto/trust-store";
import {
  PLUGIN_HOST_RPC_PROTOCOL,
  PLUGIN_HOST_RPC_VERSION,
  PluginHostMessageRouter,
  type PluginHostFrameWindow,
  type PluginHostRpcContext,
  type PluginHostRpcRequestEnvelope,
} from "../host-rpc/host-rpc";
import {
  createEncryptedPluginSyncedStorageStore,
  purgePluginApplicationLocalData,
  registerPluginHostStorageHandlers,
  retainPluginHostStorageHandlers,
  type PluginCredentialBroker,
  type PluginHostStorageServices,
  type PluginLocalStore,
  type PluginSyncedStorageStore,
} from "../storage/host-storage";
import { PluginHostCredentialStore } from "../credential/host-credential";
import {
  registerPluginHostNetworkHandlers,
  type PluginNetworkEndpointPolicy,
} from "../network/host-network";

vi.mock("@/shared/lib/crypto/trust-store", () => ({
  deletePluginRuntimePins: vi.fn(async () => undefined),
}));

const apiMocks = vi.hoisted(() => ({
  DELETE: vi.fn(),
  GET: vi.fn(),
  POST: vi.fn(),
  PUT: vi.fn(),
  withUserPopParams: vi.fn((params: unknown) => params),
}));

vi.mock("@/shared/api/core", () => ({
  ApiError: class ApiError extends Error {
    readonly error: Record<string, unknown>;
    readonly status: number;

    constructor(status: number, error: Record<string, unknown>) {
      super("api_error");
      this.error = error;
      this.status = status;
    }
  },
  client: {
    DELETE: apiMocks.DELETE,
    GET: apiMocks.GET,
    POST: apiMocks.POST,
    PUT: apiMocks.PUT,
  },
  withUserPopParams: apiMocks.withUserPopParams,
}));

const cryptoWorkerMocks = vi.hoisted(() => ({
  getCryptoWorker: vi.fn(),
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: cryptoWorkerMocks.getCryptoWorker,
}));

class FakeFrameWindow implements PluginHostFrameWindow {
  readonly messages: { message: unknown; targetOrigin: string; transfer: Transferable[] }[] = [];

  postMessage(message: unknown, targetOrigin: string, transfer: Transferable[] = []): void {
    this.messages.push({ message, targetOrigin, transfer });
  }
}

function createIdFactory(): () => string {
  let nextId = 0;
  return () => `storage-test-id-${++nextId}`;
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

function createRouterWithStorage(services: PluginHostStorageServices): PluginHostMessageRouter {
  const router = new PluginHostMessageRouter({
    windowTarget: { addEventListener() {}, removeEventListener() {} },
    idFactory: createIdFactory(),
  });
  registerPluginHostStorageHandlers(router, services);
  return router;
}

function boot(
  router: PluginHostMessageRouter,
  permissions: Parameters<PluginHostMessageRouter["createSession"]>[0]["permissions"],
  options: Partial<Parameters<PluginHostMessageRouter["createSession"]>[0]> = {},
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
    validateSession: () => null,
    auditSink: () => true,
    ...options,
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
  return port;
}

function requestEnvelope(
  operation: string,
  payload: unknown,
  overrides: Partial<PluginHostRpcRequestEnvelope> = {},
): PluginHostRpcRequestEnvelope {
  return {
    protocol: PLUGIN_HOST_RPC_PROTOCOL,
    version: PLUGIN_HOST_RPC_VERSION,
    kind: "request",
    request_id: `request-${operation}`,
    request_nonce: `nonce-${operation}-${Math.random()}`,
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
    operation,
    payload,
    ...overrides,
  };
}

function pluginHostContext(overrides: Partial<PluginHostRpcContext> = {}): PluginHostRpcContext {
  return {
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
    sessionId: "plugin-session-one",
    auditActor: {
      user_id: "user-one",
      device_id: "device-one",
      session_id: "session-one",
      principal_kind: "user",
      principal_id: "user-one",
    },
    auditSink: () => true,
    ...overrides,
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

function createLocalStore(): PluginLocalStore & {
  values: Map<string, unknown>;
  writes: { key: string; aadRecord: Record<string, unknown> }[];
  clearPluginData: PluginLocalStore["clearPluginData"] & ReturnType<typeof vi.fn>;
  clearPluginApplicationData: PluginLocalStore["clearPluginApplicationData"] &
    ReturnType<typeof vi.fn>;
} {
  const values = new Map<string, unknown>();
  const writes: { key: string; aadRecord: Record<string, unknown> }[] = [];
  const clearPluginData = vi.fn(async () => undefined) as PluginLocalStore["clearPluginData"] &
    ReturnType<typeof vi.fn>;
  const clearPluginApplicationData = vi.fn(
    async () => undefined,
  ) as PluginLocalStore["clearPluginApplicationData"] & ReturnType<typeof vi.fn>;

  return {
    values,
    writes,
    clearPluginData,
    clearPluginApplicationData,
    async get<T = unknown>(key: string): Promise<T | null> {
      return (values.get(key) as T | undefined) ?? null;
    },
    async set(key, value, aadRecord) {
      values.set(key, value);
      writes.push({ key, aadRecord });
    },
    async delete(key) {
      values.delete(key);
    },
  };
}

function baseServices(
  overrides: Partial<PluginHostStorageServices> = {},
): PluginHostStorageServices {
  return {
    identity: () => ({
      userId: "00000000-0000-4000-8000-000000000010",
      deviceId: "00000000-0000-4000-8000-000000000011",
    }),
    localStore: createLocalStore(),
    ...overrides,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
  apiMocks.DELETE.mockReset();
  apiMocks.GET.mockReset();
  apiMocks.POST.mockReset();
  apiMocks.PUT.mockReset();
  apiMocks.withUserPopParams.mockClear();
  cryptoWorkerMocks.getCryptoWorker.mockReset();
});

describe("plugin Host RPC storage and credential surfaces", () => {
  it("stores user-local plugin data under an application/user/device DSK namespace", async () => {
    const localStore = createLocalStore();
    const auditSink = vi.fn(() => true);
    const router = createRouterWithStorage(baseServices({ localStore }));
    const port = boot(router, ["storage:read:userLocal", "storage:write:userLocal"], {
      auditSink,
    });

    port.postMessage(
      requestEnvelope("storage.userLocal.set", {
        key: "settings",
        value: { theme: "compact" },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      payload: { stored: true },
    });

    expect(localStore.writes[0]?.key).toBe(
      "refmd-plugin-user-local:package.example:00000000-0000-4000-8000-000000000001:activation.example:00000000-0000-4000-8000-000000000002:00000000-0000-4000-8000-000000000010:00000000-0000-4000-8000-000000000011:settings",
    );
    expect(localStore.writes[0]?.aadRecord).toMatchObject({
      protocol: "refmd.plugin-local-storage",
      surface: "userLocal",
      workspace_id: "00000000-0000-4000-8000-000000000002",
      package_id: "package.example",
      application_id: "00000000-0000-4000-8000-000000000001",
      activation_id: "activation.example",
      user_id: "00000000-0000-4000-8000-000000000010",
      device_id: "00000000-0000-4000-8000-000000000011",
      key: "settings",
    });
    expect(auditSink).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "plugin.storage.written",
        operation: "storage.userLocal.set",
        result: "allow",
        resource: expect.objectContaining({
          id: "plugin.example:settings",
        }),
      }),
    );

    port.postMessage(requestEnvelope("storage.userLocal.get", { key: "settings" }));

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      payload: { value: { theme: "compact" } },
    });
  });

  it("rejects storage writes without the matching capability", async () => {
    const router = createRouterWithStorage(baseServices());
    const port = boot(router, ["storage:read:userLocal"]);

    port.postMessage(
      requestEnvelope("storage.userLocal.set", {
        key: "settings",
        value: { theme: "compact" },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "permission_denied" },
    });
  });

  it("rejects cache writes with plaintext read authority when cache high-risk consent is missing", async () => {
    const localStore = createLocalStore();
    const auditSink = vi.fn(() => true);
    const router = createRouterWithStorage(baseServices({ localStore }));
    const port = boot(router, ["document:read:active", "storage:write:cache"], {
      auditSink,
      highRiskConsents: [],
    });

    port.postMessage(
      requestEnvelope("storage.cache.set", {
        key: "derived-index",
        value: { terms: ["alpha"] },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "high_risk_consent_required" },
    });
    expect(localStore.writes).toHaveLength(0);
    expect(auditSink).not.toHaveBeenCalledWith(
      expect.objectContaining({
        type: "plugin.storage.written",
        result: "allow",
      }),
    );
  });

  it("allows cache writes with plaintext read authority when cache high-risk consent is present", async () => {
    const localStore = createLocalStore();
    const auditSink = vi.fn(() => true);
    const router = createRouterWithStorage(baseServices({ localStore }));
    const port = boot(router, ["document:read:active", "storage:write:cache"], {
      auditSink,
      highRiskConsents: ["plaintext_cache_storage"],
    });

    port.postMessage(
      requestEnvelope("storage.cache.set", {
        key: "derived-index",
        value: { terms: ["alpha"] },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      payload: { stored: true },
    });
    expect(localStore.writes).toHaveLength(1);
    expect(auditSink).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "plugin.storage.written",
        operation: "storage.cache.set",
        result: "allow",
      }),
    );
  });

  it("does not write local storage when audit fails", async () => {
    const localStore = createLocalStore();
    const router = createRouterWithStorage(baseServices({ localStore }));
    const port = boot(router, ["storage:write:userLocal", "storage:write:cache"], {
      auditSink: () => false,
    });

    port.postMessage(
      requestEnvelope("storage.userLocal.set", {
        key: "settings",
        value: { theme: "compact" },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "storage_audit_unavailable" },
    });
    expect(localStore.writes).toHaveLength(0);

    port.postMessage(
      requestEnvelope("storage.cache.set", {
        key: "transient",
        value: { cached: true },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "storage_audit_unavailable" },
    });
    expect(localStore.writes).toHaveLength(0);
  });

  it("routes workspace and document storage through the Host-supplied synced store", async () => {
    const syncedStore: PluginSyncedStorageStore = {
      get: vi.fn(async () => ({ saved: true })),
      set: vi.fn(async () => undefined),
      delete: vi.fn(async () => undefined),
    };
    const router = createRouterWithStorage(baseServices({ syncedStore }));
    const port = boot(
      router,
      [
        "storage:read:workspace",
        "storage:write:workspace",
        "storage:read:document",
        "storage:write:document",
      ],
      {
        documentScope: { allowedDocumentIds: ["00000000-0000-4000-8000-000000000099"] },
        stateHeadHash: "state-head-1",
        consentHeadHash: "consent-head-1",
      },
    );

    port.postMessage(
      requestEnvelope(
        "storage.document.set",
        {
          key: "index",
          document_id: "00000000-0000-4000-8000-000000000099",
          value: { encrypted: true },
        },
        { resource: { document_id: "00000000-0000-4000-8000-000000000099" } },
      ),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      payload: { stored: true },
    });
    expect(syncedStore.set).toHaveBeenCalledWith(
      expect.objectContaining({
        surface: "document",
        key: "index",
        documentId: "00000000-0000-4000-8000-000000000099",
        value: { encrypted: true },
        context: expect.objectContaining({
          stateHeadHash: "state-head-1",
          consentHeadHash: "consent-head-1",
        }),
      }),
    );

    port.postMessage(
      requestEnvelope(
        "storage.document.set",
        {
          key: "index",
          document_id: "00000000-0000-4000-8000-000000000098",
          value: { encrypted: true },
        },
        { resource: { document_id: "00000000-0000-4000-8000-000000000098" } },
      ),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "document_scope_denied" },
    });

    port.postMessage(requestEnvelope("storage.workspace.get", { key: "settings" }));

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      payload: { value: { saved: true } },
    });
    expect(syncedStore.get).toHaveBeenCalledWith(
      expect.objectContaining({
        surface: "workspace",
        key: "settings",
        context: expect.objectContaining({
          stateHeadHash: "state-head-1",
          consentHeadHash: "consent-head-1",
        }),
      }),
    );
  });

  it("requires concrete Host document identity for active and selected document storage", async () => {
    const syncedStore: PluginSyncedStorageStore = {
      get: vi.fn(async () => ({ saved: true })),
      set: vi.fn(async () => undefined),
      delete: vi.fn(async () => undefined),
    };
    const permissions = ["storage:read:document", "storage:write:document"] as const;

    const semanticRouter = createRouterWithStorage(baseServices({ syncedStore }));
    const semanticPort = boot(semanticRouter, permissions, {
      documentScope: {
        activeDocumentReadAllowed: true,
        selectedDocumentsReadAllowed: true,
      },
    });

    semanticPort.postMessage(
      requestEnvelope(
        "storage.document.set",
        {
          key: "index",
          document_id: "00000000-0000-4000-8000-000000000099",
          value: { encrypted: true },
        },
        { resource: { document_id: "00000000-0000-4000-8000-000000000099" } },
      ),
    );

    await expect(waitForPortMessage(semanticPort)).resolves.toMatchObject({
      kind: "error",
      error: { code: "document_scope_denied" },
    });
    expect(syncedStore.set).not.toHaveBeenCalled();

    const concreteRouter = createRouterWithStorage(baseServices({ syncedStore }));
    const concretePort = boot(concreteRouter, permissions, {
      documentScope: {
        activeDocumentReadAllowed: true,
        activeDocumentId: "00000000-0000-4000-8000-000000000099",
      },
    });

    concretePort.postMessage(
      requestEnvelope(
        "storage.document.set",
        {
          key: "index",
          document_id: "00000000-0000-4000-8000-000000000099",
          value: { encrypted: true },
        },
        { resource: { document_id: "00000000-0000-4000-8000-000000000099" } },
      ),
    );

    await expect(waitForPortMessage(concretePort)).resolves.toMatchObject({
      kind: "response",
      payload: { stored: true },
    });

    concretePort.postMessage(
      requestEnvelope(
        "storage.document.set",
        {
          key: "index",
          document_id: "00000000-0000-4000-8000-000000000098",
          value: { encrypted: true },
        },
        { resource: { document_id: "00000000-0000-4000-8000-000000000098" } },
      ),
    );

    await expect(waitForPortMessage(concretePort)).resolves.toMatchObject({
      kind: "error",
      error: { code: "document_scope_denied" },
    });
  });

  it("does not write server-synced storage when durable audit fails", async () => {
    const syncedStore: PluginSyncedStorageStore = {
      get: vi.fn(async () => null),
      set: vi.fn(async () => undefined),
      delete: vi.fn(async () => undefined),
    };
    const router = createRouterWithStorage(baseServices({ syncedStore }));
    const port = boot(router, ["storage:write:workspace"], { auditSink: () => false });

    port.postMessage(
      requestEnvelope("storage.workspace.set", {
        key: "settings",
        value: { encrypted: true },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "storage_audit_unavailable" },
    });
    expect(syncedStore.set).not.toHaveBeenCalled();
  });

  it("uses writer activation metadata for server-synced KV storage AAD", async () => {
    const encryptPluginStorage = vi.fn(async (_params: Record<string, unknown>) => ({
      ciphertext: new Uint8Array([1, 2, 3]),
      nonce: new Uint8Array([4, 5, 6]),
      keyVersion: 9,
    }));
    const decryptPluginStorage = vi.fn(async (_params: Record<string, unknown>) =>
      new TextEncoder().encode(JSON.stringify({ saved: true })),
    );
    cryptoWorkerMocks.getCryptoWorker.mockReturnValue({
      decryptPluginStorage,
      encryptPluginStorage,
    });
    apiMocks.PUT.mockResolvedValue({
      response: new Response(null, { status: 200 }),
      data: {
        activation_id: "activation.example",
        ciphertext: "AQID",
        nonce: "BAUG",
        key_version: 9,
      },
    });
    apiMocks.GET.mockResolvedValue({
      response: new Response(null, { status: 200 }),
      data: {
        activation_id: "activation.writer",
        ciphertext: "CQgH",
        nonce: "BgUE",
        key_version: 9,
      },
    });
    const store = createEncryptedPluginSyncedStorageStore();
    const context = pluginHostContext({
      activationId: "activation.example",
      stateHeadHash: "state-head-1",
      consentHeadHash: "consent-head-1",
    });

    await expect(
      store.set({
        context,
        surface: "workspace",
        key: "settings",
        documentId: null,
        value: { saved: true },
      }),
    ).resolves.toBeUndefined();

    expect(encryptPluginStorage).toHaveBeenCalledWith(
      expect.objectContaining({
        activationId: "activation.example",
        key: "settings",
      }),
    );

    await expect(
      store.get({
        context,
        surface: "workspace",
        key: "settings",
        documentId: null,
      }),
    ).resolves.toEqual({ saved: true });

    expect(decryptPluginStorage).toHaveBeenCalledWith(
      expect.objectContaining({
        activationId: "activation.writer",
        key: "settings",
      }),
    );
  });

  it("treats missing server-synced KV storage reads as null without decrypting", async () => {
    const decryptPluginStorage = vi.fn();
    cryptoWorkerMocks.getCryptoWorker.mockReturnValue({ decryptPluginStorage });
    apiMocks.GET.mockResolvedValue({
      response: new Response(null, { status: 200 }),
      data: null,
    });
    const store = createEncryptedPluginSyncedStorageStore();

    await expect(
      store.get({
        context: pluginHostContext({
          stateHeadHash: "state-head-1",
          consentHeadHash: "consent-head-1",
        }),
        surface: "workspace",
        key: "settings",
        documentId: null,
      }),
    ).resolves.toBeNull();

    expect(decryptPluginStorage).not.toHaveBeenCalled();
  });

  it("routes workspace record storage through a distinct Host RPC surface", async () => {
    const syncedStore: PluginSyncedStorageStore = {
      get: vi.fn(async () => null),
      set: vi.fn(async () => undefined),
      delete: vi.fn(async () => undefined),
      createRecord: vi.fn(async (params) => ({ id: "record-1", kind: params.kind })),
      getRecord: vi.fn(async () => ({ id: "record-1", kind: "annotation", value: { text: "ok" } })),
      deleteRecord: vi.fn(async () => undefined),
    };
    const router = createRouterWithStorage(baseServices({ syncedStore }));
    const port = boot(router, ["storage:read:workspace", "storage:write:workspace"], {
      stateHeadHash: "state-head-1",
      consentHeadHash: "consent-head-1",
    });

    port.postMessage(
      requestEnvelope("storage.workspace.record.create", {
        kind: "annotation",
        value: { text: "ok" },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      payload: { record_id: "record-1", kind: "annotation" },
    });
    expect(syncedStore.createRecord).toHaveBeenCalledWith(
      expect.objectContaining({
        surface: "workspace",
        kind: "annotation",
        value: { text: "ok" },
        context: expect.objectContaining({
          stateHeadHash: "state-head-1",
          consentHeadHash: "consent-head-1",
        }),
      }),
    );

    port.postMessage(
      requestEnvelope("storage.workspace.record.get", {
        record_id: "record-1",
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      payload: { record_id: "record-1", kind: "annotation", value: { text: "ok" } },
    });
    expect(syncedStore.getRecord).toHaveBeenCalledWith(
      expect.objectContaining({
        recordId: "record-1",
        context: expect.objectContaining({
          stateHeadHash: "state-head-1",
          consentHeadHash: "consent-head-1",
        }),
      }),
    );

    port.postMessage(
      requestEnvelope("storage.workspace.record.delete", {
        record_id: "record-1",
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      payload: { deleted: true },
    });
    expect(syncedStore.deleteRecord).toHaveBeenCalledWith(
      expect.objectContaining({
        recordId: "record-1",
        context: expect.objectContaining({
          stateHeadHash: "state-head-1",
          consentHeadHash: "consent-head-1",
        }),
      }),
    );
  });

  it("binds server-synced records to a host-issued record storage key", async () => {
    const recordId = "10000000-0000-4000-8000-000000000001";
    const randomUuid = vi.spyOn(crypto, "randomUUID").mockReturnValue(recordId);
    const encryptPluginStorage = vi.fn(async (_params: Record<string, unknown>) => ({
      ciphertext: new Uint8Array([1, 2, 3]),
      nonce: new Uint8Array([4, 5, 6]),
      keyVersion: 9,
    }));
    const decryptPluginStorage = vi.fn(async (_params: Record<string, unknown>) =>
      new TextEncoder().encode(JSON.stringify({ text: "ok" })),
    );
    cryptoWorkerMocks.getCryptoWorker.mockReturnValue({
      decryptPluginStorage,
      encryptPluginStorage,
    });
    apiMocks.POST.mockResolvedValue({
      response: new Response(null, { status: 200 }),
      data: {
        id: recordId,
        activation_id: "activation.example",
        kind: "annotation",
        encrypted_data: "AQID",
        nonce: "BAUG",
        key_version: 9,
      },
    });
    apiMocks.GET.mockResolvedValue({
      response: new Response(null, { status: 200 }),
      data: {
        id: recordId,
        activation_id: "activation.writer",
        kind: "annotation",
        encrypted_data: "CQgH",
        nonce: "BgUE",
        key_version: 9,
      },
    });
    const store = createEncryptedPluginSyncedStorageStore();
    const createRecord = store.createRecord;
    const getRecord = store.getRecord;
    if (!createRecord || !getRecord) throw new Error("record storage unavailable");
    const context = pluginHostContext({
      stateHeadHash: "state-head-1",
      consentHeadHash: "consent-head-1",
    });

    await expect(
      createRecord({
        context,
        surface: "workspace",
        kind: "annotation",
        documentId: null,
        value: { text: "ok" },
      }),
    ).resolves.toEqual({ id: recordId, kind: "annotation" });

    expect(randomUuid).toHaveBeenCalled();
    expect(encryptPluginStorage).toHaveBeenCalledWith(
      expect.objectContaining({
        activationId: "activation.example",
        key: `record:${recordId}:annotation`,
      }),
    );
    expect(apiMocks.POST).toHaveBeenCalledWith(
      "/api/workspaces/{workspace_id}/plugin-runtime/{application_id}/records/{surface}",
      expect.objectContaining({
        body: expect.objectContaining({ id: recordId }),
      }),
    );

    await expect(
      getRecord({
        context,
        surface: "workspace",
        recordId,
        documentId: null,
      }),
    ).resolves.toEqual({ id: recordId, kind: "annotation", value: { text: "ok" } });

    expect(decryptPluginStorage).toHaveBeenCalledWith(
      expect.objectContaining({
        activationId: "activation.writer",
        key: `record:${recordId}:annotation`,
      }),
    );
  });

  it("treats missing server-synced record reads as null without decrypting", async () => {
    const decryptPluginStorage = vi.fn();
    cryptoWorkerMocks.getCryptoWorker.mockReturnValue({ decryptPluginStorage });
    apiMocks.GET.mockResolvedValue({
      response: new Response(null, { status: 200 }),
      data: null,
    });
    const store = createEncryptedPluginSyncedStorageStore();
    const getRecord = store.getRecord;
    if (!getRecord) throw new Error("record storage unavailable");

    await expect(
      getRecord({
        context: pluginHostContext({
          stateHeadHash: "state-head-1",
          consentHeadHash: "consent-head-1",
        }),
        surface: "workspace",
        recordId: "10000000-0000-4000-8000-000000000001",
        documentId: null,
      }),
    ).resolves.toBeNull();

    expect(decryptPluginStorage).not.toHaveBeenCalled();
  });

  it("returns only opaque credential handles and rejects secret-bearing payloads", async () => {
    const credentialBroker: PluginCredentialBroker = {
      use: vi.fn(async (params) => ({
        handle: "opaque-handle",
        expiresAtMs: 1_775_000_000_000,
        audience: params.audience,
        endpoint: params.endpoint,
        method: params.method,
      })),
      revokeHandle: vi.fn(),
    };
    const router = createRouterWithStorage(baseServices({ credentialBroker }));
    const port = boot(router, ["credential:use"]);

    port.postMessage(
      requestEnvelope("credential.use", {
        credential_id: "github",
        audience: "api.github.com",
        endpoint: "https://api.github.com/repos/refmdio/refmd",
        method: "get",
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      payload: {
        protocol: "refmd.plugin-credential-handle",
        handle: "opaque-handle",
        method: "GET",
      },
    });

    port.postMessage(
      requestEnvelope("credential.use", {
        credential_id: "github",
        audience: "api.github.com",
        endpoint: "https://api.github.com/repos/refmdio/refmd",
        method: "GET",
        secret: "not-allowed",
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "credential_secret_read_forbidden" },
    });
  });

  it("revokes credential handles when durable audit fails", async () => {
    const credentialBroker: PluginCredentialBroker = {
      use: vi.fn(async (params) => ({
        handle: "opaque-handle",
        expiresAtMs: 1_775_000_000_000,
        audience: params.audience,
        endpoint: params.endpoint,
        method: params.method,
      })),
      revokeHandle: vi.fn(),
    };
    const router = createRouterWithStorage(baseServices({ credentialBroker }));
    const port = boot(router, ["credential:use"], { auditSink: () => false });

    port.postMessage(
      requestEnvelope("credential.use", {
        credential_id: "github",
        audience: "api.github.com",
        endpoint: "https://api.github.com/repos/refmdio/refmd",
        method: "GET",
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "credential_audit_unavailable" },
    });
    expect(credentialBroker.use).toHaveBeenCalled();
    expect(credentialBroker.revokeHandle).toHaveBeenCalledWith("opaque-handle");
  });

  it("does not record allowed credential use when the broker rejects handle issuance", async () => {
    const auditSink = vi.fn(() => true);
    const credentialBroker: PluginCredentialBroker = {
      use: vi.fn(async () => {
        throw new Error("credential_not_found");
      }),
      revokeHandle: vi.fn(),
    };
    const router = createRouterWithStorage(baseServices({ credentialBroker }));
    const port = boot(router, ["credential:use"], { auditSink });

    port.postMessage(
      requestEnvelope("credential.use", {
        credential_id: "github",
        audience: "api.github.com",
        endpoint: "https://api.github.com/repos/refmdio/refmd",
        method: "GET",
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
    });
    expect(auditSink).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "plugin.credential.used", result: "allow" }),
    );
    expect(credentialBroker.revokeHandle).not.toHaveBeenCalled();
  });

  it("backs credential handles with the same Host store used by network fetch", async () => {
    const credentialStore = new PluginHostCredentialStore({
      store: vi.fn(async () => undefined),
      load: vi.fn(async () => null),
      delete: vi.fn(async () => undefined),
      purgeApplication: vi.fn(async () => undefined),
    });
    const endpoint: PluginNetworkEndpointPolicy = {
      id: "github-rest",
      url: "https://api.github.com/repos/refmdio/refmd",
      methods: ["GET"],
      routes: ["proxy"],
      headers: ["accept"],
      bodySchema: "none",
      maxRequestBytes: 1024,
      maxResponseBytes: 2048,
      credentialAudience: "api.github.com",
    };
    const releaseCredential = credentialStore.retainCredential({
      credentialId: "github",
      pluginId: "plugin.example",
      packageId: "package.example",
      workspaceId: "00000000-0000-4000-8000-000000000002",
      applicationId: "00000000-0000-4000-8000-000000000001",
      activationId: "activation.example",
      userId: "00000000-0000-4000-8000-000000000010",
      deviceId: "00000000-0000-4000-8000-000000000011",
      audience: "api.github.com",
      endpoint: endpoint.url,
      method: "GET",
      headers: { authorization: "Bearer host-token" },
    });
    const proxyExecutor = vi.fn(async () => ({
      status: 200,
      headers: {},
      bodyText: "ok",
    }));
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    registerPluginHostStorageHandlers(router, baseServices({ credentialBroker: credentialStore }));
    registerPluginHostNetworkHandlers(router, {
      endpointPolicy: () => endpoint,
      proxyExecutor,
      proxyRegistration: () => ({
        id: "org-proxy",
        label: "Org Proxy",
        origin: "https://proxy.example",
        scope: "workspace",
      }),
      credentialResolver: credentialStore,
    });
    const port = boot(router, ["credential:use", "network:fetch"], {
      auditActor: {
        user_id: "00000000-0000-4000-8000-000000000010",
        device_id: "00000000-0000-4000-8000-000000000011",
        session_id: "session-one",
        principal_kind: "user",
        principal_id: "00000000-0000-4000-8000-000000000010",
      },
    });

    port.postMessage(
      requestEnvelope("credential.use", {
        credential_id: "github",
        audience: "api.github.com",
        endpoint: endpoint.url,
        method: "GET",
      }),
    );
    const credentialResponse = (await waitForPortMessage(port)) as {
      payload?: { handle?: string };
    };
    const handle = credentialResponse.payload?.handle;
    expect(handle).toMatch(/^credential\./);

    port.postMessage(
      requestEnvelope("app.network.fetch", {
        endpoint_id: endpoint.id,
        route: "proxy",
        method: "GET",
        headers: {},
        credential_handle: handle,
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      payload: { body_text: "ok" },
    });
    expect(proxyExecutor).toHaveBeenCalledWith(
      expect.objectContaining({
        credentialHandle: handle,
        headers: expect.objectContaining({ authorization: "Bearer host-token" }),
      }),
    );
    releaseCredential();
  });

  it("persists Host-managed credentials through DSK storage before issuing handles", async () => {
    const storedCredentials = new Map<string, Uint8Array>();
    const storePluginCredentialWithDsk = vi.fn(async (params: Record<string, unknown>) => {
      storedCredentials.set(params.credentialId as string, params.plaintext as Uint8Array);
    });
    const loadPluginCredentialWithDsk = vi.fn(async (params: Record<string, unknown>) => {
      return storedCredentials.get(params.credentialId as string) ?? null;
    });
    const deletePluginCredentialWithDsk = vi.fn(async () => undefined);
    const clearPluginApplicationDataWithDsk = vi.fn(async (params: Record<string, unknown>) => {
      for (const credentialId of Array.from(storedCredentials.keys())) {
        storedCredentials.delete(credentialId);
      }
      expect(params).toMatchObject({
        workspaceId: "workspace-one",
        packageId: "package.example",
        applicationId: "application-one",
        activationId: "activation.example",
        userId: "user-one",
        deviceId: "device-one",
      });
    });
    cryptoWorkerMocks.getCryptoWorker.mockReturnValue({
      storePluginCredentialWithDsk,
      loadPluginCredentialWithDsk,
      deletePluginCredentialWithDsk,
      clearPluginApplicationDataWithDsk,
    });

    const writer = new PluginHostCredentialStore();
    await writer.storeCredential({
      credentialId: "github",
      pluginId: "plugin.example",
      packageId: "package.example",
      workspaceId: "workspace-one",
      applicationId: "application-one",
      activationId: "activation.example",
      userId: "user-one",
      deviceId: "device-one",
      audience: "github",
      endpoint: "https://api.github.com/repos/refmdio/refmd/issues",
      method: "POST",
      headers: { authorization: "Bearer persisted" },
    });

    expect(storePluginCredentialWithDsk).toHaveBeenCalledWith(
      expect.objectContaining({
        workspaceId: "workspace-one",
        applicationId: "application-one",
        activationId: "activation.example",
        userId: "user-one",
        deviceId: "device-one",
        credentialId: "github",
      }),
    );
    expect(storePluginCredentialWithDsk.mock.calls[0]?.[0]).toMatchObject({
      workspaceId: "workspace-one",
      applicationId: "application-one",
      activationId: "activation.example",
      userId: "user-one",
      deviceId: "device-one",
      credentialId: "github",
    });
    const storedCall = storePluginCredentialWithDsk.mock.calls[0]?.[0] as Record<string, unknown>;
    const storedPlaintext = storedCall.plaintext as Uint8Array;
    expect(JSON.parse(new TextDecoder().decode(storedPlaintext))).toMatchObject({
      protocol: "refmd.plugin-credential",
      pluginId: "plugin.example",
      packageId: "package.example",
      workspaceId: "workspace-one",
      applicationId: "application-one",
      activationId: "activation.example",
      headers: { authorization: "Bearer persisted" },
    });

    const reader = new PluginHostCredentialStore();
    const context = pluginHostContext({
      workspaceId: "workspace-one",
      applicationId: "application-one",
      activationId: "activation.example",
      auditActor: {
        user_id: "user-one",
        device_id: "device-one",
        session_id: "session-one",
        principal_kind: "user",
        principal_id: "user-one",
      },
    });
    const issued = await reader.use({
      context,
      userId: "user-one",
      deviceId: "device-one",
      credentialId: "github",
      audience: "github",
      endpoint: "https://api.github.com/repos/refmdio/refmd/issues",
      method: "POST",
    });

    expect(loadPluginCredentialWithDsk).toHaveBeenCalledWith({
      workspaceId: "workspace-one",
      packageId: "package.example",
      applicationId: "application-one",
      activationId: "activation.example",
      userId: "user-one",
      deviceId: "device-one",
      credentialId: "github",
    });
    await expect(
      reader.resolve({
        context,
        handle: issued.handle,
        audience: "github",
        endpoint: credentialEndpoint(),
        method: "POST",
      }),
    ).resolves.toEqual({ authorization: "Bearer persisted" });

    await reader.deleteCredential({
      workspaceId: "workspace-one",
      packageId: "package.example",
      applicationId: "application-one",
      activationId: "activation.example",
      userId: "user-one",
      deviceId: "device-one",
      credentialId: "github",
    });
    expect(deletePluginCredentialWithDsk).toHaveBeenCalledWith({
      workspaceId: "workspace-one",
      packageId: "package.example",
      applicationId: "application-one",
      activationId: "activation.example",
      userId: "user-one",
      deviceId: "device-one",
      credentialId: "github",
    });
  });

  it("purges persisted Host-managed credentials during application local cleanup", async () => {
    const storedCredentials = new Map<string, Uint8Array>();
    const storePluginCredentialWithDsk = vi.fn(async (params: Record<string, unknown>) => {
      storedCredentials.set(params.credentialId as string, params.plaintext as Uint8Array);
    });
    const loadPluginCredentialWithDsk = vi.fn(async (params: Record<string, unknown>) => {
      return storedCredentials.get(params.credentialId as string) ?? null;
    });
    const deletePluginCredentialWithDsk = vi.fn(async () => undefined);
    const clearPluginApplicationDataWithDsk = vi.fn(async () => {
      storedCredentials.clear();
    });
    cryptoWorkerMocks.getCryptoWorker.mockReturnValue({
      storePluginCredentialWithDsk,
      loadPluginCredentialWithDsk,
      deletePluginCredentialWithDsk,
      clearPluginApplicationDataWithDsk,
    });

    const writer = new PluginHostCredentialStore();
    await writer.storeCredential({
      credentialId: "github",
      pluginId: "plugin.example",
      packageId: "package.example",
      workspaceId: "workspace-one",
      applicationId: "application-one",
      activationId: "activation.example",
      userId: "user-one",
      deviceId: "device-one",
      audience: "github",
      endpoint: "https://api.github.com/repos/refmdio/refmd/issues",
      method: "POST",
      headers: { authorization: "Bearer persisted" },
    });

    const context = pluginHostContext({
      workspaceId: "workspace-one",
      applicationId: "application-one",
      activationId: "activation.example",
      auditActor: {
        user_id: "user-one",
        device_id: "device-one",
        session_id: "session-one",
        principal_kind: "user",
        principal_id: "user-one",
      },
    });
    const reader = new PluginHostCredentialStore();
    await expect(
      reader.use({
        context,
        userId: "user-one",
        deviceId: "device-one",
        credentialId: "github",
        audience: "github",
        endpoint: "https://api.github.com/repos/refmdio/refmd/issues",
        method: "POST",
      }),
    ).resolves.toMatchObject({ audience: "github" });

    const localStore = createLocalStore();
    await purgePluginApplicationLocalData(
      {
        workspaceId: "workspace-one",
        packageId: "package.example",
        applicationId: "application-one",
        activationId: "activation.example",
        userId: "user-one",
        deviceId: "device-one",
      },
      baseServices({ localStore, credentialBroker: reader }),
    );

    expect(clearPluginApplicationDataWithDsk).toHaveBeenCalledWith({
      workspaceId: "workspace-one",
      packageId: "package.example",
      applicationId: "application-one",
      activationId: "activation.example",
      userId: "user-one",
      deviceId: "device-one",
    });

    const freshReader = new PluginHostCredentialStore();
    await expect(
      freshReader.use({
        context,
        userId: "user-one",
        deviceId: "device-one",
        credentialId: "github",
        audience: "github",
        endpoint: "https://api.github.com/repos/refmdio/refmd/issues",
        method: "POST",
      }),
    ).rejects.toThrow("credential is not available for this plugin runtime");
  });

  it("clears plugin local data only for secure session cleanup", async () => {
    const localStore = createLocalStore();
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
    });
    const release = retainPluginHostStorageHandlers(router, baseServices({ localStore }));

    await runBeforeSessionCleanup({ secure: false });
    expect(localStore.clearPluginData).not.toHaveBeenCalled();

    await runBeforeSessionCleanup({ secure: true });
    expect(localStore.clearPluginData).toHaveBeenCalledTimes(1);

    release();
  });

  it("purges only the target application local data and credentials", async () => {
    const localStore = createLocalStore();
    const credentialStore = new PluginHostCredentialStore({
      store: vi.fn(async () => undefined),
      load: vi.fn(async () => null),
      delete: vi.fn(async () => undefined),
      purgeApplication: vi.fn(async () => undefined),
    });
    credentialStore.retainCredential({
      credentialId: "github",
      pluginId: "plugin.example",
      packageId: "package.example",
      workspaceId: "workspace-one",
      applicationId: "application-one",
      activationId: "activation.example",
      userId: "user-one",
      deviceId: "device-one",
      audience: "github",
      endpoint: "https://api.github.com/repos/refmdio/refmd/issues",
      method: "POST",
      headers: { authorization: "Bearer one" },
    });
    credentialStore.retainCredential({
      credentialId: "github",
      pluginId: "plugin.example",
      packageId: "package.example",
      workspaceId: "workspace-one",
      applicationId: "application-two",
      activationId: "activation.example",
      userId: "user-one",
      deviceId: "device-one",
      audience: "github",
      endpoint: "https://api.github.com/repos/refmdio/refmd/issues",
      method: "POST",
      headers: { authorization: "Bearer two" },
    });

    const context = pluginHostContext({
      workspaceId: "workspace-one",
      applicationId: "application-one",
      activationId: "activation.example",
    });
    const issued = await credentialStore.use({
      context,
      userId: "user-one",
      deviceId: "device-one",
      credentialId: "github",
      audience: "github",
      endpoint: "https://api.github.com/repos/refmdio/refmd/issues",
      method: "POST",
    });

    await purgePluginApplicationLocalData(
      {
        workspaceId: "workspace-one",
        packageId: "package.example",
        applicationId: "application-one",
        activationId: "activation.example",
        userId: "user-one",
        deviceId: "device-one",
      },
      baseServices({ localStore, credentialBroker: credentialStore }),
    );

    expect(localStore.clearPluginApplicationData).toHaveBeenCalledWith({
      workspaceId: "workspace-one",
      packageId: "package.example",
      applicationId: "application-one",
      activationId: "activation.example",
      userId: "user-one",
      deviceId: "device-one",
    });
    expect(deletePluginRuntimePins).toHaveBeenCalledWith(
      "workspace-one",
      "package.example",
      "application-one",
      "activation.example",
      "user-one",
    );
    await expect(
      credentialStore.resolve({
        context,
        handle: issued.handle,
        audience: "github",
        endpoint: credentialEndpoint(),
        method: "POST",
      }),
    ).rejects.toThrow("credential handle is expired or unknown");
    await expect(
      credentialStore.use({
        context: pluginHostContext({
          workspaceId: "workspace-one",
          applicationId: "application-two",
          activationId: "activation.example",
        }),
        userId: "user-one",
        deviceId: "device-one",
        credentialId: "github",
        audience: "github",
        endpoint: "https://api.github.com/repos/refmdio/refmd/issues",
        method: "POST",
      }),
    ).resolves.toMatchObject({ audience: "github" });
  });
});

function credentialEndpoint(): PluginNetworkEndpointPolicy {
  return {
    id: "github",
    url: "https://api.github.com/repos/refmdio/refmd/issues",
    methods: ["POST"],
    routes: ["proxy"],
    bodySchema: "json",
    maxRequestBytes: 1024,
    maxResponseBytes: 2048,
  };
}
