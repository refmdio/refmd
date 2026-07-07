import { afterEach, describe, expect, it, vi } from "vite-plus/test";
import {
  PLUGIN_HOST_RPC_PROTOCOL,
  PLUGIN_HOST_RPC_VERSION,
  PluginHostMessageRouter,
  type PluginHostFrameWindow,
  type PluginHostRpcRequestEnvelope,
} from "../host-rpc/host-rpc";
import {
  createDefaultPluginHostNetworkServices,
  registerPluginHostNetworkHandlers,
  retainDefaultPluginHostNetworkProxy,
  type PluginHostNetworkServices,
  type PluginNetworkEndpointPolicy,
  type PluginNetworkExecutorRequest,
  type PluginNetworkProxyRequestSigner,
  type PluginNetworkProxyRegistration,
} from "../network/host-network";

class FakeFrameWindow implements PluginHostFrameWindow {
  readonly messages: { message: unknown; targetOrigin: string; transfer: Transferable[] }[] = [];

  postMessage(message: unknown, targetOrigin: string, transfer: Transferable[] = []): void {
    this.messages.push({ message, targetOrigin, transfer });
  }
}

let releaseRetainedProxy: (() => void) | null = null;

function parseJsonRequestBody(body: BodyInit | null | undefined): Record<string, unknown> {
  if (typeof body !== "string") {
    throw new Error("expected JSON request body string");
  }
  const parsed = JSON.parse(body) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("expected JSON request body object");
  }
  return parsed as Record<string, unknown>;
}

afterEach(() => {
  releaseRetainedProxy?.();
  releaseRetainedProxy = null;
  document
    .querySelectorAll('iframe[data-refmd-plugin-network-executor="true"]')
    .forEach((frame) => {
      frame.remove();
    });
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

const ENDPOINT: PluginNetworkEndpointPolicy = {
  id: "github-rest",
  url: "https://api.github.com/repos/refmdio/refmd/issues",
  methods: ["GET", "POST"],
  routes: ["proxy"],
  headers: ["accept", "content-type"],
  bodySchema: "json",
  maxRequestBytes: 1024,
  maxResponseBytes: 2048,
  credentialAudience: "api.github.com",
};

function createIdFactory(): () => string {
  let nextId = 0;
  return () => `network-test-id-${++nextId}`;
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

function createRouterWithNetwork(services: PluginHostNetworkServices): PluginHostMessageRouter {
  const router = new PluginHostMessageRouter({
    windowTarget: { addEventListener() {}, removeEventListener() {} },
    idFactory: createIdFactory(),
  });
  registerPluginHostNetworkHandlers(router, services);
  return router;
}

function baseServices(
  overrides: Partial<PluginHostNetworkServices> = {},
): PluginHostNetworkServices {
  return {
    endpointPolicy: vi.fn(async () => ENDPOINT),
    proxyExecutor: vi.fn(async () => ({
      status: 200,
      headers: { "content-type": "application/json", "set-cookie": "secret" },
      bodyText: '{"ok":true}',
    })),
    proxyRegistration: vi.fn(async () => proxyRegistration()),
    appOrigin: () => "https://app.refmd.example",
    ...overrides,
  };
}

function proxyRegistration(
  overrides: Partial<PluginNetworkProxyRegistration> = {},
): PluginNetworkProxyRegistration {
  return {
    id: "org-proxy",
    label: "Org Proxy",
    origin: "https://proxy.example",
    scope: "workspace",
    ...overrides,
  };
}

function proxyRequestSigner(): PluginNetworkProxyRequestSigner & {
  signProxyRequest: ReturnType<typeof vi.fn>;
} {
  return {
    signProxyRequest: vi.fn(async (subject) => ({
      transcript: {
        protocol: "refmd.plugin-network-proxy-request-transcript",
        version: 1,
        subject_hash: "proxy-subject-hash-1",
        subject,
      },
      signature: {
        protocol: "refmd.hybrid-signature",
        version: 1,
        suite_id: "refmd-v2-hybrid-signature-ed25519-mldsa65",
        suite_rank: 2,
        signing_key_id: "proxy-signing-key-1",
        transcript_hash: "proxy-subject-hash-1",
        ed25519: "ed25519-signature",
        mldsa65: "mldsa65-signature",
      },
      signing_key_id: "proxy-signing-key-1",
      hybrid_signing_public_key_material: {
        protocol: "refmd.hybrid-signing-key-material",
        owner_kind: "device",
        owner_id: "device.example",
        signing_key_id: "proxy-signing-key-1",
      },
    })),
  };
}

function proxyExecutorRequest(): PluginNetworkExecutorRequest {
  return {
    context: {
      pluginId: "plugin.example",
      packageId: "package.example",
      applicationId: "00000000-0000-4000-8000-000000000001",
      activationId: "activation.example",
      ownerScopeKind: "workspace",
      userId: "user.example",
      deviceId: "device.example",
      workspaceId: "00000000-0000-4000-8000-000000000002",
      stateHeadHash: "state-head-1",
      consentHeadHash: "consent-head-1",
      bundleHash: "bundle-hash-1",
      manifestHash: "manifest-hash-1",
      capabilityId: "capability-1",
      capabilityGrantId: "capability-grant-1",
      consentEpoch: 3,
      frameGeneration: 7,
      sessionId: "session-1",
      auditActor: {
        user_id: "00000000-0000-4000-8000-000000000003",
        device_id: "00000000-0000-4000-8000-000000000004",
        session_id: "session-1",
        principal_kind: "user",
        principal_id: "00000000-0000-4000-8000-000000000003",
      },
    },
    endpoint: ENDPOINT,
    route: "proxy",
    proxy: proxyRegistration(),
    url: "https://api.github.com/repos/refmdio/refmd/issues",
    method: "GET",
    headers: { accept: "application/json" },
    body: null,
    credentialHandle: null,
    redirect: "manual",
    requestId: "request-proxy",
  };
}

function boot(
  router: PluginHostMessageRouter,
  options: Pick<
    Parameters<PluginHostMessageRouter["createSession"]>[0],
    "permissions" | "highRiskConsents" | "auditSink"
  >,
) {
  return bootWithSession(router, options).port;
}

function bootWithSession(
  router: PluginHostMessageRouter,
  options: Pick<
    Parameters<PluginHostMessageRouter["createSession"]>[0],
    "permissions" | "highRiskConsents" | "auditSink"
  >,
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
  return { session, port };
}

function requestEnvelope(
  payload: unknown,
  overrides: Partial<PluginHostRpcRequestEnvelope> = {},
): PluginHostRpcRequestEnvelope {
  return {
    protocol: PLUGIN_HOST_RPC_PROTOCOL,
    version: PLUGIN_HOST_RPC_VERSION,
    kind: "request",
    request_id: "network-request",
    request_nonce: `network-nonce-${Math.random()}`,
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
    operation: "app.network.fetch",
    payload,
    ...overrides,
  };
}

function fetchPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    endpoint_id: "github-rest",
    route: "proxy",
    method: "GET",
    headers: { accept: "application/json" },
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

async function completeNetworkExecutorFrame(response: {
  requestId: string;
  status: number;
  bodyText: string;
  headers?: readonly [string, string][];
}): Promise<{ frame: HTMLIFrameElement; postMessage: ReturnType<typeof vi.fn> }> {
  await vi.waitFor(() => {
    expect(
      document.querySelector('iframe[data-refmd-plugin-network-executor="true"]'),
    ).toBeTruthy();
  });
  const frame = document.querySelector<HTMLIFrameElement>(
    'iframe[data-refmd-plugin-network-executor="true"]',
  );
  if (!frame?.contentWindow) throw new Error("network_executor_frame_missing");
  const postMessage = vi.fn(
    (_message: unknown, _targetOrigin: string, transfer?: readonly Transferable[]) => {
      const port = transfer?.[0] as MessagePort | undefined;
      port?.postMessage({
        protocol: "refmd.plugin-network-executor",
        requestId: response.requestId,
        ok: true,
        status: response.status,
        headers: response.headers ?? [["content-type", "application/json"]],
        bodyText: response.bodyText,
      });
    },
  );
  Object.defineProperty(frame.contentWindow, "postMessage", {
    configurable: true,
    value: postMessage,
  });
  frame.dispatchEvent(new Event("load"));
  return { frame, postMessage };
}

describe("plugin Host RPC network surface", () => {
  it("executes declared proxy requests through the Host network executor", async () => {
    const proxyExecutor = vi.fn(async () => ({
      status: 201,
      headers: { "content-type": "application/json", "set-cookie": "secret" },
      bodyText: '{"created":true}',
    }));
    const router = createRouterWithNetwork(baseServices({ proxyExecutor }));
    const port = boot(router, { permissions: ["network:fetch"] });

    port.postMessage(
      requestEnvelope(
        fetchPayload({
          method: "POST",
          body_json: { title: "network model" },
          headers: { accept: "application/json", "content-type": "application/json" },
        }),
      ),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      payload: {
        route: "proxy",
        proxy_id: "org-proxy",
        status: 201,
        headers: { "content-type": "application/json" },
        body_text: '{"created":true}',
      },
    });

    expect(proxyExecutor).toHaveBeenCalledWith(
      expect.objectContaining({
        route: "proxy",
        proxy: expect.objectContaining({ id: "org-proxy" }),
        url: "https://api.github.com/repos/refmdio/refmd/issues",
        method: "POST",
        body: '{"title":"network model"}',
        redirect: "manual",
      }),
    );
  });

  it("normalizes omitted network routes to the configured proxy route", async () => {
    const auditSink = vi.fn(() => true);
    const proxyExecutor = vi.fn(async () => ({
      status: 200,
      headers: { "content-type": "application/json" },
      bodyText: '{"ok":true}',
    }));
    const router = createRouterWithNetwork(baseServices({ proxyExecutor }));
    const port = boot(router, { permissions: ["network:fetch"], auditSink });
    const payload = fetchPayload();
    delete payload.route;

    port.postMessage(requestEnvelope(payload));

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
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
        route: "proxy",
        proxy: expect.objectContaining({ id: "org-proxy" }),
        method: "GET",
      }),
    );
    expect(auditSink).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({
        type: "plugin.network.requested",
        operation: "app.network.fetch:GET:proxy",
        action: expect.objectContaining({
          result: "allowed",
          endpoint_id: "github-rest",
          route: "proxy",
          proxy_id: "org-proxy",
          method: "GET",
        }),
      }),
    );
  });

  it("uses the default Host-owned iframe executor for proxy requests", async () => {
    const fetch = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        new Response(JSON.stringify({ session_token: "signed-executor-session" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetch);
    const services = createDefaultPluginHostNetworkServices({
      proxyRegistration: proxyRegistration(),
      requestSigner: proxyRequestSigner(),
    });
    const request = proxyExecutorRequest();
    const executePromise = services.proxyExecutor?.(request);
    expect(executePromise).toBeDefined();

    await vi.waitFor(() => {
      expect(
        document.querySelector('iframe[data-refmd-plugin-network-executor="true"]'),
      ).toBeTruthy();
    });
    const frame = document.querySelector<HTMLIFrameElement>(
      'iframe[data-refmd-plugin-network-executor="true"]',
    );
    expect(frame).toBeTruthy();
    const executorUrl = new URL(frame?.src ?? "about:blank");
    expect(executorUrl.pathname).toBe("/plugin-network-executor");
    expect(executorUrl.searchParams.get("session_token")).toBe("signed-executor-session");
    expect(frame?.getAttribute("sandbox")).toBe("allow-scripts allow-same-origin");

    expect(fetch).toHaveBeenCalledWith(
      "/api/plugin-network-executor-sessions",
      expect.objectContaining({
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/json" },
      }),
    );
    const [, sessionInit] = fetch.mock.calls[0] as [RequestInfo | URL, RequestInit];
    const sessionBody = parseJsonRequestBody(sessionInit.body);
    expect(sessionBody).toMatchObject({
      target_url: "https://proxy.example",
      target_origin: "https://proxy.example",
      route: "proxy",
      proxy_id: "org-proxy",
      method: "POST",
      header_names: ["content-type"],
      body_schema: "json",
      network_target_url: "https://api.github.com/repos/refmdio/refmd/issues",
      network_method: "GET",
      network_header_names: ["accept"],
      network_body_schema: "json",
      workspace_id: "00000000-0000-4000-8000-000000000002",
      plugin_id: "plugin.example",
      package_id: "package.example",
      application_id: "00000000-0000-4000-8000-000000000001",
      activation_id: "activation.example",
      owner_scope_kind: "workspace",
      user_id: "user.example",
      device_id: "device.example",
      endpoint_id: "github-rest",
      consent_epoch: 3,
      frame_generation: 7,
      state_head_hash: "state-head-1",
      consent_head_hash: "consent-head-1",
      bundle_hash: "bundle-hash-1",
      manifest_hash: "manifest-hash-1",
      capability_grant_id: "capability-grant-1",
      request_id: "request-proxy",
      credential_audience: "api.github.com",
      credential_handle_used: false,
      request_bytes: 0,
    });
    const executorToken = sessionBody.executor_token;
    if (typeof executorToken !== "string") {
      throw new Error("expected executor token string");
    }
    expect(executorToken).toMatch(/^[a-f0-9]{32}$/);

    const contentWindow = frame?.contentWindow;
    expect(contentWindow).toBeTruthy();
    const postMessage = vi.fn(
      (_message: unknown, _targetOrigin: string, transfer?: readonly Transferable[]) => {
        const port = transfer?.[0] as MessagePort | undefined;
        port?.postMessage({
          protocol: "refmd.plugin-network-executor",
          requestId: request.requestId,
          ok: true,
          status: 202,
          headers: [["content-type", "text/plain"]],
          bodyText: JSON.stringify({
            status: 202,
            headers: { "content-type": "text/plain" },
            body_text: "ok",
          }),
        });
      },
    );
    Object.defineProperty(contentWindow as Window, "postMessage", {
      configurable: true,
      value: postMessage,
    });

    frame?.dispatchEvent(new Event("load"));

    await expect(executePromise).resolves.toEqual({
      status: 202,
      headers: { "content-type": "text/plain" },
      bodyText: "ok",
    });
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        protocol: "refmd.plugin-network-executor",
        kind: "execute",
        executorToken,
        route: "proxy",
        url: "https://proxy.example",
      }),
      window.location.origin,
      expect.any(Array),
    );
    expect(frame?.isConnected).toBe(false);
  });

  it("keeps Host-injected credential headers out of plugin endpoint header validation", async () => {
    const signer = proxyRequestSigner();
    const fetch = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        new Response(JSON.stringify({ session_token: "signed-executor-session" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetch);
    const services = createDefaultPluginHostNetworkServices({
      proxyRegistration: proxyRegistration(),
      requestSigner: signer,
    });
    const request = {
      ...proxyExecutorRequest(),
      headers: {
        accept: "application/json",
        authorization: "Bearer host-token",
      },
      networkHeaderNames: ["accept"],
      credentialHandle: "credential.handle",
    };

    const executePromise = services.proxyExecutor?.(request);
    expect(executePromise).toBeDefined();

    await vi.waitFor(() => {
      expect(
        document.querySelector('iframe[data-refmd-plugin-network-executor="true"]'),
      ).toBeTruthy();
    });
    const [, sessionInit] = fetch.mock.calls[0] as [RequestInfo | URL, RequestInit];
    const sessionBody = parseJsonRequestBody(sessionInit.body);
    expect(sessionBody).toMatchObject({
      network_header_names: ["accept"],
      credential_audience: "api.github.com",
      credential_handle_used: true,
    });
    const signedSubject = signer.signProxyRequest.mock.calls[0]?.[0];
    expect(signedSubject?.target).toEqual(
      expect.objectContaining({
        headers: expect.objectContaining({
          accept: "application/json",
          authorization: "Bearer host-token",
        }),
      }),
    );

    const frame = document.querySelector<HTMLIFrameElement>(
      'iframe[data-refmd-plugin-network-executor="true"]',
    );
    const contentWindow = frame?.contentWindow;
    const postMessage = vi.fn(
      (_message: unknown, _targetOrigin: string, transfer?: readonly Transferable[]) => {
        const port = transfer?.[0] as MessagePort | undefined;
        port?.postMessage({
          protocol: "refmd.plugin-network-executor",
          requestId: request.requestId,
          ok: true,
          status: 200,
          headers: [],
          bodyText: JSON.stringify({ status: 200, headers: {}, body_text: "ok" }),
        });
      },
    );
    Object.defineProperty(contentWindow as Window, "postMessage", {
      configurable: true,
      value: postMessage,
    });
    frame?.dispatchEvent(new Event("load"));

    await expect(executePromise).resolves.toMatchObject({
      status: 200,
      bodyText: "ok",
    });
  });

  it("fails closed when the default iframe executor cannot mint a session", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("Bad Request", { status: 400 })),
    );
    const services = createDefaultPluginHostNetworkServices({
      proxyRegistration: proxyRegistration(),
      requestSigner: proxyRequestSigner(),
    });

    await expect(services.proxyExecutor?.(proxyExecutorRequest())).rejects.toMatchObject({
      code: "proxy_not_configured",
    });
    expect(document.querySelector('iframe[data-refmd-plugin-network-executor="true"]')).toBeNull();
  });

  it("rejects network fetch without the matching capability", async () => {
    const router = createRouterWithNetwork(baseServices());
    const port = boot(router, { permissions: [] });

    port.postMessage(requestEnvelope(fetchPayload()));

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "permission_denied" },
    });
  });

  it("rejects browser-bypassing route controls from the plugin payload", async () => {
    const router = createRouterWithNetwork(baseServices());
    const port = boot(router, { permissions: ["network:fetch"] });

    port.postMessage(requestEnvelope(fetchPayload({ mode: "no-cors" })));
    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "no_cors_forbidden" },
    });

    port.postMessage(requestEnvelope(fetchPayload({ proxy_url: "https://proxy.example" })));
    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "plugin_proxy_forbidden" },
    });

    port.postMessage(requestEnvelope(fetchPayload({ route: "extension" })));
    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "extension_route_unavailable" },
    });
  });

  it("rejects undeclared route, method, header, and private targets", async () => {
    const router = createRouterWithNetwork(baseServices());
    const port = boot(router, { permissions: ["network:fetch"] });

    port.postMessage(requestEnvelope(fetchPayload({ method: "DELETE" })));
    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "network_method_undeclared" },
    });

    port.postMessage(requestEnvelope(fetchPayload({ headers: { authorization: "Bearer token" } })));
    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "network_header_forbidden" },
    });

    const privateTargetRouter = createRouterWithNetwork(
      baseServices({
        endpointPolicy: vi.fn(async () => ({ ...ENDPOINT, url: "https://127.0.0.1/status" })),
      }),
    );
    const privateTargetPort = boot(privateTargetRouter, { permissions: ["network:fetch"] });
    privateTargetPort.postMessage(requestEnvelope(fetchPayload()));
    await expect(waitForPortMessage(privateTargetPort)).resolves.toMatchObject({
      kind: "error",
      error: { code: "network_target_forbidden" },
    });
  });

  it("rejects metadata hosts, IP literals, and non-canonical endpoint URLs", async () => {
    for (const [url, code] of [
      ["https://metadata.google.internal/computeMetadata/v1", "network_target_forbidden"],
      ["https://metadata.google.internal./computeMetadata/v1", "network_target_forbidden"],
      ["https://localhost./status", "network_target_forbidden"],
      ["https://printer.local./status", "network_target_forbidden"],
      ["https://203.0.113.10/status", "network_target_forbidden"],
      ["https://bücher.example/status", "network_url_invalid"],
      ["https://api.github.com:443/repos/refmdio/refmd/issues", "network_url_invalid"],
      ["https://api.github.com:8443/repos/refmdio/refmd/issues", "network_url_invalid"],
      ["https://api.github.com/repos/refmdio/refmd/%2e%2e/issues", "network_url_invalid"],
    ] as const) {
      const router = createRouterWithNetwork(
        baseServices({
          endpointPolicy: vi.fn(async () => ({ ...ENDPOINT, url })),
        }),
      );
      const port = boot(router, { permissions: ["network:fetch"] });
      port.postMessage(requestEnvelope(fetchPayload()));
      await expect(waitForPortMessage(port)).resolves.toMatchObject({
        kind: "error",
        error: { code },
      });
    }
  });

  it("rejects app-origin network endpoints instead of treating the app server as an endpoint", async () => {
    const proxyExecutor = vi.fn(async () => ({
      status: 200,
      headers: {},
      bodyText: "ok",
    }));
    const router = createRouterWithNetwork(
      baseServices({
        proxyExecutor,
        endpointPolicy: vi.fn(async () => ({
          ...ENDPOINT,
          url: "https://app.refmd.example/api/documents",
        })),
      }),
    );
    const port = boot(router, { permissions: ["network:fetch"] });

    port.postMessage(requestEnvelope(fetchPayload()));

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "network_target_forbidden" },
    });
    expect(proxyExecutor).not.toHaveBeenCalled();
  });

  it("audits denied network routes before returning policy errors", async () => {
    const auditSink = vi.fn(() => true);
    const router = createRouterWithNetwork(
      baseServices({
        endpointPolicy: vi.fn(async () => null),
      }),
    );
    const port = boot(router, {
      permissions: ["network:fetch", "document:read:active"],
      highRiskConsents: ["plaintext_network_egress"],
      auditSink,
    });

    port.postMessage(requestEnvelope(fetchPayload()));

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "network_endpoint_unknown" },
    });
    expect(auditSink).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "plugin.network.blocked",
        operation: "app.network.fetch:GET:proxy",
        action: expect.objectContaining({
          result: "denied",
          reason_code: "network_endpoint_unknown",
          endpoint_id: "github-rest",
          route: "proxy",
          method: "GET",
          request_bytes: 0,
          response_bytes: 0,
          credential_handle_used: false,
        }),
      }),
    );

    const privateTargetAudit = vi.fn(() => true);
    const privateTargetRouter = createRouterWithNetwork(
      baseServices({
        endpointPolicy: vi.fn(async () => ({ ...ENDPOINT, url: "https://127.0.0.1/status" })),
      }),
    );
    const privateTargetPort = boot(privateTargetRouter, {
      permissions: ["network:fetch"],
      auditSink: privateTargetAudit,
    });
    privateTargetPort.postMessage(requestEnvelope(fetchPayload()));

    await expect(waitForPortMessage(privateTargetPort)).resolves.toMatchObject({
      kind: "error",
      error: { code: "network_target_forbidden" },
    });
    expect(privateTargetAudit).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "plugin.network.blocked",
        operation: "app.network.fetch:GET:proxy",
        resource: expect.objectContaining({
          id: "github-rest",
          version_hash: "https://127.0.0.1/status|route=proxy|credential=no|proxy=none",
        }),
        action: expect.objectContaining({
          result: "denied",
          reason_code: "network_target_forbidden",
          endpoint_id: "github-rest",
          route: "proxy",
          method: "GET",
          target_origin: "https://127.0.0.1",
          target_path: "/status",
          request_bytes: 0,
          response_bytes: 0,
          credential_handle_used: false,
        }),
      }),
    );
  });

  it("denies network egress before executor when audit is unavailable", async () => {
    const proxyExecutor = vi.fn(async () => ({
      status: 200,
      headers: {},
      bodyText: "ok",
    }));
    const router = createRouterWithNetwork(baseServices({ proxyExecutor }));
    const port = boot(router, { permissions: ["network:fetch"], auditSink: undefined });

    port.postMessage(requestEnvelope(fetchPayload()));

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "network_audit_unavailable" },
    });
    expect(proxyExecutor).not.toHaveBeenCalled();
  });

  it("denies network egress before executor when audit sink rejects the event", async () => {
    const proxyExecutor = vi.fn(async () => ({
      status: 200,
      headers: {},
      bodyText: "ok",
    }));
    const router = createRouterWithNetwork(baseServices({ proxyExecutor }));
    const port = boot(router, { permissions: ["network:fetch"], auditSink: () => false });

    port.postMessage(requestEnvelope(fetchPayload()));

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "network_audit_unavailable" },
    });
    expect(proxyExecutor).not.toHaveBeenCalled();
  });

  it("waits for durable network audit rejection before executor dispatch", async () => {
    const proxyExecutor = vi.fn(async () => ({
      status: 200,
      headers: {},
      bodyText: "ok",
    }));
    const auditSink = vi.fn(async () => false);
    const router = createRouterWithNetwork(baseServices({ proxyExecutor }));
    const port = boot(router, {
      permissions: ["network:fetch", "document:read:active"],
      highRiskConsents: ["plaintext_network_egress"],
      auditSink,
    });

    port.postMessage(requestEnvelope(fetchPayload()));

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "network_audit_unavailable" },
    });
    expect(auditSink).toHaveBeenCalled();
    expect(proxyExecutor).not.toHaveBeenCalled();
  });

  it("audits route metadata before sending network egress", async () => {
    const proxyExecutor = vi.fn(async () => ({
      status: 200,
      headers: {},
      bodyText: "ok",
    }));
    const auditSink = vi.fn(() => true);
    const router = createRouterWithNetwork(
      baseServices({
        proxyExecutor,
        endpointPolicy: vi.fn(async () => ({ ...ENDPOINT, bodySchema: "text" as const })),
      }),
    );
    const port = boot(router, {
      permissions: ["network:fetch", "document:read:active"],
      highRiskConsents: ["plaintext_network_egress"],
      auditSink,
    });

    port.postMessage(requestEnvelope(fetchPayload({ method: "POST", body_text: "hello" })));

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      payload: { body_text: "ok" },
    });
    expect(auditSink.mock.invocationCallOrder[0]).toBeLessThan(
      proxyExecutor.mock.invocationCallOrder[0] ?? Number.POSITIVE_INFINITY,
    );
    expect(proxyExecutor.mock.invocationCallOrder[0]).toBeLessThan(
      auditSink.mock.invocationCallOrder[1] ?? Number.POSITIVE_INFINITY,
    );
    expect(auditSink).toHaveBeenNthCalledWith(
      1,
      expect.objectContaining({
        type: "plugin.network.requested",
        requestId: "network-request",
        operation: "app.network.fetch:POST:proxy",
        action: expect.objectContaining({
          result: "allowed",
          endpoint_id: "github-rest",
          route: "proxy",
          proxy_id: "org-proxy",
          method: "POST",
          target_origin: "https://api.github.com",
          target_path: "/repos/refmdio/refmd/issues",
          request_bytes: 5,
          credential_handle_used: false,
        }),
        resource: expect.objectContaining({
          kind: "network_endpoint",
          id: "github-rest",
          version_hash:
            "https://api.github.com/repos/refmdio/refmd/issues|route=proxy|credential=no|proxy=org-proxy",
        }),
        correlation: expect.objectContaining({
          execution_context_id: null,
        }),
        sensitivity: expect.objectContaining({
          egress_bytes: 5,
          plaintext_scope_kind: "active_document",
        }),
      }),
    );
    expect(auditSink).toHaveBeenNthCalledWith(
      2,
      expect.objectContaining({
        type: "plugin.network.requested",
        requestId: "network-request",
        operation: "app.network.fetch:POST:proxy",
        action: expect.objectContaining({
          result: "completed",
          request_bytes: 5,
          response_bytes: 2,
        }),
        correlation: expect.objectContaining({
          execution_context_id: null,
        }),
        sensitivity: expect.objectContaining({
          egress_bytes: 7,
          plaintext_scope_kind: "active_document",
        }),
      }),
    );
  });

  it("audits active execution context correlation for typed plaintext network calls", async () => {
    const proxyExecutor = vi.fn(async () => ({
      status: 200,
      headers: {},
      bodyText: "ok",
    }));
    const auditSink = vi.fn(() => true);
    const router = createRouterWithNetwork(baseServices({ proxyExecutor }));
    const { session, port } = bootWithSession(router, {
      permissions: ["network:fetch", "document:read:active"],
      highRiskConsents: ["plaintext_network_egress"],
      auditSink,
    });
    const executionContext = session.issueExecutionContext({
      kind: "typed_action",
      hostInvocation: { kind: "typed_action", userGesture: true },
      resource: { document_id: "doc-1" },
      plaintextScope: { kind: "active_document", maxBytes: 256 },
      allowedOperations: ["network.typed_action"],
      expiresAtMs: Date.now() + 60_000,
    });

    port.postMessage(
      requestEnvelope(fetchPayload(), {
        execution_context_id: executionContext.execution_context_id,
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      payload: { body_text: "ok" },
    });
    expect(auditSink).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "plugin.network.requested",
        correlation: expect.objectContaining({
          execution_context_id: executionContext.execution_context_id,
        }),
        sensitivity: expect.objectContaining({
          plaintext_scope_kind: "active_document",
        }),
      }),
    );
  });

  it("rejects removed direct and auto routes before executor dispatch", async () => {
    const proxyExecutor = vi.fn(async () => ({
      status: 200,
      headers: {},
      bodyText: "proxied",
    }));
    const auditSink = vi.fn(() => true);
    const router = createRouterWithNetwork(baseServices({ proxyExecutor }));
    const port = boot(router, {
      permissions: ["network:fetch", "document:read:active"],
      highRiskConsents: ["plaintext_network_egress"],
      auditSink,
    });

    for (const route of ["direct", "auto"] as const) {
      port.postMessage(requestEnvelope(fetchPayload({ route })));
      await expect(waitForPortMessage(port)).resolves.toMatchObject({
        kind: "error",
        error: { code: "network_route_unavailable" },
      });
    }

    expect(proxyExecutor).not.toHaveBeenCalled();
  });

  it("returns a typed error when proxy is not configured", async () => {
    const router = createRouterWithNetwork(
      baseServices({
        proxyExecutor: vi.fn(async () => ({
          status: 200,
          headers: {},
          bodyText: "proxied",
        })),
        proxyRegistration: undefined,
      }),
    );
    const port = boot(router, { permissions: ["network:fetch"] });

    port.postMessage(requestEnvelope(fetchPayload({ route: "proxy" })));

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "proxy_not_configured" },
    });
  });

  it("executes proxy requests only through configured external proxy registrations", async () => {
    const proxyExecutor = vi.fn(async () => ({
      status: 200,
      headers: { "content-type": "application/json" },
      bodyText: '{"proxied":true}',
    }));
    const router = createRouterWithNetwork(
      baseServices({
        proxyExecutor,
        proxyRegistration: vi.fn(async () =>
          proxyRegistration({ origin: "https://proxy.example/path" }),
        ),
      }),
    );
    const port = boot(router, { permissions: ["network:fetch"] });

    port.postMessage(requestEnvelope(fetchPayload({ route: "proxy" })));

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      payload: {
        route: "proxy",
        proxy_id: "org-proxy",
        status: 200,
        body_text: '{"proxied":true}',
      },
    });
    expect(proxyExecutor).toHaveBeenCalledWith(
      expect.objectContaining({
        route: "proxy",
        proxy: expect.objectContaining({
          id: "org-proxy",
          origin: "https://proxy.example/path",
        }),
        url: "https://api.github.com/repos/refmdio/refmd/issues",
        method: "GET",
      }),
    );
  });

  it("executes Host-configured workspace proxy registration with a Host-signed envelope", async () => {
    const signer = proxyRequestSigner();
    releaseRetainedProxy = retainDefaultPluginHostNetworkProxy({
      registration: proxyRegistration({
        id: "workspace-proxy",
        label: "Workspace Proxy",
        origin: "https://proxy.example/refmd",
        scope: "workspace",
        operatorLabel: "Example NetOps",
        allowedWorkspaceIds: ["00000000-0000-4000-8000-000000000002"],
        allowedUserIds: ["user.example"],
        verificationMaterial: { response_signing_key: "proxy-key-1" },
        policy: { max_response_size: 2048 },
      }),
      requestSigner: signer,
    });
    const fetch = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        new Response(JSON.stringify({ session_token: "signed-proxy-executor-session" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetch);
    const services = {
      ...createDefaultPluginHostNetworkServices(),
      endpointPolicy: () => ({ ...ENDPOINT, routes: ["proxy"] as const }),
    };
    const router = createRouterWithNetwork(services);
    const port = boot(router, { permissions: ["network:fetch"] });

    port.postMessage(requestEnvelope(fetchPayload({ route: "proxy" })));
    const proxyResponse = JSON.stringify({
      status: 200,
      headers: { "content-type": "application/json" },
      body_text: '{"proxied":true}',
    });
    const { postMessage } = await completeNetworkExecutorFrame({
      requestId: "network-request",
      status: 200,
      bodyText: proxyResponse,
    });

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      payload: {
        route: "proxy",
        proxy_id: "workspace-proxy",
        status: 200,
        body_text: '{"proxied":true}',
      },
    });
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith(
      "/api/plugin-network-executor-sessions",
      expect.objectContaining({
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/json" },
      }),
    );
    const firstCall = fetch.mock.calls[0];
    if (!firstCall) {
      throw new Error("proxy_fetch_missing");
    }
    const [, init] = firstCall as [RequestInfo | URL, RequestInit];
    const sessionBody = JSON.parse(init.body as string);
    expect(sessionBody).toMatchObject({
      target_url: "https://proxy.example/refmd",
      target_origin: "https://proxy.example",
      network_target_url: "https://api.github.com/repos/refmdio/refmd/issues",
      network_method: "GET",
      network_header_names: ["accept"],
      network_body_schema: "json",
      route: "proxy",
      proxy_id: "workspace-proxy",
      method: "POST",
      header_names: ["content-type"],
      body_schema: "json",
      max_response_bytes: 2048,
      endpoint_id: "github-rest",
      owner_scope_kind: "workspace",
      user_id: "user.example",
      device_id: "device.example",
      consent_epoch: 3,
      request_bytes: 0,
    });
    expect(sessionBody.executor_token).toMatch(/^[a-f0-9]{32}$/);
    expect(postMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        protocol: "refmd.plugin-network-executor",
        kind: "execute",
        executorToken: sessionBody.executor_token,
        route: "proxy",
        url: "https://proxy.example/refmd",
        method: "POST",
      }),
      window.location.origin,
      expect.any(Array),
    );
    const executeBody = postMessage.mock.calls[0]?.[0] as { body?: string };
    const body = JSON.parse(String(executeBody.body));
    expect(body).toMatchObject({
      protocol: "refmd.plugin-network-proxy-request",
      version: 1,
      signing_key_id: "proxy-signing-key-1",
      signature: {
        protocol: "refmd.hybrid-signature",
        signing_key_id: "proxy-signing-key-1",
        transcript_hash: "proxy-subject-hash-1",
      },
      transcript: {
        protocol: "refmd.plugin-network-proxy-request-transcript",
        subject_hash: "proxy-subject-hash-1",
      },
      subject: {
        protocol: "refmd.plugin-network-proxy-request-subject",
        proxy: {
          id: "workspace-proxy",
          scope: "workspace",
          origin: "https://proxy.example/refmd",
        },
        target: {
          url: "https://api.github.com/repos/refmdio/refmd/issues",
          method: "GET",
        },
        endpoint: {
          id: "github-rest",
          max_response_bytes: 2048,
          credential_audience: "api.github.com",
        },
        runtime: {
          package_id: "package.example",
          application_id: "00000000-0000-4000-8000-000000000001",
          activation_id: "activation.example",
          workspace_id: "00000000-0000-4000-8000-000000000002",
          user_id: "user.example",
          device_id: "device.example",
          owner_scope_kind: "workspace",
          consent_epoch: 3,
          frame_generation: 7,
          capability_grant_id: "capability-grant-1",
          credential_handle_used: false,
        },
      },
    });
    expect(Object.keys(body.subject.proxy).sort()).toEqual(["id", "origin", "scope"]);
    expect(Object.keys(body.subject.target).sort()).toEqual([
      "body_text",
      "headers",
      "method",
      "url",
    ]);
    expect(Object.keys(body.subject.endpoint).sort()).toEqual([
      "credential_audience",
      "id",
      "max_request_bytes",
      "max_response_bytes",
    ]);
    expect(Object.keys(body.subject.runtime).sort()).toEqual([
      "activation_id",
      "application_id",
      "capability_grant_id",
      "consent_epoch",
      "credential_handle_used",
      "device_id",
      "frame_generation",
      "owner_scope_kind",
      "package_id",
      "plugin_id",
      "request_id",
      "user_id",
      "workspace_id",
    ]);
    expect(signer.signProxyRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        protocol: "refmd.plugin-network-proxy-request-subject",
        request_id: "network-request",
        target: expect.objectContaining({
          url: "https://api.github.com/repos/refmdio/refmd/issues",
          method: "GET",
        }),
        runtime: expect.objectContaining({
          package_id: "package.example",
          application_id: "00000000-0000-4000-8000-000000000001",
          activation_id: "activation.example",
          workspace_id: "00000000-0000-4000-8000-000000000002",
          user_id: "user.example",
          device_id: "device.example",
          owner_scope_kind: "workspace",
          consent_epoch: 3,
          frame_generation: 7,
          capability_grant_id: "capability-grant-1",
          credential_handle_used: false,
        }),
      }),
    );
  });

  it("omits optional credential audience from the signed proxy subject when the endpoint has none", async () => {
    const signer = proxyRequestSigner();
    releaseRetainedProxy = retainDefaultPluginHostNetworkProxy({
      registration: proxyRegistration({
        id: "workspace-proxy",
        label: "Workspace Proxy",
        origin: "https://proxy.example/refmd",
        scope: "workspace",
      }),
      requestSigner: signer,
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async (_input: RequestInfo | URL, _init?: RequestInit) =>
          new Response(JSON.stringify({ session_token: "signed-proxy-executor-session" }), {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
      ),
    );
    const services = {
      ...createDefaultPluginHostNetworkServices(),
      endpointPolicy: () => {
        const { credentialAudience: _credentialAudience, ...endpoint } = ENDPOINT;
        return { ...endpoint, routes: ["proxy"] as const };
      },
    };
    const router = createRouterWithNetwork(services);
    const port = boot(router, { permissions: ["network:fetch"] });

    port.postMessage(requestEnvelope(fetchPayload({ route: "proxy" })));
    await completeNetworkExecutorFrame({
      requestId: "network-request",
      status: 200,
      bodyText: JSON.stringify({ status: 200, headers: {}, body_text: "ok" }),
    });

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      payload: {
        route: "proxy",
        proxy_id: "workspace-proxy",
        status: 200,
        body_text: "ok",
      },
    });
    const signedSubject = signer.signProxyRequest.mock.calls[0]?.[0];
    expect(signedSubject?.endpoint).toEqual({
      id: "github-rest",
      max_request_bytes: 1024,
      max_response_bytes: 2048,
    });
  });

  it("does not follow workspace proxy redirects with the signed envelope", async () => {
    const signer = proxyRequestSigner();
    releaseRetainedProxy = retainDefaultPluginHostNetworkProxy({
      registration: proxyRegistration({
        id: "workspace-proxy",
        label: "Workspace Proxy",
        origin: "https://proxy.example/refmd",
        scope: "workspace",
      }),
      requestSigner: signer,
    });
    const fetch = vi.fn(
      async (_input: RequestInfo | URL, _init?: RequestInit) =>
        new Response(JSON.stringify({ session_token: "signed-proxy-executor-session" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    );
    vi.stubGlobal("fetch", fetch);
    const services = {
      ...createDefaultPluginHostNetworkServices(),
      endpointPolicy: () => ({ ...ENDPOINT, routes: ["proxy"] as const }),
    };
    const router = createRouterWithNetwork(services);
    const port = boot(router, { permissions: ["network:fetch"] });

    port.postMessage(requestEnvelope(fetchPayload({ route: "proxy" })));
    await completeNetworkExecutorFrame({
      requestId: "network-request",
      status: 307,
      bodyText: "",
      headers: [["location", "https://redirected.example/refmd"]],
    });

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "proxy_network_error" },
    });
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith(
      "/api/plugin-network-executor-sessions",
      expect.objectContaining({
        method: "POST",
        credentials: "same-origin",
      }),
    );
  });

  it("does not create proxy registration from public env configuration", async () => {
    vi.stubEnv("VITE_REFMD_PLUGIN_NETWORK_PROXY_ID", "workspace-proxy");
    vi.stubEnv("VITE_REFMD_PLUGIN_NETWORK_PROXY_LABEL", "Workspace Proxy");
    vi.stubEnv("VITE_REFMD_PLUGIN_NETWORK_PROXY_ORIGIN", "https://proxy.example/refmd");
    vi.stubEnv("VITE_REFMD_PLUGIN_NETWORK_PROXY_SCOPE", "workspace");
    vi.stubEnv("VITE_REFMD_PLUGIN_NETWORK_PROXY_SIGNING_KEY_ID", "public-key-id");
    vi.stubEnv("VITE_REFMD_PLUGIN_NETWORK_PROXY_LEGACY_SECRET", "public-secret");
    const signer = proxyRequestSigner();
    releaseRetainedProxy = retainDefaultPluginHostNetworkProxy({ requestSigner: signer });
    const fetch = vi.fn(async () => new Response(JSON.stringify({ status: 200, body_text: "ok" })));
    vi.stubGlobal("fetch", fetch);
    const services = {
      ...createDefaultPluginHostNetworkServices(),
      endpointPolicy: () => ({ ...ENDPOINT, routes: ["proxy"] as const }),
    };
    const router = createRouterWithNetwork(services);
    const port = boot(router, { permissions: ["network:fetch"] });

    port.postMessage(requestEnvelope(fetchPayload({ route: "proxy" })));

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "proxy_not_configured" },
    });
    expect(fetch).not.toHaveBeenCalled();
    expect(signer.signProxyRequest).not.toHaveBeenCalled();
  });

  it("wires Host-configured workspace proxy registration into default network services", async () => {
    const proxyExecutor = vi.fn(async () => ({
      status: 200,
      headers: { "content-type": "application/json" },
      bodyText: '{"proxied":true}',
    }));
    releaseRetainedProxy = retainDefaultPluginHostNetworkProxy({
      executor: proxyExecutor,
      registration: proxyRegistration({
        id: "workspace-proxy",
        label: "Workspace Proxy",
        origin: "https://proxy.example/refmd",
        scope: "workspace",
      }),
    });
    const services = {
      ...createDefaultPluginHostNetworkServices(),
      endpointPolicy: () => ({ ...ENDPOINT, routes: ["proxy"] as const }),
    };
    const router = createRouterWithNetwork(services);
    const port = boot(router, { permissions: ["network:fetch"] });

    port.postMessage(requestEnvelope(fetchPayload({ route: "proxy" })));

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      payload: {
        route: "proxy",
        proxy_id: "workspace-proxy",
        status: 200,
        body_text: '{"proxied":true}',
      },
    });
    expect(proxyExecutor).toHaveBeenCalledWith(
      expect.objectContaining({
        route: "proxy",
        proxy: expect.objectContaining({
          id: "workspace-proxy",
          origin: "https://proxy.example/refmd",
          scope: "workspace",
        }),
      }),
    );
  });

  it("rejects same-origin proxy registrations instead of treating the app server as a proxy", async () => {
    const router = createRouterWithNetwork(
      baseServices({
        proxyExecutor: vi.fn(async () => ({
          status: 200,
          headers: {},
          bodyText: "proxied",
        })),
        proxyRegistration: vi.fn(async () =>
          proxyRegistration({
            id: "app-origin",
            label: "App Origin",
            origin: "https://app.refmd.example/plugin-proxy",
            scope: "workspace",
          }),
        ),
      }),
    );
    const port = boot(router, { permissions: ["network:fetch"] });

    port.postMessage(requestEnvelope(fetchPayload({ route: "proxy" })));

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "refmd_proxy_forbidden" },
    });
  });

  it("injects Host-resolved credential headers without accepting plugin secret headers", async () => {
    const proxyExecutor = vi.fn(async () => ({
      status: 200,
      headers: {},
      bodyText: "ok",
    }));
    const credentialResolver = {
      resolve: vi.fn(async () => ({ authorization: "Bearer host-token" })),
    };
    const router = createRouterWithNetwork(baseServices({ proxyExecutor, credentialResolver }));
    const port = boot(router, { permissions: ["network:fetch"] });

    port.postMessage(requestEnvelope(fetchPayload({ credential_handle: "opaque-handle" })));

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      payload: { body_text: "ok" },
    });
    expect(credentialResolver.resolve).toHaveBeenCalledWith(
      expect.objectContaining({
        handle: "opaque-handle",
        audience: "api.github.com",
        method: "GET",
      }),
    );
    expect(proxyExecutor).toHaveBeenCalledWith(
      expect.objectContaining({
        headers: expect.objectContaining({ authorization: "Bearer host-token" }),
        credentialHandle: "opaque-handle",
      }),
    );
  });

  it("requires high-risk consent when plaintext read authority can reach network fetch", async () => {
    const router = createRouterWithNetwork(baseServices());
    const port = boot(router, { permissions: ["network:fetch", "document:read:active"] });

    port.postMessage(requestEnvelope(fetchPayload()));

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "high_risk_consent_required" },
    });
  });

  it("requires workspace export consent for workspace read and network fetch", async () => {
    const router = createRouterWithNetwork(baseServices());
    const port = boot(router, {
      permissions: ["network:fetch", "document:read:workspace"],
      highRiskConsents: ["plaintext_network_egress"],
    });

    port.postMessage(requestEnvelope(fetchPayload()));

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "workspace_network_egress_consent_required" },
    });
  });
});
