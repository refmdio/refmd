import {
  PluginHostRpcError,
  type PluginHostMessageRouter,
  type PluginHostRpcContext,
  type PluginHostRpcHandler,
  type PluginHostRpcHandlerOwnerDescriptor,
} from "../host-rpc/host-rpc";
import {
  emitPluginSecurityAudit,
  pluginAuditSucceeded,
  type PluginHostRpcOperationPolicy,
  type PluginPlaintextScopeKind,
} from "../capability/capability-enforcement";
import { getDefaultPluginHostCredentialStore } from "../credential/host-credential";

export type PluginNetworkRoute = "proxy" | "extension";
export type PluginNetworkBodySchema = "none" | "json" | "text";

export interface PluginNetworkEndpointPolicy {
  id: string;
  url: string;
  methods: readonly string[];
  routes: readonly PluginNetworkRoute[];
  headers?: readonly string[];
  bodySchema?: PluginNetworkBodySchema;
  maxRequestBytes: number;
  maxResponseBytes: number;
  credentialAudience?: string;
}

export interface PluginNetworkExecutorRequest {
  context: PluginHostRpcContext;
  endpoint: PluginNetworkEndpointPolicy;
  route: Extract<PluginNetworkRoute, "proxy">;
  proxy: PluginNetworkProxyRegistration | null;
  url: string;
  method: string;
  headers: Record<string, string>;
  networkHeaderNames?: readonly string[];
  body: string | null;
  credentialHandle: string | null;
  redirect: "manual";
  requestId: string;
  signal?: AbortSignal;
}

export interface PluginNetworkExecutorResponse {
  status: number;
  headers?: Headers | Record<string, string> | readonly [string, string][];
  bodyText: string;
}

export interface PluginNetworkProxyRegistration {
  id: string;
  label: string;
  origin: string;
  scope: "user" | "workspace";
  operatorLabel?: string;
  allowedWorkspaceIds?: readonly string[];
  allowedUserIds?: readonly string[];
  verificationMaterial?: Record<string, unknown>;
  revoked?: boolean;
  policy?: Record<string, unknown>;
}

export interface PluginNetworkProxyRequestSubject extends Record<string, unknown> {
  protocol: "refmd.plugin-network-proxy-request-subject";
  version: 1;
  request_id: string;
  proxy: Record<string, unknown>;
  target: Record<string, unknown>;
  endpoint: Record<string, unknown>;
  runtime: Record<string, unknown>;
}

export interface PluginNetworkProxyRequestSignature {
  transcript: Record<string, unknown>;
  signature: Record<string, unknown>;
  signing_key_id: string;
  hybrid_signing_public_key_material?: Record<string, unknown>;
}

export interface PluginNetworkProxyRequestSigner {
  signProxyRequest(
    subject: PluginNetworkProxyRequestSubject,
  ): Promise<PluginNetworkProxyRequestSignature>;
}

export interface PluginCredentialHeaderResolver {
  resolve(params: PluginCredentialNetworkUseParams): Promise<Record<string, string>>;
}

export interface PluginCredentialNetworkUseParams {
  context: PluginHostRpcContext;
  endpoint: PluginNetworkEndpointPolicy;
  handle: string;
  audience: string;
  method: string;
}

export interface PluginHostNetworkServices {
  endpointPolicy(
    context: PluginHostRpcContext,
    endpointId: string,
  ): PluginNetworkEndpointPolicy | null | Promise<PluginNetworkEndpointPolicy | null>;
  proxyExecutor?: (request: PluginNetworkExecutorRequest) => Promise<PluginNetworkExecutorResponse>;
  proxyRegistration?: (
    context: PluginHostRpcContext,
    endpoint: PluginNetworkEndpointPolicy,
  ) => PluginNetworkProxyRegistration | null | Promise<PluginNetworkProxyRegistration | null>;
  credentialResolver?: PluginCredentialHeaderResolver;
  appOrigin?: () => string | null;
}

export interface PluginHostNetworkProxyConfiguration {
  registration?:
    | PluginNetworkProxyRegistration
    | ((
        context: PluginHostRpcContext,
        endpoint: PluginNetworkEndpointPolicy,
      ) => PluginNetworkProxyRegistration | null | Promise<PluginNetworkProxyRegistration | null>);
  executor?: (request: PluginNetworkExecutorRequest) => Promise<PluginNetworkExecutorResponse>;
  requestSigner?: PluginNetworkProxyRequestSigner;
}

export interface PluginHostNetworkDefaultOptions {
  proxyRegistration?: PluginNetworkProxyRegistration | null;
  requestSigner?: PluginNetworkProxyRequestSigner | null;
}

interface PluginNetworkFetchPayload {
  endpoint_id?: unknown;
  route?: unknown;
  method?: unknown;
  headers?: unknown;
  body_text?: unknown;
  body_json?: unknown;
  credential_handle?: unknown;
  mode?: unknown;
  url?: unknown;
  proxy_url?: unknown;
  proxy_credential?: unknown;
  proxy_id?: unknown;
}

const registeredRouters = new WeakMap<
  PluginHostMessageRouter,
  { retainCount: number; dispose: () => void }
>();

const NETWORK_FETCH_POLICY: PluginHostRpcOperationPolicy = {
  requiredPermissions: ["network:fetch"],
  plaintext: null,
  networkFetch: {
    operation: "network.fetch",
    highRiskConsent: "required",
    workspaceExportConsent: "required",
  },
};

const FORBIDDEN_PLUGIN_HEADERS = new Set(["authorization", "cookie", "proxy-authorization"]);
const SIMPLE_BODY_SCHEMAS = new Set<PluginNetworkBodySchema>(["none", "json", "text"]);
const MAX_DEFAULT_REQUEST_BYTES = 64 * 1024;
const MAX_DEFAULT_RESPONSE_BYTES = 512 * 1024;
const NETWORK_EXECUTOR_PROTOCOL = "refmd.plugin-network-executor";
const NETWORK_EXECUTOR_LOAD_TIMEOUT_MS = 10_000;
const NETWORK_EXECUTOR_SESSION_PATH = "/api/plugin-network-executor-sessions";
const NETWORK_EXECUTOR_TOKEN_BYTES = 16;
const PROXY_ENVELOPE_MAX_BYTES = 1024 * 1024;
const FORBIDDEN_METADATA_HOSTS = new Set([
  "metadata",
  "metadata.google.internal",
  "169.254.169.254",
  "169.254.169.253",
  "100.100.100.200",
]);
let defaultProxyConfiguration: PluginHostNetworkProxyConfiguration | null = null;

export function retainDefaultPluginHostNetworkProxy(
  configuration: PluginHostNetworkProxyConfiguration,
): () => void {
  defaultProxyConfiguration = configuration;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    if (defaultProxyConfiguration === configuration) defaultProxyConfiguration = null;
  };
}

export function createDefaultPluginHostNetworkServices(
  options: PluginHostNetworkDefaultOptions = {},
): PluginHostNetworkServices {
  const proxyConfiguration = defaultProxyConfiguration;
  const registration = proxyConfiguration?.registration ?? options.proxyRegistration ?? null;
  const proxyExecutor =
    proxyConfiguration?.executor ??
    (registration
      ? defaultProxyExecutor(proxyConfiguration?.requestSigner ?? options.requestSigner ?? null)
      : null);
  return {
    endpointPolicy: () => null,
    credentialResolver: getDefaultPluginHostCredentialStore(),
    ...(proxyExecutor
      ? {
          proxyExecutor,
          proxyRegistration: proxyRegistrationService(registration),
        }
      : {}),
  };
}

export function retainPluginHostNetworkHandlers(
  router: PluginHostMessageRouter,
  services: PluginHostNetworkServices = createDefaultPluginHostNetworkServices(),
): () => void {
  const existing = registeredRouters.get(router);
  if (existing) {
    existing.retainCount += 1;
    return () => releasePluginHostNetworkHandlers(router);
  }

  const unregisterHandlers = registerPluginHostNetworkHandlers(router, services);
  registeredRouters.set(router, {
    retainCount: 1,
    dispose: unregisterHandlers,
  });

  return () => releasePluginHostNetworkHandlers(router);
}

export function registerPluginHostNetworkHandlers(
  router: PluginHostMessageRouter,
  services: PluginHostNetworkServices,
  owner?: PluginHostRpcHandlerOwnerDescriptor,
): () => void {
  return registerHandler(
    router,
    owner,
    "app.network.fetch",
    networkFetchHandler(services),
    NETWORK_FETCH_POLICY,
  );
}

function releasePluginHostNetworkHandlers(router: PluginHostMessageRouter): void {
  const registration = registeredRouters.get(router);
  if (!registration) return;
  registration.retainCount -= 1;
  if (registration.retainCount > 0) return;
  registration.dispose();
  registeredRouters.delete(router);
}

function registerHandler(
  router: PluginHostMessageRouter,
  owner: PluginHostRpcHandlerOwnerDescriptor | undefined,
  operation: string,
  handler: PluginHostRpcHandler,
  policy: PluginHostRpcOperationPolicy,
): () => void {
  if (owner) return router.registerOwnerHandler(owner, operation, handler, policy);
  return router.registerHandler(operation, handler, policy);
}

function networkFetchHandler(services: PluginHostNetworkServices): PluginHostRpcHandler {
  return async (context, request) => {
    const auditContext: NetworkAuditContext = {
      executionContextId: request.auditExecutionContextId ?? null,
      plaintextScopeKind: request.plaintextScopeKind ?? "none",
    };
    const blockedAudit = createNetworkBlockedAuditDraft(request.requestId, auditContext);
    try {
      const payload = networkPayload(request.payload);
      blockedAudit.endpointId = stringValue(payload.endpoint_id);
      blockedAudit.route = stringValue(payload.route);
      blockedAudit.method = stringValue(payload.method)?.toUpperCase() ?? null;
      blockedAudit.credentialHandle = stringValue(payload.credential_handle);
      rejectPluginControlledNetworkFields(payload);

      const endpointId = requiredPayloadString(payload.endpoint_id, "endpoint_id");
      const endpoint = await services.endpointPolicy(context, endpointId);
      blockedAudit.endpoint = endpoint ?? null;
      if (!endpoint || endpoint.id !== endpointId) {
        throw new PluginHostRpcError(
          "network_endpoint_unknown",
          "network endpoint is not declared",
        );
      }

      const route = networkRoute(payload.route);
      blockedAudit.route = route;
      const method = requiredPayloadString(payload.method, "method").toUpperCase();
      blockedAudit.method = method;
      blockedAudit.url = endpoint.url;
      const url = canonicalEndpointUrl(endpoint.url, services.appOrigin?.() ?? defaultAppOrigin());
      blockedAudit.url = url;
      const headers = networkHeaders(payload.headers, endpoint);
      const body = networkBody(payload, endpoint);
      blockedAudit.body = body;
      const credentialHandle = optionalPayloadString(
        payload.credential_handle,
        "credential_handle",
      );
      blockedAudit.credentialHandle = credentialHandle;
      validateEndpointRequest(endpoint, route, method, headers, body);

      const credentialHeaders = await resolveCredentialHeaders(
        services,
        context,
        endpoint,
        method,
        credentialHandle,
      );
      const requestHeaders = { ...headers, ...credentialHeaders };

      return await executeProxyRequest(
        services,
        context,
        endpoint,
        url,
        method,
        requestHeaders,
        Object.keys(headers),
        body,
        credentialHandle,
        request.requestId,
        auditContext,
        blockedAudit,
        request.signal,
      );
    } catch (error) {
      if (request.signal.aborted) {
        throw abortError(request.signal);
      }
      if (error instanceof PluginHostRpcError && error.code !== "network_audit_unavailable") {
        await emitRequiredNetworkBlockedAudit(context, blockedAudit, error.code);
      }
      throw error;
    }
  };
}

async function executeProxyRequest(
  services: PluginHostNetworkServices,
  context: PluginHostRpcContext,
  endpoint: PluginNetworkEndpointPolicy,
  url: string,
  method: string,
  headers: Record<string, string>,
  networkHeaderNames: readonly string[],
  body: string | null,
  credentialHandle: string | null,
  requestId: string,
  auditContext: NetworkAuditContext,
  blockedAudit: NetworkBlockedAuditDraft,
  signal?: AbortSignal,
): Promise<unknown> {
  const proxy = await configuredProxy(services, context, endpoint);
  blockedAudit.proxy = proxy;
  if (!proxy || !services.proxyExecutor) {
    throw new PluginHostRpcError("proxy_not_configured", "network proxy route is not configured");
  }

  return executeNetworkRequest(
    services,
    "proxy",
    context,
    endpoint,
    url,
    method,
    headers,
    networkHeaderNames,
    body,
    credentialHandle,
    requestId,
    auditContext,
    proxy,
    signal,
  );
}

async function executeNetworkRequest(
  services: PluginHostNetworkServices,
  route: Extract<PluginNetworkRoute, "proxy">,
  context: PluginHostRpcContext,
  endpoint: PluginNetworkEndpointPolicy,
  url: string,
  method: string,
  headers: Record<string, string>,
  networkHeaderNames: readonly string[],
  body: string | null,
  credentialHandle: string | null,
  requestId: string,
  auditContext: NetworkAuditContext,
  proxy: PluginNetworkProxyRegistration | null = null,
  signal?: AbortSignal,
): Promise<unknown> {
  const executor = services.proxyExecutor;
  if (!executor) {
    throw new PluginHostRpcError("proxy_not_configured", "network proxy route is not configured");
  }

  await emitRequiredNetworkAudit(context, {
    endpoint,
    route,
    url,
    method,
    body,
    credentialHandle,
    proxy,
    requestId,
    ...auditContext,
  });

  let response: PluginNetworkExecutorResponse;
  try {
    response = await executor({
      context,
      endpoint,
      route,
      proxy,
      url,
      method,
      headers,
      networkHeaderNames,
      body,
      credentialHandle,
      redirect: "manual",
      requestId,
      signal,
    });
  } catch (error) {
    if (error instanceof PluginHostRpcError) throw error;
    throw new PluginHostRpcError("proxy_network_error", errorMessage(error));
  }

  const bodyText = response.bodyText ?? "";
  if (byteLength(bodyText) > normalizedMaxResponseBytes(endpoint)) {
    throw new PluginHostRpcError(
      "network_response_too_large",
      "network response exceeds the configured byte limit",
    );
  }
  await emitRequiredNetworkAudit(context, {
    endpoint,
    route,
    url,
    method,
    body,
    credentialHandle,
    proxy,
    requestId,
    ...auditContext,
    byteCounts: {
      requestBytes: body ? byteLength(body) : 0,
      responseBytes: byteLength(bodyText),
    },
  });

  return {
    route,
    ...(proxy ? { proxy_id: proxy.id } : {}),
    status: response.status,
    headers: responseHeaders(response.headers),
    body_text: bodyText,
  };
}

interface NetworkAuditParams {
  endpoint: PluginNetworkEndpointPolicy;
  route: Extract<PluginNetworkRoute, "proxy">;
  url: string;
  method: string;
  body: string | null;
  credentialHandle: string | null;
  proxy: PluginNetworkProxyRegistration | null;
  requestId: string;
  executionContextId: string | null;
  plaintextScopeKind: PluginPlaintextScopeKind;
}

interface NetworkAuditByteCounts {
  requestBytes: number;
  responseBytes: number | null;
}

interface NetworkAuditContext {
  executionContextId: string | null;
  plaintextScopeKind: PluginPlaintextScopeKind;
}

interface NetworkBlockedAuditDraft extends NetworkAuditContext {
  requestId: string;
  endpointId: string | null;
  endpoint: PluginNetworkEndpointPolicy | null;
  route: string | null;
  method: string | null;
  url: string | null;
  body: string | null;
  credentialHandle: string | null;
  proxy: PluginNetworkProxyRegistration | null;
  fallbackReason: string | null;
}

function createNetworkBlockedAuditDraft(
  requestId: string,
  auditContext: NetworkAuditContext,
): NetworkBlockedAuditDraft {
  return {
    requestId,
    ...auditContext,
    endpointId: null,
    endpoint: null,
    route: null,
    method: null,
    url: null,
    body: null,
    credentialHandle: null,
    proxy: null,
    fallbackReason: null,
  };
}

async function emitRequiredNetworkAudit(
  context: PluginHostRpcContext,
  params: NetworkAuditParams & { byteCounts?: NetworkAuditByteCounts },
): Promise<void> {
  if (!context.auditSink) {
    throw new PluginHostRpcError(
      "network_audit_unavailable",
      "network fetch audit event could not be recorded",
    );
  }

  const requestBytes =
    params.byteCounts?.requestBytes ?? (params.body ? byteLength(params.body) : 0);
  const responseBytes = params.byteCounts?.responseBytes ?? null;
  const auditOk = await pluginAuditSucceeded(
    emitPluginSecurityAudit(context.auditSink, context, {
      type: "plugin.network.requested",
      operation: `app.network.fetch:${params.method}:${params.route}`,
      result: "allow",
      actionResult: responseBytes === null ? "allowed" : "completed",
      requestId: params.requestId,
      executionContextId: params.executionContextId,
      plaintextScopeKind: params.plaintextScopeKind,
      payloadKind: "network.typed_action",
      egressBytes: requestBytes + (responseBytes ?? 0),
      resourceKind: "network_endpoint",
      resourceId: params.endpoint.id,
      versionHash: networkAuditVersion(params),
      actionMetadata: networkAuditActionMetadata(params, { requestBytes, responseBytes }),
    }),
  );

  if (!auditOk) {
    throw new PluginHostRpcError(
      "network_audit_unavailable",
      "network fetch audit event could not be recorded",
    );
  }
}

function networkAuditActionMetadata(
  params: NetworkAuditParams,
  byteCounts: NetworkAuditByteCounts,
): Record<string, boolean | number | string | null> {
  const parsed = new URL(params.url);
  return {
    ...optionalActionValue("response_bytes", byteCounts.responseBytes),
    ...optionalActionValue("proxy_id", params.proxy?.id ?? null),
    endpoint_id: params.endpoint.id,
    route: params.route,
    method: params.method,
    target_origin: parsed.origin,
    target_path: parsed.pathname,
    request_bytes: byteCounts.requestBytes,
    credential_handle_used: params.credentialHandle !== null,
  };
}

function networkAuditVersion(params: NetworkAuditParams): string {
  return [
    canonicalUrlForAudit(params.url),
    `route=${params.route}`,
    `credential=${params.credentialHandle ? "yes" : "no"}`,
    `proxy=${params.proxy?.id ?? "none"}`,
  ].join("|");
}

async function emitRequiredNetworkBlockedAudit(
  context: PluginHostRpcContext,
  params: NetworkBlockedAuditDraft,
  reasonCode: string,
): Promise<void> {
  if (!context.auditSink) {
    throw new PluginHostRpcError(
      "network_audit_unavailable",
      "network blocked audit event could not be recorded",
    );
  }

  const auditOk = await pluginAuditSucceeded(
    emitPluginSecurityAudit(context.auditSink, context, {
      type: "plugin.network.blocked",
      operation: `app.network.fetch:${params.method ?? "unknown"}:${params.route ?? "unknown"}`,
      result: "deny",
      actionResult: "denied",
      reasonCode,
      requestId: params.requestId,
      executionContextId: params.executionContextId,
      plaintextScopeKind: params.plaintextScopeKind,
      payloadKind: "network.typed_action",
      egressBytes: params.body ? byteLength(params.body) : 0,
      resourceKind: "network_endpoint",
      resourceId: params.endpoint?.id ?? params.endpointId ?? "unknown",
      versionHash: networkBlockedAuditVersion(params),
      actionMetadata: networkBlockedAuditActionMetadata(params),
    }),
  );

  if (!auditOk) {
    throw new PluginHostRpcError(
      "network_audit_unavailable",
      "network blocked audit event could not be recorded",
    );
  }
}

function networkBlockedAuditActionMetadata(
  params: NetworkBlockedAuditDraft,
): Record<string, boolean | number | string | null> {
  const parsed = params.url ? safeParsedUrl(params.url) : null;
  return {
    ...optionalActionValue("target_origin", parsed?.origin ?? null),
    ...optionalActionValue("target_path", parsed?.pathname ?? null),
    ...optionalActionValue("proxy_id", params.proxy?.id ?? null),
    ...optionalActionValue("fallback_reason", params.fallbackReason),
    endpoint_id: params.endpoint?.id ?? params.endpointId ?? "unknown",
    route: params.route ?? "unknown",
    method: params.method ?? "unknown",
    request_bytes: params.body ? byteLength(params.body) : 0,
    response_bytes: 0,
    credential_handle_used: params.credentialHandle !== null,
  };
}

function optionalActionValue(
  key: string,
  value: boolean | number | string | null,
): Record<string, boolean | number | string> {
  return value === null ? {} : { [key]: value };
}

function safeParsedUrl(value: string): URL | null {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function networkBlockedAuditVersion(params: NetworkBlockedAuditDraft): string {
  return [
    params.url ? safeCanonicalUrlForAudit(params.url) : "unknown",
    `route=${params.route ?? "unknown"}`,
    `credential=${params.credentialHandle ? "yes" : "no"}`,
    `proxy=${params.proxy?.id ?? "none"}`,
  ].join("|");
}

function canonicalUrlForAudit(url: string): string {
  const parsed = new URL(url);
  return `${parsed.origin}${parsed.pathname}`;
}

function safeCanonicalUrlForAudit(url: string): string {
  try {
    return canonicalUrlForAudit(url);
  } catch {
    return "invalid";
  }
}

async function configuredProxy(
  services: PluginHostNetworkServices,
  context: PluginHostRpcContext,
  endpoint: PluginNetworkEndpointPolicy,
): Promise<PluginNetworkProxyRegistration | null> {
  if (!services.proxyExecutor || !services.proxyRegistration) return null;
  const proxy = await services.proxyRegistration(context, endpoint);
  if (!proxy) return null;
  return validateProxyRegistration(proxy, services.appOrigin?.() ?? defaultAppOrigin());
}

function proxyRegistrationService(
  registration: PluginHostNetworkProxyConfiguration["registration"] | null,
): NonNullable<PluginHostNetworkServices["proxyRegistration"]> {
  return async (context, endpoint) => {
    if (!registration) return null;
    if (typeof registration === "function") return registration(context, endpoint);
    return registration;
  };
}

function validateProxyRegistration(
  proxy: PluginNetworkProxyRegistration,
  appOrigin: string | null,
): PluginNetworkProxyRegistration {
  if (!proxy.id || !proxy.label || !proxy.origin) {
    throw new PluginHostRpcError("proxy_not_configured", "network proxy route is not configured");
  }
  let proxyOrigin: string;
  let proxyBaseUrl: string;
  try {
    const parsed = new URL(proxy.origin);
    proxyOrigin = parsed.origin;
    proxyBaseUrl = `${parsed.origin}${parsed.pathname.replace(/\/$/, "")}`;
  } catch {
    throw new PluginHostRpcError("proxy_not_configured", "network proxy origin is invalid");
  }

  if (appOrigin && proxyOrigin === appOrigin) {
    throw new PluginHostRpcError(
      "refmd_proxy_forbidden",
      "application origin cannot be used as a plugin network proxy",
    );
  }

  return { ...proxy, origin: proxyBaseUrl };
}

function defaultAppOrigin(): string | null {
  return typeof location === "object" && typeof location.origin === "string"
    ? location.origin
    : null;
}

async function executeRequestWithNetworkExecutor(
  request: PluginNetworkExecutorRequest,
  errorCode: "proxy_network_error",
  session: NetworkExecutorSessionOptions = {},
): Promise<PluginNetworkExecutorResponse> {
  if (typeof document !== "object" || typeof MessageChannel !== "function") {
    throw new PluginHostRpcError(
      "proxy_not_configured",
      "browser network executor is not available",
    );
  }

  const executorToken = networkExecutorToken();
  assertNotAborted(request.signal);
  const sessionToken = await createNetworkExecutorSession(
    request,
    executorToken,
    session,
    request.signal,
  );
  const frame = document.createElement("iframe");
  frame.title = "Plugin network executor";
  frame.hidden = true;
  frame.setAttribute("aria-hidden", "true");
  frame.setAttribute("data-refmd-plugin-network-executor", "true");
  frame.setAttribute("sandbox", "allow-scripts allow-same-origin");
  frame.src = pluginNetworkExecutorUrl(sessionToken);

  const parent = document.body ?? document.documentElement;
  if (!parent) {
    throw new PluginHostRpcError("proxy_not_configured", "document body is unavailable");
  }

  parent.append(frame);

  try {
    await waitForFrameLoad(frame, request.signal);
    return await executeRequestInFrame(frame, request, executorToken, errorCode, request.signal);
  } finally {
    frame.remove();
  }
}

function defaultProxyExecutor(
  signer: PluginNetworkProxyRequestSigner | null,
): (request: PluginNetworkExecutorRequest) => Promise<PluginNetworkExecutorResponse> {
  return async (request) => {
    const proxy = request.proxy;
    if (!proxy) {
      throw new PluginHostRpcError("proxy_not_configured", "network proxy route is not configured");
    }
    if (!signer) {
      throw new PluginHostRpcError(
        "proxy_signature_unavailable",
        "network proxy request signer is not configured",
      );
    }

    const subject = defaultProxyRequestSubject(request, proxy);
    const envelope = await signedProxyRequestEnvelope(subject, signer);
    const body = JSON.stringify(envelope);
    const executorRequest: PluginNetworkExecutorRequest = {
      ...request,
      endpoint: {
        ...request.endpoint,
        url: proxy.origin,
        headers: ["content-type"],
        bodySchema: "json",
        maxRequestBytes: Math.min(Math.max(byteLength(body), 1), PROXY_ENVELOPE_MAX_BYTES),
      },
      url: proxy.origin,
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    };

    const response = await executeRequestWithNetworkExecutor(
      executorRequest,
      "proxy_network_error",
      {
        networkTargetUrl: request.url,
        networkMethod: request.method,
        networkHeaderNames: request.networkHeaderNames ?? Object.keys(request.headers),
        networkBodySchema: request.endpoint.bodySchema ?? "none",
        requestBytes: request.body ? byteLength(request.body) : 0,
      },
    );
    if (response.status < 200 || response.status >= 300) {
      throw new PluginHostRpcError("proxy_network_error", "network proxy rejected the request");
    }
    const payload = parseJson(response.bodyText);
    return defaultProxyExecutorResponse(payload);
  };
}

function defaultProxyRequestSubject(
  request: PluginNetworkExecutorRequest,
  proxy: PluginNetworkProxyRegistration,
): PluginNetworkProxyRequestSubject {
  return {
    protocol: "refmd.plugin-network-proxy-request-subject",
    version: 1,
    request_id: request.requestId,
    proxy: {
      id: proxy.id,
      scope: proxy.scope,
      origin: proxy.origin,
    },
    target: {
      url: request.url,
      method: request.method,
      headers: request.headers,
      body_text: request.body ?? "",
    },
    endpoint: {
      id: request.endpoint.id,
      max_request_bytes: normalizedMaxRequestBytes(request.endpoint),
      max_response_bytes: normalizedMaxResponseBytes(request.endpoint),
      ...(request.endpoint.credentialAudience
        ? { credential_audience: request.endpoint.credentialAudience }
        : {}),
    },
    runtime: {
      workspace_id: request.context.workspaceId,
      plugin_id: request.context.pluginId,
      package_id: request.context.packageId,
      application_id: request.context.applicationId,
      activation_id: request.context.activationId,
      frame_generation: request.context.frameGeneration,
      user_id: request.context.userId,
      device_id: request.context.deviceId,
      owner_scope_kind: request.context.ownerScopeKind,
      consent_epoch: request.context.consentEpoch,
      capability_grant_id: request.context.capabilityGrantId,
      request_id: request.requestId,
      credential_handle_used: request.credentialHandle !== null,
    },
  };
}

async function signedProxyRequestEnvelope(
  subject: PluginNetworkProxyRequestSubject,
  signer: PluginNetworkProxyRequestSigner,
): Promise<Record<string, unknown>> {
  let signed: PluginNetworkProxyRequestSignature;
  try {
    signed = await signer.signProxyRequest(subject);
  } catch (error) {
    if (error instanceof PluginHostRpcError) throw error;
    throw new PluginHostRpcError("proxy_signature_unavailable", errorMessage(error));
  }

  const signature = signed.signature;
  const transcript = signed.transcript;
  const signingKeyId = signed.signing_key_id;
  if (!isRecord(signature) || !isRecord(transcript) || !stringValue(signingKeyId)) {
    throw new PluginHostRpcError(
      "proxy_signature_unavailable",
      "network proxy request signature is invalid",
    );
  }

  return {
    protocol: "refmd.plugin-network-proxy-request",
    version: 1,
    subject,
    signing_key_id: signingKeyId,
    signature,
    transcript,
    verification: {
      hybrid_signing_public_key_material: signed.hybrid_signing_public_key_material ?? null,
    },
  };
}

function defaultProxyExecutorResponse(payload: unknown): PluginNetworkExecutorResponse {
  if (!isRecord(payload)) {
    throw new PluginHostRpcError("proxy_protocol_invalid", "network proxy response is invalid");
  }
  if (payload.ok === false) {
    const code = typeof payload.error_code === "string" ? payload.error_code : "proxy_rejected";
    const message =
      typeof payload.message === "string" ? payload.message : "network proxy rejected";
    throw new PluginHostRpcError(code, message);
  }
  const status = Number(payload.status);
  const bodyText = typeof payload.body_text === "string" ? payload.body_text : null;
  if (!Number.isInteger(status) || status < 100 || status > 599 || bodyText === null) {
    throw new PluginHostRpcError("proxy_protocol_invalid", "network proxy response is invalid");
  }
  return {
    status,
    headers: proxyResponseHeaders(payload.headers),
    bodyText,
  };
}

function proxyResponseHeaders(value: unknown): Record<string, string> {
  if (!isRecord(value)) return {};
  return Object.fromEntries(
    Object.entries(value).filter(
      (entry): entry is [string, string] =>
        typeof entry[0] === "string" && typeof entry[1] === "string",
    ),
  );
}

interface NetworkExecutorSessionOptions {
  networkTargetUrl?: string;
  networkMethod?: string;
  networkHeaderNames?: readonly string[];
  networkBodySchema?: PluginNetworkBodySchema;
  requestBytes?: number;
}

async function createNetworkExecutorSession(
  request: PluginNetworkExecutorRequest,
  executorToken: string,
  options: NetworkExecutorSessionOptions = {},
  signal?: AbortSignal,
): Promise<string> {
  const response = await fetch(NETWORK_EXECUTOR_SESSION_PATH, {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    signal,
    body: JSON.stringify({
      executor_token: executorToken,
      target_url: request.url,
      target_origin: new URL(request.url).origin,
      route: request.route,
      ...(request.proxy ? { proxy_id: request.proxy.id } : {}),
      method: request.method,
      header_names: Object.keys(request.headers),
      body_schema: request.endpoint.bodySchema ?? "none",
      max_request_bytes: normalizedMaxRequestBytes(request.endpoint),
      max_response_bytes: normalizedMaxResponseBytes(request.endpoint),
      network_target_url: options.networkTargetUrl ?? request.url,
      network_method: options.networkMethod ?? request.method,
      network_header_names: options.networkHeaderNames ?? Object.keys(request.headers),
      network_body_schema: options.networkBodySchema ?? request.endpoint.bodySchema ?? "none",
      workspace_id: request.context.workspaceId,
      plugin_id: request.context.pluginId,
      package_id: request.context.packageId,
      application_id: request.context.applicationId,
      activation_id: request.context.activationId,
      owner_scope_kind: request.context.ownerScopeKind,
      user_id: request.context.userId,
      device_id: request.context.deviceId,
      endpoint_id: request.endpoint.id,
      consent_epoch: request.context.consentEpoch,
      frame_generation: request.context.frameGeneration,
      state_head_hash: request.context.stateHeadHash,
      consent_head_hash: request.context.consentHeadHash,
      bundle_hash: request.context.bundleHash,
      manifest_hash: request.context.manifestHash,
      capability_grant_id: request.context.capabilityGrantId,
      request_id: request.requestId,
      credential_audience: request.endpoint.credentialAudience ?? null,
      credential_handle_used: request.credentialHandle !== null,
      request_bytes: options.requestBytes ?? (request.body ? byteLength(request.body) : 0),
    }),
  });

  if (!response.ok) {
    throw new PluginHostRpcError("proxy_not_configured", "network executor session was rejected");
  }

  const value: unknown = await response.json();
  if (!isRecord(value) || typeof value.session_token !== "string" || !value.session_token) {
    throw new PluginHostRpcError("proxy_not_configured", "network executor session is invalid");
  }
  return value.session_token;
}

function pluginNetworkExecutorUrl(sessionToken: string): string {
  const params = new URLSearchParams({ session_token: sessionToken });
  return `/plugin-network-executor?${params.toString()}`;
}

function waitForFrameLoad(frame: HTMLIFrameElement, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortError(signal));
      return;
    }

    const timeout = window.setTimeout(() => {
      cleanup();
      reject(new PluginHostRpcError("proxy_not_configured", "network executor did not load"));
    }, NETWORK_EXECUTOR_LOAD_TIMEOUT_MS);

    const cleanup = () => {
      window.clearTimeout(timeout);
      frame.removeEventListener("load", onLoad);
      frame.removeEventListener("error", onError);
      signal?.removeEventListener("abort", onAbort);
    };

    const onLoad = () => {
      cleanup();
      resolve();
    };

    const onError = () => {
      cleanup();
      reject(new PluginHostRpcError("proxy_not_configured", "network executor failed to load"));
    };

    const onAbort = () => {
      cleanup();
      reject(abortError(signal));
    };

    frame.addEventListener("load", onLoad, { once: true });
    frame.addEventListener("error", onError, { once: true });
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

function executeRequestInFrame(
  frame: HTMLIFrameElement,
  request: PluginNetworkExecutorRequest,
  executorToken: string,
  errorCode: "proxy_network_error",
  signal?: AbortSignal,
): Promise<PluginNetworkExecutorResponse> {
  const contentWindow = frame.contentWindow;
  if (!contentWindow) {
    throw new PluginHostRpcError("proxy_not_configured", "network executor window is unavailable");
  }

  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortError(signal));
      return;
    }

    const channel = new MessageChannel();
    const timeout = window.setTimeout(() => {
      cleanup();
      reject(new PluginHostRpcError(errorCode, "network executor timed out"));
    }, NETWORK_EXECUTOR_LOAD_TIMEOUT_MS);

    const cleanup = () => {
      window.clearTimeout(timeout);
      channel.port1.removeEventListener("message", onMessage as EventListener);
      signal?.removeEventListener("abort", onAbort);
      channel.port1.close();
    };

    const onMessage = (event: MessageEvent<unknown>) => {
      const response = pluginNetworkExecutorResponse(event.data, request.requestId);
      if (!response) return;
      cleanup();
      if (response.ok) {
        resolve({
          status: response.status,
          headers: response.headers,
          bodyText: response.bodyText,
        });
      } else {
        reject(new PluginHostRpcError(errorCode, response.message || "network request failed"));
      }
    };
    const onAbort = () => {
      cleanup();
      reject(abortError(signal));
    };

    channel.port1.addEventListener("message", onMessage as EventListener);
    signal?.addEventListener("abort", onAbort, { once: true });
    channel.port1.start();
    contentWindow.postMessage(
      networkExecutorFrameRequest(request, executorToken),
      window.location.origin,
      [channel.port2],
    );
  });
}

function assertNotAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw abortError(signal);
}

function abortError(signal: AbortSignal | undefined): PluginHostRpcError {
  const reason = signal?.reason;
  if (reason instanceof PluginHostRpcError) return reason;
  if (reason instanceof Error) return new PluginHostRpcError("session_closed", reason.message);
  return new PluginHostRpcError("session_closed", "plugin session is closed");
}

function networkExecutorFrameRequest(
  request: PluginNetworkExecutorRequest,
  executorToken: string,
): Record<string, unknown> {
  return {
    protocol: NETWORK_EXECUTOR_PROTOCOL,
    kind: "execute",
    requestId: request.requestId,
    executorToken,
    route: request.route,
    url: request.url,
    method: request.method,
    headers: request.headers,
    body: request.body,
  };
}

function networkExecutorToken(): string {
  const cryptoSource = globalThis.crypto;
  if (!cryptoSource || typeof cryptoSource.getRandomValues !== "function") {
    throw new PluginHostRpcError(
      "proxy_not_configured",
      "network executor token source is unavailable",
    );
  }
  const bytes = cryptoSource.getRandomValues(new Uint8Array(NETWORK_EXECUTOR_TOKEN_BYTES));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

type PluginNetworkExecutorFrameResponse =
  | {
      protocol: typeof NETWORK_EXECUTOR_PROTOCOL;
      requestId: string;
      ok: true;
      status: number;
      headers: readonly [string, string][];
      bodyText: string;
    }
  | {
      protocol: typeof NETWORK_EXECUTOR_PROTOCOL;
      requestId: string;
      ok: false;
      message?: string;
    };

function pluginNetworkExecutorResponse(
  value: unknown,
  requestId: string,
): PluginNetworkExecutorFrameResponse | null {
  if (!isRecord(value)) return null;
  if (value.protocol !== NETWORK_EXECUTOR_PROTOCOL || value.requestId !== requestId) return null;
  if (value.ok === false) {
    return {
      protocol: NETWORK_EXECUTOR_PROTOCOL,
      requestId,
      ok: false,
      ...(typeof value.message === "string" ? { message: value.message } : {}),
    };
  }
  if (
    value.ok === true &&
    Number.isSafeInteger(value.status) &&
    Array.isArray(value.headers) &&
    typeof value.bodyText === "string"
  ) {
    const status = Number(value.status);
    return {
      protocol: NETWORK_EXECUTOR_PROTOCOL,
      requestId,
      ok: true,
      status,
      headers: value.headers.filter(
        (entry): entry is [string, string] =>
          Array.isArray(entry) &&
          entry.length === 2 &&
          typeof entry[0] === "string" &&
          typeof entry[1] === "string",
      ),
      bodyText: value.bodyText,
    };
  }
  return null;
}

function networkPayload(payload: unknown): PluginNetworkFetchPayload {
  if (!isRecord(payload)) {
    throw new PluginHostRpcError("network_payload_invalid", "network payload must be an object");
  }
  return payload;
}

function rejectPluginControlledNetworkFields(payload: PluginNetworkFetchPayload): void {
  if (payload.url !== undefined) {
    throw new PluginHostRpcError(
      "network_url_forbidden",
      "network URL must come from the endpoint policy",
    );
  }

  if (
    payload.proxy_url !== undefined ||
    payload.proxy_credential !== undefined ||
    payload.proxy_id !== undefined
  ) {
    throw new PluginHostRpcError(
      "plugin_proxy_forbidden",
      "network proxy settings must come from Host configuration",
    );
  }

  if (payload.mode === "no-cors") {
    throw new PluginHostRpcError("no_cors_forbidden", "network fetch does not allow no-cors mode");
  }
}

function networkRoute(value: unknown): PluginNetworkRoute {
  if (value === undefined) return "proxy";
  if (value === "proxy") return value;
  if (value === "direct" || value === "auto") {
    throw new PluginHostRpcError(
      "network_route_unavailable",
      "network route is no longer supported",
    );
  }
  if (value === "extension") {
    throw new PluginHostRpcError(
      "extension_route_unavailable",
      "network extension route is reserved",
    );
  }
  throw new PluginHostRpcError("network_route_invalid", "network route is not supported");
}

function networkHeaders(
  value: unknown,
  endpoint: PluginNetworkEndpointPolicy,
): Record<string, string> {
  if (value === undefined) return {};
  if (!isRecord(value)) {
    throw new PluginHostRpcError("network_headers_invalid", "network headers must be an object");
  }

  const allowedHeaders = new Set((endpoint.headers ?? []).map((header) => header.toLowerCase()));
  const headers: Record<string, string> = {};
  for (const [name, headerValue] of Object.entries(value)) {
    const normalizedName = name.toLowerCase();
    if (!headerNameAllowed(normalizedName)) {
      throw new PluginHostRpcError("network_header_forbidden", "network header is not allowed");
    }
    if (!allowedHeaders.has(normalizedName)) {
      throw new PluginHostRpcError("network_header_undeclared", "network header is not declared");
    }
    if (typeof headerValue !== "string") {
      throw new PluginHostRpcError(
        "network_headers_invalid",
        "network header value must be a string",
      );
    }
    headers[normalizedName] = headerValue;
  }
  return headers;
}

function headerNameAllowed(name: string): boolean {
  return headerNameSyntaxAllowed(name) && !FORBIDDEN_PLUGIN_HEADERS.has(name);
}

function headerNameSyntaxAllowed(name: string): boolean {
  return /^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(name);
}

function networkBody(
  payload: PluginNetworkFetchPayload,
  endpoint: PluginNetworkEndpointPolicy,
): string | null {
  const hasText = payload.body_text !== undefined;
  const hasJson = payload.body_json !== undefined;
  if (hasText && hasJson) {
    throw new PluginHostRpcError(
      "network_body_invalid",
      "network request must provide only one body",
    );
  }

  const bodySchema = endpoint.bodySchema ?? "none";
  if (!SIMPLE_BODY_SCHEMAS.has(bodySchema)) {
    throw new PluginHostRpcError(
      "network_body_schema_invalid",
      "network body schema is not supported",
    );
  }

  if (!hasText && !hasJson) return null;
  if (bodySchema === "none") {
    throw new PluginHostRpcError(
      "network_body_forbidden",
      "network endpoint does not accept a body",
    );
  }

  if (bodySchema === "text") {
    if (typeof payload.body_text !== "string") {
      throw new PluginHostRpcError("network_body_invalid", "network text body must be a string");
    }
    return payload.body_text;
  }

  if (hasText) {
    throw new PluginHostRpcError("network_body_invalid", "network JSON body must be sent as JSON");
  }

  try {
    return JSON.stringify(payload.body_json ?? null);
  } catch {
    throw new PluginHostRpcError("network_body_invalid", "network JSON body is not serializable");
  }
}

async function resolveCredentialHeaders(
  services: PluginHostNetworkServices,
  context: PluginHostRpcContext,
  endpoint: PluginNetworkEndpointPolicy,
  method: string,
  handle: string | null,
): Promise<Record<string, string>> {
  if (!handle) return {};
  if (!endpoint.credentialAudience) {
    throw new PluginHostRpcError(
      "credential_audience_required",
      "network endpoint does not declare a credential audience",
    );
  }
  if (!services.credentialResolver) {
    throw new PluginHostRpcError("credential_unavailable", "credential resolver is not configured");
  }

  const headers = await services.credentialResolver.resolve({
    context,
    endpoint,
    handle,
    audience: endpoint.credentialAudience,
    method,
  });
  for (const name of Object.keys(headers)) {
    if (!headerNameSyntaxAllowed(name.toLowerCase())) {
      throw new PluginHostRpcError(
        "credential_header_forbidden",
        "credential header is not allowed",
      );
    }
  }
  return Object.fromEntries(
    Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value]),
  );
}

function validateEndpointRequest(
  endpoint: PluginNetworkEndpointPolicy,
  route: PluginNetworkRoute,
  method: string,
  headers: Record<string, string>,
  body: string | null,
): void {
  if (route === "extension") {
    throw new PluginHostRpcError(
      "extension_route_unavailable",
      "network extension route is reserved",
    );
  }
  if (!endpoint.routes.includes(route)) {
    throw new PluginHostRpcError("network_route_undeclared", "network route is not declared");
  }
  if (!endpoint.methods.map((allowedMethod) => allowedMethod.toUpperCase()).includes(method)) {
    throw new PluginHostRpcError("network_method_undeclared", "network method is not declared");
  }
  for (const name of Object.keys(headers)) {
    if (FORBIDDEN_PLUGIN_HEADERS.has(name)) {
      throw new PluginHostRpcError("network_header_forbidden", "network header is not allowed");
    }
  }
  if (body != null && byteLength(body) > normalizedMaxRequestBytes(endpoint)) {
    throw new PluginHostRpcError(
      "network_request_too_large",
      "network request exceeds the configured byte limit",
    );
  }
}

function canonicalEndpointUrl(url: string, appOrigin: string | null): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new PluginHostRpcError("network_url_invalid", "network endpoint URL is invalid");
  }

  const rawLower = url.toLowerCase();
  if (parsed.protocol !== "https:") {
    throw new PluginHostRpcError("network_url_invalid", "network endpoint URL must use HTTPS");
  }
  if (parsed.port && parsed.port !== "443") {
    throw new PluginHostRpcError(
      "network_url_invalid",
      "network endpoint URL must not use a non-default port",
    );
  }
  const rawHost = rawEndpointHost(url);
  if (!rawHost || rawHost !== parsed.hostname) {
    throw new PluginHostRpcError(
      "network_url_invalid",
      "network endpoint URL host must already be canonical",
    );
  }
  if (parsed.username || parsed.password) {
    throw new PluginHostRpcError(
      "network_url_invalid",
      "network endpoint URL must not include userinfo",
    );
  }
  if (parsed.hash) {
    throw new PluginHostRpcError(
      "network_url_invalid",
      "network endpoint URL must not include a fragment",
    );
  }
  if (/%2f|%5c|%2e/.test(rawLower) || /(?:^|\/)\.{1,2}(?:\/|$)/.test(url)) {
    throw new PluginHostRpcError("network_url_invalid", "network endpoint URL path is ambiguous");
  }
  if (parsed.toString() !== normalizedEndpointInput(url)) {
    throw new PluginHostRpcError(
      "network_url_invalid",
      "network endpoint URL must already be canonical",
    );
  }
  if (isForbiddenHost(parsed.hostname)) {
    throw new PluginHostRpcError(
      "network_target_forbidden",
      "network endpoint target is not allowed",
    );
  }
  if (appOrigin && parsed.origin === appOrigin) {
    throw new PluginHostRpcError(
      "network_target_forbidden",
      "network endpoint target is not allowed",
    );
  }

  return parsed.toString();
}

function rawEndpointHost(url: string): string | null {
  const match = /^https:\/\/(?:[^@/?#]*@)?(\[[^\]]+\]|[^:/?#]+)(?::\d+)?(?:[/?#]|$)/.exec(url);
  if (!match?.[1]) return null;
  return match[1].replace(/^\[|\]$/g, "");
}

function normalizedEndpointInput(url: string): string {
  if (/^https:\/\/[^/?#]+$/.test(url)) return `${url}/`;
  return url;
}

function isForbiddenHost(hostname: string): boolean {
  const host = hostname
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.+$/g, "");
  if (FORBIDDEN_METADATA_HOSTS.has(host)) return true;
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) return true;
  if (host.includes(":")) return true;
  if (
    host === "::1" ||
    host.startsWith("fe80:") ||
    host.startsWith("fc") ||
    host.startsWith("fd")
  ) {
    return true;
  }

  const octets = host.split(".").map((part) => Number(part));
  if (
    octets.length !== 4 ||
    octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
  ) {
    return false;
  }

  return true;
}

function responseHeaders(
  headers: PluginNetworkExecutorResponse["headers"],
): Record<string, string> {
  if (!headers) return {};
  const entries =
    headers instanceof Headers
      ? Array.from(headers.entries())
      : Array.isArray(headers)
        ? headers
        : Object.entries(headers);
  const result: Record<string, string> = {};
  for (const [name, value] of entries) {
    const normalizedName = name.toLowerCase();
    if (normalizedName === "set-cookie" || normalizedName === "set-cookie2") continue;
    result[normalizedName] = value;
  }
  return result;
}

function normalizedMaxRequestBytes(endpoint: PluginNetworkEndpointPolicy): number {
  return normalizeByteLimit(endpoint.maxRequestBytes, MAX_DEFAULT_REQUEST_BYTES);
}

function normalizedMaxResponseBytes(endpoint: PluginNetworkEndpointPolicy): number {
  return normalizeByteLimit(endpoint.maxResponseBytes, MAX_DEFAULT_RESPONSE_BYTES);
}

function normalizeByteLimit(value: number, fallback: number): number {
  if (!Number.isSafeInteger(value) || value <= 0) return fallback;
  return value;
}

function requiredPayloadString(value: unknown, field: string): string {
  if (typeof value === "string" && value.trim() !== "") return value;
  throw new PluginHostRpcError(`${field}_invalid`, `${field} must be a non-empty string`);
}

function optionalPayloadString(value: unknown, field: string): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value === "string" && value.trim() !== "") return value;
  throw new PluginHostRpcError(`${field}_invalid`, `${field} must be a non-empty string`);
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" ? value : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function byteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "network request failed";
}

function parseJson(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}
