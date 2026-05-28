import { sha256 } from "@noble/hashes/sha2.js";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import {
  canonicalizeStrictBytes,
  canonicalizeStrictValueBytes,
  type StrictJsonValue,
} from "@/shared/lib/crypto/jcs";
import {
  PLUGIN_HOST_RPC_DEFAULT_TIMEOUT_MS,
  PLUGIN_HOST_RPC_PROTOCOL,
  PLUGIN_HOST_RPC_VERSION,
  PluginHostMessageRouter,
  type PluginHostRpcContext,
  type PluginHostRpcSessionValidator,
  type PluginHostRpcSession,
} from "../host-rpc/host-rpc";
import { assertThirdPartyPluginSandboxTarget } from "../execution-policy/execution-policy";
import type {
  PluginAuditActor,
  PluginAuditSink,
  PluginDocumentScope,
  PluginHighRiskConsent,
  PluginPermission,
} from "../capability/capability-enforcement";
import {
  emitPluginSecurityAudit,
  pluginAuditSucceeded,
  validatePluginPermissionGrant,
} from "../capability/capability-enforcement";

export const PLUGIN_SANDBOX_ATTRIBUTE = "allow-scripts";

const PLUGIN_RUNTIME_CSP_DIRECTIVES = {
  defaultSrc: "default-src 'none'",
  sandbox: "sandbox allow-scripts",
  styleSrc: "style-src 'unsafe-inline'",
  imgSrc: "img-src blob: data:",
  fontSrc: "font-src blob: data:",
  connectSrc: "connect-src 'none'",
  mediaSrc: "media-src blob: data:",
  frameSrc: "frame-src 'none'",
  childSrc: "child-src 'none'",
  workerSrc: "worker-src 'none'",
  objectSrc: "object-src 'none'",
  baseUri: "base-uri 'none'",
  formAction: "form-action 'none'",
  manifestSrc: "manifest-src 'none'",
  frameAncestors: "frame-ancestors 'self'",
} as const;

const PLUGIN_RUNTIME_CSP_ALLOWED_DIRECTIVE_NAMES = new Set([
  "script-src",
  ...Object.values(PLUGIN_RUNTIME_CSP_DIRECTIVES).map((directive) => directive.split(/\s+/, 1)[0]),
]);
const FORBIDDEN_HOST_API_TOKENS = [
  "getApp",
  "workspaceManager",
  "WorkspaceLeaf",
  "renderPluginContent",
  "renderTrustedBuiltinContent",
  "TrustedHostWorkspace",
  "registerDomEvent",
  "registerView",
  "registerEditorExtension",
  "addSidebarPanel",
  "addStatusBarItem",
] as const;

export interface PluginRuntimeCspOptions {
  scriptSha256Hashes: readonly [string, ...string[]];
  wasmCapable?: boolean;
}

export interface PluginSandboxBundleInput {
  mainJsBytes: Uint8Array;
  manifestJsonBytes: Uint8Array;
  stylesCssBytes?: Uint8Array;
  bundleHash: string;
  mainJsHash: string;
  manifestHash: string;
  stylesCssHash: string;
  resourceManifestHash: string;
  resourceManifest?: readonly PluginSandboxResourceManifestEntry[];
  resources?: readonly PluginSandboxResourceInput[];
}

export interface PluginSandboxBundleArtifact {
  mainScript: string;
  stylesCss: string;
  bundleHash: string;
  mainJsHash: string;
  manifestHash: string;
  stylesCssHash: string;
  resourceManifestHash: string;
  resourceManifest: readonly PluginSandboxResourceManifestEntry[];
  resources: readonly PluginSandboxResourceArtifact[];
  scriptSha256Hash: string;
}

export interface PluginSandboxResourceManifestEntry {
  path: string;
  kind: string;
  media_type: string;
  byte_length: number;
  hash: string;
  executable: boolean;
}

export interface PluginSandboxResourceInput {
  path: string;
  kind: string;
  mediaType: string;
  byteLength: number;
  hash: string;
  bytes: Uint8Array;
}

export interface PluginSandboxResourceArtifact extends PluginSandboxResourceInput {
  bytes: Uint8Array;
}

export interface CreatePluginSandboxIframeOptions {
  ownerDocument: Document;
  src: string;
  title?: string;
  className?: string;
}

export interface CreatePluginSandboxRuntimeOptions extends Omit<
  CreatePluginSandboxIframeOptions,
  "ownerDocument" | "src"
> {
  container: HTMLElement;
  router: PluginHostMessageRouter;
  validateSession: PluginHostRpcSessionValidator;
  pluginId: string;
  packageId: string;
  applicationId: string;
  activationId: string;
  ownerScopeKind: string;
  workspaceId: string;
  userId: string;
  deviceId: string;
  stateHeadHash?: string;
  consentHeadHash?: string;
  bundleHash: string;
  manifestHash: string;
  capabilityId: string;
  capabilityGrantId: string;
  consentEpoch: number;
  permissions?: readonly PluginPermission[];
  documentScope?: PluginDocumentScope;
  documentScopeProvider?: () => PluginDocumentScope | undefined;
  highRiskConsents?: readonly PluginHighRiskConsent[];
  auditSink?: PluginAuditSink;
  frameGeneration: number;
  frameScope?: "primary" | "secondary";
  bootNonce: string;
  sandboxDocumentUrl: string;
  bundle?: PluginSandboxBundleArtifact;
  additionalScriptSha256Hashes?: readonly string[];
  rootElementId?: string;
  startupSignal?: AbortSignal;
  beforeSandboxDocumentLoad?(session: PluginHostRpcSession): void | ((reason?: string) => void);
}

export interface PluginSandboxRuntime {
  iframe: HTMLIFrameElement;
  session: PluginHostRpcSession;
  destroy(reason?: string): void;
}

export class PluginSandboxRuntimeError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "PluginSandboxRuntimeError";
    this.code = code;
  }
}

export async function createPluginSandboxRuntime(
  options: CreatePluginSandboxRuntimeOptions,
): Promise<PluginSandboxRuntime> {
  assertThirdPartyPluginSandboxTarget("sandbox_iframe");
  assertRuntimeCapabilityIdentity(options);
  assertStartupNotAborted(options.startupSignal);

  const { bootNonce, frameGeneration, sandboxDocumentUrl } =
    assertSandboxDocumentSessionMetadata(options);
  const iframe = options.container.ownerDocument.createElement("iframe");
  iframe.setAttribute("sandbox", PLUGIN_SANDBOX_ATTRIBUTE);
  iframe.setAttribute("referrerpolicy", "no-referrer");
  if (options.title) {
    iframe.title = options.title;
  }
  if (options.className) {
    iframe.className = options.className;
  }

  const permissionGrantError = validatePluginPermissionGrant(options.permissions ?? []);
  if (permissionGrantError) {
    const context = runtimePreSessionAuditContext(options, frameGeneration, bootNonce);
    const auditOk = await pluginAuditSucceeded(
      emitPluginSecurityAudit(options.auditSink, context, {
        type: "plugin.capability.denied",
        operation: "plugin.capability.deny",
        result: "deny",
        actionResult: "denied",
        reasonCode: permissionGrantError.code,
        payloadKind: "unknown",
      }),
    );
    if (!auditOk) {
      iframe.remove();
      throw new PluginSandboxRuntimeError(
        "capability_audit_unavailable",
        "plugin capability denial audit event could not be recorded",
      );
    }
    iframe.remove();
    throw new PluginSandboxRuntimeError(permissionGrantError.code, permissionGrantError.message);
  }

  try {
    options.container.append(iframe);
  } catch (error) {
    iframe.remove();
    throw error;
  }

  let session: PluginHostRpcSession;
  let unregisterStartupAbort: (() => void) | undefined;
  try {
    session = options.router.createSession({
      pluginId: options.pluginId,
      packageId: options.packageId,
      applicationId: options.applicationId,
      activationId: options.activationId,
      ownerScopeKind: options.ownerScopeKind,
      workspaceId: options.workspaceId,
      userId: options.userId,
      deviceId: options.deviceId,
      stateHeadHash: options.stateHeadHash,
      consentHeadHash: options.consentHeadHash,
      bundleHash: options.bundleHash,
      manifestHash: options.manifestHash,
      capabilityId: options.capabilityId,
      capabilityGrantId: options.capabilityGrantId,
      consentEpoch: options.consentEpoch,
      permissions: options.permissions,
      documentScope: options.documentScope,
      documentScopeProvider: options.documentScopeProvider,
      highRiskConsents: options.highRiskConsents,
      auditActor: runtimeAuditActor(options, null),
      auditSink: options.auditSink,
      frameGeneration,
      frameScope: options.frameScope,
      bootNonce,
      validateSession: options.validateSession,
      contentWindow: iframe.contentWindow,
      frameElement: iframe,
      expectsInitialFrameLoad: true,
    });
    unregisterStartupAbort = registerStartupAbort(options.startupSignal, session);
  } catch (error) {
    iframe.remove();
    throw error;
  }

  let capabilityIssued = false;
  let capabilityRevoked = false;
  let destroyed = false;
  let unregisterBeforeLoad: (() => void) | undefined;
  let unregisterSandboxLoadedAudit: (() => void) | undefined;
  const auditCapabilityRevoked = (reason: string) => {
    if (!capabilityIssued || capabilityRevoked) return;
    capabilityRevoked = true;
    if (isAuthorityRevocationTeardownReason(reason)) return;
    if (reason === "frame_navigation") {
      void pluginAuditSucceeded(
        emitPluginSecurityAudit(options.auditSink, session.securityAuditContext(), {
          type: "plugin.runtime.navigation_suspected",
          operation: "plugin.runtime.navigation.detect",
          result: "allow",
          actionResult: "completed",
          reasonCode: reason,
          payloadKind: "unknown",
        }),
      );
    }
    void pluginAuditSucceeded(
      emitPluginSecurityAudit(options.auditSink, session.securityAuditContext(), {
        type: "plugin.capability.revoked",
        operation: "plugin.capability.revoke",
        result: "allow",
        actionResult: "completed",
        reasonCode: reason,
        payloadKind: "unknown",
      }),
    );
  };
  const unregisterCapabilityRevocationAudit = session.onClose(auditCapabilityRevoked);
  unregisterSandboxLoadedAudit = session.onBootAuthenticated(() => {
    void pluginAuditSucceeded(
      emitPluginSecurityAudit(options.auditSink, session.securityAuditContext(), {
        type: "plugin.sandbox.loaded",
        operation: "plugin.sandbox.load",
        result: "allow",
        actionResult: "completed",
        payloadKind: "unknown",
      }),
    ).then((auditOk) => {
      if (!auditOk && !session.closed) {
        session.close("sandbox_audit_unavailable");
      }
    });
  });

  try {
    assertStartupSessionOpen(session, options.startupSignal);
    const capabilityAuditOk = await pluginAuditSucceeded(
      emitPluginSecurityAudit(options.auditSink, session.securityAuditContext(), {
        type: "plugin.capability.issued",
        operation: "plugin.capability.issue",
        result: "allow",
        actionResult: "completed",
        payloadKind: "unknown",
      }),
    );
    if (!capabilityAuditOk) {
      assertStartupSessionOpen(session, options.startupSignal);
      throw new PluginSandboxRuntimeError(
        "capability_audit_unavailable",
        "plugin capability issuance audit event could not be recorded",
      );
    }
    assertStartupSessionOpen(session, options.startupSignal);
    capabilityIssued = true;

    const bundleImportAuditOk = await pluginAuditSucceeded(
      emitPluginSecurityAudit(options.auditSink, session.securityAuditContext(), {
        type: "plugin.bundle.imported",
        operation: "plugin.bundle.import",
        result: "allow",
        actionResult: "completed",
        payloadKind: "unknown",
      }),
    );
    if (!bundleImportAuditOk) {
      assertStartupSessionOpen(session, options.startupSignal);
      throw new PluginSandboxRuntimeError(
        "bundle_import_audit_unavailable",
        "plugin bundle import audit event could not be recorded",
      );
    }
    assertStartupSessionOpen(session, options.startupSignal);

    unregisterBeforeLoad = options.beforeSandboxDocumentLoad?.(session) ?? undefined;
    assertStartupSessionOpen(session, options.startupSignal);
    await loadSandboxDocumentFrame(iframe, sandboxDocumentUrl);
    assertStartupSessionOpen(session, options.startupSignal);
    assertPluginSandboxIframe(iframe);
    assertStartupSessionOpen(session, options.startupSignal);
  } catch (error) {
    unregisterBeforeLoad?.();
    unregisterBeforeLoad = undefined;
    unregisterSandboxLoadedAudit?.();
    unregisterSandboxLoadedAudit = undefined;
    unregisterStartupAbort?.();
    unregisterStartupAbort = undefined;
    session.close("sandbox_append_failed");
    unregisterCapabilityRevocationAudit();
    iframe.remove();
    throw error;
  }
  unregisterStartupAbort?.();
  unregisterStartupAbort = undefined;

  return {
    iframe,
    session,
    destroy(reason = "sandbox_destroyed") {
      if (destroyed) return;
      destroyed = true;
      if (!isAuthorityRevocationTeardownReason(reason)) {
        void pluginAuditSucceeded(
          emitPluginSecurityAudit(options.auditSink, session.securityAuditContext(), {
            type: "plugin.sandbox.destroyed",
            operation: "plugin.sandbox.destroy",
            result: "allow",
            actionResult: "completed",
            reasonCode: reason,
            payloadKind: "unknown",
          }),
        );
      }
      unregisterSandboxLoadedAudit?.();
      unregisterSandboxLoadedAudit = undefined;
      session.close(reason);
      unregisterCapabilityRevocationAudit();
      iframe.remove();
    },
  };
}

function isAuthorityRevocationTeardownReason(reason: string): boolean {
  return (
    reason === "workspace_deleted" ||
    reason === "workspace_left" ||
    reason === "workspace_changed" ||
    reason === "workspace_cleanup" ||
    reason === "session_cleanup" ||
    reason === "plugin_application_deleted" ||
    reason === "plugin_application_disabled" ||
    reason === "plugin_application_policy_denied" ||
    reason === "plugin_activation_deleted" ||
    reason === "plugin_activation_disabled" ||
    reason === "plugin_consent_revoked" ||
    reason === "plugin_bundle_updated" ||
    reason === "plugin_runtime_uninstalled" ||
    reason === "plugin_runtime_activation_deleted"
  );
}

function registerStartupAbort(
  signal: AbortSignal | undefined,
  session: PluginHostRpcSession,
): (() => void) | undefined {
  if (!signal) return undefined;
  if (signal.aborted) {
    session.close("runtime_startup_superseded");
    return undefined;
  }
  const abort = () => {
    session.close("runtime_startup_superseded");
  };
  signal.addEventListener("abort", abort, { once: true });
  return () => signal.removeEventListener("abort", abort);
}

function assertStartupNotAborted(signal: AbortSignal | undefined): void {
  if (!signal?.aborted) return;
  throw new PluginSandboxRuntimeError(
    "runtime_startup_superseded",
    "plugin runtime startup was superseded before sandbox boot completed",
  );
}

function assertStartupSessionOpen(
  session: PluginHostRpcSession,
  signal: AbortSignal | undefined,
): void {
  assertStartupNotAborted(signal);
  if (!session.closed) return;
  throw new PluginSandboxRuntimeError(
    "runtime_startup_superseded",
    "plugin runtime startup was superseded before sandbox boot completed",
  );
}

function loadSandboxDocumentFrame(iframe: HTMLIFrameElement, src: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      iframe.removeEventListener("load", onLoad);
      iframe.removeEventListener("error", onError);
    };
    const onLoad = () => {
      cleanup();
      resolve();
    };
    const onError = () => {
      cleanup();
      reject(
        new PluginSandboxRuntimeError(
          "sandbox_document_load_failed",
          "plugin sandbox document route could not be loaded",
        ),
      );
    };

    iframe.addEventListener("load", onLoad);
    iframe.addEventListener("error", onError);
    iframe.setAttribute("src", src);
  });
}

function runtimePreSessionAuditContext(
  options: CreatePluginSandboxRuntimeOptions,
  frameGeneration: number,
  bootNonce: string,
): PluginHostRpcContext {
  const sessionId = `plugin-sandbox:${bootNonce}`;
  return {
    pluginId: options.pluginId,
    packageId: options.packageId,
    applicationId: options.applicationId,
    activationId: options.activationId,
    ownerScopeKind: options.ownerScopeKind,
    workspaceId: options.workspaceId,
    userId: options.userId,
    deviceId: options.deviceId,
    stateHeadHash: options.stateHeadHash,
    consentHeadHash: options.consentHeadHash,
    bundleHash: options.bundleHash,
    manifestHash: options.manifestHash,
    capabilityId: options.capabilityId,
    capabilityGrantId: options.capabilityGrantId,
    consentEpoch: options.consentEpoch,
    frameGeneration,
    frameScope: options.frameScope,
    sessionId,
    auditActor: runtimeAuditActor(options, sessionId),
    auditSink: options.auditSink ?? null,
  };
}

function assertRuntimeCapabilityIdentity(options: CreatePluginSandboxRuntimeOptions): void {
  if (!options.capabilityId || !options.capabilityGrantId) {
    throw new PluginSandboxRuntimeError(
      "plugin_runtime_capability_grant_required",
      "plugin runtime requires a host-issued capability grant",
    );
  }
}

function assertSandboxDocumentSessionMetadata(
  options: Pick<
    CreatePluginSandboxRuntimeOptions,
    "bootNonce" | "frameGeneration" | "sandboxDocumentUrl"
  >,
): { bootNonce: string; frameGeneration: number; sandboxDocumentUrl: string } {
  if (!options.bootNonce || options.frameGeneration === undefined || !options.sandboxDocumentUrl) {
    throw new PluginSandboxRuntimeError(
      "plugin_runtime_sandbox_document_session_required",
      "plugin runtime requires a host-issued sandbox document session",
    );
  }

  return {
    bootNonce: assertOpaqueToken(options.bootNonce, "boot_nonce"),
    frameGeneration: assertPositiveInteger(options.frameGeneration, "frame_generation"),
    sandboxDocumentUrl: assertSandboxDocumentUrl(options.sandboxDocumentUrl),
  };
}

function runtimeAuditActor(
  options: Pick<CreatePluginSandboxRuntimeOptions, "userId" | "deviceId">,
  sessionId: string | null,
): PluginAuditActor {
  return {
    user_id: options.userId,
    device_id: options.deviceId,
    session_id: sessionId,
    principal_kind: "user",
    principal_id: options.userId,
  };
}

export function createPluginSandboxIframe(
  options: CreatePluginSandboxIframeOptions,
): HTMLIFrameElement {
  if (!options.src) {
    throw new PluginSandboxRuntimeError(
      "plugin_runtime_sandbox_document_session_required",
      "plugin sandbox iframe requires a host-issued sandbox document URL",
    );
  }

  const iframe = options.ownerDocument.createElement("iframe");
  iframe.setAttribute("sandbox", PLUGIN_SANDBOX_ATTRIBUTE);
  iframe.setAttribute("referrerpolicy", "no-referrer");
  iframe.setAttribute("src", assertSandboxDocumentUrl(options.src));

  if (options.title) {
    iframe.title = options.title;
  }

  if (options.className) {
    iframe.className = options.className;
  }

  assertPluginSandboxIframe(iframe);
  return iframe;
}

export function assertPluginSandboxIframe(iframe: HTMLIFrameElement): void {
  const sandbox = iframe.getAttribute("sandbox");
  if (sandboxTokens(sandbox).includes("allow-same-origin")) {
    throw new PluginSandboxRuntimeError(
      "allow_same_origin_forbidden",
      "plugin iframe must not use allow-same-origin",
    );
  }

  if (sandbox !== PLUGIN_SANDBOX_ATTRIBUTE) {
    throw new PluginSandboxRuntimeError(
      "invalid_sandbox_attribute",
      'plugin iframe sandbox must be exactly "allow-scripts"',
    );
  }

  if (iframe.hasAttribute("srcdoc")) {
    throw new PluginSandboxRuntimeError(
      "srcdoc_runtime_forbidden",
      "plugin iframe runtime must use sandbox document route src, not srcdoc",
    );
  }

  if (!iframe.hasAttribute("src")) {
    throw new PluginSandboxRuntimeError(
      "missing_sandbox_document_runtime",
      "plugin iframe runtime must be backed by sandbox document route src",
    );
  }
  assertSandboxDocumentUrl(iframe.getAttribute("src") ?? "");

  if (iframe.getAttribute("referrerpolicy") !== "no-referrer") {
    throw new PluginSandboxRuntimeError(
      "invalid_referrer_policy",
      'plugin iframe referrerpolicy must be "no-referrer"',
    );
  }
}

function sandboxTokens(value: string | null): string[] {
  return value?.split(/\s+/).filter(Boolean) ?? [];
}

export function createPluginSandboxBundleArtifact(
  input: PluginSandboxBundleInput,
): PluginSandboxBundleArtifact {
  assertBlake3Hash(input.mainJsHash, "main_js_hash");
  assertBlake3Hash(input.manifestHash, "manifest_hash");
  assertBlake3Hash(input.stylesCssHash, "styles_css_hash");
  assertBlake3Hash(input.resourceManifestHash, "resource_manifest_hash");
  assertBlake3Hash(input.bundleHash, "bundle_hash");

  const stylesCssBytes = input.stylesCssBytes ?? new Uint8Array();
  const resourceManifest = assertResourceManifest(input.resourceManifest ?? []);
  const resources = assertResources(input.resources ?? [], resourceManifest);
  assertByteHash(input.mainJsBytes, input.mainJsHash, "main_js_hash");
  assertByteHash(input.manifestJsonBytes, input.manifestHash, "manifest_hash");
  assertByteHash(stylesCssBytes, input.stylesCssHash, "styles_css_hash");
  assertResourceManifestHash(resourceManifest, input.resourceManifestHash);
  assertBundleHash(
    input.manifestHash,
    input.mainJsHash,
    input.stylesCssHash,
    input.resourceManifestHash,
    input.bundleHash,
  );

  const mainScript = decodePluginSource(input.mainJsBytes, "main.js");
  const stylesCss = decodePluginSource(stylesCssBytes, "styles.css");
  assertSafeInlineScript(mainScript);
  assertSafeInlineStyle(stylesCss);
  assertSingleBundleScript(mainScript);

  return Object.freeze({
    mainScript,
    stylesCss,
    bundleHash: input.bundleHash,
    mainJsHash: input.mainJsHash,
    manifestHash: input.manifestHash,
    stylesCssHash: input.stylesCssHash,
    resourceManifestHash: input.resourceManifestHash,
    resourceManifest,
    resources,
    scriptSha256Hash: scriptSha256(mainScript),
  });
}

export function buildPluginRuntimeCsp(options: PluginRuntimeCspOptions): string {
  const scriptSrc = [
    "script-src",
    ...options.scriptSha256Hashes.map((hash) => `'sha256-${assertCspHash(hash)}'`),
    ...(options.wasmCapable === true ? ["'wasm-unsafe-eval'"] : []),
  ].join(" ");

  const csp = [
    PLUGIN_RUNTIME_CSP_DIRECTIVES.defaultSrc,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.sandbox,
    scriptSrc,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.styleSrc,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.imgSrc,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.fontSrc,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.connectSrc,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.mediaSrc,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.frameSrc,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.childSrc,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.workerSrc,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.objectSrc,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.baseUri,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.formAction,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.manifestSrc,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.frameAncestors,
  ].join("; ");

  assertPluginRuntimeCsp(csp);
  return csp;
}

export function assertPluginRuntimeCsp(csp: string): void {
  const directives = parseCspDirectives(csp);
  const requiredExactDirectives = [
    PLUGIN_RUNTIME_CSP_DIRECTIVES.defaultSrc,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.sandbox,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.styleSrc,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.imgSrc,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.fontSrc,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.connectSrc,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.mediaSrc,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.frameSrc,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.childSrc,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.workerSrc,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.objectSrc,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.baseUri,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.formAction,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.manifestSrc,
    PLUGIN_RUNTIME_CSP_DIRECTIVES.frameAncestors,
  ];

  for (const requiredDirective of requiredExactDirectives) {
    const [name] = requiredDirective.split(/\s+/, 1);
    if (directives.get(name) !== requiredDirective) {
      throw new PluginSandboxRuntimeError(
        "invalid_runtime_csp",
        `plugin runtime CSP must include ${requiredDirective}`,
      );
    }
  }

  for (const name of directives.keys()) {
    if (!PLUGIN_RUNTIME_CSP_ALLOWED_DIRECTIVE_NAMES.has(name)) {
      throw new PluginSandboxRuntimeError(
        "invalid_runtime_csp",
        `plugin runtime CSP must not include ${name} directive`,
      );
    }
  }

  for (const [name, directive] of directives) {
    if (name !== "frame-ancestors" && directive.includes("'self'")) {
      throw new PluginSandboxRuntimeError(
        "runtime_csp_self_forbidden",
        "plugin runtime CSP must not allow self for runtime resource directives",
      );
    }
  }

  const scriptSrc = directives.get("script-src");
  if (!scriptSrc) {
    throw new PluginSandboxRuntimeError(
      "missing_script_src",
      "plugin runtime CSP must define script-src",
    );
  }

  const scriptTokens = scriptSrc.split(/\s+/).slice(1);
  const scriptHashTokens = scriptTokens.filter((token) =>
    /^'sha256-(?:[A-Za-z0-9+/]{43}=|[A-Za-z0-9_-]{43})'$/.test(token),
  );

  if (scriptHashTokens.length === 0) {
    throw new PluginSandboxRuntimeError(
      "missing_script_hash",
      "plugin runtime CSP script-src must contain at least one SHA-256 hash",
    );
  }

  for (const token of scriptTokens) {
    if (
      token !== "'wasm-unsafe-eval'" &&
      !/^'sha256-(?:[A-Za-z0-9+/]{43}=|[A-Za-z0-9_-]{43})'$/.test(token)
    ) {
      throw new PluginSandboxRuntimeError(
        "non_hash_script_src_forbidden",
        "plugin runtime CSP script-src must contain only SHA-256 hashes and wasm-unsafe-eval",
      );
    }
  }
}

export interface PluginBootScriptOptions {
  bootNonce: string;
  frameGeneration: number;
  resources?: readonly PluginSandboxResourceArtifact[];
  capabilityGrantId?: string;
  consentEpoch?: number;
  applicationId?: string;
  bundleHash?: string;
  manifestHash?: string;
  resourceManifestHash?: string;
  browserTarget?: string;
  wasmCapable?: boolean;
}

export function buildPluginBootScript(options: PluginBootScriptOptions): string {
  const safeBootNonce = assertOpaqueToken(options.bootNonce, "boot_nonce");
  const frameGeneration = assertNonNegativeInteger(options.frameGeneration, "frame_generation");
  const resourceContext = resourceApiContext(options);
  const wasmCapable = options.wasmCapable === true;
  const resourceRecords = (options.resources ?? []).map((resource) => ({
    path: resource.path,
    kind: resource.kind,
    mediaType: resource.mediaType,
    byteLength: resource.byteLength,
    hash: resource.hash,
    executable: resource.kind === "wasm",
    bytes: base64(resource.bytes),
  }));

  return [
    "(() => {",
    '"use strict";',
    `const protocol = ${JSON.stringify(PLUGIN_HOST_RPC_PROTOCOL)};`,
    `const version = ${PLUGIN_HOST_RPC_VERSION};`,
    `const bootNonce = ${JSON.stringify(safeBootNonce)};`,
    `const frameGeneration = ${frameGeneration};`,
    `const resourceContext = ${JSON.stringify(resourceContext)};`,
    `const resourceRecords = ${JSON.stringify(resourceRecords)};`,
    `const wasmCapable = ${JSON.stringify(wasmCapable)};`,
    "const NativeWebAssembly = globalThis.WebAssembly;",
    "const objectUrls = new Set();",
    "const resourceMap = new Map(resourceRecords.map((entry) => [entry.path, Object.freeze(entry)]));",
    "let resourceApiActive = false;",
    "function resourceBytes(entry) {",
    "const binary = atob(entry.bytes);",
    "const bytes = new Uint8Array(binary.length);",
    "for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);",
    "return bytes;",
    "}",
    ...resourceHashScriptLines(),
    "function assertResourceApiActive() {",
    "if (!resourceApiActive || !hostPort || connectedFrameGeneration !== frameGeneration) throw new Error('plugin_resource_context_stale');",
    "if (resourceMap.size > 0 && (!resourceContext.capabilityGrantId || !resourceContext.applicationId || !resourceContext.bundleHash || !resourceContext.manifestHash || !resourceContext.resourceManifestHash)) throw new Error('plugin_resource_context_stale');",
    "if (wasmCapable && !resourceContext.browserTarget) throw new Error('plugin_resource_context_stale');",
    "}",
    "function resourceEntry(path, requestedKind) {",
    "assertResourceApiActive();",
    "if (typeof path !== 'string' || !resourceMap.has(path)) throw new Error('plugin_resource_not_found');",
    "const entry = resourceMap.get(path);",
    "if (requestedKind && entry.kind !== requestedKind) throw new Error(requestedKind === 'wasm' ? 'plugin_wasm_resource_required' : 'plugin_resource_kind_mismatch');",
    "if (!entry.hash || !Number.isInteger(entry.byteLength) || entry.byteLength < 0) throw new Error('plugin_resource_manifest_invalid');",
    "const bytes = resourceBytes(entry);",
    "if (bytes.byteLength !== entry.byteLength) throw new Error('plugin_resource_integrity_invalid');",
    "if (blake3Base64Url(bytes) !== entry.hash) throw new Error('plugin_resource_integrity_invalid');",
    "return { entry, bytes };",
    "}",
    "function deactivateResources() {",
    "resourceApiActive = false;",
    "for (const url of objectUrls) URL.revokeObjectURL(url);",
    "objectUrls.clear();",
    "resourceMap.clear();",
    "}",
    "const resources = Object.freeze({",
    "async read(path, expectedKind) {",
    "const checked = resourceEntry(path, expectedKind);",
    "return checked.bytes.slice();",
    "},",
    "async objectUrl(path) {",
    "const { entry, bytes } = resourceEntry(path);",
    "if (entry.kind === 'wasm') throw new Error('plugin_resource_object_url_forbidden');",
    "const url = URL.createObjectURL(new Blob([bytes], { type: entry.mediaType }));",
    "objectUrls.add(url);",
    "return url;",
    "},",
    "async revokeObjectUrl(url) {",
    "if (objectUrls.has(url)) { URL.revokeObjectURL(url); objectUrls.delete(url); }",
    "},",
    ...wasmResourceScriptLines(wasmCapable),
    "});",
    "try { Object.defineProperty(globalThis, 'WebAssembly', { value: undefined, configurable: false, enumerable: false, writable: false }); } catch (_) { }",
    "let hostPort = null;",
    "let connectedFrameGeneration = null;",
    "let rpcContext = null;",
    "let bootReadyTimer = null;",
    "const pendingPortListeners = [];",
    "const loadListeners = new Set();",
    "const unloadListeners = new Set();",
    "let lifecycleLoaded = false;",
    "let lifecycleUnloaded = false;",
    "let nextRequestSequence = 0;",
    "const pendingRequests = new Map();",
    "function rejectPendingRequests(code, message) {",
    "for (const [requestId, pending] of pendingRequests) { pendingRequests.delete(requestId); clearTimeout(pending.timeoutId); const error = new Error(message || 'plugin_rpc_error'); error.code = code; pending.reject(error); }",
    "}",
    "function assertRpcActive() { if (!hostPort || connectedFrameGeneration !== frameGeneration) throw new Error('plugin_host_port_not_connected'); if (!rpcContext || !rpcContext.plugin_id || !rpcContext.package_id || !rpcContext.application_id || !rpcContext.activation_id || !rpcContext.owner_scope_kind || !rpcContext.workspace_id || !rpcContext.user_id || !rpcContext.device_id || !rpcContext.bundle_hash || !rpcContext.manifest_hash || !rpcContext.capability_id || !rpcContext.capability_grant_id || !Number.isInteger(rpcContext.consent_epoch)) throw new Error('plugin_rpc_context_unavailable'); }",
    "function request(operation, payload, options) {",
    "assertRpcActive();",
    "if (typeof operation !== 'string' || operation.trim() === '') throw new Error('plugin_rpc_operation_invalid');",
    "const requestId = 'plugin-request-' + Date.now().toString(36) + '-' + (++nextRequestSequence).toString(36);",
    "const envelope = Object.assign({}, rpcContext, { protocol, version, kind: 'request', request_id: requestId, request_nonce: requestId + '-nonce', frame_generation: frameGeneration, operation, payload });",
    "if (options && Object.prototype.hasOwnProperty.call(options, 'resource')) envelope.resource = options.resource;",
    "if (options && typeof options.executionContextId === 'string') envelope.execution_context_id = options.executionContextId;",
    `return new Promise((resolve, reject) => { const timeoutId = setTimeout(() => { pendingRequests.delete(requestId); reject(new Error('plugin_rpc_timeout')); }, ${PLUGIN_HOST_RPC_DEFAULT_TIMEOUT_MS}); pendingRequests.set(requestId, { resolve, reject, timeoutId }); try { hostPort.postMessage(envelope); } catch (error) { pendingRequests.delete(requestId); clearTimeout(timeoutId); reject(error); } });`,
    "}",
    "const runtime = Object.freeze({",
    "get connected() { return hostPort !== null; },",
    "get context() { return rpcContext; },",
    "postMessage(message) { if (!hostPort) throw new Error('plugin_host_port_not_connected'); hostPort.postMessage(message); },",
    "request,",
    "addEventListener(type, listener) { if (hostPort) { hostPort.addEventListener(type, listener); return; } pendingPortListeners.push({ type, listener }); },",
    "removeEventListener(type, listener) { for (let index = pendingPortListeners.length - 1; index >= 0; index -= 1) { const entry = pendingPortListeners[index]; if (entry.type === type && entry.listener === listener) pendingPortListeners.splice(index, 1); } if (hostPort) hostPort.removeEventListener(type, listener); },",
    "});",
    "function fixedRequest(operation) { return (payload, options) => request(operation, payload, options); }",
    "function respond(requestId, payload) { runtime.postMessage({ protocol, version, kind: 'response', request_id: requestId, payload }); }",
    "function onRequest(operation, listener) { if (typeof listener !== 'function') throw new Error('plugin_listener_invalid'); const handler = (event) => { const message = event.data; if (!message || message.protocol !== protocol || message.version !== version || message.kind !== 'request' || message.operation !== operation) return; listener(message); }; runtime.addEventListener('message', handler); return Object.freeze({ dispose() { runtime.removeEventListener('message', handler); } }); }",
    "function requestEvent(message) { const payload = message.payload && typeof message.payload === 'object' ? message.payload : {}; const executionContextId = typeof message.execution_context_id === 'string' ? message.execution_context_id : payload.execution_context_id; return Object.freeze({ operation: message.operation, requestId: message.request_id, executionContextId, resource: message.resource, payload, respond(value) { respond(message.request_id, value); } }); }",
    "function lifecycleHandle(set, listener, code) { if (typeof listener !== 'function') throw new Error(code); set.add(listener); return Object.freeze({ dispose() { set.delete(listener); } }); }",
    "function runLifecycleListener(listener) { Promise.resolve().then(() => listener()).catch(() => undefined); }",
    "function onload(listener) { const handle = lifecycleHandle(loadListeners, listener, 'plugin_onload_listener_invalid'); if (lifecycleLoaded && !lifecycleUnloaded) runLifecycleListener(listener); return handle; }",
    "function onunload(listener) { return lifecycleHandle(unloadListeners, listener, 'plugin_onunload_listener_invalid'); }",
    "function fireLoad() { if (lifecycleLoaded || lifecycleUnloaded) return; lifecycleLoaded = true; for (const listener of Array.from(loadListeners)) runLifecycleListener(listener); }",
    "function fireUnload() { if (lifecycleUnloaded) return; lifecycleUnloaded = true; for (const listener of Array.from(unloadListeners)) runLifecycleListener(listener); loadListeners.clear(); unloadListeners.clear(); }",
    "function registrationHandle(localId, response) { const id = response && typeof response === 'object' && typeof response.id === 'string' ? response.id : undefined; let disposed = false; return Object.freeze({ id, localId, dispose() { if (disposed) return Promise.resolve({ local_id: localId }); disposed = true; return request('ui.contribution.unregister', { local_id: localId }); } }); }",
    "function registerContribution(operation, payload) { return request(operation, payload).then((response) => registrationHandle(payload.local_id, response)); }",
    "const runtimeInfo = Object.freeze({ get connected() { return hostPort !== null; }, get context() { return rpcContext; } });",
    "const documents = Object.freeze({ getActiveDocument: fixedRequest('documents.getActiveDocument'), getSelectedDocuments: fixedRequest('documents.getSelectedDocuments'), queryWorkspaceDocuments: fixedRequest('documents.queryWorkspaceDocuments') });",
    "const editor = Object.freeze({ setValue: fixedRequest('editor.setValue'), replaceSelection: fixedRequest('editor.replaceSelection'), registerContribution: fixedRequest('editor.contribution.register'), getFormatterInput: fixedRequest('formatter.getInput'), getDiagnosticsContext: fixedRequest('diagnostics.getContext'), getDecorationContext: fixedRequest('decoration.getContext'), getSuggestionContext: fixedRequest('suggestion.getContext'), onRequest(listener) { if (typeof listener !== 'function') throw new Error('plugin_listener_invalid'); const handlers = ['editor.command.run', 'formatter.run', 'diagnostics.run', 'decoration.run', 'suggestion.run'].map((operation) => onRequest(operation, (message) => listener(requestEvent(message)))); return Object.freeze({ dispose() { for (const handler of handlers) handler.dispose(); } }); } });",
    "const storage = Object.freeze({ userLocal: Object.freeze({ get: fixedRequest('storage.userLocal.get'), set: fixedRequest('storage.userLocal.set'), delete: fixedRequest('storage.userLocal.delete') }), cache: Object.freeze({ get: fixedRequest('storage.cache.get'), set: fixedRequest('storage.cache.set'), delete: fixedRequest('storage.cache.delete') }), workspace: Object.freeze({ get: fixedRequest('storage.workspace.get'), set: fixedRequest('storage.workspace.set'), delete: fixedRequest('storage.workspace.delete'), recordCreate: fixedRequest('storage.workspace.record.create'), recordGet: fixedRequest('storage.workspace.record.get'), recordDelete: fixedRequest('storage.workspace.record.delete') }), document: Object.freeze({ get: fixedRequest('storage.document.get'), set: fixedRequest('storage.document.set'), delete: fixedRequest('storage.document.delete'), recordCreate: fixedRequest('storage.document.record.create'), recordGet: fixedRequest('storage.document.record.get'), recordDelete: fixedRequest('storage.document.record.delete') }) });",
    "const network = Object.freeze({ fetch: fixedRequest('app.network.fetch') });",
    "const credential = Object.freeze({ use: fixedRequest('credential.use') });",
    "function descriptorObject(descriptor) { return descriptor && typeof descriptor === 'object' ? descriptor : {}; }",
    "function camelOrSnake(input, camel, snake) { return input[camel] !== undefined ? input[camel] : input[snake]; }",
    "function requireStringField(input, camel, snake, code) { const value = camelOrSnake(input, camel, snake); if (typeof value !== 'string' || value.length === 0) throw new Error(code); return value; }",
    "function requireObjectField(input, camel, snake, code) { const value = camelOrSnake(input, camel, snake); if (!value || typeof value !== 'object') throw new Error(code); return value; }",
    "function requireArrayField(input, camel, snake, code) { const value = camelOrSnake(input, camel, snake); if (!Array.isArray(value)) throw new Error(code); return value; }",
    "function assignOptionalString(payload, key, value) { if (typeof value === 'string') payload[key] = value; }",
    "function assignOptionalObject(payload, key, value) { if (value && typeof value === 'object') payload[key] = value; }",
    "function copyBaseContribution(payload, input) { assignOptionalString(payload, 'label', input.label); assignOptionalString(payload, 'icon', input.icon); if (Number.isSafeInteger(input.order)) payload.order = input.order; assignOptionalObject(payload, 'when', input.when); return payload; }",
    "function localId(input, code) { return requireStringField(input, 'localId', 'local_id', code); }",
    "function commandRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); const payload = copyBaseContribution({ surface: 'command', local_id: localId(input, 'plugin_command_local_id_required'), title: requireStringField(input, 'title', 'title', 'plugin_command_title_required') }, input); assignOptionalString(payload, 'category', input.category); assignOptionalObject(payload, 'enablement', input.enablement); assignOptionalString(payload, 'plaintext_request', camelOrSnake(input, 'plaintextRequest', 'plaintext_request')); assignOptionalObject(payload, 'document_query', camelOrSnake(input, 'documentQuery', 'document_query')); return payload; }",
    "function statusItemRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); const value = requireObjectField(input, 'value', 'value', 'plugin_status_value_required'); const payload = copyBaseContribution({ surface: 'status', local_id: localId(input, 'plugin_status_local_id_required'), zone: requireStringField(input, 'zone', 'zone', 'plugin_status_zone_required'), value }, input); assignOptionalString(payload, 'plaintext_request', camelOrSnake(input, 'plaintextRequest', 'plaintext_request')); if (Number.isSafeInteger(input.maxWidth)) payload.max_width = input.maxWidth; else if (Number.isSafeInteger(input.max_width)) payload.max_width = input.max_width; return payload; }",
    "function sidebarPanelRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); const locations = requireArrayField(input, 'allowedLocations', 'allowed_locations', 'plugin_sidebar_panel_locations_required'); const payload = copyBaseContribution({ surface: 'sidebar_panel', local_id: localId(input, 'plugin_sidebar_panel_local_id_required'), panel_id: requireStringField(input, 'panelId', 'panel_id', 'plugin_sidebar_panel_id_required'), title: requireStringField(input, 'title', 'title', 'plugin_sidebar_panel_title_required'), allowed_locations: locations }, input); if (Number.isSafeInteger(input.defaultWidth)) payload.default_width = input.defaultWidth; else if (Number.isSafeInteger(input.default_width)) payload.default_width = input.default_width; return payload; }",
    "function workspaceTileRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); const payload = copyBaseContribution({ surface: 'workspace_tile', local_id: localId(input, 'plugin_workspace_tile_local_id_required'), tile_id: requireStringField(input, 'tileId', 'tile_id', 'plugin_workspace_tile_tile_id_required'), title: requireStringField(input, 'title', 'title', 'plugin_workspace_tile_title_required'), scope: input.scope }, input); if (input.scope !== 'workspace' && input.scope !== 'document') throw new Error('plugin_workspace_tile_scope_required'); assignOptionalString(payload, 'preferred_open', camelOrSnake(input, 'preferredOpen', 'preferred_open')); return payload; }",
    "function workspaceTileActionRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); const payload = copyBaseContribution({ surface: 'workspace_tile_action', local_id: localId(input, 'plugin_workspace_tile_action_local_id_required'), tile_ref: requireObjectField(input, 'tileRef', 'tile_ref', 'plugin_workspace_tile_action_tile_ref_required'), action_id: requireStringField(input, 'actionId', 'action_id', 'plugin_workspace_tile_action_id_required'), title: requireStringField(input, 'title', 'title', 'plugin_workspace_tile_action_title_required'), placement: requireStringField(input, 'placement', 'placement', 'plugin_workspace_tile_action_placement_required') }, input); assignOptionalObject(payload, 'document_query', camelOrSnake(input, 'documentQuery', 'document_query')); return payload; }",
    "function auxiliaryPaneActionPayload(action) { const input = descriptorObject(action); const payload = { action_id: requireStringField(input, 'actionId', 'action_id', 'plugin_auxiliary_pane_action_id_required'), title: requireStringField(input, 'title', 'title', 'plugin_auxiliary_pane_action_title_required'), command_ref: requireObjectField(input, 'commandRef', 'command_ref', 'plugin_auxiliary_pane_action_command_ref_required') }; assignOptionalString(payload, 'icon', input.icon); if (Number.isSafeInteger(input.order)) payload.order = input.order; return payload; }",
    "function auxiliaryPaneRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); const locations = requireArrayField(input, 'allowedLocations', 'allowed_locations', 'plugin_auxiliary_pane_locations_required'); const payload = copyBaseContribution({ surface: 'auxiliary_pane', local_id: localId(input, 'plugin_auxiliary_pane_local_id_required'), pane_id: requireStringField(input, 'paneId', 'pane_id', 'plugin_auxiliary_pane_pane_id_required'), title: requireStringField(input, 'title', 'title', 'plugin_auxiliary_pane_title_required'), allowed_locations: locations }, input); if (Number.isSafeInteger(input.defaultWidth)) payload.default_width = input.defaultWidth; else if (Number.isSafeInteger(input.default_width)) payload.default_width = input.default_width; if (Array.isArray(input.actions)) payload.actions = input.actions.map(auxiliaryPaneActionPayload); return payload; }",
    "function documentTreeActionRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); return copyBaseContribution({ surface: 'document_tree_action', local_id: localId(input, 'plugin_document_tree_action_local_id_required'), placement: requireStringField(input, 'placement', 'placement', 'plugin_document_tree_action_placement_required'), title: requireStringField(input, 'title', 'title', 'plugin_document_tree_action_title_required'), command_ref: requireObjectField(input, 'commandRef', 'command_ref', 'plugin_document_tree_action_command_ref_required') }, input); }",
    "function documentTreeBadgeRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); const payload = copyBaseContribution({ surface: 'document_tree_badge', local_id: localId(input, 'plugin_document_tree_badge_local_id_required'), placement: requireStringField(input, 'placement', 'placement', 'plugin_document_tree_badge_placement_required') }, input); assignOptionalString(payload, 'text', input.text); assignOptionalString(payload, 'plaintext_request', camelOrSnake(input, 'plaintextRequest', 'plaintext_request')); assignOptionalString(payload, 'tone', input.tone); return payload; }",
    "function documentTreeDecorationRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); const payload = copyBaseContribution({ surface: 'document_tree_decoration', local_id: localId(input, 'plugin_document_tree_decoration_local_id_required'), placement: requireStringField(input, 'placement', 'placement', 'plugin_document_tree_decoration_placement_required') }, input); assignOptionalString(payload, 'tone', input.tone); return payload; }",
    "function documentTreeVirtualSectionRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); return copyBaseContribution({ surface: 'document_tree_virtual_section', local_id: localId(input, 'plugin_document_tree_virtual_section_local_id_required'), placement: requireStringField(input, 'placement', 'placement', 'plugin_document_tree_virtual_section_placement_required'), title: requireStringField(input, 'title', 'title', 'plugin_document_tree_virtual_section_title_required'), source_command_ref: requireObjectField(input, 'sourceCommandRef', 'source_command_ref', 'plugin_document_tree_virtual_section_source_command_ref_required') }, input); }",
    "function settingsIframeRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); return copyBaseContribution({ surface: 'settings_iframe', local_id: localId(input, 'plugin_settings_iframe_local_id_required'), settings_id: requireStringField(input, 'settingsId', 'settings_id', 'plugin_settings_iframe_settings_id_required'), title: requireStringField(input, 'title', 'title', 'plugin_settings_iframe_title_required'), placement: requireStringField(input, 'placement', 'placement', 'plugin_settings_iframe_placement_required'), iframe_panel_id: requireStringField(input, 'iframePanelId', 'iframe_panel_id', 'plugin_settings_iframe_panel_id_required') }, input); }",
    "function settingsDeclarativeRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); const sections = input.sections; if (!Array.isArray(sections)) throw new Error('plugin_settings_sections_required'); const payload = copyBaseContribution({ surface: 'settings_declarative', local_id: localId(input, 'plugin_settings_declarative_local_id_required'), settings_id: requireStringField(input, 'settingsId', 'settings_id', 'plugin_settings_declarative_settings_id_required'), title: requireStringField(input, 'title', 'title', 'plugin_settings_declarative_title_required'), placement: requireStringField(input, 'placement', 'placement', 'plugin_settings_declarative_placement_required'), sections }, input); assignOptionalObject(payload, 'submit_command_ref', camelOrSnake(input, 'submitCommandRef', 'submit_command_ref')); return payload; }",
    "function menuItemRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); const payload = copyBaseContribution({ surface: 'menu_item', local_id: localId(input, 'plugin_menu_item_local_id_required'), placement: requireStringField(input, 'placement', 'placement', 'plugin_menu_item_placement_required'), title: requireStringField(input, 'title', 'title', 'plugin_menu_item_title_required'), command_ref: requireObjectField(input, 'commandRef', 'command_ref', 'plugin_menu_item_command_ref_required') }, input); assignOptionalObject(payload, 'enablement', input.enablement); return payload; }",
    "function modalDeclarativeRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); const payload = copyBaseContribution({ surface: 'declarative_modal', local_id: localId(input, 'plugin_modal_local_id_required'), modal_id: requireStringField(input, 'modalId', 'modal_id', 'plugin_modal_id_required'), title: requireStringField(input, 'title', 'title', 'plugin_modal_title_required'), trigger_command_ref: requireObjectField(input, 'triggerCommandRef', 'trigger_command_ref', 'plugin_modal_trigger_command_ref_required'), body: requireObjectField(input, 'body', 'body', 'plugin_modal_body_required') }, input); assignOptionalObject(payload, 'submit_command_ref', camelOrSnake(input, 'submitCommandRef', 'submit_command_ref')); return payload; }",
    "const commands = Object.freeze({ register(descriptor) { return registerContribution('ui.command.register', commandRegistrationPayload(descriptor)); }, onInvoke(listener) { return onRequest('ui.command.invoke', (message) => listener(requestEvent(message))); } });",
    "const ui = Object.freeze({ status: Object.freeze({ registerItem(descriptor) { return registerContribution('ui.status.register_item', statusItemRegistrationPayload(descriptor)); }, updateItem(descriptor) { return request('ui.status.update_item', statusItemRegistrationPayload(descriptor)); }, onRefresh(listener) { return onRequest('ui.status.refresh', (message) => listener(requestEvent(message))); } }), sidebar: Object.freeze({ registerPanel(descriptor) { return registerContribution('ui.sidebar.register_panel', sidebarPanelRegistrationPayload(descriptor)); } }), workspace: Object.freeze({ registerTile(descriptor) { return registerContribution('ui.workspace.register_tile', workspaceTileRegistrationPayload(descriptor)); }, registerTileAction(descriptor) { return registerContribution('ui.workspace.register_tile_action', workspaceTileActionRegistrationPayload(descriptor)); }, onTileRender(listener) { return onRequest('ui.workspace_tile.render', (message) => listener(requestEvent(message))); }, onTileAction(listener) { return onRequest('ui.workspace_tile.action', (message) => listener(requestEvent(message))); } }), auxiliary: Object.freeze({ registerPane(descriptor) { return registerContribution('ui.auxiliary.register_pane', auxiliaryPaneRegistrationPayload(descriptor)); } }), documentTree: Object.freeze({ registerAction(descriptor) { return registerContribution('ui.document_tree.register_action', documentTreeActionRegistrationPayload(descriptor)); }, registerBadge(descriptor) { return registerContribution('ui.document_tree.register_badge', documentTreeBadgeRegistrationPayload(descriptor)); }, onBadgeRefresh(listener) { return onRequest('ui.document_tree.badge.refresh', (message) => listener(requestEvent(message))); }, registerDecoration(descriptor) { return registerContribution('ui.document_tree.register_decoration', documentTreeDecorationRegistrationPayload(descriptor)); }, registerVirtualSection(descriptor) { return registerContribution('ui.document_tree.register_virtual_section', documentTreeVirtualSectionRegistrationPayload(descriptor)); } }), settings: Object.freeze({ registerIframe(descriptor) { return registerContribution('ui.settings.register_iframe', settingsIframeRegistrationPayload(descriptor)); }, registerDeclarative(descriptor) { return registerContribution('ui.settings.register_declarative', settingsDeclarativeRegistrationPayload(descriptor)); } }), menu: Object.freeze({ registerItem(descriptor) { return registerContribution('ui.menu.register_item', menuItemRegistrationPayload(descriptor)); } }), modal: Object.freeze({ registerDeclarative(descriptor) { return registerContribution('ui.modal.register_declarative', modalDeclarativeRegistrationPayload(descriptor)); } }) });",
    "function rendererRequestOptions(context) { const options = {}; if (context && typeof context.executionContextId === 'string') options.executionContextId = context.executionContextId; if (context && Object.prototype.hasOwnProperty.call(context, 'resource')) options.resource = context.resource; return options; }",
    "function rendererResponsePayload(value) { if (value && typeof value === 'object') return value; return { rendered: true }; }",
    "function rendererErrorPayload(error) { return { rendered: false, error: error instanceof Error ? error.message : String(error) }; }",
    "const rendererListeners = new Map();",
    "let rendererDispatchRegistered = false;",
    "function rendererListenerKey(kind, type) { return String(kind) + ':' + String(type); }",
    "function rendererContext(message) { const payload = message.payload && typeof message.payload === 'object' ? message.payload : {}; const executionContextId = typeof payload.execution_context_id === 'string' ? payload.execution_context_id : undefined; return Object.freeze({ executionContextId, kind: payload.kind, type: payload.type, resource: message.resource, requestId: message.request_id, getSource() { return renderer.getSource(this); }, setHeight(height) { return renderer.setHeight(this, height); } }); }",
    "function rendererDispatch(event) { const message = event.data; if (!message || message.protocol !== protocol || message.version !== version || message.kind !== 'request' || message.operation !== 'renderer.render') return; const context = rendererContext(message); const listener = rendererListeners.get(rendererListenerKey(context.kind, context.type)); if (typeof listener !== 'function') { runtime.postMessage({ protocol, version, kind: 'response', request_id: message.request_id, payload: { rendered: false, error: 'renderer_listener_not_registered' } }); return; } Promise.resolve().then(() => listener(context)).then((result) => runtime.postMessage({ protocol, version, kind: 'response', request_id: message.request_id, payload: rendererResponsePayload(result) }), (error) => runtime.postMessage({ protocol, version, kind: 'response', request_id: message.request_id, payload: rendererErrorPayload(error) })); }",
    "function ensureRendererDispatch() { if (rendererDispatchRegistered) return; rendererDispatchRegistered = true; runtime.addEventListener('message', rendererDispatch); }",
    "function registerRendererListener(kind, type, listener) { if (typeof listener !== 'function') throw new Error('renderer_listener_invalid'); const key = rendererListenerKey(kind, type); rendererListeners.set(key, listener); ensureRendererDispatch(); return Object.freeze({ dispose() { if (rendererListeners.get(key) === listener) rendererListeners.delete(key); } }); }",
    "const renderer = Object.freeze({",
    "async getSource(context) { const response = await request('renderer.getSource', {}, rendererRequestOptions(context)); if (!response || typeof response !== 'object') return ''; const source = response.source; return typeof source === 'string' ? source : String(source ?? ''); },",
    "async setHeight(context, height) { if (!Number.isFinite(height) || height < 0) throw new Error('renderer_height_invalid'); return request('renderer.setHeight', { execution_context_id: context && context.executionContextId, height: Math.ceil(height) }, rendererRequestOptions(context)); },",
    "register_block(type, listener) { if (typeof type !== 'string' || type.length === 0) throw new Error('renderer_block_type_required'); return registerRendererListener('block', type, listener); },",
    "register_inline_code(listener) { return registerRendererListener('inline', 'code', listener); },",
    "});",
    "Object.defineProperty(globalThis, 'refmd', { value: Object.freeze({ runtime: runtimeInfo, onload, onunload, resources, renderer, documents, editor, storage, network, credential, commands, ui }), configurable: false, enumerable: false, writable: false });",
    "window.addEventListener('message', (event) => {",
    "const data = event.data;",
    "if (!data || data.protocol !== protocol || data.version !== version || data.kind !== 'boot-port') return;",
    "if (event.source !== window.parent || data.frame_generation !== frameGeneration) return;",
    "event.stopImmediatePropagation();",
    "event.stopPropagation();",
    "const port = event.ports && event.ports[0];",
    "if (!port || (typeof MessagePort !== 'undefined' && !(port instanceof MessagePort))) return;",
    "if (hostPort) return;",
    "stopBootReady();",
    "hostPort = port;",
    "connectedFrameGeneration = data.frame_generation;",
    "hostPort.addEventListener('message', (portEvent) => {",
    "const portData = portEvent.data;",
    "if (!portData || portData.protocol !== protocol || portData.version !== version) return;",
    "if (portData.kind === 'boot-context' && portData.frame_generation === frameGeneration) { rpcContext = portData.runtime_context || null; resourceApiActive = true; fireLoad(); return; }",
    "if ((portData.kind === 'response' || portData.kind === 'error') && pendingRequests.has(portData.request_id)) { const pending = pendingRequests.get(portData.request_id); pendingRequests.delete(portData.request_id); clearTimeout(pending.timeoutId); if (portData.kind === 'response') pending.resolve(portData.payload); else { const error = new Error(portData.error && portData.error.message || 'plugin_rpc_error'); error.code = portData.error && portData.error.code; pending.reject(error); } return; }",
    "if (portData.kind === 'host-lifecycle' && portData.lifecycle === 'close') { fireUnload(); hostPort = null; pendingPortListeners.length = 0; rejectPendingRequests('session_closed', portData.reason || 'plugin session is closed'); deactivateResources(); }",
    "});",
    "for (const entry of pendingPortListeners) hostPort.addEventListener(entry.type, entry.listener);",
    "hostPort.start();",
    "hostPort.postMessage({ protocol, version, kind: 'boot-ack', boot_nonce: bootNonce, frame_generation: frameGeneration });",
    "});",
    "window.addEventListener('pagehide', () => { fireUnload(); deactivateResources(); });",
    "window.addEventListener('unload', () => { fireUnload(); deactivateResources(); });",
    "function sendBootReady() { if (hostPort) { stopBootReady(); return; } window.parent.postMessage({ protocol, version, kind: 'boot-ready' }, '*'); }",
    "function stopBootReady() { if (bootReadyTimer !== null) { clearInterval(bootReadyTimer); bootReadyTimer = null; } }",
    "function startBootReady() { if (bootReadyTimer !== null || hostPort) return; sendBootReady(); bootReadyTimer = setInterval(sendBootReady, 250); }",
    "if (document.readyState === 'loading') window.addEventListener('DOMContentLoaded', startBootReady, { once: true }); else queueMicrotask(startBootReady);",
    "})();",
  ].join("\n");
}

function wasmResourceScriptLines(wasmCapable: boolean): string[] {
  if (!wasmCapable) {
    return ["async instantiateWasm() { throw new Error('plugin_wasm_resource_unavailable'); },"];
  }

  return [
    "async instantiateWasm(path, imports) {",
    "const { bytes } = resourceEntry(path, 'wasm');",
    "if (!NativeWebAssembly || typeof NativeWebAssembly.instantiate !== 'function') throw new Error('plugin_wasm_runtime_unavailable');",
    "const result = await NativeWebAssembly.instantiate(bytes, imports || {});",
    "return result && result.instance ? result.instance : result;",
    "},",
  ];
}

function resourceHashScriptLines(): string[] {
  return [
    "function blake3Base64Url(bytes) {",
    "const IV = [0x6A09E667,0xBB67AE85,0x3C6EF372,0xA54FF53A,0x510E527F,0x9B05688C,0x1F83D9AB,0x5BE0CD19];",
    "const PERM = [2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8];",
    "const CHUNK_START = 1, CHUNK_END = 2, PARENT = 4, ROOT = 8;",
    "function rotr(value, bits) { return (value >>> bits) | (value << (32 - bits)); }",
    "function blockWords(block) {",
    "const words = new Array(16).fill(0);",
    "for (let index = 0; index < block.length; index += 1) words[index >> 2] = (words[index >> 2] | (block[index] << (8 * (index & 3)))) >>> 0;",
    "return words;",
    "}",
    "function compress(cv, block, counter, blockLength, flags) {",
    "const state = [...cv, ...IV.slice(0, 4), counter >>> 0, Math.floor(counter / 0x100000000) >>> 0, blockLength >>> 0, flags >>> 0];",
    "let message = block.slice();",
    "function mix(a, b, c, d, x, y) {",
    "state[a] = (state[a] + state[b] + x) >>> 0; state[d] = rotr((state[d] ^ state[a]) >>> 0, 16) >>> 0;",
    "state[c] = (state[c] + state[d]) >>> 0; state[b] = rotr((state[b] ^ state[c]) >>> 0, 12) >>> 0;",
    "state[a] = (state[a] + state[b] + y) >>> 0; state[d] = rotr((state[d] ^ state[a]) >>> 0, 8) >>> 0;",
    "state[c] = (state[c] + state[d]) >>> 0; state[b] = rotr((state[b] ^ state[c]) >>> 0, 7) >>> 0;",
    "}",
    "for (let round = 0; round < 7; round += 1) {",
    "mix(0,4,8,12,message[0],message[1]); mix(1,5,9,13,message[2],message[3]); mix(2,6,10,14,message[4],message[5]); mix(3,7,11,15,message[6],message[7]);",
    "mix(0,5,10,15,message[8],message[9]); mix(1,6,11,12,message[10],message[11]); mix(2,7,8,13,message[12],message[13]); mix(3,4,9,14,message[14],message[15]);",
    "message = PERM.map((index) => message[index]);",
    "}",
    "return [state[0] ^ state[8], state[1] ^ state[9], state[2] ^ state[10], state[3] ^ state[11], state[4] ^ state[12], state[5] ^ state[13], state[6] ^ state[14], state[7] ^ state[15], state[8] ^ cv[0], state[9] ^ cv[1], state[10] ^ cv[2], state[11] ^ cv[3], state[12] ^ cv[4], state[13] ^ cv[5], state[14] ^ cv[6], state[15] ^ cv[7]].map((word) => word >>> 0);",
    "}",
    "function digestBytes(words) {",
    "const digest = new Uint8Array(32);",
    "for (let index = 0; index < 8; index += 1) { const word = words[index]; digest[index * 4] = word & 255; digest[index * 4 + 1] = (word >>> 8) & 255; digest[index * 4 + 2] = (word >>> 16) & 255; digest[index * 4 + 3] = (word >>> 24) & 255; }",
    "return digest;",
    "}",
    "function chunkOutput(chunk, chunkIndex) {",
    "let cv = IV.slice();",
    "let output = null;",
    "for (let offset = 0, blockIndex = 0; offset < chunk.length || (chunk.length === 0 && offset === 0); offset += 64, blockIndex += 1) {",
    "const block = chunk.slice(offset, Math.min(offset + 64, chunk.length));",
    "const isLast = offset + 64 >= chunk.length;",
    "const flags = (blockIndex === 0 ? CHUNK_START : 0) | (isLast ? CHUNK_END : 0);",
    "const words = blockWords(block);",
    "output = { cv: cv.slice(), block: words, counter: chunkIndex, blockLength: block.length, flags };",
    "if (!isLast) cv = compress(cv, words, chunkIndex, 64, flags).slice(0, 8);",
    "if (chunk.length === 0) break;",
    "}",
    "return output;",
    "}",
    "function encodeBase64Url(data) { return btoa(String.fromCharCode(...data)).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/g, ''); }",
    "const outputs = [];",
    "const chunkCount = Math.max(1, Math.ceil(bytes.length / 1024));",
    "for (let index = 0; index < chunkCount; index += 1) outputs.push(chunkOutput(bytes.slice(index * 1024, Math.min((index + 1) * 1024, bytes.length)), index));",
    "if (outputs.length === 1) return encodeBase64Url(digestBytes(compress(outputs[0].cv, outputs[0].block, outputs[0].counter, outputs[0].blockLength, outputs[0].flags | ROOT)));",
    "let cvs = outputs.map((output) => compress(output.cv, output.block, output.counter, output.blockLength, output.flags).slice(0, 8));",
    "function parentOutput(left, right, root) { return compress(IV, [...left, ...right], 0, 64, PARENT | (root ? ROOT : 0)); }",
    "while (cvs.length > 2) { const next = []; for (let index = 0; index < cvs.length; index += 2) next.push(index + 1 < cvs.length ? parentOutput(cvs[index], cvs[index + 1], false).slice(0, 8) : cvs[index]); cvs = next; }",
    "return encodeBase64Url(digestBytes(parentOutput(cvs[0], cvs[1], true)));",
    "}",
  ];
}

function resourceApiContext(options: PluginBootScriptOptions): Record<string, unknown> {
  const hasResources = (options.resources ?? []).length > 0;
  if (!hasResources) return {};

  return {
    capabilityGrantId: requiredResourceContextString(
      options.capabilityGrantId,
      "capability_grant_id",
    ),
    applicationId: requiredResourceContextString(options.applicationId, "application_id"),
    consentEpoch: assertPositiveInteger(options.consentEpoch, "consent_epoch"),
    frameGeneration: assertPositiveInteger(options.frameGeneration, "frame_generation"),
    bundleHash: requiredResourceContextString(options.bundleHash, "bundle_hash"),
    manifestHash: requiredResourceContextString(options.manifestHash, "manifest_hash"),
    resourceManifestHash: requiredResourceContextString(
      options.resourceManifestHash,
      "resource_manifest_hash",
    ),
    ...(options.wasmCapable === true
      ? { browserTarget: requiredResourceContextString(options.browserTarget, "browser_target") }
      : {}),
  };
}

function requiredResourceContextString(value: string | undefined, field: string): string {
  if (typeof value === "string" && value.trim() !== "") return value;
  throw new PluginSandboxRuntimeError(
    "plugin_resource_context_invalid",
    `${field} is required for plugin resources`,
  );
}

function assertPositiveInteger(value: number | undefined, field: string): number {
  if (Number.isInteger(value) && value !== undefined && value > 0) return value;
  throw new PluginSandboxRuntimeError(
    "plugin_resource_context_invalid",
    `${field} is required for plugin resources`,
  );
}

export function scriptSha256(scriptText: string): string {
  return base64(sha256(new TextEncoder().encode(scriptText)));
}

function assertCspHash(value: string): string {
  if (!/^(?:[A-Za-z0-9+/]{43}=|[A-Za-z0-9_-]{43})$/.test(value)) {
    throw new PluginSandboxRuntimeError(
      "invalid_csp_hash",
      "plugin runtime CSP hash must be a base64/base64url sha256 digest",
    );
  }

  return value;
}

function assertBlake3Hash(value: string, field: string): void {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) {
    throw new PluginSandboxRuntimeError(
      "invalid_bundle_hash",
      `${field} must be a BLAKE3 base64url digest`,
    );
  }
}

function assertByteHash(bytes: Uint8Array, expectedHash: string, field: string): void {
  if (blake3Base64Url(bytes) !== expectedHash) {
    throw new PluginSandboxRuntimeError("bundle_hash_mismatch", `${field} does not match bytes`);
  }
}

function assertBundleHash(
  manifestHash: string,
  mainJsHash: string,
  stylesCssHash: string,
  resourceManifestHash: string,
  expectedHash: string,
): void {
  const packageHash = blake3Base64Url(
    canonicalizeStrictBytes({
      manifest_hash: manifestHash,
      main_js_hash: mainJsHash,
      styles_css_hash: stylesCssHash,
      resource_manifest_hash: resourceManifestHash,
    }),
  );

  if (packageHash !== expectedHash) {
    throw new PluginSandboxRuntimeError(
      "bundle_hash_mismatch",
      "bundle_hash does not match plugin bundle bytes",
    );
  }
}

function assertResourceManifest(
  manifest: readonly PluginSandboxResourceManifestEntry[],
): readonly PluginSandboxResourceManifestEntry[] {
  const seen = new Set<string>();
  const entries = [...manifest].map((entry) => {
    assertResourcePath(entry.path);
    assertBlake3Hash(entry.hash, "resource_hash");
    if (!Number.isSafeInteger(entry.byte_length) || entry.byte_length < 0) {
      throw new PluginSandboxRuntimeError(
        "invalid_resource_manifest",
        "resource byte_length must be a non-negative safe integer",
      );
    }
    if (typeof entry.kind !== "string" || entry.kind.trim() === "") {
      throw new PluginSandboxRuntimeError("invalid_resource_manifest", "resource kind is required");
    }
    if (typeof entry.media_type !== "string" || entry.media_type.trim() === "") {
      throw new PluginSandboxRuntimeError(
        "invalid_resource_manifest",
        "resource media_type is required",
      );
    }
    if (entry.executable !== (entry.kind === "wasm")) {
      throw new PluginSandboxRuntimeError(
        "invalid_resource_manifest",
        "resource executable flag must match kind",
      );
    }
    if (seen.has(entry.path)) {
      throw new PluginSandboxRuntimeError("invalid_resource_manifest", "duplicate resource path");
    }
    seen.add(entry.path);
    return Object.freeze({ ...entry });
  });

  entries.sort((left, right) => left.path.localeCompare(right.path));
  return Object.freeze(entries);
}

function assertResourceManifestHash(
  manifest: readonly PluginSandboxResourceManifestEntry[],
  expectedHash: string,
): void {
  if (
    blake3Base64Url(canonicalizeStrictValueBytes([...manifest] as unknown as StrictJsonValue)) !==
    expectedHash
  ) {
    throw new PluginSandboxRuntimeError(
      "bundle_hash_mismatch",
      "resource_manifest_hash does not match resource manifest",
    );
  }
}

function assertResources(
  resources: readonly PluginSandboxResourceInput[],
  manifest: readonly PluginSandboxResourceManifestEntry[],
): readonly PluginSandboxResourceArtifact[] {
  const manifestByPath = new Map(manifest.map((entry) => [entry.path, entry]));
  const resourceByPath = new Map<string, PluginSandboxResourceArtifact>();

  for (const resource of resources) {
    assertResourcePath(resource.path);
    const manifestEntry = manifestByPath.get(resource.path);
    if (!manifestEntry) {
      throw new PluginSandboxRuntimeError("resource_manifest_mismatch", "resource is undeclared");
    }
    if (
      resource.kind !== manifestEntry.kind ||
      resource.mediaType !== manifestEntry.media_type ||
      resource.byteLength !== manifestEntry.byte_length ||
      resource.hash !== manifestEntry.hash
    ) {
      throw new PluginSandboxRuntimeError(
        "resource_manifest_mismatch",
        "resource metadata does not match manifest",
      );
    }
    if (resource.bytes.byteLength !== resource.byteLength) {
      throw new PluginSandboxRuntimeError(
        "resource_manifest_mismatch",
        "resource byte length does not match manifest",
      );
    }
    assertByteHash(resource.bytes, resource.hash, "resource_hash");
    if (resourceByPath.has(resource.path)) {
      throw new PluginSandboxRuntimeError("resource_manifest_mismatch", "duplicate resource path");
    }
    resourceByPath.set(
      resource.path,
      Object.freeze({ ...resource, bytes: resource.bytes.slice() }),
    );
  }

  if (resourceByPath.size !== manifestByPath.size) {
    throw new PluginSandboxRuntimeError(
      "resource_manifest_mismatch",
      "resource payload must include every manifest entry",
    );
  }

  return Object.freeze(
    [...resourceByPath.values()].sort((left, right) => left.path.localeCompare(right.path)),
  );
}

function assertResourcePath(path: string): void {
  if (
    typeof path !== "string" ||
    !path.startsWith("resources/") ||
    path.includes("\\") ||
    path.includes("//") ||
    path.includes("/../") ||
    path.endsWith(".js")
  ) {
    throw new PluginSandboxRuntimeError(
      "invalid_resource_manifest",
      "resource path must be a non-JavaScript resources/ path",
    );
  }
}

function decodePluginSource(bytes: Uint8Array, filename: string): string {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new PluginSandboxRuntimeError(
      "plugin_source_encoding_invalid",
      `${filename} must be valid UTF-8`,
    );
  }
}

function assertSafeInlineScript(source: string): void {
  assertNoInlineHtmlBreakout(source, "plugin_script_inline_forbidden");
}

function assertSafeInlineStyle(source: string): void {
  assertNoInlineHtmlBreakout(source, "plugin_style_inline_forbidden");
}

function assertNoInlineHtmlBreakout(source: string, code: string): void {
  if (
    /<\/(?:script|style)/iu.test(source) ||
    source.includes("<!--") ||
    source.includes("-->") ||
    hasUnsafeControlCharacter(source)
  ) {
    throw new PluginSandboxRuntimeError(
      code,
      "plugin source contains characters unsafe for inline sandbox serialization",
    );
  }
}

function hasUnsafeControlCharacter(source: string): boolean {
  for (let index = 0; index < source.length; index += 1) {
    const code = source.charCodeAt(index);
    if (code === 0x00 || (code > 0x00 && code <= 0x08) || code === 0x0b || code === 0x0c) {
      return true;
    }
    if ((code >= 0x0e && code <= 0x1f) || code === 0x7f) {
      return true;
    }
  }
  return false;
}

function assertSingleBundleScript(source: string): void {
  const normalized = source.replace(/\/\/[^\r\n]*|\/\*[\s\S]*?\*\//gu, "");
  const compact = normalizeComputedStringConcatenations(normalized.replace(/\s+/gu, ""));

  if (
    /\bimport\s*(?:\(|["'{*A-Za-z])/u.test(normalized) ||
    /\bfrom\s*["']/u.test(normalized) ||
    /\bimportScripts\s*\(/u.test(normalized) ||
    /\bnavigator\s*\.\s*serviceWorker\b/u.test(normalized) ||
    /\bnew\s+(?:SharedWorker|Worker|Blob)\s*\(/u.test(normalized) ||
    /\bURL\s*\.\s*createObjectURL\s*\(/u.test(normalized) ||
    compact.includes("newWorker(") ||
    compact.includes("newSharedWorker(") ||
    compact.includes("newBlob(") ||
    compact.includes('navigator["serviceWorker"]') ||
    compact.includes("navigator['serviceWorker']") ||
    compact.includes("navigator[`serviceWorker`]") ||
    compact.includes('URL["createObjectURL"]') ||
    compact.includes("URL['createObjectURL']") ||
    compact.includes("URL[`createObjectURL`]") ||
    hasComputedRuntimeDependency(compact) ||
    /<script\b/iu.test(source) ||
    /<link\b/iu.test(source)
  ) {
    throw new PluginSandboxRuntimeError(
      "plugin_bundle_dependency_forbidden",
      "plugin bundle must be a verified single inline module without runtime dependencies",
    );
  }

  if (
    FORBIDDEN_HOST_API_TOKENS.some((token) => source.includes(token) || compact.includes(token))
  ) {
    throw new PluginSandboxRuntimeError(
      "plugin_bundle_dependency_forbidden",
      "plugin bundle must not reference Host-owned app internals",
    );
  }
}

function hasComputedRuntimeDependency(compact: string): boolean {
  return COMPUTED_RUNTIME_DEPENDENCY_PATTERNS.some((pattern) => pattern.test(compact));
}

const COMPUTED_RUNTIME_DEPENDENCY_PATTERNS = [
  /(?:navigator|globalThis|window|self)\[[`"']serviceWorker[`"']\]/u,
  /(?:globalThis|window|self)\[[`"']importScripts[`"']\]\(/u,
  /new\(*?(?:globalThis|window|self)\[[`"'](?:Worker|SharedWorker|Blob)[`"']\]\)*\(/u,
  /(?:URL|\(*?(?:globalThis|window|self)\[[`"']URL[`"']\]\)*?)\[[`"']createObjectURL[`"']\]\(/u,
];

function normalizeComputedStringConcatenations(source: string): string {
  let previous = source;
  while (true) {
    const next = previous.replace(/(["'])([A-Za-z]+)\1\+(["'])([A-Za-z]+)\3/gu, '"$2$4"');
    if (next === previous) return next;
    previous = next;
  }
}

function assertNonNegativeInteger(value: number, field: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new PluginSandboxRuntimeError(
      "invalid_non_negative_integer",
      `${field} must be a non-negative safe integer`,
    );
  }

  return value;
}

function parseCspDirectives(csp: string): Map<string, string> {
  const directives = new Map<string, string>();
  for (const directive of csp.split(";")) {
    const normalized = directive.trim().replace(/\s+/g, " ");
    if (!normalized) {
      continue;
    }

    const [name] = normalized.split(/\s+/, 1);
    if (directives.has(name)) {
      throw new PluginSandboxRuntimeError(
        "invalid_runtime_csp",
        `plugin runtime CSP must not include duplicate ${name} directives`,
      );
    }
    directives.set(name, normalized);
  }

  return directives;
}

function assertOpaqueToken(value: string, field: string): string {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new PluginSandboxRuntimeError(
      "invalid_opaque_token",
      `${field} contains characters that are unsafe for the plugin sandbox bootstrap`,
    );
  }

  return value;
}

function assertSandboxDocumentUrl(value: string): string {
  if (!value.startsWith("/api/plugin-runtime/sandbox-documents/")) {
    throw new PluginSandboxRuntimeError(
      "invalid_sandbox_document_url",
      "plugin sandbox document URL must use the Host sandbox document route",
    );
  }

  return value;
}

function base64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}
