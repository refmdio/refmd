import { Script, createContext } from "node:vm";
import { describe, expect, it, vi } from "vite-plus/test";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import {
  canonicalizeStrictBytes,
  canonicalizeStrictValueBytes,
  type StrictJsonValue,
} from "@/shared/lib/crypto/jcs";
import {
  PLUGIN_HOST_RPC_PROTOCOL,
  PLUGIN_HOST_RPC_VERSION,
  PluginHostMessageRouter,
  type PluginHostRpcSession,
} from "../host-rpc/host-rpc";
import { PluginHostCredentialStore } from "../credential/host-credential";
import {
  PLUGIN_SANDBOX_ATTRIBUTE,
  PluginSandboxRuntimeError,
  assertPluginSandboxIframe,
  assertPluginRuntimeCsp,
  buildPluginBootScript,
  buildPluginRuntimeCsp,
  createPluginSandboxBundleArtifact,
  createPluginSandboxIframe,
  createPluginSandboxRuntime,
  scriptSha256,
} from "./sandbox-runtime";

const TEST_HASH = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const TEST_BUNDLE_HASH = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
interface RegistrationHandle {
  id?: string;
  localId: string;
  dispose(): Promise<unknown>;
}

type FakeSandboxWindowEvent = {
  data: unknown;
  ports: FakeSandboxMessagePort[];
  source: unknown;
  stopImmediatePropagation(): void;
  stopPropagation(): void;
};

async function dispatchSandboxDocumentLoad(
  container: HTMLElement,
  expectedSrc: string,
): Promise<HTMLIFrameElement> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const iframe = container.querySelector("iframe");
    if (iframe instanceof HTMLIFrameElement && iframe.getAttribute("src") === expectedSrc) {
      iframe.dispatchEvent(new Event("load"));
      return iframe;
    }

    await new Promise((resolve) => setTimeout(resolve, 0));
  }

  throw new Error("sandbox document frame was not loaded by the test");
}

class FakeSandboxWindow {
  readonly parent = { postMessage() {} };
  private readonly listeners: Array<(event: FakeSandboxWindowEvent) => void> = [];

  addEventListener(type: string, listener: (event: FakeSandboxWindowEvent) => void): void {
    if (type === "message") this.listeners.push(listener);
  }

  dispatch(event: { data: unknown; ports: FakeSandboxMessagePort[]; source?: unknown }): void {
    let stopped = false;
    const messageEvent: FakeSandboxWindowEvent = {
      source: this.parent,
      ...event,
      stopImmediatePropagation() {
        stopped = true;
      },
      stopPropagation() {},
    };

    for (const listener of this.listeners) {
      listener(messageEvent);
      if (stopped) break;
    }
  }
}

class FakeSandboxMessagePort {
  readonly posted: unknown[] = [];
  private readonly listeners = new Set<(event: { data: unknown }) => void>();

  addEventListener(type: string, listener: (event: { data: unknown }) => void): void {
    if (type === "message") this.listeners.add(listener);
  }

  removeEventListener(type: string, listener: (event: { data: unknown }) => void): void {
    if (type === "message") this.listeners.delete(listener);
  }

  dispatch(data: unknown): void {
    for (const listener of this.listeners) listener({ data });
  }

  postMessage(data: unknown): void {
    this.posted.push(data);
  }
  start(): void {}
}

function runSandboxBootScript(
  script: string,
  options: {
    sandboxGlobal: unknown;
    eventTarget: unknown;
    btoa?: (data: string) => string;
  },
): void {
  const hasBtoa = options.btoa !== undefined;
  const parameters = hasBtoa
    ? "globalThis, window, atob, btoa, URL, Blob, MessagePort"
    : "globalThis, window, atob, URL, Blob, MessagePort";
  const args = hasBtoa
    ? "sandboxGlobal, eventTarget, atob, btoa, URL, Blob, FakeSandboxMessagePort"
    : "sandboxGlobal, eventTarget, atob, URL, Blob, FakeSandboxMessagePort";
  const context = createContext({
    sandboxGlobal: options.sandboxGlobal,
    eventTarget: options.eventTarget,
    atob,
    btoa: options.btoa ?? btoa,
    URL,
    Blob,
    document,
    queueMicrotask,
    setTimeout,
    clearTimeout,
    setInterval,
    clearInterval,
    Promise,
    Uint8Array,
    ArrayBuffer,
    TextEncoder,
    TextDecoder,
    WebAssembly,
    FakeSandboxMessagePort,
  });

  new Script(`(function(${parameters}) {\n${script}\n})(${args});`).runInContext(context);
}

function expectRecordMethod(target: unknown, key: string): void {
  const record = target && typeof target === "object" ? (target as Record<string, unknown>) : {};
  expect(typeof record[key]).toBe("function");
}

async function waitForPosted(
  port: FakeSandboxMessagePort,
  predicate: (message: unknown) => boolean,
): Promise<unknown> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const match = port.posted.find(predicate);
    if (match) return match;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }

  throw new Error("expected sandbox port message was not posted");
}

async function authenticateRuntimeSession(session: PluginHostRpcSession): Promise<void> {
  session.completeBoot();
  await (
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

function dispatchBootContext(port: FakeSandboxMessagePort): void {
  port.dispatch({
    protocol: PLUGIN_HOST_RPC_PROTOCOL,
    version: PLUGIN_HOST_RPC_VERSION,
    kind: "boot-context",
    frame_generation: 3,
    runtime_context: {
      plugin_id: "plugin.example",
      package_id: "package.example",
      application_id: "application.example",
      activation_id: "activation.example",
      owner_scope_kind: "workspace",
      workspace_id: "workspace.example",
      user_id: "user.example",
      device_id: "device.example",
      bundle_hash: "bundle.example",
      manifest_hash: "manifest.example",
      capability_id: "capability.example",
      capability_grant_id: "grant.example",
      consent_epoch: 1,
      frame_scope: "primary",
    },
  });
}

describe("plugin sandbox runtime", () => {
  it("builds a plugin runtime CSP without app-origin or direct network authority", () => {
    const csp = buildPluginRuntimeCsp({ scriptSha256Hashes: [TEST_HASH] });

    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain(`script-src 'sha256-${TEST_HASH}'`);
    expect(csp).toContain("connect-src 'none'");
    expect(csp).toContain("worker-src 'none'");
    expect(csp).toContain("form-action 'none'");
    expect(csp).toContain("base-uri 'none'");
    expect(csp).toContain("frame-ancestors 'self'");
    expect(csp).not.toContain("script-src 'self'");
    expect(csp).not.toContain("style-src 'self'");
    expect(csp).not.toContain("connect-src 'self'");
    expect(csp).not.toContain("worker-src 'self'");
    expect(csp).not.toContain("frame-src 'self'");
    expect(csp).not.toContain("script-src blob:");
    expect(csp).not.toContain("script-src data:");
    expect(csp).not.toContain("'unsafe-eval'");
  });

  it("allows only wasm-unsafe-eval for the WASM-capable runtime CSP variant", () => {
    const csp = buildPluginRuntimeCsp({ scriptSha256Hashes: [TEST_HASH], wasmCapable: true });

    expect(csp).toContain(`script-src 'sha256-${TEST_HASH}' 'wasm-unsafe-eval'`);
    expect(csp).not.toContain("'unsafe-eval'");
    expect(() => assertPluginRuntimeCsp(csp)).not.toThrow();
    expect(() =>
      assertPluginRuntimeCsp(csp.replace("'wasm-unsafe-eval'", "'unsafe-eval'")),
    ).toThrow(
      expect.objectContaining({
        code: "non_hash_script_src_forbidden",
      } satisfies Partial<PluginSandboxRuntimeError>),
    );
  });

  it("rejects plugin runtime CSP widening for scripts, self, network, workers, and forms", () => {
    const csp = buildPluginRuntimeCsp({ scriptSha256Hashes: [TEST_HASH] });

    expect(() =>
      assertPluginRuntimeCsp(csp.replace("connect-src 'none'", "connect-src 'self'")),
    ).toThrow(
      expect.objectContaining({
        code: "invalid_runtime_csp",
      } satisfies Partial<PluginSandboxRuntimeError>),
    );
    expect(() =>
      assertPluginRuntimeCsp(csp.replace("worker-src 'none'", "worker-src 'self'")),
    ).toThrow(
      expect.objectContaining({
        code: "invalid_runtime_csp",
      } satisfies Partial<PluginSandboxRuntimeError>),
    );
    expect(() =>
      assertPluginRuntimeCsp(csp.replace("form-action 'none'", "form-action 'self'")),
    ).toThrow(
      expect.objectContaining({
        code: "invalid_runtime_csp",
      } satisfies Partial<PluginSandboxRuntimeError>),
    );
    expect(() =>
      assertPluginRuntimeCsp(csp.replace("img-src blob: data:", "img-src https:")),
    ).toThrow(
      expect.objectContaining({
        code: "invalid_runtime_csp",
      } satisfies Partial<PluginSandboxRuntimeError>),
    );
    expect(() =>
      assertPluginRuntimeCsp(csp.replace("media-src blob: data:", "media-src https:")),
    ).toThrow(
      expect.objectContaining({
        code: "invalid_runtime_csp",
      } satisfies Partial<PluginSandboxRuntimeError>),
    );
    expect(() =>
      assertPluginRuntimeCsp(
        csp.replace(`script-src 'sha256-${TEST_HASH}'`, `script-src 'sha256-${TEST_HASH}' blob:`),
      ),
    ).toThrow(
      expect.objectContaining({
        code: "non_hash_script_src_forbidden",
      } satisfies Partial<PluginSandboxRuntimeError>),
    );
    expect(() => buildPluginRuntimeCsp({ scriptSha256Hashes: ["short"] })).toThrow(
      expect.objectContaining({
        code: "invalid_csp_hash",
      } satisfies Partial<PluginSandboxRuntimeError>),
    );
  });

  it("rejects duplicate runtime CSP directives that could hide widened policy", () => {
    const csp = buildPluginRuntimeCsp({ scriptSha256Hashes: [TEST_HASH] });

    for (const widenedDirective of [
      `script-src https://plugins.example; script-src 'sha256-${TEST_HASH}'`,
      "connect-src https://exfil.example; connect-src 'none'",
      "worker-src blob:; worker-src 'none'",
      "form-action https://exfil.example; form-action 'none'",
    ]) {
      const directiveName = widenedDirective.split(/\s+/, 1)[0];
      const requiredDirective = csp
        .split("; ")
        .find((directive) => directive.startsWith(`${directiveName} `));
      expect(requiredDirective).toBeDefined();
      expect(() =>
        assertPluginRuntimeCsp(csp.replace(requiredDirective ?? "", widenedDirective)),
      ).toThrow(
        expect.objectContaining({
          code: "invalid_runtime_csp",
        } satisfies Partial<PluginSandboxRuntimeError>),
      );
    }
  });

  it("rejects extra runtime CSP directives that could override fixed policy", () => {
    const csp = buildPluginRuntimeCsp({ scriptSha256Hashes: [TEST_HASH] });

    for (const extraDirective of [
      "script-src-elem https://plugins.example",
      "script-src-attr 'unsafe-inline'",
      "report-uri https://reports.example",
    ]) {
      expect(() => assertPluginRuntimeCsp(`${csp}; ${extraDirective}`)).toThrow(
        expect.objectContaining({
          code: "invalid_runtime_csp",
        } satisfies Partial<PluginSandboxRuntimeError>),
      );
    }
  });

  it("keeps verified bundle bytes and CSP hashes deterministic for route rendering", () => {
    const mainScript = 'const message = "ready";\nexport { message };';
    const stylesCss = ".plugin-root { color: red; }";
    const manifestJson = '{"id":"plugin.example","version":"1.0.0"}';
    const bundle = createPluginSandboxBundleArtifact(
      bundleInput({ mainScript, stylesCss, manifestJson }),
    );
    const bootScriptHash = scriptSha256(
      buildPluginBootScript({ bootNonce: "boot_nonce_1", frameGeneration: 3 }),
    );

    expect(bundle.mainScript).toBe(mainScript);
    expect(bundle.stylesCss).toBe(stylesCss);
    expect(bundle.scriptSha256Hash).toBe(scriptSha256(mainScript));
    expect(
      buildPluginRuntimeCsp({
        scriptSha256Hashes: [bootScriptHash, bundle.scriptSha256Hash],
      }),
    ).toContain(`script-src 'sha256-${bootScriptHash}' 'sha256-${bundle.scriptSha256Hash}'`);
  });

  it("binds package resources to the bundle and exposes the sandbox resource facade", () => {
    const resourceBytes = textBytes('{"items":[1,2,3]}');
    const input = bundleInput({
      mainScript: "export {};",
      resources: [
        {
          path: "resources/data/index.json",
          kind: "json",
          mediaType: "application/json",
          bytes: resourceBytes,
        },
      ],
    });
    const bundle = createPluginSandboxBundleArtifact(input);
    const bootScript = buildPluginBootScript({
      bootNonce: "boot_nonce_1",
      frameGeneration: 3,
      resources: bundle.resources,
      ...resourceBootContext(input.resourceManifestHash),
    });

    expect(bundle.resources).toHaveLength(1);
    expect(bundle.resources[0]?.path).toBe("resources/data/index.json");
    expect(bootScript).toContain("Object.defineProperty(globalThis, 'refmd'");
    expect(bootScript).toContain("resources/data/index.json");
    expect(bootScript).toContain("plugin_resource_context_stale");
    expect(bootScript).toContain("resourceManifestHash");
    expect(bootScript).toContain("plugin_resource_integrity_invalid");
    expect(bootScript).toContain("host-lifecycle");
    expect(bootScript).toContain("resourceMap.clear()");
    expect(bootScript).toContain("async instantiateWasm() { throw new Error");
    expect(bootScript).not.toContain("NativeWebAssembly.instantiate");
    expect(bootScript).toContain("Object.defineProperty(globalThis, 'WebAssembly'");

    expect(() =>
      createPluginSandboxBundleArtifact({
        ...input,
        resources: [{ ...input.resources[0]!, bytes: textBytes("tampered") }],
      }),
    ).toThrow(
      expect.objectContaining({
        code: "resource_manifest_mismatch",
      } satisfies Partial<PluginSandboxRuntimeError>),
    );
  });

  it("keeps WASM disabled in the default boot helper", async () => {
    const eventTarget = new FakeSandboxWindow();
    const sandboxGlobal = {
      WebAssembly,
      refmd: undefined as
        | {
            resources: {
              read(path: string, expectedKind?: string): Promise<Uint8Array>;
              instantiateWasm(path: string, imports?: WebAssembly.Imports): Promise<never>;
              objectUrl(path: string): Promise<string>;
            };
          }
        | undefined,
    };
    const wasmBytes = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
    const jsonBytes = textBytes("{}");
    const script = buildPluginBootScript({
      bootNonce: "boot_nonce_1",
      frameGeneration: 3,
      resources: [
        {
          path: "resources/engine/search.wasm",
          kind: "wasm",
          mediaType: "application/wasm",
          bytes: wasmBytes,
          byteLength: wasmBytes.byteLength,
          hash: blake3Base64Url(wasmBytes),
        },
        {
          path: "resources/data/index.json",
          kind: "json",
          mediaType: "application/json",
          bytes: jsonBytes,
          byteLength: jsonBytes.byteLength,
          hash: blake3Base64Url(jsonBytes),
        },
      ],
      ...resourceBootContext(TEST_HASH),
    });

    runSandboxBootScript(script, { sandboxGlobal, eventTarget });
    const port = new FakeSandboxMessagePort();
    eventTarget.dispatch({
      data: {
        protocol: PLUGIN_HOST_RPC_PROTOCOL,
        version: PLUGIN_HOST_RPC_VERSION,
        kind: "boot-port",
        frame_generation: 3,
      },
      ports: [port],
    });
    dispatchBootContext(port);

    expect(sandboxGlobal.WebAssembly).toBeUndefined();
    await expect(
      sandboxGlobal.refmd?.resources
        .read("resources/data/index.json", "json")
        .then((bytes) => [...bytes]),
    ).resolves.toEqual([...textBytes("{}")]);
    await expect(
      sandboxGlobal.refmd?.resources.read("resources/data/index.json", "image"),
    ).rejects.toThrow("plugin_resource_kind_mismatch");
    await expect(
      sandboxGlobal.refmd?.resources.instantiateWasm("resources/engine/search.wasm"),
    ).rejects.toThrow("plugin_wasm_resource_unavailable");
    await expect(
      sandboxGlobal.refmd?.resources.instantiateWasm("resources/data/index.json"),
    ).rejects.toThrow("plugin_wasm_resource_unavailable");
    await expect(
      sandboxGlobal.refmd?.resources.objectUrl("resources/engine/search.wasm"),
    ).rejects.toThrow("plugin_resource_object_url_forbidden");
    port.dispatch({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "host-lifecycle",
      lifecycle: "close",
    });
    await expect(
      sandboxGlobal.refmd?.resources.read("resources/data/index.json", "json"),
    ).rejects.toThrow("plugin_resource_context_stale");
  });

  it("exposes only declared resource bytes through the WASM-capable boot helper", async () => {
    const eventTarget = new FakeSandboxWindow();
    const sandboxGlobal = {
      WebAssembly,
      refmd: undefined as
        | {
            resources: {
              instantiateWasm(
                path: string,
                imports?: WebAssembly.Imports,
              ): Promise<WebAssembly.Instance>;
              objectUrl(path: string): Promise<string>;
            };
          }
        | undefined,
    };
    const wasmBytes = new Uint8Array([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
    const jsonBytes = textBytes("{}");
    const script = buildPluginBootScript({
      bootNonce: "boot_nonce_1",
      frameGeneration: 3,
      resources: [
        {
          path: "resources/engine/search.wasm",
          kind: "wasm",
          mediaType: "application/wasm",
          bytes: wasmBytes,
          byteLength: wasmBytes.byteLength,
          hash: blake3Base64Url(wasmBytes),
        },
        {
          path: "resources/data/index.json",
          kind: "json",
          mediaType: "application/json",
          bytes: jsonBytes,
          byteLength: jsonBytes.byteLength,
          hash: blake3Base64Url(jsonBytes),
        },
      ],
      ...resourceBootContext(TEST_HASH),
      browserTarget: "vitest-jsdom",
      wasmCapable: true,
    });

    runSandboxBootScript(script, { sandboxGlobal, eventTarget });
    const port = new FakeSandboxMessagePort();
    eventTarget.dispatch({
      data: {
        protocol: PLUGIN_HOST_RPC_PROTOCOL,
        version: PLUGIN_HOST_RPC_VERSION,
        kind: "boot-port",
        frame_generation: 3,
      },
      ports: [port],
    });
    dispatchBootContext(port);

    expect(sandboxGlobal.WebAssembly).toBeUndefined();
    await expect(
      sandboxGlobal.refmd?.resources.instantiateWasm("resources/engine/search.wasm"),
    ).resolves.toBeInstanceOf(WebAssembly.Instance);
    await expect(
      sandboxGlobal.refmd?.resources.instantiateWasm("resources/data/index.json"),
    ).rejects.toThrow("plugin_wasm_resource_required");
    await expect(
      sandboxGlobal.refmd?.resources.objectUrl("resources/engine/search.wasm"),
    ).rejects.toThrow("plugin_resource_object_url_forbidden");
  });

  it("rejects same-length resource byte corruption before exposing sandbox resources", async () => {
    const eventTarget = new FakeSandboxWindow();
    const sandboxGlobal = {
      WebAssembly,
      refmd: undefined as
        | {
            resources: {
              read(path: string, expectedKind?: string): Promise<Uint8Array>;
              objectUrl(path: string): Promise<string>;
            };
          }
        | undefined,
    };
    const validBytes = textBytes("{}");
    const corruptBytes = textBytes("[]");
    const script = buildPluginBootScript({
      bootNonce: "boot_nonce_1",
      frameGeneration: 3,
      resources: [
        {
          path: "resources/data/index.json",
          kind: "json",
          mediaType: "application/json",
          bytes: validBytes,
          byteLength: validBytes.byteLength,
          hash: blake3Base64Url(validBytes),
        },
      ],
      ...resourceBootContext(TEST_HASH),
    }).replace(
      btoa(String.fromCharCode(...validBytes)),
      btoa(String.fromCharCode(...corruptBytes)),
    );

    runSandboxBootScript(script, { sandboxGlobal, eventTarget, btoa });
    const port = new FakeSandboxMessagePort();
    eventTarget.dispatch({
      data: {
        protocol: PLUGIN_HOST_RPC_PROTOCOL,
        version: PLUGIN_HOST_RPC_VERSION,
        kind: "boot-port",
        frame_generation: 3,
      },
      ports: [port],
    });
    dispatchBootContext(port);

    await expect(
      sandboxGlobal.refmd?.resources.read("resources/data/index.json", "json"),
    ).rejects.toThrow("plugin_resource_integrity_invalid");
    await expect(
      sandboxGlobal.refmd?.resources.objectUrl("resources/data/index.json"),
    ).rejects.toThrow("plugin_resource_integrity_invalid");
  });

  it("rejects unverified or non-inline-safe plugin bundle bytes before route rendering", () => {
    const valid = bundleInput({ mainScript: "export {};" });

    expect(() =>
      createPluginSandboxBundleArtifact({
        ...valid,
        mainJsHash: blake3Base64Url(textBytes("different")),
      }),
    ).toThrow(
      expect.objectContaining({
        code: "bundle_hash_mismatch",
      } satisfies Partial<PluginSandboxRuntimeError>),
    );

    expect(() =>
      createPluginSandboxBundleArtifact(
        bundleInput({
          mainJsBytes: new Uint8Array([0xff]),
          stylesCss: "",
          manifestJson: '{"id":"plugin.example","version":"1.0.0"}',
        }),
      ),
    ).toThrow(
      expect.objectContaining({
        code: "plugin_source_encoding_invalid",
      } satisfies Partial<PluginSandboxRuntimeError>),
    );

    expect(() =>
      createPluginSandboxBundleArtifact(bundleInput({ mainScript: 'const marker = "</script>";' })),
    ).toThrow(
      expect.objectContaining({
        code: "plugin_script_inline_forbidden",
      } satisfies Partial<PluginSandboxRuntimeError>),
    );

    expect(() =>
      createPluginSandboxBundleArtifact(bundleInput({ stylesCss: "/* </style> */" })),
    ).toThrow(
      expect.objectContaining({
        code: "plugin_style_inline_forbidden",
      } satisfies Partial<PluginSandboxRuntimeError>),
    );
  });

  it("rejects bundle code that would fetch unresolved runtime dependencies", () => {
    for (const mainScript of [
      'import value from "dep";',
      'const dep = import("dep");',
      'const dep = import/* blocked */("dep");',
      'importScripts("dep.js");',
      'navigator.serviceWorker.register("sw.js");',
      'navigator["serviceWorker"].register("sw.js");',
      'new Worker("worker.js");',
      'new/**/Worker("worker.js");',
      'new Blob(["export {}"], { type: "text/javascript" });',
      "URL.createObjectURL(new Blob([]));",
      'URL["createObjectURL"](new Blob([]));',
      'navigator["service" + "Worker"].register("sw.js");',
      'navigator["serv" + "ice" + "Worker"].register("sw.js");',
      'globalThis["import" + "Scripts"]("dep.js");',
      'globalThis["im" + "port" + "Scripts"]("dep.js");',
      "navigator[`serviceWorker`].register('sw.js');",
      "globalThis[`importScripts`]('dep.js');",
      'new globalThis["Worker"]("worker.js");',
      'new (globalThis["Worker"])("worker.js");',
      "new globalThis[`Worker`]('worker.js');",
      'new window["Shared" + "Worker"]("worker.js");',
      'new (window["Shared" + "Worker"])("worker.js");',
      'new self["Bl" + "ob"](["export {}"]);',
      'new (self["Bl" + "ob"])(["export {}"]);',
      "new self[`Blob`](['export {}']);",
      'URL["create" + "ObjectURL"](new Blob([]));',
      'globalThis["URL"]["create" + "ObjectURL"](new Blob([]));',
      '(globalThis["URL"])["create" + "ObjectURL"](new Blob([]));',
      "URL[`createObjectURL`](new Blob([]));",
      "globalThis[`URL`][`createObjectURL`](new Blob([]));",
    ]) {
      expect(
        () => createPluginSandboxBundleArtifact(bundleInput({ mainScript })),
        mainScript,
      ).toThrow(
        expect.objectContaining({
          code: "plugin_bundle_dependency_forbidden",
        } satisfies Partial<PluginSandboxRuntimeError>),
      );
    }
  });

  it("rejects bundle code that references Host-owned app internals", () => {
    for (const forbiddenHostApi of [
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
    ]) {
      expect(
        () =>
          createPluginSandboxBundleArtifact(
            bundleInput({ mainScript: `globalThis.${forbiddenHostApi};` }),
          ),
        forbiddenHostApi,
      ).toThrow(
        expect.objectContaining({
          code: "plugin_bundle_dependency_forbidden",
        } satisfies Partial<PluginSandboxRuntimeError>),
      );
    }

    for (const mainScript of [
      'globalThis["get" + "App"]?.();',
      'window["workspace" + "Manager"];',
      'self["Workspace" + "Leaf"];',
      'globalThis["render" + "Plugin" + "Content"];',
      'globalThis["register" + "Dom" + "Event"];',
    ]) {
      expect(
        () => createPluginSandboxBundleArtifact(bundleInput({ mainScript })),
        mainScript,
      ).toThrow(
        expect.objectContaining({
          code: "plugin_bundle_dependency_forbidden",
        } satisfies Partial<PluginSandboxRuntimeError>),
      );
    }
  });

  it("creates only allow-scripts sandbox iframes backed by the sandbox document route", () => {
    const iframe = createPluginSandboxIframe({
      ownerDocument: document,
      src: "/api/plugin-runtime/sandbox-documents/session-one",
      title: "Plugin",
      className: "plugin-frame",
    });

    expect(iframe.getAttribute("sandbox")).toBe(PLUGIN_SANDBOX_ATTRIBUTE);
    expect(sandboxTokens(iframe)).toContain("allow-scripts");
    expect(sandboxTokens(iframe)).not.toContain("allow-same-origin");
    expect(iframe.hasAttribute("srcdoc")).toBe(false);
    expect(iframe.getAttribute("src")).toBe("/api/plugin-runtime/sandbox-documents/session-one");
    expect(iframe.getAttribute("referrerpolicy")).toBe("no-referrer");
    expect(iframe.title).toBe("Plugin");
    expect(iframe.className).toBe("plugin-frame");
  });

  it("rejects sandbox iframe creation without a Host-issued sandbox document URL", () => {
    expect(() =>
      createPluginSandboxIframe({
        ownerDocument: document,
      } as never),
    ).toThrow(
      expect.objectContaining({
        code: "plugin_runtime_sandbox_document_session_required",
      } satisfies Partial<PluginSandboxRuntimeError>),
    );
  });

  it("rejects plugin sandbox iframes backed by srcdoc instead of the document route", () => {
    const iframe = document.createElement("iframe");
    iframe.setAttribute("sandbox", PLUGIN_SANDBOX_ATTRIBUTE);
    iframe.setAttribute("referrerpolicy", "no-referrer");
    iframe.setAttribute("srcdoc", "<!doctype html>");
    expect(() => assertPluginSandboxIframe(iframe)).toThrow(
      expect.objectContaining({
        code: "srcdoc_runtime_forbidden",
      } satisfies Partial<PluginSandboxRuntimeError>),
    );
  });

  it("rejects sandbox flags and invalid route-backed frames that would break the opaque-origin boundary", () => {
    const iframe = document.createElement("iframe");
    iframe.setAttribute("referrerpolicy", "no-referrer");
    iframe.setAttribute("src", "/api/plugin-runtime/sandbox-documents/session-one");
    iframe.setAttribute("sandbox", "allow-scripts allow-same-origin");

    expect(() => assertPluginSandboxIframe(iframe)).toThrow(
      expect.objectContaining({
        name: "PluginSandboxRuntimeError",
        code: "allow_same_origin_forbidden",
      } satisfies Partial<PluginSandboxRuntimeError>),
    );

    iframe.setAttribute("sandbox", PLUGIN_SANDBOX_ATTRIBUTE);
    iframe.setAttribute("src", "https://plugins.example/runtime.html");

    expect(() => assertPluginSandboxIframe(iframe)).toThrow(
      expect.objectContaining({
        name: "PluginSandboxRuntimeError",
        code: "invalid_sandbox_document_url",
      } satisfies Partial<PluginSandboxRuntimeError>),
    );
  });

  it("rejects sandbox variants that would enable parent-origin, navigation, forms, or popup authority", () => {
    for (const forbiddenToken of [
      "allow-forms",
      "allow-popups",
      "allow-top-navigation",
      "allow-downloads",
    ]) {
      const iframe = document.createElement("iframe");
      iframe.setAttribute("sandbox", `${PLUGIN_SANDBOX_ATTRIBUTE} ${forbiddenToken}`);
      iframe.setAttribute("referrerpolicy", "no-referrer");
      iframe.setAttribute("src", "/api/plugin-runtime/sandbox-documents/session-one");

      expect(() => assertPluginSandboxIframe(iframe), forbiddenToken).toThrow(
        expect.objectContaining({
          code: "invalid_sandbox_attribute",
        } satisfies Partial<PluginSandboxRuntimeError>),
      );
    }

    const missingSrcdoc = document.createElement("iframe");
    missingSrcdoc.setAttribute("sandbox", PLUGIN_SANDBOX_ATTRIBUTE);
    missingSrcdoc.setAttribute("referrerpolicy", "no-referrer");

    expect(() => assertPluginSandboxIframe(missingSrcdoc)).toThrow(
      expect.objectContaining({
        code: "missing_sandbox_document_runtime",
      } satisfies Partial<PluginSandboxRuntimeError>),
    );

    const leakingReferrer = document.createElement("iframe");
    leakingReferrer.setAttribute("sandbox", PLUGIN_SANDBOX_ATTRIBUTE);
    leakingReferrer.setAttribute("src", "/api/plugin-runtime/sandbox-documents/session-one");

    expect(() => assertPluginSandboxIframe(leakingReferrer)).toThrow(
      expect.objectContaining({
        code: "invalid_referrer_policy",
      } satisfies Partial<PluginSandboxRuntimeError>),
    );
  });

  it("creates a Host RPC session for the sandbox and tears both down together", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
    });
    const container = document.createElement("div");
    document.body.append(container);
    const auditSink = vi.fn((_event: unknown) => true);

    const runtimePromise = createPluginSandboxRuntime({
      container,
      router,
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
      consentEpoch: 1,
      validateSession: () => null,
      auditSink,
      frameGeneration: 3,
      bootNonce: "boot-nonce-one",
      sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/session-one",
      additionalScriptSha256Hashes: [TEST_BUNDLE_HASH],
      title: "Runtime Plugin",
    });
    const iframe = await dispatchSandboxDocumentLoad(
      container,
      "/api/plugin-runtime/sandbox-documents/session-one",
    );
    const runtime = await runtimePromise;

    expect(container.contains(runtime.iframe)).toBe(true);
    expect(runtime.iframe).toBe(iframe);
    expect(runtime.iframe.getAttribute("sandbox")).toBe(PLUGIN_SANDBOX_ATTRIBUTE);
    expect(runtime.iframe.hasAttribute("srcdoc")).toBe(false);
    expect(runtime.iframe.getAttribute("src")).toBe(
      "/api/plugin-runtime/sandbox-documents/session-one",
    );
    expect(runtime.session.bootNonce).toBe("boot-nonce-one");
    expect(runtime.session.frameGeneration).toBe(3);
    expect(runtime.session.connected).toBe(false);
    expect(auditSink).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "plugin.capability.issued",
        operation: "plugin.capability.issue",
        result: "allow",
      }),
    );
    expect(auditSink).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "plugin.bundle.imported",
        operation: "plugin.bundle.import",
        result: "allow",
      }),
    );
    expect(auditSink).not.toHaveBeenCalledWith(
      expect.objectContaining({
        type: "plugin.sandbox.loaded",
      }),
    );
    await authenticateRuntimeSession(runtime.session);
    expect(runtime.session.connected).toBe(true);
    expect(auditSink).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "plugin.sandbox.loaded",
        operation: "plugin.sandbox.load",
        result: "allow",
      }),
    );
    expect(runtime.session.securityAuditContext().auditActor).toEqual({
      user_id: "user.example",
      device_id: "device.example",
      session_id: null,
      principal_kind: "user",
      principal_id: "user.example",
    });

    const credentialStore = new PluginHostCredentialStore();
    const credentialEndpoint = "https://api.example.test/data";
    const releaseCredential = credentialStore.retainCredential({
      credentialId: "api-key",
      pluginId: "plugin.example",
      packageId: "package.example",
      workspaceId: "00000000-0000-4000-8000-000000000002",
      applicationId: "00000000-0000-4000-8000-000000000001",
      activationId: "activation.example",
      userId: "user.example",
      deviceId: "device.example",
      audience: "api.example.test",
      endpoint: credentialEndpoint,
      method: "GET",
      headers: { authorization: "Bearer host-token" },
    });
    const context = runtime.session.securityAuditContext();
    const issued = await credentialStore.use({
      context,
      credentialId: "api-key",
      userId: "user.example",
      deviceId: "device.example",
      audience: "api.example.test",
      endpoint: credentialEndpoint,
      method: "GET",
    });
    await expect(
      credentialStore.resolve({
        context,
        handle: issued.handle,
        audience: "api.example.test",
        endpoint: {
          id: "api",
          url: credentialEndpoint,
          methods: ["GET"],
          routes: ["proxy"],
          maxRequestBytes: 1024,
          maxResponseBytes: 2048,
          credentialAudience: "api.example.test",
        },
        method: "GET",
      }),
    ).resolves.toEqual({ authorization: "Bearer host-token" });
    releaseCredential();

    runtime.destroy("test_destroy");
    runtime.destroy("test_destroy_again");

    expect(auditSink).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "plugin.capability.revoked",
        operation: "plugin.capability.revoke",
        reasonCode: "test_destroy",
      }),
    );
    const auditEvents = auditSink.mock.calls.map(
      ([event]) => event as { type: string; reasonCode?: string },
    );
    expect(auditEvents.filter((event) => event.type === "plugin.sandbox.destroyed")).toHaveLength(
      1,
    );
    expect(auditEvents.filter((event) => event.type === "plugin.capability.revoked")).toHaveLength(
      1,
    );
    expect(container.contains(runtime.iframe)).toBe(false);
    expect(runtime.session.connected).toBe(false);
    container.remove();
  });

  it("rejects runtime creation before iframe or session creation when sandbox document session metadata is missing", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
    });
    const createSessionSpy = vi.spyOn(router, "createSession");
    const container = document.createElement("div");
    document.body.append(container);

    await expect(
      createPluginSandboxRuntime({
        container,
        router,
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
        consentEpoch: 1,
        validateSession: () => null,
        auditSink: () => true,
        sandboxDocumentUrl: undefined,
        bootNonce: "boot-nonce-one",
        frameGeneration: 3,
      } as never),
    ).rejects.toMatchObject({
      code: "plugin_runtime_sandbox_document_session_required",
    } satisfies Partial<PluginSandboxRuntimeError>);

    expect(createSessionSpy).not.toHaveBeenCalled();
    expect(container.querySelector("iframe")).toBeNull();
    container.remove();
  });

  it("aborts startup without treating audit rejection as fatal after the session is superseded", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
    });
    const container = document.createElement("div");
    document.body.append(container);
    const applicationId = "00000000-0000-4000-8000-000000000001";
    const auditSink = vi.fn((event: unknown) => {
      if (
        event &&
        typeof event === "object" &&
        (event as { type?: unknown }).type === "plugin.capability.issued"
      ) {
        router.closeByApplication(applicationId, "application_changed");
      }
      return true;
    });

    await expect(
      createPluginSandboxRuntime({
        container,
        router,
        pluginId: "plugin.example",
        packageId: "package.example",
        applicationId,
        activationId: "activation.example",
        ownerScopeKind: "workspace",
        userId: "user.example",
        deviceId: "device.example",
        workspaceId: "00000000-0000-4000-8000-000000000002",
        bundleHash: "bundle-hash-1",
        manifestHash: "manifest-hash-1",
        capabilityId: "capability-1",
        capabilityGrantId: "capability-grant-1",
        consentEpoch: 1,
        validateSession: () => null,
        auditSink,
        frameGeneration: 3,
        bootNonce: "boot-nonce-one",
        sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/session-one",
        additionalScriptSha256Hashes: [TEST_BUNDLE_HASH],
        title: "Runtime Plugin",
      }),
    ).rejects.toMatchObject({
      code: "runtime_startup_superseded",
    } satisfies Partial<PluginSandboxRuntimeError>);

    expect(auditSink).toHaveBeenCalledTimes(1);
    expect(container.querySelector("iframe")).toBeNull();
    container.remove();
  });

  it("closes a booting session when runtime startup is aborted", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
    });
    const container = document.createElement("div");
    document.body.append(container);
    const abortController = new AbortController();
    const auditSink = vi.fn((event: unknown) => {
      if (
        event &&
        typeof event === "object" &&
        (event as { type?: unknown }).type === "plugin.capability.issued"
      ) {
        abortController.abort("runtime_startup_superseded");
      }
      return true;
    });

    await expect(
      createPluginSandboxRuntime({
        container,
        router,
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
        consentEpoch: 1,
        validateSession: () => null,
        auditSink,
        startupSignal: abortController.signal,
        frameGeneration: 3,
        bootNonce: "boot-nonce-one",
        sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/session-one",
        additionalScriptSha256Hashes: [TEST_BUNDLE_HASH],
        title: "Runtime Plugin",
      }),
    ).rejects.toMatchObject({
      code: "runtime_startup_superseded",
    } satisfies Partial<PluginSandboxRuntimeError>);

    expect(auditSink).toHaveBeenCalledTimes(1);
    expect(container.querySelector("iframe")).toBeNull();
    container.remove();
  });

  it("audits sanitized navigation suspicion when a connected sandbox frame navigates", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
    });
    const container = document.createElement("div");
    document.body.append(container);
    const auditSink = vi.fn((_event: unknown) => true);

    const runtimePromise = createPluginSandboxRuntime({
      container,
      router,
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
      consentEpoch: 1,
      validateSession: () => null,
      auditSink,
      frameGeneration: 3,
      bootNonce: "boot-nonce-one",
      sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/session-one",
      additionalScriptSha256Hashes: [TEST_BUNDLE_HASH],
      title: "Runtime Plugin",
    });
    const iframe = await dispatchSandboxDocumentLoad(
      container,
      "/api/plugin-runtime/sandbox-documents/session-one",
    );
    const runtime = await runtimePromise;

    runtime.session.completeBoot();
    await (
      runtime.session as unknown as {
        handlePortMessage(message: unknown): Promise<void>;
      }
    ).handlePortMessage({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "boot-ack",
      boot_nonce: runtime.session.bootNonce,
      frame_generation: runtime.session.frameGeneration,
    });
    expect(runtime.session.connected).toBe(true);

    iframe.dispatchEvent(new Event("load"));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(runtime.session.connected).toBe(false);
    const auditEvents = auditSink.mock.calls.map(
      ([event]) =>
        event as {
          type: string;
          reasonCode?: string;
          action?: Record<string, unknown>;
          resource?: Record<string, unknown>;
        },
    );
    const navigationAudit = auditEvents.find(
      (event) => event.type === "plugin.runtime.navigation_suspected",
    );
    expect(navigationAudit).toMatchObject({
      reasonCode: "frame_navigation",
      action: {
        operation: "plugin.runtime.navigation.detect",
        result: "completed",
        reason_code: "frame_navigation",
      },
      resource: {
        kind: "plugin",
        id: "plugin.example",
      },
    });
    expect(JSON.stringify(navigationAudit)).not.toContain("https://");
    expect(auditEvents.filter((event) => event.type === "plugin.capability.revoked")).toHaveLength(
      1,
    );
    expect(container.contains(runtime.iframe)).toBe(false);
    container.remove();
  });

  it("audits sanitized navigation suspicion when an authenticating sandbox frame navigates", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
    });
    const container = document.createElement("div");
    document.body.append(container);
    const auditSink = vi.fn((_event: unknown) => true);

    const runtimePromise = createPluginSandboxRuntime({
      container,
      router,
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
      consentEpoch: 1,
      validateSession: () => null,
      auditSink,
      frameGeneration: 3,
      bootNonce: "boot-nonce-one",
      sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/session-one",
      additionalScriptSha256Hashes: [TEST_BUNDLE_HASH],
      title: "Runtime Plugin",
    });
    const iframe = await dispatchSandboxDocumentLoad(
      container,
      "/api/plugin-runtime/sandbox-documents/session-one",
    );
    const runtime = await runtimePromise;

    runtime.session.completeBoot();
    expect(runtime.session.connected).toBe(false);
    expect(runtime.session.closed).toBe(false);

    iframe.dispatchEvent(new Event("load"));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(runtime.session.connected).toBe(false);
    expect(runtime.session.closed).toBe(true);
    const auditEvents = auditSink.mock.calls.map(
      ([event]) =>
        event as {
          type: string;
          reasonCode?: string;
          action?: Record<string, unknown>;
          resource?: Record<string, unknown>;
        },
    );
    const navigationAudit = auditEvents.find(
      (event) => event.type === "plugin.runtime.navigation_suspected",
    );
    expect(navigationAudit).toMatchObject({
      reasonCode: "frame_navigation",
      action: {
        operation: "plugin.runtime.navigation.detect",
        result: "completed",
        reason_code: "frame_navigation",
      },
      resource: {
        kind: "plugin",
        id: "plugin.example",
      },
    });
    expect(JSON.stringify(navigationAudit)).not.toContain("https://");
    expect(auditEvents.filter((event) => event.type === "plugin.capability.revoked")).toHaveLength(
      1,
    );
    expect(container.contains(runtime.iframe)).toBe(false);
    container.remove();
  });

  it("audits capability denial before rejecting dangerous grants", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
    });
    const container = document.createElement("div");
    document.body.append(container);
    const auditSink = vi.fn(() => true);

    await expect(
      createPluginSandboxRuntime({
        container,
        router,
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
        consentEpoch: 1,
        validateSession: () => null,
        frameGeneration: 3,
        bootNonce: "boot-nonce-one",
        sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/session-one",
        permissions: ["document:read:active", "storage:write:workspace"],
        auditSink,
        title: "Runtime Plugin",
      }),
    ).rejects.toMatchObject(
      expect.objectContaining({
        code: "dangerous_permission_combination",
      } satisfies Partial<PluginSandboxRuntimeError>),
    );

    expect(auditSink).toHaveBeenCalledWith(
      expect.objectContaining({
        type: "plugin.capability.denied",
        operation: "plugin.capability.deny",
        result: "deny",
        reasonCode: "dangerous_permission_combination",
      }),
    );
    expect(container.childElementCount).toBe(0);
    container.remove();
  });

  it("fails closed when capability issuance audit is unavailable", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
    });
    const container = document.createElement("div");
    document.body.append(container);

    await expect(
      createPluginSandboxRuntime({
        container,
        router,
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
        consentEpoch: 1,
        validateSession: () => null,
        frameGeneration: 3,
        bootNonce: "boot-nonce-one",
        sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/session-one",
        auditSink: () => false,
        title: "Runtime Plugin",
      }),
    ).rejects.toMatchObject(
      expect.objectContaining({
        code: "capability_audit_unavailable",
      } satisfies Partial<PluginSandboxRuntimeError>),
    );

    expect(container.childElementCount).toBe(0);
    container.remove();
  });

  it("arms the Host RPC session before assigning the sandbox document src", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: undefined,
      idFactory: createIdFactory(),
    });
    const container = document.createElement("div");
    document.body.append(container);
    let handledDuringSrcAssignment = false;
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
      if (name === "src") {
        const session = Array.from(
          (
            router as unknown as {
              sessionsById: Map<
                string,
                {
                  bootNonce: string;
                  contentWindow: Window | null;
                  frameGeneration: number;
                  handlePortMessage(message: unknown): Promise<void>;
                }
              >;
            }
          ).sessionsById.values(),
        )[0];
        handledDuringSrcAssignment = router.handleWindowMessage({
          data: {
            protocol: PLUGIN_HOST_RPC_PROTOCOL,
            version: PLUGIN_HOST_RPC_VERSION,
            kind: "boot-ready",
          },
          source: session?.contentWindow,
        } as unknown as MessageEvent);
        void session?.handlePortMessage({
          protocol: PLUGIN_HOST_RPC_PROTOCOL,
          version: PLUGIN_HOST_RPC_VERSION,
          kind: "boot-ack",
          boot_nonce: session.bootNonce,
          frame_generation: session.frameGeneration,
        });
        this.dispatchEvent(new Event("load"));
      }

      return result;
    };

    let runtime: Awaited<ReturnType<typeof createPluginSandboxRuntime>> | null = null;
    try {
      runtime = await createPluginSandboxRuntime({
        container,
        router,
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
        consentEpoch: 1,
        validateSession: () => null,
        auditSink: () => true,
        frameGeneration: 3,
        bootNonce: "boot-nonce-one",
        sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/session-one",
        title: "Runtime Plugin",
      });
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
    }

    expect(runtime).not.toBeNull();
    expect(handledDuringSrcAssignment).toBe(true);
    expect(runtime!.session.bootNonce).toBe("boot-nonce-one");
    expect(runtime!.session.connected).toBe(true);

    runtime!.destroy("test_destroy");
    container.remove();
  });

  it("keeps the boot script deterministic and exposes only the frozen refmd facade", () => {
    const script = buildPluginBootScript({
      bootNonce: "boot_nonce_1",
      frameGeneration: 3,
    });

    expect(script).toBe(buildPluginBootScript({ bootNonce: "boot_nonce_1", frameGeneration: 3 }));
    expect(script).toContain('"refmd.plugin-host-rpc"');
    expect(script).toContain("kind: 'boot-ready'");
    expect(script).toContain("kind !== 'boot-port'");
    expect(script).toContain("portData.kind === 'boot-context'");
    expect(script).toContain("event.source !== window.parent");
    expect(script).toContain("data.frame_generation !== frameGeneration");
    expect(script).toContain("event.stopImmediatePropagation();");
    expect(script).toContain("event.stopPropagation();");
    expect(script).toContain("pendingPortListeners");
    expect(script).toContain("addEventListener(type, listener)");
    expect(script).toContain("request(operation, payload, options)");
    expect(script).toContain("plugin_rpc_timeout");
    expect(script).toContain("}, 120000); pendingRequests.set(requestId");
    const pendingRequestIndex = script.indexOf("pendingRequests.set(requestId");
    const postRequestIndex = script.indexOf("hostPort.postMessage(envelope);");
    expect(pendingRequestIndex).toBeGreaterThan(-1);
    expect(postRequestIndex).toBeGreaterThan(-1);
    expect(pendingRequestIndex).toBeLessThan(postRequestIndex);
    expect(script).toContain("const commands = Object.freeze");
    expect(script).toContain("delete: fixedRequest('storage.userLocal.delete')");
    expect(script).toContain("delete: fixedRequest('storage.cache.delete')");
    expect(script).toContain("delete: fixedRequest('storage.workspace.delete')");
    expect(script).toContain("delete: fixedRequest('storage.document.delete')");
    expect(script).toContain("recordDelete: fixedRequest('storage.workspace.record.delete')");
    expect(script).toContain("recordDelete: fixedRequest('storage.document.record.delete')");
    expect(script).toContain("ui.command.register");
    expect(script).toContain("onInvoke(listener)");
    expect(script).not.toContain("registerWorkspaceTile");
    expect(script).toContain("const ui = Object.freeze");
    expect(script).toContain("registerItem(descriptor)");
    expect(script).toContain("ui.status.register_item");
    expect(script).toContain("updateItem(descriptor)");
    expect(script).toContain("ui.status.update_item");
    expect(script).toContain("registerPanel(descriptor)");
    expect(script).toContain("ui.sidebar.register_panel");
    expect(script).toContain("registerTile(descriptor)");
    expect(script).toContain("ui.workspace.register_tile");
    expect(script).toContain("workspaceTileActionRegistrationPayload(descriptor)");
    expect(script).toContain("registerTileAction(descriptor)");
    expect(script).toContain("ui.workspace.register_tile_action");
    expect(script).not.toContain("ui.workspace.register_panel");
    expect(script).not.toContain("openTile(descriptor)");
    expect(script).not.toContain("ui.workspace.open_tile");
    expect(script).toContain("onTileRender(listener)");
    expect(script).toContain("ui.workspace_tile.render");
    expect(script).toContain("onTileAction(listener)");
    expect(script).toContain("ui.workspace_tile.action");
    expect(script).toContain("registerPane(descriptor)");
    expect(script).toContain("ui.auxiliary.register_pane");
    expect(script).toContain("registerAction(descriptor)");
    expect(script).toContain("ui.document_tree.register_action");
    expect(script).toContain("registerBadge(descriptor)");
    expect(script).toContain("ui.document_tree.register_badge");
    expect(script).toContain("onRefresh(listener)");
    expect(script).toContain("ui.status.refresh");
    expect(script).toContain("onBadgeRefresh(listener)");
    expect(script).toContain("ui.document_tree.badge.refresh");
    expect(script).toContain("registerDecoration(descriptor)");
    expect(script).toContain("ui.document_tree.register_decoration");
    expect(script).toContain("registerVirtualSection(descriptor)");
    expect(script).toContain("ui.document_tree.register_virtual_section");
    expect(script).toContain("registerIframe(descriptor)");
    expect(script).toContain("ui.settings.register_iframe");
    expect(script).toContain("registerDeclarative(descriptor)");
    expect(script).toContain("ui.settings.register_declarative");
    expect(script).toContain("ui.menu.register_item");
    expect(script).toContain("ui.modal.register_declarative");
    expect(script).not.toContain("onCommandInvoke");
    expect(script).toContain(
      "getSelectedDocuments: fixedRequest('documents.getSelectedDocuments')",
    );
    expect(script).toContain("replaceSelection: fixedRequest('editor.replaceSelection')");
    expect(script).toContain("rejectPendingRequests('session_closed'");
    expect(script).toContain("runtime: runtimeInfo");
    expect(script).toContain("onload");
    expect(script).toContain("onunload");
    expect(script).toContain("registerContribution");
    expect(script).toContain("ui.contribution.unregister");
    expect(script).toContain("commands");
    expect(script).toContain("network");
    expect(script).toContain("credential");
    expect(script).toContain("renderer.getSource");
    expect(script).toContain("renderer.setHeight");
    expect(script).toContain("register_block(type, listener)");
    expect(script).toContain("register_inline_code(listener)");
    expect(script).not.toContain("onRender(listener)");
    expect(script).toContain("runtime_context");
    expect(script).not.toContain("data.runtime_context");
    expect(script).toContain("get context() { return rpcContext; }");
    expect(script).toContain("plugin_rpc_context_unavailable");
    expect(script).toContain("DOMContentLoaded");
    expect(script).toContain("sendBootReady");
    expect(script).toContain("startBootReady");
    expect(script).toContain("stopBootReady");
    expect(script).toContain("setInterval(sendBootReady, 250)");
    expect(script).toContain("boot_nonce_1");
    expect(script).toContain("kind: 'boot-ack'");
    expect(script).toContain("boot_nonce: bootNonce");
    expect(script).not.toContain("kind: 'boot-ready', boot_nonce");
    expect(script).not.toContain("kind: 'boot-port', boot_nonce");
    expect(script).not.toContain("__refmdPluginHostRpc");
    expect(script).toContain("window.parent.postMessage");
    expect(script).not.toContain("document.cookie");
    expect(script).not.toContain("window.parent.document");
    expect(script).not.toContain("document.body");
    expect(script).not.toContain("localStorage");
    expect(script).not.toContain("indexedDB");
    expect(script).not.toContain("fetch(");
    expect(script).not.toContain("import(");
    expect(script).not.toContain("import ");
    for (const forbiddenHostApi of [
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
    ]) {
      expect(script).not.toContain(forbiddenHostApi);
    }
  });

  it("does not expose the raw boot port to plugin window message listeners", () => {
    const script = buildPluginBootScript({
      bootNonce: "boot_nonce_1",
      frameGeneration: 3,
    });
    const sandboxGlobal: {
      refmd?: { runtime?: { connected: boolean } };
    } = {};
    const eventTarget = new FakeSandboxWindow();
    runSandboxBootScript(script, { sandboxGlobal, eventTarget });

    const leakedPorts: FakeSandboxMessagePort[] = [];
    eventTarget.addEventListener("message", (event) => {
      const port = event.ports[0];
      if (port) leakedPorts.push(port);
    });

    const port = new FakeSandboxMessagePort();
    eventTarget.dispatch({
      data: {
        protocol: PLUGIN_HOST_RPC_PROTOCOL,
        version: PLUGIN_HOST_RPC_VERSION,
        kind: "boot-port",
        frame_generation: 3,
      },
      ports: [port],
    });

    expect(leakedPorts).toEqual([]);
    expect(sandboxGlobal.refmd?.runtime?.connected).toBe(true);
  });

  it("exposes the runtime UI facade without DOM-backed host objects", async () => {
    const script = buildPluginBootScript({
      bootNonce: "boot_nonce_1",
      frameGeneration: 3,
    });
    const sandboxGlobal: {
      refmd?: {
        onload?: (listener: () => void) => { dispose(): void };
        onunload?: (listener: () => void) => { dispose(): void };
        commands?: {
          register(descriptor: Record<string, unknown>): Promise<RegistrationHandle>;
          onInvoke(
            listener: (event: {
              operation?: string;
              executionContextId?: string;
              payload?: Record<string, unknown>;
              respond(payload: Record<string, unknown>): void;
            }) => void,
          ): { dispose(): void };
        };
        ui?: {
          status?: {
            registerItem(descriptor: Record<string, unknown>): Promise<RegistrationHandle>;
            updateItem(descriptor: Record<string, unknown>): Promise<Record<string, unknown>>;
            onRefresh(
              listener: (event: {
                operation?: string;
                executionContextId?: string;
                resource?: Record<string, unknown>;
                payload?: Record<string, unknown>;
                respond(payload: Record<string, unknown>): void;
              }) => void,
            ): { dispose(): void };
          };
          sidebar?: {
            registerPanel(descriptor: Record<string, unknown>): Promise<RegistrationHandle>;
          };
          workspace?: {
            registerTile(descriptor: {
              localId: string;
              tileId: string;
              title: string;
              scope: "workspace" | "document";
              preferredOpen?: "manual" | "document_menu" | "command";
            }): Promise<RegistrationHandle>;
            registerTileAction(descriptor: {
              localId: string;
              tileRef: Record<string, unknown>;
              actionId: string;
              title: string;
              placement: "tile_toolbar" | "tile_menu" | "refresh";
              documentQuery?: {
                scope: "workspace";
                max_documents: number;
                max_bytes: number;
                reason?: string;
              };
            }): Promise<RegistrationHandle>;
            onTileRender(
              listener: (event: {
                operation?: string;
                executionContextId?: string;
                resource?: Record<string, unknown>;
                payload?: Record<string, unknown>;
                respond(payload: Record<string, unknown>): void;
              }) => void,
            ): { dispose(): void };
            onTileAction(
              listener: (event: {
                operation?: string;
                executionContextId?: string;
                resource?: Record<string, unknown>;
                payload?: Record<string, unknown>;
                respond(payload: Record<string, unknown>): void;
              }) => void,
            ): { dispose(): void };
          };
          auxiliary?: {
            registerPane(descriptor: {
              localId: string;
              paneId: string;
              title: string;
              allowedLocations: string[];
              actions?: {
                actionId: string;
                title: string;
                commandRef: Record<string, unknown>;
              }[];
            }): Promise<RegistrationHandle>;
          };
          documentTree?: {
            registerAction(descriptor: Record<string, unknown>): Promise<RegistrationHandle>;
            registerBadge(descriptor: Record<string, unknown>): Promise<RegistrationHandle>;
            onBadgeRefresh(
              listener: (event: {
                operation?: string;
                executionContextId?: string;
                resource?: Record<string, unknown>;
                payload?: Record<string, unknown>;
                respond(payload: Record<string, unknown>): void;
              }) => void,
            ): { dispose(): void };
            registerDecoration(descriptor: Record<string, unknown>): Promise<RegistrationHandle>;
            registerVirtualSection(
              descriptor: Record<string, unknown>,
            ): Promise<RegistrationHandle>;
          };
          settings?: {
            registerIframe(descriptor: Record<string, unknown>): Promise<RegistrationHandle>;
            registerDeclarative(descriptor: Record<string, unknown>): Promise<RegistrationHandle>;
          };
          menu?: { registerItem(descriptor: Record<string, unknown>): Promise<RegistrationHandle> };
          modal?: {
            registerDeclarative(descriptor: Record<string, unknown>): Promise<RegistrationHandle>;
          };
        };
        runtime?: { connected: boolean; context: unknown };
        documents?: unknown;
        renderer?: unknown;
      };
    } = {};
    const eventTarget = new FakeSandboxWindow();
    runSandboxBootScript(script, { sandboxGlobal, eventTarget });

    expect(sandboxGlobal.refmd).toBeTruthy();
    expectRecordMethod(sandboxGlobal.refmd, "onload");
    expectRecordMethod(sandboxGlobal.refmd, "onunload");
    expectRecordMethod(sandboxGlobal.refmd!.commands, "register");
    expectRecordMethod(sandboxGlobal.refmd!.commands, "onInvoke");
    expectRecordMethod(sandboxGlobal.refmd!.ui?.status, "registerItem");
    expectRecordMethod(sandboxGlobal.refmd!.ui?.status, "updateItem");
    expectRecordMethod(sandboxGlobal.refmd!.ui?.status, "onRefresh");
    expectRecordMethod(sandboxGlobal.refmd!.ui?.sidebar, "registerPanel");
    expectRecordMethod(sandboxGlobal.refmd!.ui?.workspace, "registerTile");
    expectRecordMethod(sandboxGlobal.refmd!.ui?.workspace, "registerTileAction");
    expect(
      (sandboxGlobal.refmd!.ui?.workspace as { openTile?: unknown } | undefined)?.openTile,
    ).toBeUndefined();
    expectRecordMethod(sandboxGlobal.refmd!.ui?.workspace, "onTileRender");
    expectRecordMethod(sandboxGlobal.refmd!.ui?.workspace, "onTileAction");
    expectRecordMethod(sandboxGlobal.refmd!.ui?.auxiliary, "registerPane");
    expectRecordMethod(sandboxGlobal.refmd!.ui?.documentTree, "registerAction");
    expectRecordMethod(sandboxGlobal.refmd!.ui?.documentTree, "registerBadge");
    expectRecordMethod(sandboxGlobal.refmd!.ui?.documentTree, "onBadgeRefresh");
    expectRecordMethod(sandboxGlobal.refmd!.ui?.documentTree, "registerDecoration");
    expectRecordMethod(sandboxGlobal.refmd!.ui?.documentTree, "registerVirtualSection");
    expectRecordMethod(sandboxGlobal.refmd!.ui?.settings, "registerIframe");
    expectRecordMethod(sandboxGlobal.refmd!.ui?.settings, "registerDeclarative");
    expectRecordMethod(sandboxGlobal.refmd!.ui?.menu, "registerItem");
    expectRecordMethod(sandboxGlobal.refmd!.ui?.modal, "registerDeclarative");
    expect(sandboxGlobal.refmd!.documents).toBeTruthy();
    expect(sandboxGlobal.refmd!.renderer).toBeTruthy();
    const lifecycleEvents: string[] = [];
    sandboxGlobal.refmd!.onload?.(() => lifecycleEvents.push("load"));
    sandboxGlobal.refmd!.onunload?.(() => lifecycleEvents.push("unload"));

    const port = new FakeSandboxMessagePort();
    eventTarget.dispatch({
      data: {
        protocol: PLUGIN_HOST_RPC_PROTOCOL,
        version: PLUGIN_HOST_RPC_VERSION,
        kind: "boot-port",
        frame_generation: 3,
      },
      ports: [port],
    });
    dispatchBootContext(port);
    await Promise.resolve();
    expect(lifecycleEvents).toEqual(["load"]);

    async function expectFacadeRequest(
      action: () => Promise<RegistrationHandle>,
      operation: string,
      payload: Record<string, unknown>,
    ): Promise<RegistrationHandle> {
      const requestPromise = action();
      const request = await waitForPosted(
        port,
        (message) =>
          typeof message === "object" &&
          message !== null &&
          (message as { operation?: string }).operation === operation &&
          (message as { payload?: { local_id?: unknown } }).payload?.local_id === payload.local_id,
      );
      expect(request).toMatchObject({ kind: "request", operation, payload });
      port.dispatch({
        protocol: PLUGIN_HOST_RPC_PROTOCOL,
        version: PLUGIN_HOST_RPC_VERSION,
        kind: "response",
        request_id: (request as { request_id: string }).request_id,
        payload: { id: `${payload.local_id as string}-id` },
      });
      const handle = await requestPromise;
      expect(handle).toMatchObject({
        id: `${payload.local_id as string}-id`,
        localId: payload.local_id,
      });
      expectRecordMethod(handle, "dispose");
      return handle;
    }

    const workspaceFacade = sandboxGlobal.refmd!.ui!.workspace as {
      registerTileAction(descriptor: Record<string, unknown>): Promise<RegistrationHandle>;
    };
    const auxiliaryFacade = sandboxGlobal.refmd!.ui!.auxiliary as {
      registerPane(descriptor: Record<string, unknown>): Promise<RegistrationHandle>;
    };

    expect(() =>
      sandboxGlobal.refmd!.ui!.status!.registerItem({
        localId: "status-missing-zone",
        value: { kind: "text", text: "Ready" },
      }),
    ).toThrowError("plugin_status_zone_required");
    expect(() =>
      sandboxGlobal.refmd!.ui!.sidebar!.registerPanel({
        localId: "sidebar-missing-locations",
        panelId: "sidebar",
        title: "Sidebar",
      }),
    ).toThrowError("plugin_sidebar_panel_locations_required");
    expect(() =>
      workspaceFacade.registerTileAction({
        localId: "preview.refresh.missing-placement",
        tileRef: { kind: "local_tile", local_id: "preview" },
        actionId: "refresh",
        title: "Refresh",
      }),
    ).toThrowError("plugin_workspace_tile_action_placement_required");
    expect(() =>
      auxiliaryFacade.registerPane({
        localId: "comments-missing-locations",
        paneId: "comments",
        title: "Comments",
      }),
    ).toThrowError("plugin_auxiliary_pane_locations_required");
    expect(() =>
      sandboxGlobal.refmd!.ui!.settings!.registerIframe({
        localId: "settings-frame-missing-placement",
        settingsId: "settings",
        title: "Settings",
        iframePanelId: "settings-frame",
      }),
    ).toThrowError("plugin_settings_iframe_placement_required");
    expect(() =>
      sandboxGlobal.refmd!.ui!.settings!.registerDeclarative({
        localId: "settings-form-missing-placement",
        settingsId: "settings-form",
        title: "Settings Form",
        sections: [{ fields: [{ kind: "checkbox", name: "enabled", label: "Enabled" }] }],
      }),
    ).toThrowError("plugin_settings_declarative_placement_required");

    await expectFacadeRequest(
      () =>
        sandboxGlobal.refmd!.commands!.register({
          localId: "command",
          title: "Run command",
          plaintextRequest: "none",
        }),
      "ui.command.register",
      {
        surface: "command",
        local_id: "command",
        title: "Run command",
        plaintext_request: "none",
      },
    );

    await expectFacadeRequest(
      () =>
        sandboxGlobal.refmd!.ui!.status!.registerItem({
          localId: "status",
          zone: "normal",
          value: { kind: "text", text: "Ready" },
          maxWidth: 120,
        }),
      "ui.status.register_item",
      {
        surface: "status",
        local_id: "status",
        zone: "normal",
        value: { kind: "text", text: "Ready" },
        max_width: 120,
      },
    );

    await expectFacadeRequest(
      () =>
        sandboxGlobal.refmd!.ui!.status!.registerItem({
          localId: "contextual-status",
          zone: "normal",
          value: { kind: "text" },
          plaintextRequest: "active_document",
        }),
      "ui.status.register_item",
      {
        surface: "status",
        local_id: "contextual-status",
        zone: "normal",
        value: { kind: "text" },
        plaintext_request: "active_document",
      },
    );

    const statusUpdatePromise = sandboxGlobal.refmd!.ui!.status!.updateItem({
      localId: "status",
      zone: "normal",
      value: { kind: "text", text: "Updated" },
      maxWidth: 120,
    });
    const statusUpdateRequest = await waitForPosted(
      port,
      (message) =>
        typeof message === "object" &&
        message !== null &&
        (message as { operation?: string }).operation === "ui.status.update_item",
    );
    expect(statusUpdateRequest).toMatchObject({
      kind: "request",
      operation: "ui.status.update_item",
      payload: {
        surface: "status",
        local_id: "status",
        zone: "normal",
        value: { kind: "text", text: "Updated" },
        max_width: 120,
      },
    });
    port.dispatch({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: (statusUpdateRequest as { request_id: string }).request_id,
      payload: { id: "status-id" },
    });
    await expect(statusUpdatePromise).resolves.toEqual({ id: "status-id" });

    await expectFacadeRequest(
      () =>
        sandboxGlobal.refmd!.ui!.sidebar!.registerPanel({
          localId: "sidebar",
          panelId: "sidebar",
          title: "Sidebar",
          allowedLocations: ["left"],
        }),
      "ui.sidebar.register_panel",
      {
        surface: "sidebar_panel",
        local_id: "sidebar",
        panel_id: "sidebar",
        title: "Sidebar",
        allowed_locations: ["left"],
      },
    );

    const registration = sandboxGlobal.refmd!.ui!.workspace!.registerTile({
      localId: "preview",
      tileId: "preview",
      title: "Board",
      scope: "workspace",
      preferredOpen: "command",
    });
    const registrationRequest = await waitForPosted(
      port,
      (message) =>
        typeof message === "object" &&
        message !== null &&
        (message as { operation?: string }).operation === "ui.workspace.register_tile",
    );
    expect(registrationRequest).toMatchObject({
      kind: "request",
      operation: "ui.workspace.register_tile",
      payload: {
        surface: "workspace_tile",
        local_id: "preview",
        tile_id: "preview",
        title: "Board",
        scope: "workspace",
        preferred_open: "command",
      },
    });
    port.dispatch({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: (registrationRequest as { request_id: string }).request_id,
      payload: { id: "preview-id" },
    });
    const registrationHandle = await registration;
    expect(registrationHandle).toMatchObject({ id: "preview-id", localId: "preview" });
    expectRecordMethod(registrationHandle, "dispose");

    await expectFacadeRequest(
      () =>
        sandboxGlobal.refmd!.ui!.workspace!.registerTileAction({
          localId: "preview.refresh",
          tileRef: { kind: "local_tile", local_id: "preview" },
          actionId: "refresh",
          title: "Refresh",
          placement: "refresh",
          documentQuery: {
            scope: "workspace",
            max_documents: 25,
            max_bytes: 4096,
            reason: "Build board",
          },
        }),
      "ui.workspace.register_tile_action",
      {
        surface: "workspace_tile_action",
        local_id: "preview.refresh",
        tile_ref: { kind: "local_tile", local_id: "preview" },
        action_id: "refresh",
        title: "Refresh",
        placement: "refresh",
        document_query: {
          scope: "workspace",
          max_documents: 25,
          max_bytes: 4096,
          reason: "Build board",
        },
      },
    );

    const disposeRequestPromise = registrationHandle.dispose();
    const disposeRequest = await waitForPosted(
      port,
      (message) =>
        typeof message === "object" &&
        message !== null &&
        (message as { operation?: string }).operation === "ui.contribution.unregister",
    );
    expect(disposeRequest).toMatchObject({
      kind: "request",
      operation: "ui.contribution.unregister",
      payload: { local_id: "preview" },
    });
    port.dispatch({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: (disposeRequest as { request_id: string }).request_id,
      payload: { local_id: "preview" },
    });
    await expect(disposeRequestPromise).resolves.toEqual({ local_id: "preview" });
    await expect(registrationHandle.dispose()).resolves.toEqual({ local_id: "preview" });

    const commandRef = { kind: "local_command", local_id: "command" };
    const auxiliaryRegistration = sandboxGlobal.refmd!.ui!.auxiliary!.registerPane({
      localId: "comments",
      paneId: "comments",
      title: "Comments",
      allowedLocations: ["right"],
      actions: [{ actionId: "send", title: "Send", commandRef }],
    });
    const auxiliaryRegistrationRequest = await waitForPosted(
      port,
      (message) =>
        typeof message === "object" &&
        message !== null &&
        (message as { operation?: string }).operation === "ui.auxiliary.register_pane",
    );
    expect(auxiliaryRegistrationRequest).toMatchObject({
      kind: "request",
      operation: "ui.auxiliary.register_pane",
      payload: {
        surface: "auxiliary_pane",
        local_id: "comments",
        pane_id: "comments",
        title: "Comments",
        allowed_locations: ["right"],
        actions: [
          {
            action_id: "send",
            title: "Send",
            command_ref: commandRef,
          },
        ],
      },
    });
    port.dispatch({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: (auxiliaryRegistrationRequest as { request_id: string }).request_id,
      payload: { id: "comments-id" },
    });
    await expect(auxiliaryRegistration).resolves.toMatchObject({
      id: "comments-id",
      localId: "comments",
    });

    await expectFacadeRequest(
      () =>
        sandboxGlobal.refmd!.ui!.documentTree!.registerAction({
          localId: "document-action",
          placement: "row_context_menu",
          title: "Document Action",
          commandRef,
        }),
      "ui.document_tree.register_action",
      {
        surface: "document_tree_action",
        local_id: "document-action",
        placement: "row_context_menu",
        title: "Document Action",
        command_ref: commandRef,
      },
    );

    await expectFacadeRequest(
      () =>
        sandboxGlobal.refmd!.ui!.documentTree!.registerBadge({
          localId: "document-badge",
          placement: "row_trailing_badge",
          text: "1",
        }),
      "ui.document_tree.register_badge",
      {
        surface: "document_tree_badge",
        local_id: "document-badge",
        placement: "row_trailing_badge",
        text: "1",
      },
    );

    await expectFacadeRequest(
      () =>
        sandboxGlobal.refmd!.ui!.documentTree!.registerBadge({
          localId: "contextual-document-badge",
          placement: "row_trailing_badge",
          plaintextRequest: "active_document",
        }),
      "ui.document_tree.register_badge",
      {
        surface: "document_tree_badge",
        local_id: "contextual-document-badge",
        placement: "row_trailing_badge",
        plaintext_request: "active_document",
      },
    );

    await expectFacadeRequest(
      () =>
        sandboxGlobal.refmd!.ui!.documentTree!.registerDecoration({
          localId: "document-decoration",
          placement: "row_prefix",
          tone: "info",
        }),
      "ui.document_tree.register_decoration",
      {
        surface: "document_tree_decoration",
        local_id: "document-decoration",
        placement: "row_prefix",
        tone: "info",
      },
    );

    await expectFacadeRequest(
      () =>
        sandboxGlobal.refmd!.ui!.documentTree!.registerVirtualSection({
          localId: "document-section",
          placement: "before_tree",
          title: "Section",
          sourceCommandRef: commandRef,
        }),
      "ui.document_tree.register_virtual_section",
      {
        surface: "document_tree_virtual_section",
        local_id: "document-section",
        placement: "before_tree",
        title: "Section",
        source_command_ref: commandRef,
      },
    );

    await expectFacadeRequest(
      () =>
        sandboxGlobal.refmd!.ui!.settings!.registerIframe({
          localId: "settings-frame",
          settingsId: "settings",
          title: "Settings",
          placement: "plugin_settings",
          iframePanelId: "settings-frame",
        }),
      "ui.settings.register_iframe",
      {
        surface: "settings_iframe",
        local_id: "settings-frame",
        settings_id: "settings",
        title: "Settings",
        placement: "plugin_settings",
        iframe_panel_id: "settings-frame",
      },
    );

    const sections = [{ fields: [{ kind: "checkbox", name: "enabled", label: "Enabled" }] }];

    await expectFacadeRequest(
      () =>
        sandboxGlobal.refmd!.ui!.settings!.registerDeclarative({
          localId: "settings-form",
          settingsId: "settings-form",
          title: "Settings Form",
          placement: "plugin_settings",
          sections,
          submitCommandRef: commandRef,
        }),
      "ui.settings.register_declarative",
      {
        surface: "settings_declarative",
        local_id: "settings-form",
        settings_id: "settings-form",
        title: "Settings Form",
        placement: "plugin_settings",
        sections,
        submit_command_ref: commandRef,
      },
    );

    await expectFacadeRequest(
      () =>
        sandboxGlobal.refmd!.ui!.menu!.registerItem({
          localId: "menu",
          placement: "command_palette",
          title: "Menu Item",
          commandRef,
        }),
      "ui.menu.register_item",
      {
        surface: "menu_item",
        local_id: "menu",
        placement: "command_palette",
        title: "Menu Item",
        command_ref: commandRef,
      },
    );

    const modalBody = {
      kind: "schema_form",
      fields: [{ kind: "text", name: "value", label: "Value", max_length: 64 }],
    };

    await expectFacadeRequest(
      () =>
        sandboxGlobal.refmd!.ui!.modal!.registerDeclarative({
          localId: "modal",
          modalId: "modal",
          title: "Modal",
          triggerCommandRef: commandRef,
          body: modalBody,
          submitCommandRef: commandRef,
        }),
      "ui.modal.register_declarative",
      {
        surface: "declarative_modal",
        local_id: "modal",
        modal_id: "modal",
        title: "Modal",
        trigger_command_ref: commandRef,
        body: modalBody,
        submit_command_ref: commandRef,
      },
    );

    const receivedEvents: Array<{
      operation?: string;
      executionContextId?: string;
      documentId?: unknown;
    }> = [];
    const subscription = sandboxGlobal.refmd!.ui!.workspace!.onTileRender((event) => {
      receivedEvents.push({
        operation: event.operation,
        executionContextId: event.executionContextId,
        documentId: event.resource?.document_id,
      });
      event.respond({ rendered: true });
    });
    port.dispatch({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "request",
      request_id: "workspace-tile-render-1",
      operation: "ui.workspace_tile.render",
      execution_context_id: "panel-context-1",
      resource: { document_id: "document-1" },
      payload: { tile_id: "preview" },
    });
    const renderResponse = await waitForPosted(
      port,
      (message) =>
        typeof message === "object" &&
        message !== null &&
        (message as { request_id?: string }).request_id === "workspace-tile-render-1",
    );
    expect(receivedEvents).toEqual([
      {
        operation: "ui.workspace_tile.render",
        executionContextId: "panel-context-1",
        documentId: "document-1",
      },
    ]);
    expect(renderResponse).toMatchObject({
      kind: "response",
      request_id: "workspace-tile-render-1",
      payload: { rendered: true },
    });

    subscription.dispose();

    const statusEvents: Array<{
      operation?: string;
      executionContextId?: string;
      documentId?: unknown;
    }> = [];
    const statusSubscription = sandboxGlobal.refmd!.ui!.status!.onRefresh((event) => {
      statusEvents.push({
        operation: event.operation,
        executionContextId: event.executionContextId,
        documentId: event.resource?.document_id,
      });
      event.respond({ value: { kind: "text", text: "12 words" } });
    });
    port.dispatch({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "request",
      request_id: "status-refresh-1",
      operation: "ui.status.refresh",
      execution_context_id: "status-context-1",
      resource: { document_id: "document-1" },
      payload: { local_id: "contextual-status" },
    });
    const statusResponse = await waitForPosted(
      port,
      (message) =>
        typeof message === "object" &&
        message !== null &&
        (message as { request_id?: string }).request_id === "status-refresh-1",
    );
    expect(statusEvents).toEqual([
      {
        operation: "ui.status.refresh",
        executionContextId: "status-context-1",
        documentId: "document-1",
      },
    ]);
    expect(statusResponse).toMatchObject({
      kind: "response",
      request_id: "status-refresh-1",
      payload: { value: { kind: "text", text: "12 words" } },
    });
    statusSubscription.dispose();

    const badgeEvents: Array<{
      operation?: string;
      executionContextId?: string;
      documentId?: unknown;
    }> = [];
    const badgeSubscription = sandboxGlobal.refmd!.ui!.documentTree!.onBadgeRefresh((event) => {
      badgeEvents.push({
        operation: event.operation,
        executionContextId: event.executionContextId,
        documentId: event.resource?.document_id,
      });
      event.respond({ text: "Summary", tone: "info" });
    });
    port.dispatch({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "request",
      request_id: "badge-refresh-1",
      operation: "ui.document_tree.badge.refresh",
      execution_context_id: "badge-context-1",
      resource: { document_id: "document-1" },
      payload: { local_id: "contextual-document-badge" },
    });
    const badgeResponse = await waitForPosted(
      port,
      (message) =>
        typeof message === "object" &&
        message !== null &&
        (message as { request_id?: string }).request_id === "badge-refresh-1",
    );
    expect(badgeEvents).toEqual([
      {
        operation: "ui.document_tree.badge.refresh",
        executionContextId: "badge-context-1",
        documentId: "document-1",
      },
    ]);
    expect(badgeResponse).toMatchObject({
      kind: "response",
      request_id: "badge-refresh-1",
      payload: { text: "Summary", tone: "info" },
    });
    badgeSubscription.dispose();

    const commandEvents: Array<{ operation?: string; executionContextId?: string }> = [];
    const commandSubscription = sandboxGlobal.refmd!.commands!.onInvoke((event) => {
      commandEvents.push({
        operation: event.operation,
        executionContextId: event.executionContextId,
      });
      event.respond({ handled: true });
    });
    port.dispatch({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "request",
      request_id: "command-invoke-1",
      operation: "ui.command.invoke",
      execution_context_id: "command-context-1",
      payload: { local_id: "command" },
    });
    const commandResponse = await waitForPosted(
      port,
      (message) =>
        typeof message === "object" &&
        message !== null &&
        (message as { request_id?: string }).request_id === "command-invoke-1",
    );
    expect(commandEvents).toEqual([
      {
        operation: "ui.command.invoke",
        executionContextId: "command-context-1",
      },
    ]);
    expect(commandResponse).toMatchObject({
      kind: "response",
      request_id: "command-invoke-1",
      payload: { handled: true },
    });

    commandSubscription.dispose();
    port.dispatch({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "host-lifecycle",
      lifecycle: "close",
      reason: "test-close",
    });
    await Promise.resolve();
    expect(lifecycleEvents).toEqual(["load", "unload"]);
  });

  it("normalizes editor request execution contexts from the request payload", async () => {
    const script = buildPluginBootScript({
      bootNonce: "boot_nonce_1",
      frameGeneration: 3,
    });
    const sandboxGlobal: {
      refmd?: {
        editor: {
          onRequest(
            listener: (event: {
              operation?: string;
              executionContextId?: string;
              respond(payload: Record<string, unknown>): void;
            }) => void,
          ): { dispose(): void };
        };
      };
    } = {};
    const eventTarget = new FakeSandboxWindow();
    runSandboxBootScript(script, { sandboxGlobal, eventTarget });
    const port = new FakeSandboxMessagePort();
    eventTarget.dispatch({
      data: {
        protocol: PLUGIN_HOST_RPC_PROTOCOL,
        version: PLUGIN_HOST_RPC_VERSION,
        kind: "boot-port",
        frame_generation: 3,
      },
      ports: [port],
    });
    dispatchBootContext(port);

    const receivedEvents: Array<{ operation?: string; executionContextId?: string }> = [];
    sandboxGlobal.refmd!.editor.onRequest((event) => {
      receivedEvents.push({
        operation: event.operation,
        executionContextId: event.executionContextId,
      });
      event.respond({ handled: true });
    });
    port.dispatch({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "request",
      request_id: "formatter-request-1",
      operation: "formatter.run",
      payload: { execution_context_id: "formatter-context-1" },
    });

    const response = await waitForPosted(
      port,
      (message) =>
        typeof message === "object" &&
        message !== null &&
        (message as { request_id?: string }).request_id === "formatter-request-1",
    );
    expect(receivedEvents).toEqual([
      { operation: "formatter.run", executionContextId: "formatter-context-1" },
    ]);
    expect(response).toMatchObject({
      kind: "response",
      request_id: "formatter-request-1",
      payload: { handled: true },
    });
  });

  it("registers block and inline renderer handlers through the refmd renderer facade", async () => {
    const script = buildPluginBootScript({
      bootNonce: "boot_nonce_1",
      frameGeneration: 3,
    });
    const sandboxGlobal: {
      refmd?: {
        renderer: {
          register_block: (
            type: string,
            listener: (context: {
              kind?: string;
              type?: string;
              getSource(): Promise<string>;
              setHeight(height: number): Promise<unknown>;
            }) => Promise<Record<string, unknown>>,
          ) => { dispose(): void };
          register_inline_code: (
            listener: (context: {
              kind?: string;
              type?: string;
              getSource(): Promise<string>;
              setHeight(height: number): Promise<unknown>;
            }) => Promise<Record<string, unknown>>,
          ) => { dispose(): void };
        };
      };
    } = {};
    const eventTarget = new FakeSandboxWindow();
    runSandboxBootScript(script, { sandboxGlobal, eventTarget });
    const port = new FakeSandboxMessagePort();
    eventTarget.dispatch({
      data: {
        protocol: PLUGIN_HOST_RPC_PROTOCOL,
        version: PLUGIN_HOST_RPC_VERSION,
        kind: "boot-port",
        frame_generation: 3,
      },
      ports: [port],
    });
    dispatchBootContext(port);

    const renderedContexts: Array<{ kind?: string; type?: string; source: string }> = [];
    sandboxGlobal.refmd!.renderer.register_block("refmd-renderer-demo", async (context) => {
      const source = await context.getSource();
      renderedContexts.push({ kind: context.kind, type: context.type, source });
      await context.setHeight(42.2);
      return { rendered: true };
    });
    sandboxGlobal.refmd!.renderer.register_inline_code(async (context) => {
      const source = await context.getSource();
      renderedContexts.push({ kind: context.kind, type: context.type, source });
      return { rendered: true, inline: true };
    });
    port.dispatch({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "request",
      request_id: "render-request-1",
      operation: "renderer.render",
      payload: {
        execution_context_id: "renderer-context-1",
        kind: "block",
        type: "refmd-renderer-demo",
      },
      resource: { document_id: "document-1", block_id: "block-1" },
    });

    const sourceRequest = (await waitForPosted(
      port,
      (message) =>
        typeof message === "object" &&
        message !== null &&
        (message as { operation?: string }).operation === "renderer.getSource",
    )) as {
      request_id: string;
      execution_context_id?: string;
      resource?: Record<string, unknown>;
    };
    expect(sourceRequest.execution_context_id).toBe("renderer-context-1");
    expect(sourceRequest.resource).toEqual({ document_id: "document-1", block_id: "block-1" });

    port.dispatch({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: sourceRequest.request_id,
      payload: { source: "graph TD; A-->B" },
    });

    const heightRequest = (await waitForPosted(
      port,
      (message) =>
        typeof message === "object" &&
        message !== null &&
        (message as { operation?: string }).operation === "renderer.setHeight",
    )) as {
      request_id: string;
      payload?: Record<string, unknown>;
    };
    expect(heightRequest.payload).toEqual({
      execution_context_id: "renderer-context-1",
      height: 43,
    });

    port.dispatch({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: heightRequest.request_id,
      payload: { height: 43 },
    });

    const renderResponse = await waitForPosted(
      port,
      (message) =>
        typeof message === "object" &&
        message !== null &&
        (message as { request_id?: string }).request_id === "render-request-1",
    );
    expect(renderResponse).toMatchObject({
      kind: "response",
      request_id: "render-request-1",
      payload: { rendered: true },
    });
    expect(renderedContexts).toEqual([
      { kind: "block", type: "refmd-renderer-demo", source: "graph TD; A-->B" },
    ]);

    port.dispatch({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "request",
      request_id: "inline-render-request-1",
      operation: "renderer.render",
      payload: {
        execution_context_id: "renderer-inline-context-1",
        kind: "inline",
        type: "code",
      },
      resource: { document_id: "document-1", inline_id: "inline-1" },
    });
    const inlineSourceRequest = (await waitForPosted(
      port,
      (message) =>
        typeof message === "object" &&
        message !== null &&
        (message as { operation?: string }).operation === "renderer.getSource" &&
        (message as { execution_context_id?: string }).execution_context_id ===
          "renderer-inline-context-1",
    )) as {
      request_id: string;
      execution_context_id?: string;
      resource?: Record<string, unknown>;
    };
    expect(inlineSourceRequest.resource).toEqual({
      document_id: "document-1",
      inline_id: "inline-1",
    });
    port.dispatch({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: inlineSourceRequest.request_id,
      payload: { source: "`inline`" },
    });
    const inlineResponse = await waitForPosted(
      port,
      (message) =>
        typeof message === "object" &&
        message !== null &&
        (message as { request_id?: string }).request_id === "inline-render-request-1",
    );
    expect(inlineResponse).toMatchObject({
      kind: "response",
      request_id: "inline-render-request-1",
      payload: { rendered: true, inline: true },
    });
    expect(renderedContexts).toEqual([
      { kind: "block", type: "refmd-renderer-demo", source: "graph TD; A-->B" },
      { kind: "inline", type: "code", source: "`inline`" },
    ]);
  });

  it("rejects plugin-side pending RPC when the Host closes the lifecycle", async () => {
    const script = buildPluginBootScript({
      bootNonce: "boot_nonce_1",
      frameGeneration: 3,
    });
    const sandboxGlobal: {
      refmd?: {
        network: {
          fetch(payload?: unknown): Promise<unknown>;
        };
      };
    } = {};
    const eventTarget = new FakeSandboxWindow();
    runSandboxBootScript(script, { sandboxGlobal, eventTarget });
    const port = new FakeSandboxMessagePort();
    eventTarget.dispatch({
      data: {
        protocol: PLUGIN_HOST_RPC_PROTOCOL,
        version: PLUGIN_HOST_RPC_VERSION,
        kind: "boot-port",
        frame_generation: 3,
      },
      ports: [port],
    });
    dispatchBootContext(port);

    const pending = sandboxGlobal.refmd?.network.fetch({ endpoint_id: "pending" });
    expect(pending).toBeInstanceOf(Promise);
    port.dispatch({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "host-lifecycle",
      lifecycle: "close",
      reason: "application_removed",
    });

    await expect(pending).rejects.toMatchObject({
      code: "session_closed",
      message: "application_removed",
    });
  });
});

function createIdFactory(): () => string {
  let nextId = 0;
  return () => `test-id-${++nextId}`;
}

function sandboxTokens(iframe: HTMLIFrameElement): string[] {
  return iframe.getAttribute("sandbox")?.split(/\s+/).filter(Boolean) ?? [];
}

function resourceBootContext(resourceManifestHash: string) {
  return {
    capabilityGrantId: "capability-grant-1",
    applicationId: "application-1",
    consentEpoch: 1,
    bundleHash: "bundle-hash-1",
    manifestHash: "manifest-hash-1",
    resourceManifestHash,
  };
}

function bundleInput(options: {
  mainScript?: string;
  mainJsBytes?: Uint8Array;
  stylesCss?: string;
  manifestJson?: string;
  resources?: readonly {
    path: string;
    kind: string;
    mediaType: string;
    bytes: Uint8Array;
  }[];
}) {
  const mainJsBytes = options.mainJsBytes ?? textBytes(options.mainScript ?? "export {};");
  const stylesCssBytes = textBytes(options.stylesCss ?? "");
  const manifestJsonBytes = textBytes(
    options.manifestJson ?? '{"id":"plugin.example","version":"1.0.0"}',
  );
  const resources = options.resources ?? [];
  const resourceManifest = resources
    .map((resource) => ({
      path: resource.path,
      kind: resource.kind,
      media_type: resource.mediaType,
      byte_length: resource.bytes.byteLength,
      hash: blake3Base64Url(resource.bytes),
      executable: resource.kind === "wasm",
    }))
    .sort((left, right) => left.path.localeCompare(right.path));
  const resourceManifestHash = blake3Base64Url(
    canonicalizeStrictValueBytes(resourceManifest as unknown as StrictJsonValue),
  );
  return {
    mainJsBytes,
    stylesCssBytes,
    manifestJsonBytes,
    mainJsHash: blake3Base64Url(mainJsBytes),
    stylesCssHash: blake3Base64Url(stylesCssBytes),
    manifestHash: blake3Base64Url(manifestJsonBytes),
    resourceManifestHash,
    resourceManifest,
    resources: resources.map((resource) => ({
      path: resource.path,
      kind: resource.kind,
      mediaType: resource.mediaType,
      byteLength: resource.bytes.byteLength,
      hash: blake3Base64Url(resource.bytes),
      bytes: resource.bytes,
    })),
    bundleHash: blake3Base64Url(
      canonicalizeStrictBytes({
        manifest_hash: blake3Base64Url(manifestJsonBytes),
        main_js_hash: blake3Base64Url(mainJsBytes),
        styles_css_hash: blake3Base64Url(stylesCssBytes),
        resource_manifest_hash: resourceManifestHash,
      }),
    ),
  };
}

function textBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}
