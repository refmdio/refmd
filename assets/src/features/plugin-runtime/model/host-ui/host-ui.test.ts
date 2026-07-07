import { afterEach, describe, expect, it, vi } from "vite-plus/test";
import {
  PLUGIN_HOST_RPC_PROTOCOL,
  PLUGIN_HOST_RPC_VERSION,
  PluginHostMessageRouter,
  PluginHostRpcError,
  type PluginHostFrameWindow,
  type PluginHostRpcRequestEnvelope,
} from "../../lib/host-rpc/host-rpc";
import type { PluginAuditEvent } from "../../lib/capability/capability-enforcement";
import {
  closePluginUiModal,
  createPluginUiContributionRegistry,
  getActivePluginUiModalId,
  invokePluginUiCommand,
  pluginContributionId,
  pluginUiCommandResourcePayload,
  pluginUiEntryCommandEnabled,
  pluginUiEntryMatchesResource,
  registerPluginHostUiHandlers,
  validatePluginUiContribution,
  type PluginHostUiServices,
  type PluginUiContribution,
  type PluginUiCommandSurface,
  type PluginUiWorkspaceTileSurface,
} from "./host-ui";
import { renderPluginUiSettingsContribution } from "../../ui/host-ui/settings-renderer";

class FakeFrameWindow implements PluginHostFrameWindow {
  readonly messages: { message: unknown; targetOrigin: string; transfer: Transferable[] }[] = [];

  postMessage(message: unknown, targetOrigin: string, transfer: Transferable[] = []): void {
    this.messages.push({ message, targetOrigin, transfer });
  }
}

function createIdFactory(): () => string {
  let nextId = 0;
  return () => `ui-test-id-${++nextId}`;
}

function assertMessagePort(port: MessagePort | undefined): asserts port is MessagePort {
  expect(port).toBeInstanceOf(MessagePort);
}

function assertHTMLElement(value: unknown): asserts value is HTMLElement {
  expect(value).toBeInstanceOf(HTMLElement);
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

function owner() {
  return {
    pluginId: "plugin.example",
    packageId: "package.example",
    workspaceId: "00000000-0000-4000-8000-000000000012",
    applicationId: "00000000-0000-4000-8000-000000000011",
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
}

function uiId(localId: string, descriptor = owner()): string {
  return pluginContributionId(descriptor, localId);
}

afterEach(() => {
  closePluginUiModal();
});

function createRouterWithUi() {
  const router = new PluginHostMessageRouter({
    windowTarget: { addEventListener() {}, removeEventListener() {} },
    idFactory: createIdFactory(),
  });
  const registry = createPluginUiContributionRegistry();
  registerPluginHostUiHandlers(
    router,
    {
      registry,
      auditSink: () => true,
      commandSurface: {
        add() {},
        remove() {},
      },
    },
    owner(),
  );
  return { router, registry };
}

function boot(
  router: PluginHostMessageRouter,
  permissions: Parameters<PluginHostMessageRouter["createSession"]>[0]["permissions"] = [
    "ui:command",
    "ui:menu_item",
    "ui:statusbar",
    "ui:sidebar",
    "ui:document_tree:*",
    "ui:settings_iframe",
    "ui:settings_declarative",
    "ui:declarative_modal",
  ],
  options: Partial<Parameters<PluginHostMessageRouter["createSession"]>[0]> = {},
) {
  const frame = new FakeFrameWindow();
  const session = router.createSession({
    pluginId: "plugin.example",
    packageId: "package.example",
    applicationId: "00000000-0000-4000-8000-000000000011",
    activationId: "activation.example",
    ownerScopeKind: "workspace",
    userId: "user.example",
    deviceId: "device.example",
    workspaceId: "00000000-0000-4000-8000-000000000012",
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
  return { session, port };
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
    request_id: "ui-request",
    request_nonce: `ui-nonce-${Math.random()}`,
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
    operation,
    payload,
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

async function waitForCollectedMessage<T>(
  messages: readonly unknown[],
  predicate: (message: unknown) => message is T,
): Promise<T> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const message = messages.find(predicate);
    if (message) return message;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error("expected plugin Host RPC message was not observed");
}

describe("plugin Host UI contribution registry", () => {
  it("registers command and command-scoped menu contributions through Host RPC", async () => {
    const { router, registry } = createRouterWithUi();
    const { port } = boot(router);

    port.postMessage(
      requestEnvelope("ui.command.register", {
        surface: "command",
        local_id: "open.panel",
        title: "Open panel",
        plaintext_request: "none",
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      payload: { id: uiId("open.panel") },
    });

    port.postMessage(
      requestEnvelope("ui.menu.register_item", {
        surface: "menu_item",
        local_id: "open.panel.menu",
        placement: "command_palette",
        title: "Open panel",
        command_ref: { kind: "local_command", local_id: "open.panel" },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      payload: { id: uiId("open.panel.menu") },
    });
    expect(registry.list()).toHaveLength(2);
  });

  it("keeps third-party contribution ids stable across owner freshness changes", () => {
    const firstOwner = owner();
    const secondOwner = {
      ...firstOwner,
      workspaceId: "00000000-0000-4000-8000-000000000099",
      bundleHash: "bundle-hash-2",
      manifestHash: "manifest-hash-2",
      frameGeneration: firstOwner.frameGeneration + 1,
      consentEpoch: firstOwner.consentEpoch + 1,
      capabilityGrantId: "capability-grant-2",
    };

    expect(pluginContributionId(firstOwner, "open.panel")).toBe(
      `plugin:${firstOwner.applicationId}:${firstOwner.activationId}:open.panel`,
    );
    expect(pluginContributionId(secondOwner, "open.panel")).toBe(
      pluginContributionId(firstOwner, "open.panel"),
    );
  });

  it("separates third-party contribution ids across activations", () => {
    const firstOwner = owner();
    const secondOwner = {
      ...firstOwner,
      activationId: "activation.two",
    };

    expect(pluginContributionId(secondOwner, "open.panel")).not.toBe(
      pluginContributionId(firstOwner, "open.panel"),
    );
  });

  it("rejects missing capability before schema registration", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const auditEvents: PluginAuditEvent[] = [];
    registerPluginHostUiHandlers(router, { registry, auditSink: () => true }, owner());
    const { port } = boot(router, ["ui:command"], {
      auditSink(event) {
        auditEvents.push(event);
        return true;
      },
    });

    port.postMessage(
      requestEnvelope("ui.status.register_item", {
        surface: "status",
        local_id: "word.count",
        zone: "normal",
        value: { kind: "text", text: "12 words" },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "permission_denied" },
    });
    expect(registry.list()).toHaveLength(0);
    expect(auditEvents.at(-1)).toMatchObject({
      type: "plugin.ui.capability_mismatch_rejected",
      payloadKind: "ui.contribution",
      reasonCode: "permission_denied",
      action: { result: "denied" },
    });
  });

  it("authorizes document tree contributions with sidebar or document tree capability", async () => {
    const documentTreeContributions = [
      {
        operation: "ui.document_tree.register_action",
        payload: {
          surface: "document_tree_action",
          local_id: "tree.action",
          placement: "row_context_menu",
          title: "Open note",
          command_ref: { kind: "local_command", local_id: "open.note" },
        },
      },
      {
        operation: "ui.document_tree.register_badge",
        payload: {
          surface: "document_tree_badge",
          local_id: "tree.badge",
          placement: "row_trailing_badge",
          text: "Todo",
        },
      },
      {
        operation: "ui.document_tree.register_decoration",
        payload: {
          surface: "document_tree_decoration",
          local_id: "tree.decoration",
          placement: "row_prefix",
          tone: "info",
        },
      },
      {
        operation: "ui.document_tree.register_virtual_section",
        payload: {
          surface: "document_tree_virtual_section",
          local_id: "tree.section",
          placement: "before_tree",
          title: "Plugin notes",
          source_command_ref: { kind: "local_command", local_id: "load.section" },
        },
      },
    ] as const;

    for (const permissions of [["ui:sidebar"], ["ui:document_tree:*"]] as const) {
      const router = new PluginHostMessageRouter({
        windowTarget: { addEventListener() {}, removeEventListener() {} },
        idFactory: createIdFactory(),
      });
      const registry = createPluginUiContributionRegistry();
      const ownerDescriptor = owner();
      registry.register(ownerDescriptor, {
        surface: "command",
        local_id: "open.note",
        title: "Open note",
      });
      registry.register(ownerDescriptor, {
        surface: "command",
        local_id: "load.section",
        title: "Load section",
      });
      const { session, port } = boot(router, [...permissions]);
      registerPluginHostUiHandlers(
        router,
        { registry, auditSink: () => true },
        ownerDescriptor,
        session,
      );

      for (const contribution of documentTreeContributions) {
        port.postMessage(requestEnvelope(contribution.operation, contribution.payload));
        await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });
      }

      expect(registry.list()).toHaveLength(documentTreeContributions.length + 2);
    }
  });

  it("rejects document tree contributions without sidebar or document tree capability", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const auditEvents: PluginAuditEvent[] = [];
    const { session, port } = boot(router, ["ui:command"], {
      auditSink(event) {
        auditEvents.push(event);
        return true;
      },
    });
    registerPluginHostUiHandlers(router, { registry, auditSink: () => true }, owner(), session);

    port.postMessage(
      requestEnvelope("ui.document_tree.register_badge", {
        surface: "document_tree_badge",
        local_id: "tree.badge",
        placement: "row_trailing_badge",
        text: "Todo",
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "permission_denied" },
    });
    expect(registry.list()).toHaveLength(0);
    expect(auditEvents.at(-1)).toMatchObject({
      type: "plugin.ui.capability_mismatch_rejected",
      payloadKind: "ui.contribution",
      reasonCode: "permission_denied",
      action: { result: "denied" },
    });
  });

  it("rejects legacy Host UI operation names", async () => {
    const { router, registry } = createRouterWithUi();
    const { port } = boot(router, ["ui:statusbar", "ui:sidebar"]);

    port.postMessage(
      requestEnvelope("ui.status.register", {
        surface: "status",
        local_id: "word.count",
        zone: "normal",
        value: { kind: "text", text: "12 words" },
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "unknown_operation" },
    });

    port.postMessage(
      requestEnvelope("ui.sidebar_panel.register", {
        surface: "sidebar_panel",
        local_id: "outline",
        panel_id: "outline",
        title: "Outline",
        allowed_locations: ["right"],
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "unknown_operation" },
    });

    expect(registry.list()).toHaveLength(0);
  });

  it("updates registered status items through Host RPC without unregistering them", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const ownerDescriptor = owner();
    const auditEvents: PluginAuditEvent[] = [];
    const statusItems: { id: string; text: string }[] = [];
    const removedIds: string[] = [];
    const { session, port } = boot(router, ["ui:statusbar"], {
      auditSink(event) {
        auditEvents.push(event);
        return true;
      },
    });
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink(event) {
          auditEvents.push(event);
          return true;
        },
        statusSurface: {
          add(item) {
            statusItems.push({
              id: item.id,
              text: item.content.kind === "text" ? item.content.text : "iframe",
            });
          },
          remove(id) {
            removedIds.push(id);
          },
        },
      },
      ownerDescriptor,
      session,
    );

    port.postMessage(
      requestEnvelope("ui.status.register_item", {
        surface: "status",
        local_id: "storage.status",
        zone: "normal",
        value: { kind: "text", text: "Ready" },
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      payload: { id: uiId("storage.status", ownerDescriptor) },
    });

    port.postMessage(
      requestEnvelope("ui.status.update_item", {
        surface: "status",
        local_id: "storage.status",
        zone: "normal",
        value: { kind: "text", text: "Done" },
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "response",
      payload: { id: uiId("storage.status", ownerDescriptor) },
    });

    expect(statusItems).toEqual([
      { id: uiId("storage.status", ownerDescriptor), text: "Ready" },
      { id: uiId("storage.status", ownerDescriptor), text: "Done" },
    ]);
    expect(removedIds).toEqual([]);
    expect(registry.list("status")).toHaveLength(1);
    expect(auditEvents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: "plugin.ui.registration.accepted",
          operation: "ui.status.update_item",
          payloadKind: "ui.contribution",
        }),
      ]),
    );
  });

  it("rejects status item updates before registration", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const { session, port } = boot(router, ["ui:statusbar"]);
    registerPluginHostUiHandlers(
      router,
      { registry, auditSink: () => true, statusSurface: { add() {}, remove() {} } },
      owner(),
      session,
    );

    port.postMessage(
      requestEnvelope("ui.status.update_item", {
        surface: "status",
        local_id: "missing.status",
        zone: "normal",
        value: { kind: "text", text: "Done" },
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "ui_contribution_unknown" },
    });
  });

  it("fails closed when UI boundary denial audit cannot be recorded", async () => {
    const { router, registry } = createRouterWithUi();
    const { port } = boot(router, ["ui:command"], { auditSink: () => false });

    port.postMessage(
      requestEnvelope("ui.status.register_item", {
        surface: "status",
        local_id: "word.count",
        zone: "normal",
        value: { kind: "text", text: "12 words" },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "ui_audit_failed" },
    });
    expect(registry.list()).toHaveLength(0);
  });

  it("rejects persistent Host UI text from plaintext-capable plugins", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const auditEvents: PluginAuditEvent[] = [];
    const { session, port } = boot(router, [
      "ui:statusbar",
      "ui:document_tree:*",
      "document:read:active",
    ]);
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink(event) {
          auditEvents.push(event);
          return true;
        },
      },
      owner(),
      session,
    );

    port.postMessage(
      requestEnvelope("ui.status.register_item", {
        surface: "status",
        local_id: "word.count",
        zone: "normal",
        value: { kind: "text", text: "12 words" },
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "ui_plaintext_display_denied" },
    });

    port.postMessage(
      requestEnvelope("ui.document_tree.register_badge", {
        surface: "document_tree_badge",
        local_id: "summary.badge",
        placement: "row_trailing_badge",
        text: "Summary",
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "ui_plaintext_display_denied" },
    });

    expect(registry.list()).toHaveLength(0);
    expect(auditEvents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: "plugin.ui.registration.rejected",
          operation: "ui.status.register_item",
          reasonCode: "ui_plaintext_display_denied",
        }),
        expect.objectContaining({
          type: "plugin.ui.registration.rejected",
          operation: "ui.document_tree.register_badge",
          reasonCode: "ui_plaintext_display_denied",
        }),
      ]),
    );
  });

  it("allows plaintext-capable status and badge text only through Host contextual refresh", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const auditEvents: PluginAuditEvent[] = [];
    const statusItems: { id: string; text: string }[] = [];
    const { session, port } = boot(router, [
      "ui:statusbar",
      "ui:document_tree:*",
      "document:read:active",
    ]);
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink(event) {
          auditEvents.push(event);
          return true;
        },
        plaintextContext: {
          activeDocument: () => ({ documentId: "document-active", maxBytes: 4096 }),
        },
        statusSurface: {
          add(item) {
            statusItems.push({
              id: item.id,
              text: item.content.kind === "text" ? item.content.text : "iframe",
            });
          },
          remove() {},
        },
      },
      owner(),
      session,
    );
    const messages: unknown[] = [];
    port.addEventListener("message", (event) => {
      if (!isBootContextMessage(event.data)) messages.push(event.data);
    });
    port.start();

    port.postMessage(
      requestEnvelope("ui.status.register_item", {
        surface: "status",
        local_id: "word.count",
        zone: "normal",
        value: { kind: "text" },
        plaintext_request: "active_document",
      }),
    );
    await expect(
      waitForCollectedMessage(
        messages,
        (message): message is PluginHostRpcRequestEnvelope =>
          typeof message === "object" &&
          message !== null &&
          "kind" in message &&
          message.kind === "response" &&
          "payload" in message,
      ),
    ).resolves.toMatchObject({
      kind: "response",
      payload: { id: uiId("word.count") },
    });

    const statusRefresh = await waitForCollectedMessage(
      messages,
      (message): message is PluginHostRpcRequestEnvelope =>
        typeof message === "object" &&
        message !== null &&
        "operation" in message &&
        message.operation === "ui.status.refresh",
    );
    expect(statusRefresh).toMatchObject({
      kind: "request",
      operation: "ui.status.refresh",
      execution_context_id: expect.any(String),
      resource: { document_id: "document-active" },
      payload: { contribution_id: uiId("word.count"), local_id: "word.count" },
    });
    port.postMessage({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: statusRefresh!.request_id,
      payload: { value: { kind: "text", text: "12 words" } },
    });
    await new Promise((resolve) => setTimeout(resolve, 0));

    port.postMessage(
      requestEnvelope("ui.document_tree.register_badge", {
        surface: "document_tree_badge",
        local_id: "summary.badge",
        placement: "row_trailing_badge",
        plaintext_request: "active_document",
      }),
    );
    await expect(
      waitForCollectedMessage(
        messages,
        (message): message is PluginHostRpcRequestEnvelope =>
          typeof message === "object" &&
          message !== null &&
          "kind" in message &&
          message.kind === "response" &&
          "payload" in message &&
          typeof message.payload === "object" &&
          message.payload !== null &&
          "id" in message.payload &&
          message.payload.id === uiId("summary.badge"),
      ),
    ).resolves.toMatchObject({
      kind: "response",
      payload: { id: uiId("summary.badge") },
    });

    const badgeRefresh = await waitForCollectedMessage(
      messages,
      (message): message is PluginHostRpcRequestEnvelope =>
        typeof message === "object" &&
        message !== null &&
        "operation" in message &&
        message.operation === "ui.document_tree.badge.refresh",
    );
    expect(badgeRefresh).toMatchObject({
      kind: "request",
      operation: "ui.document_tree.badge.refresh",
      execution_context_id: expect.any(String),
      resource: { document_id: "document-active" },
      payload: { contribution_id: uiId("summary.badge"), local_id: "summary.badge" },
    });
    port.postMessage({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: badgeRefresh!.request_id,
      payload: { text: "Summary", tone: "info" },
    });
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(statusItems).toEqual([
      { id: uiId("word.count"), text: "" },
      { id: uiId("word.count"), text: "12 words" },
    ]);
    expect(registry.list("document_tree_badge")[0]).toMatchObject({
      display: { text: "Summary", tone: "info" },
    });
    expect(auditEvents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: "plugin.ui.invocation.accepted",
          operation: "ui.status.refresh",
        }),
        expect.objectContaining({
          type: "plugin.ui.invocation.accepted",
          operation: "ui.document_tree.badge.refresh",
        }),
      ]),
    );
  });

  it("records stale UI owner and consent denials before handler dispatch", async () => {
    const staleFrameRouter = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
      validateSession: () => ({ code: "plugin_runtime_stale", message: "runtime is stale" }),
    });
    const staleFrameEvents: PluginAuditEvent[] = [];
    registerPluginHostUiHandlers(
      staleFrameRouter,
      { registry: createPluginUiContributionRegistry(), auditSink: () => true },
      owner(),
    );
    const { port: staleFramePort } = boot(staleFrameRouter, ["ui:command"], {
      validateSession: undefined,
      auditSink(event) {
        staleFrameEvents.push(event);
        return true;
      },
    });

    staleFramePort.postMessage(
      requestEnvelope("ui.command.register", {
        surface: "command",
        local_id: "open.panel",
        title: "Open panel",
      }),
    );

    await expect(waitForPortMessage(staleFramePort)).resolves.toMatchObject({
      kind: "error",
      error: { code: "plugin_runtime_stale" },
    });
    expect(staleFrameEvents.at(-1)).toMatchObject({
      type: "plugin.ui.owner_stale_frame_rejected",
      reasonCode: "plugin_runtime_stale",
    });

    const staleConsentEvents: PluginAuditEvent[] = [];
    const { router } = createRouterWithUi();
    const { port } = boot(router, ["ui:command"], {
      auditSink(event) {
        staleConsentEvents.push(event);
        return true;
      },
    });

    port.postMessage(
      requestEnvelope(
        "ui.command.register",
        {
          surface: "command",
          local_id: "open.panel",
          title: "Open panel",
        },
        { consent_epoch: 4 },
      ),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "consent_epoch_mismatch" },
    });
    expect(staleConsentEvents.at(-1)).toMatchObject({
      type: "plugin.ui.consent_stale_rejected",
      reasonCode: "consent_epoch_mismatch",
    });
  });

  it("records accepted UI registrations before exposing them to Host surfaces", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const auditEvents: PluginAuditEvent[] = [];
    const commandIds: string[] = [];
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink(event) {
          auditEvents.push(event);
          return true;
        },
        commandSurface: {
          add(command) {
            commandIds.push(command.id);
          },
          remove(commandId) {
            const index = commandIds.indexOf(commandId);
            if (index >= 0) commandIds.splice(index, 1);
          },
        },
      },
      owner(),
    );
    const { port } = boot(router, ["ui:command"]);

    port.postMessage(
      requestEnvelope("ui.command.register", {
        surface: "command",
        local_id: "open.panel",
        title: "Open panel",
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });
    expect(auditEvents.at(-1)).toMatchObject({
      type: "plugin.ui.registration.accepted",
      payloadKind: "ui.contribution",
      operation: "ui.command.register",
      action: { result: "allowed" },
    });
    expect(commandIds).toEqual([uiId("open.panel")]);
  });

  it("keeps Host UI registrations invisible while accepted audit is pending", async () => {
    async function runDelayedRegistration(params: {
      operation: string;
      payload: unknown;
      permissions: Parameters<PluginHostMessageRouter["createSession"]>[0]["permissions"];
      services: Omit<PluginHostUiServices, "registry" | "auditSink">;
      expectPending: (registry: ReturnType<typeof createPluginUiContributionRegistry>) => void;
      expectAccepted: (registry: ReturnType<typeof createPluginUiContributionRegistry>) => void;
    }) {
      const router = new PluginHostMessageRouter({
        windowTarget: { addEventListener() {}, removeEventListener() {} },
        idFactory: createIdFactory(),
      });
      const registry = createPluginUiContributionRegistry();
      let resolveAudit: (value: boolean) => void = () => {};
      let markAuditStarted: () => void = () => {};
      const auditStarted = new Promise<void>((resolve) => {
        markAuditStarted = resolve;
      });
      const auditResult = new Promise<boolean>((resolve) => {
        resolveAudit = resolve;
      });

      registerPluginHostUiHandlers(
        router,
        {
          registry,
          auditSink() {
            markAuditStarted();
            return auditResult;
          },
          ...params.services,
        },
        owner(),
      );
      const { port } = boot(router, params.permissions);
      const response = waitForPortMessage(port);

      port.postMessage(requestEnvelope(params.operation, params.payload));
      await auditStarted;
      params.expectPending(registry);
      resolveAudit(true);
      await expect(response).resolves.toMatchObject({ kind: "response" });
      params.expectAccepted(registry);
    }

    const commandIds: string[] = [];
    await runDelayedRegistration({
      operation: "ui.command.register",
      permissions: ["ui:command"],
      payload: {
        surface: "command",
        local_id: "open.panel",
        title: "Open panel",
      },
      services: {
        commandSurface: {
          add(command) {
            commandIds.push(command.id);
          },
          remove(commandId) {
            const index = commandIds.indexOf(commandId);
            if (index >= 0) commandIds.splice(index, 1);
          },
        },
      },
      expectPending(registry) {
        expect(registry.list()).toEqual([]);
        expect(commandIds).toEqual([]);
      },
      expectAccepted(registry) {
        expect(registry.list()).toHaveLength(1);
        expect(commandIds).toEqual([uiId("open.panel")]);
      },
    });

    const statusIds: string[] = [];
    await runDelayedRegistration({
      operation: "ui.status.register_item",
      permissions: ["ui:statusbar"],
      payload: {
        surface: "status",
        local_id: "word.count",
        zone: "normal",
        value: { kind: "text", text: "12 words" },
      },
      services: {
        statusSurface: {
          add(item) {
            statusIds.push(item.id);
          },
          remove(id) {
            const index = statusIds.indexOf(id);
            if (index >= 0) statusIds.splice(index, 1);
          },
        },
      },
      expectPending(registry) {
        expect(registry.list()).toEqual([]);
        expect(statusIds).toEqual([]);
      },
      expectAccepted(registry) {
        expect(registry.list()).toHaveLength(1);
        expect(statusIds).toEqual([uiId("word.count")]);
      },
    });

    const workspaceTileIds: string[] = [];
    await runDelayedRegistration({
      operation: "ui.workspace.register_tile",
      permissions: ["ui:workspace_tile"],
      payload: {
        surface: "workspace_tile",
        local_id: "slides.preview",
        tile_id: "slides.preview",
        title: "Slides preview",
        scope: "document",
        preferred_open: "document_menu",
      },
      services: {
        iframeSurface: { mount() {}, unmount() {} },
        workspaceTileSurface: {
          add(tile) {
            workspaceTileIds.push(tile.id);
          },
          remove(id) {
            const index = workspaceTileIds.indexOf(id);
            if (index >= 0) workspaceTileIds.splice(index, 1);
          },
        },
      },
      expectPending(registry) {
        expect(registry.list()).toEqual([]);
        expect(workspaceTileIds).toEqual([]);
      },
      expectAccepted(registry) {
        expect(registry.list()).toHaveLength(1);
        expect(workspaceTileIds).toEqual([uiId("slides.preview")]);
      },
    });

    const auxiliaryPaneIds: string[] = [];
    await runDelayedRegistration({
      operation: "ui.auxiliary.register_pane",
      permissions: ["ui:auxiliary_pane"],
      payload: {
        surface: "auxiliary_pane",
        local_id: "comments",
        pane_id: "comments",
        title: "Comments",
        allowed_locations: ["right"],
      },
      services: {
        iframeSurface: { mount() {}, unmount() {} },
        auxiliaryPaneSurface: {
          add(pane) {
            auxiliaryPaneIds.push(pane.id);
          },
          remove(id) {
            const index = auxiliaryPaneIds.indexOf(id);
            if (index >= 0) auxiliaryPaneIds.splice(index, 1);
          },
        },
      },
      expectPending(registry) {
        expect(registry.list()).toEqual([]);
        expect(auxiliaryPaneIds).toEqual([]);
      },
      expectAccepted(registry) {
        expect(registry.list()).toHaveLength(1);
        expect(auxiliaryPaneIds).toEqual([uiId("comments")]);
      },
    });
  });

  it("rolls back registration when the UI audit sink rejects the event", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const commandIds: string[] = [];
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink: () => false,
        commandSurface: {
          add(command) {
            commandIds.push(command.id);
          },
          remove(commandId) {
            const index = commandIds.indexOf(commandId);
            if (index >= 0) commandIds.splice(index, 1);
          },
        },
      },
      owner(),
    );
    const { port } = boot(router, ["ui:command"]);

    port.postMessage(
      requestEnvelope("ui.command.register", {
        surface: "command",
        local_id: "open.panel",
        title: "Open panel",
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "ui_audit_failed" },
    });
    expect(registry.list()).toHaveLength(0);
    expect(commandIds).toEqual([]);
  });

  it("rolls back registration after accepted audit when the session closes during materialization", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const auditEvents: PluginAuditEvent[] = [];
    const commandIds: string[] = [];
    const { session, port } = boot(router, ["ui:command"]);
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink(event) {
          auditEvents.push(event);
          return true;
        },
        commandSurface: {
          add(command) {
            commandIds.push(command.id);
            session.close("registration_owner_closed");
          },
          remove(commandId) {
            const index = commandIds.indexOf(commandId);
            if (index >= 0) commandIds.splice(index, 1);
          },
        },
      },
      owner(),
      session,
    );

    port.postMessage(
      requestEnvelope("ui.command.register", {
        surface: "command",
        local_id: "open.panel",
        title: "Open panel",
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "host-lifecycle",
      lifecycle: "close",
      reason: "registration_owner_closed",
    });
    expect(registry.list()).toHaveLength(0);
    expect(commandIds).toEqual([]);
    expect(auditEvents.map((event) => event.type)).toContain("plugin.ui.registration.accepted");
    expect(auditEvents.map((event) => event.type)).not.toContain("plugin.ui.registration.rejected");
  });

  it("rolls back registration when Host surface materialization fails", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const auditEvents: PluginAuditEvent[] = [];
    const commandIds: string[] = [];
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink(event) {
          auditEvents.push(event);
          return true;
        },
        commandSurface: {
          add(command) {
            commandIds.push(command.id);
            throw new Error("surface unavailable");
          },
          remove(commandId) {
            const index = commandIds.indexOf(commandId);
            if (index >= 0) commandIds.splice(index, 1);
          },
        },
      },
      owner(),
    );
    const { port } = boot(router, ["ui:command"]);

    port.postMessage(
      requestEnvelope("ui.command.register", {
        surface: "command",
        local_id: "open.panel",
        title: "Open panel",
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "ui_surface_add_failed" },
    });
    expect(registry.list()).toHaveLength(0);
    expect(commandIds).toEqual([]);
    expect(auditEvents.at(-1)).toMatchObject({
      type: "plugin.ui.registration.rejected",
      action: { result: "denied", reason_code: "ui_surface_add_failed" },
    });
  });

  it("rejects command registration when the Host command surface is unavailable", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink: () => true,
      },
      owner(),
    );
    const { port } = boot(router, ["ui:command"]);

    port.postMessage(
      requestEnvelope("ui.command.register", {
        surface: "command",
        local_id: "open.panel",
        title: "Open panel",
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "ui_surface_unavailable" },
    });
    expect(registry.list()).toHaveLength(0);
  });

  it("records rejected UI registrations when payload validation fails", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const auditEvents: PluginAuditEvent[] = [];
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink(event) {
          auditEvents.push(event);
          return true;
        },
      },
      owner(),
    );
    const { port } = boot(router, ["ui:command"]);

    port.postMessage(
      requestEnvelope("ui.command.register", {
        surface: "command",
        local_id: "bad.command",
        title: "Verified encryption",
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "ui_protected_label_denied" },
    });
    expect(auditEvents.at(-1)).toMatchObject({
      type: "plugin.ui.registration.rejected",
      payloadKind: "ui.contribution",
      operation: "ui.command.register",
      action: { result: "denied", reason_code: "ui_protected_label_denied" },
    });
    expect(registry.list()).toHaveLength(0);
  });

  it("rejects host objects, raw markup, and protected wording", () => {
    expect(() =>
      validatePluginUiContribution({
        surface: "status",
        local_id: "bad.status",
        zone: "normal",
        value: { kind: "text", text: "Verified encryption" },
      }),
    ).toThrowError(expect.objectContaining({ code: "ui_protected_label_denied" }));

    expect(() =>
      validatePluginUiContribution({
        surface: "declarative_modal",
        local_id: "bad.modal",
        modal_id: "bad.modal",
        title: "Bad modal",
        trigger_command_ref: { kind: "local_command", local_id: "open.panel" },
        body: { kind: "schema_form", fields: [], raw_html: "<b>bad</b>" },
      } as never),
    ).toThrowError(expect.objectContaining({ code: "ui_schema_forbidden" }));

    expect(() =>
      validatePluginUiContribution({
        surface: "command",
        local_id: "bad.command",
        title: "Bad command",
        callback: () => undefined,
      } as never),
    ).toThrowError(expect.objectContaining({ code: "ui_schema_forbidden" }));

    expect(() =>
      validatePluginUiContribution({
        surface: "command",
        local_id: "plugin:open.panel",
        title: "Bad command",
      }),
    ).toThrowError(expect.objectContaining({ code: "ui_local_id_invalid" }));

    expect(() =>
      validatePluginUiContribution({
        surface: "command",
        local_id: "bad.workspace",
        title: "Bad workspace query",
        plaintext_request: "workspace_documents",
      } as never),
    ).toThrowError(expect.objectContaining({ code: "ui_schema_invalid" }));
  });

  it("validates workspace document query reason text", () => {
    const validContribution: PluginUiContribution = {
      surface: "command",
      local_id: "summarize.workspace",
      title: "Summarize workspace",
      document_query: {
        scope: "workspace",
        max_documents: 25,
        max_bytes: 4096,
        reason: "Summarize project notes",
      },
    };

    expect(validatePluginUiContribution(validContribution)).toEqual(validContribution);

    const invalidReasons = [
      "",
      "x".repeat(200),
      "Security approval summary",
      "Summarize\u0000notes",
      "<svg onload=alert(1)>",
      "[Summarize](https://example.com)",
    ];

    for (const reason of invalidReasons) {
      expect(() =>
        validatePluginUiContribution({
          surface: "command",
          local_id: "bad.workspace.reason",
          title: "Bad workspace query",
          document_query: {
            scope: "workspace",
            max_documents: 25,
            max_bytes: 4096,
            reason,
          },
        }),
      ).toThrowError(expect.objectContaining({ code: expect.stringMatching(/^ui_|^permission/) }));
    }
  });

  it("rejects workspace document query command registration before materialization without workspace authority", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const commands: Parameters<PluginUiCommandSurface["add"]>[0][] = [];
    const { session, port } = boot(router, ["ui:command"], {
      documentScope: { workspaceReadAllowed: true },
    });
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink: () => true,
        commandSurface: {
          add(command) {
            commands.push(command);
          },
          remove() {},
        },
      },
      owner(),
      session,
    );

    port.postMessage(
      requestEnvelope("ui.command.register", {
        surface: "command",
        local_id: "summarize.workspace",
        title: "Summarize workspace",
        document_query: { scope: "workspace", max_documents: 25, max_bytes: 4096 },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "permission_denied" },
    });
    expect(registry.list()).toEqual([]);
    expect(commands).toEqual([]);
  });

  it("rejects workspace tile placement document query and validates tile action query authority", () => {
    const registry = createPluginUiContributionRegistry();
    const contribution = {
      surface: "workspace_tile",
      local_id: "board",
      tile_id: "board",
      title: "Board",
      scope: "workspace",
      document_query: { scope: "workspace", max_documents: 25, max_bytes: 4096 },
    } as unknown as PluginUiContribution;

    expect(() => validatePluginUiContribution(contribution)).toThrowError(
      expect.objectContaining({ code: "ui_schema_invalid" }),
    );
    expect(() =>
      registry.register(owner(), contribution, ["ui:workspace_tile", "document:read:workspace"], {
        workspaceReadAllowed: true,
      }),
    ).toThrowError(expect.objectContaining({ code: "ui_schema_invalid" }));

    const actionContribution: PluginUiContribution = {
      surface: "workspace_tile_action",
      local_id: "board.refresh",
      tile_ref: { kind: "local_tile", local_id: "board" },
      action_id: "refresh",
      title: "Refresh",
      placement: "refresh",
      document_query: { scope: "workspace", max_documents: 25, max_bytes: 4096 },
    };

    expect(validatePluginUiContribution(actionContribution)).toEqual(actionContribution);
    expect(() =>
      validatePluginUiContribution({
        ...actionContribution,
        placement: undefined,
      } as unknown as PluginUiContribution),
    ).toThrowError(expect.objectContaining({ code: "ui_schema_invalid" }));

    expect(() =>
      registry.register(owner(), actionContribution, ["ui:workspace_tile"], {
        workspaceReadAllowed: true,
      }),
    ).toThrowError(expect.objectContaining({ code: "permission_denied" }));

    expect(() =>
      registry.register(
        owner(),
        actionContribution,
        ["ui:workspace_tile", "document:read:workspace"],
        {},
      ),
    ).toThrowError(expect.objectContaining({ code: "document_scope_denied" }));
  });

  it("rejects command refs outside the same owner", () => {
    const registry = createPluginUiContributionRegistry();
    const firstOwner = owner();
    const secondOwner = {
      ...owner(),
      applicationId: "00000000-0000-4000-8000-000000000099",
      activationId: "activation.example",
    };

    registry.register(firstOwner, {
      surface: "command",
      local_id: "open.panel",
      title: "Open panel",
    });

    expect(() =>
      registry.register(secondOwner, {
        surface: "menu_item",
        local_id: "open.panel.menu",
        placement: "command_palette",
        title: "Open panel",
        command_ref: { kind: "local_command", local_id: "open.panel" },
      }),
    ).toThrowError(expect.objectContaining({ code: "ui_command_ref_denied" }));

    expect(() =>
      registry.register(secondOwner, {
        surface: "auxiliary_pane",
        local_id: "comments",
        pane_id: "comments",
        title: "Comments",
        allowed_locations: ["right"],
        actions: [
          {
            action_id: "send",
            title: "Send",
            command_ref: { kind: "local_command", local_id: "open.panel" },
          },
        ],
      }),
    ).toThrowError(expect.objectContaining({ code: "ui_command_ref_denied" }));
  });

  it("clears owner entries on handler teardown", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const unregister = registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink: () => true,
        commandSurface: {
          add() {},
          remove() {},
        },
      },
      owner(),
    );
    const { port } = boot(router, ["ui:command"]);

    port.postMessage(
      requestEnvelope("ui.command.register", {
        surface: "command",
        local_id: "open.panel",
        title: "Open panel",
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });
    expect(registry.list()).toHaveLength(1);

    unregister();
    expect(registry.list()).toHaveLength(0);
  });

  it("records owner cleanup lifecycle and live UI entry disposal without keeping entries alive", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const auditEvents: PluginAuditEvent[] = [];
    const { session, port } = boot(router, ["ui:command"]);
    const unregister = registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink(event) {
          auditEvents.push(event);
          return true;
        },
        commandSurface: {
          add() {},
          remove() {},
        },
      },
      owner(),
      session,
    );

    port.postMessage(
      requestEnvelope("ui.command.register", {
        surface: "command",
        local_id: "open.panel",
        title: "Open panel",
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });

    unregister();
    await Promise.resolve();

    expect(registry.list()).toHaveLength(0);
    expect(auditEvents.map((event) => event.type)).toEqual(
      expect.arrayContaining([
        "plugin.ui.iframe.lifecycle",
        "plugin.ui.iframe.closed_with_live_entries",
        "plugin.ui.registry_entry_disposed",
      ]),
    );
  });

  it("records cleanup audits for authority-revocation teardown reasons", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const auditEvents: PluginAuditEvent[] = [];
    const { session, port } = boot(router, ["ui:command"]);
    const unregister = registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink(event) {
          auditEvents.push(event);
          return true;
        },
        commandSurface: {
          add() {},
          remove() {},
        },
      },
      owner(),
      session,
    );

    port.postMessage(
      requestEnvelope("ui.command.register", {
        surface: "command",
        local_id: "open.panel",
        title: "Open panel",
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });

    unregister("workspace_left");
    await Promise.resolve();

    const cleanupEvents = auditEvents.filter((event) =>
      [
        "plugin.ui.iframe.lifecycle",
        "plugin.ui.iframe.closed_with_live_entries",
        "plugin.ui.registry_entry_disposed",
      ].includes(event.type),
    );
    expect(registry.list()).toHaveLength(0);
    expect(cleanupEvents.map((event) => event.type)).toEqual([
      "plugin.ui.iframe.lifecycle",
      "plugin.ui.iframe.closed_with_live_entries",
      "plugin.ui.registry_entry_disposed",
    ]);
    expect(cleanupEvents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          class: "security_runtime",
          action: expect.objectContaining({
            operation: "ui.cleanup",
            reason_code: "workspace_left",
            result: "denied",
          }),
        }),
      ]),
    );
  });

  it("skips Host UI cleanup audits during session cleanup", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const auditEvents: PluginAuditEvent[] = [];
    const { session, port } = boot(router, ["ui:command"]);
    const unregister = registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink(event) {
          auditEvents.push(event);
          return true;
        },
        commandSurface: {
          add() {},
          remove() {},
        },
      },
      owner(),
      session,
    );

    port.postMessage(
      requestEnvelope("ui.command.register", {
        surface: "command",
        local_id: "open.panel",
        title: "Open panel",
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });

    unregister("session_cleanup");
    await Promise.resolve();

    expect(registry.list()).toHaveLength(0);
    expect(auditEvents.filter((event) => event.action.operation === "ui.cleanup")).toEqual([]);
  });

  it("keeps authority-revocation cleanup fail-closed when cleanup audit fails", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const auditEvents: PluginAuditEvent[] = [];
    const { session, port } = boot(router, ["ui:command"]);
    const unregister = registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink(event) {
          auditEvents.push(event);
          return ![
            "plugin.ui.iframe.lifecycle",
            "plugin.ui.iframe.closed_with_live_entries",
            "plugin.ui.registry_entry_disposed",
          ].includes(event.type);
        },
        commandSurface: {
          add() {},
          remove() {},
        },
      },
      owner(),
      session,
    );

    port.postMessage(
      requestEnvelope("ui.command.register", {
        surface: "command",
        local_id: "open.panel",
        title: "Open panel",
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });

    unregister("plugin_consent_revoked");
    await Promise.resolve();
    await Promise.resolve();

    expect(registry.list()).toHaveLength(0);
    expect(auditEvents).toContainEqual(
      expect.objectContaining({
        type: "plugin.ui.registry_entry_disposed",
        action: expect.objectContaining({
          operation: "ui.cleanup",
          reason_code: "plugin_consent_revoked",
        }),
      }),
    );
  });

  it("mirrors registered commands to the Host command surface", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const commandIds: string[] = [];
    const unregister = registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink: () => true,
        commandSurface: {
          add(command) {
            commandIds.push(command.id);
          },
          remove(commandId) {
            const index = commandIds.indexOf(commandId);
            if (index >= 0) commandIds.splice(index, 1);
          },
        },
      },
      owner(),
    );
    const { port } = boot(router, ["ui:command"]);

    port.postMessage(
      requestEnvelope("ui.command.register", {
        surface: "command",
        local_id: "open.panel",
        title: "Open panel",
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });
    expect(commandIds).toEqual([uiId("open.panel")]);

    port.postMessage(
      requestEnvelope("ui.contribution.unregister", {
        local_id: "open.panel",
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });
    expect(commandIds).toEqual([]);

    unregister();
  });

  it("mirrors command palette menu items to the Host command surface", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const commandIds: string[] = [];
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink: () => true,
        commandSurface: {
          add(command) {
            commandIds.push(command.id);
          },
          remove(commandId) {
            const index = commandIds.indexOf(commandId);
            if (index >= 0) commandIds.splice(index, 1);
          },
        },
      },
      owner(),
    );
    const { port } = boot(router, ["ui:command", "ui:menu_item"]);

    port.postMessage(
      requestEnvelope("ui.command.register", {
        surface: "command",
        local_id: "open.panel",
        title: "Open panel",
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });
    port.postMessage(
      requestEnvelope("ui.menu.register_item", {
        surface: "menu_item",
        local_id: "open.panel.palette",
        placement: "command_palette",
        title: "Open panel menu",
        command_ref: { kind: "local_command", local_id: "open.panel" },
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });

    expect(commandIds).toEqual([uiId("open.panel"), uiId("open.panel.palette")]);
  });

  it("keeps materialized command ids distinct across owner generations", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const firstOwner = owner();
    const nextOwner = {
      ...owner(),
      frameGeneration: 8,
      consentEpoch: 4,
      capabilityGrantId: "capability-grant-2",
    };
    const commandIds: string[] = [];
    const commandSurface = {
      add(command: { id: string }) {
        commandIds.push(command.id);
      },
      remove(commandId: string) {
        const index = commandIds.indexOf(commandId);
        if (index >= 0) commandIds.splice(index, 1);
      },
    };
    registerPluginHostUiHandlers(
      router,
      { registry, auditSink: () => true, commandSurface },
      firstOwner,
    );
    registerPluginHostUiHandlers(
      router,
      { registry, auditSink: () => true, commandSurface },
      nextOwner,
    );
    const first = boot(router, ["ui:command"]);
    const next = boot(router, ["ui:command"], {
      frameGeneration: nextOwner.frameGeneration,
      consentEpoch: nextOwner.consentEpoch,
      capabilityGrantId: nextOwner.capabilityGrantId,
    });

    first.port.postMessage(
      requestEnvelope("ui.command.register", {
        surface: "command",
        local_id: "open.panel",
        title: "Open panel",
      }),
    );
    await expect(waitForPortMessage(first.port)).resolves.toMatchObject({ kind: "response" });
    next.port.postMessage(
      requestEnvelope(
        "ui.command.register",
        {
          surface: "command",
          local_id: "open.panel",
          title: "Open panel",
        },
        {
          frame_generation: nextOwner.frameGeneration,
          consent_epoch: nextOwner.consentEpoch,
          capability_grant_id: nextOwner.capabilityGrantId,
        },
      ),
    );
    await expect(waitForPortMessage(next.port)).resolves.toMatchObject({ kind: "response" });

    expect(commandIds).toEqual([uiId("open.panel", firstOwner), uiId("open.panel", nextOwner)]);

    first.port.postMessage(
      requestEnvelope("ui.contribution.unregister", {
        local_id: "open.panel",
      }),
    );
    await expect(waitForPortMessage(first.port)).resolves.toMatchObject({ kind: "response" });
    expect(commandIds).toEqual([uiId("open.panel", nextOwner)]);
  });

  it("evaluates Host-owned UI predicates before rendering or invoking entries", () => {
    const registry = createPluginUiContributionRegistry();
    const ownerDescriptor = owner();
    registry.register(ownerDescriptor, {
      surface: "command",
      local_id: "open.panel",
      title: "Open panel",
      enablement: {
        kind: "all",
        of: [{ kind: "document_open" }, { kind: "capability", has: "document:read:active" }],
      },
    });
    registry.register(ownerDescriptor, {
      surface: "menu_item",
      local_id: "open.panel.menu",
      placement: "document_tab_menu",
      title: "Open panel menu",
      command_ref: { kind: "local_command", local_id: "open.panel" },
      when: { kind: "resource_kind", is: "document" },
    });
    registry.register(ownerDescriptor, {
      surface: "document_tree_badge",
      local_id: "selected.badge",
      placement: "row_trailing_badge",
      text: "Selected",
      tone: "info",
      when: { kind: "selection_present" },
    });

    const commandEntry = registry
      .list()
      .find((entry) => entry.contribution.local_id === "open.panel");
    const menuEntry = registry
      .list()
      .find((entry) => entry.contribution.local_id === "open.panel.menu");
    const badgeEntry = registry
      .list()
      .find((entry) => entry.contribution.local_id === "selected.badge");
    const documentContext = {
      resourceKind: "document" as const,
      workspaceId: ownerDescriptor.workspaceId,
      documentOpen: true,
      selectionPresent: false,
      capabilities: ["document:read:active"],
    };

    expect(pluginUiEntryMatchesResource(menuEntry!, documentContext)).toBe(true);
    expect(
      pluginUiEntryMatchesResource(menuEntry!, {
        ...documentContext,
        workspaceId: "00000000-0000-4000-8000-000000000099",
      }),
    ).toBe(false);
    expect(pluginUiEntryCommandEnabled(commandEntry!, documentContext, registry)).toBe(true);
    expect(pluginUiEntryCommandEnabled(menuEntry!, documentContext, registry)).toBe(true);
    expect(pluginUiEntryMatchesResource(badgeEntry!, documentContext)).toBe(false);
    expect(
      pluginUiEntryCommandEnabled(
        menuEntry!,
        { ...documentContext, resourceKind: "workspace" },
        registry,
      ),
    ).toBe(false);
    expect(
      pluginUiEntryCommandEnabled(
        menuEntry!,
        {
          ...documentContext,
          capabilities: [],
        },
        registry,
      ),
    ).toBe(false);
    expect(pluginUiCommandResourcePayload(menuEntry!, documentContext, registry)).toBeNull();
    expect(
      pluginUiCommandResourcePayload(
        menuEntry!,
        { ...documentContext, documentId: "document-1" },
        registry,
      ),
    ).toEqual({
      resource: {
        kind: "document",
        workspace_id: ownerDescriptor.workspaceId,
        document_id: "document-1",
      },
    });
  });

  it("retains registered capabilities on listed UI entries", () => {
    const registry = createPluginUiContributionRegistry();
    const ownerDescriptor = owner();
    registry.register(
      ownerDescriptor,
      {
        surface: "document_tree_badge",
        local_id: "summarize",
        placement: "row_trailing_badge",
        text: "Summarize",
        tone: "info",
        when: { kind: "capability", has: "document:read:active" },
      },
      ["document:read:active"],
    );

    const entry = registry.list("document_tree_badge")[0];
    expect(entry.capabilities).toEqual(["document:read:active"]);
    expect(
      pluginUiEntryMatchesResource(entry, {
        resourceKind: "document",
        workspaceId: ownerDescriptor.workspaceId,
        documentOpen: true,
        capabilities: entry.capabilities,
      }),
    ).toBe(true);
  });

  it("guards materialized workspace commands with Host resource predicates", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const commands: Parameters<PluginUiCommandSurface["add"]>[0][] = [];
    let activeDocumentId: string | null = null;
    const { session, port } = boot(router, ["ui:command"]);
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink: () => true,
        commandSurface: {
          add(command) {
            commands.push(command);
          },
          remove() {},
        },
        resourceContext: {
          workspace() {
            return {
              resourceKind: "workspace",
              workspaceId: owner().workspaceId,
              capabilities: ["document:read:active"],
            };
          },
          activeDocument() {
            if (!activeDocumentId) return null;
            return {
              resourceKind: "document",
              workspaceId: owner().workspaceId,
              documentId: activeDocumentId,
              documentOpen: true,
              selectionPresent: false,
              capabilities: ["document:read:active"],
            };
          },
        },
      },
      owner(),
      session,
    );
    const messages: unknown[] = [];
    port.addEventListener("message", (event) => messages.push(event.data));
    port.start();

    port.postMessage(
      requestEnvelope("ui.command.register", {
        surface: "command",
        local_id: "open.active",
        title: "Open active",
        when: { kind: "resource_kind", is: "document" },
        enablement: { kind: "capability", has: "document:read:active" },
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });
    messages.length = 0;

    const command = commands.at(-1);
    expect(command?.checkCallback?.(true)).toBe(false);
    command?.callback();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(messages).toEqual([]);

    activeDocumentId = "document-1";
    expect(command?.checkCallback?.(true)).toBe(true);
    command?.callback();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(messages.at(-1)).toMatchObject({
      kind: "request",
      operation: "ui.command.invoke",
      payload: {
        contribution_id: uiId("open.active"),
        local_id: "open.active",
        payload: {
          resource: {
            kind: "document",
            workspace_id: owner().workspaceId,
            document_id: "document-1",
          },
        },
      },
    });
  });

  it("guards command palette execution with active editor resource predicates", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const commands: Parameters<PluginUiCommandSurface["add"]>[0][] = [];
    let selectionPresent = false;
    const { session, port } = boot(router, ["ui:command"]);
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink: () => true,
        commandSurface: {
          add(command) {
            commands.push(command);
          },
          remove() {},
        },
        resourceContext: {
          workspace() {
            return { resourceKind: "workspace", workspaceId: owner().workspaceId };
          },
          activeDocument() {
            return {
              resourceKind: "document",
              workspaceId: owner().workspaceId,
              documentId: "document-1",
              documentOpen: true,
              selectionPresent,
            };
          },
        },
      },
      owner(),
      session,
    );

    port.postMessage(
      requestEnvelope("ui.command.register", {
        surface: "command",
        local_id: "wrap.selection",
        title: "Wrap selection",
        when: { kind: "selection_present" },
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });

    const command = commands.at(-1);
    expect(command?.checkCallback?.(true)).toBe(false);
    selectionPresent = true;
    expect(command?.checkCallback?.(true)).toBe(true);

    const messagePromise = waitForPortMessage(port);
    command?.checkCallback?.(false);
    await expect(messagePromise).resolves.toMatchObject({
      kind: "request",
      operation: "ui.command.invoke",
      payload: {
        contribution_id: uiId("wrap.selection"),
        local_id: "wrap.selection",
        payload: {
          resource: {
            kind: "document",
            workspace_id: owner().workspaceId,
            document_id: "document-1",
          },
        },
      },
    });
  });

  it("mirrors status, sidebar, and settings contributions to Host surfaces", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const statusIds: string[] = [];
    const sidebarIds: string[] = [];
    const workspaceTileIds: string[] = [];
    const auxiliaryPaneIds: string[] = [];
    const settingsIds: string[] = [];
    const iframeMounts: unknown[] = [];
    const iframeUnmounts: string[] = [];
    const unregister = registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink: () => true,
        statusSurface: {
          add(item) {
            statusIds.push(item.id);
          },
          remove(id) {
            const index = statusIds.indexOf(id);
            if (index >= 0) statusIds.splice(index, 1);
          },
        },
        sidebarSurface: {
          add(panel) {
            sidebarIds.push(panel.id);
            panel.render(document.createElement("div"));
            panel.hide?.();
          },
          remove(id) {
            const index = sidebarIds.indexOf(id);
            if (index >= 0) sidebarIds.splice(index, 1);
          },
        },
        workspaceTileSurface: {
          add(panel) {
            workspaceTileIds.push(panel.id);
          },
          remove(id) {
            const index = workspaceTileIds.indexOf(id);
            if (index >= 0) workspaceTileIds.splice(index, 1);
          },
        },
        auxiliaryPaneSurface: {
          add(pane) {
            auxiliaryPaneIds.push(pane.id);
            pane.render(document.createElement("div"));
          },
          remove(id) {
            const index = auxiliaryPaneIds.indexOf(id);
            if (index >= 0) auxiliaryPaneIds.splice(index, 1);
          },
        },
        settingsSurface: {
          add(tab) {
            settingsIds.push(tab.id);
          },
          remove(id) {
            const index = settingsIds.indexOf(id);
            if (index >= 0) settingsIds.splice(index, 1);
          },
        },
        iframeSurface: {
          mount(options) {
            iframeMounts.push({
              id: options.id,
              surface: options.surface,
              title: options.title,
              childCount: options.container.childElementCount,
            });
          },
          unmount(id) {
            iframeUnmounts.push(id);
          },
        },
      },
      owner(),
    );
    const { port } = boot(router, [
      "ui:statusbar",
      "ui:sidebar",
      "ui:workspace_tile",
      "ui:auxiliary_pane",
      "ui:settings_declarative",
    ]);

    port.postMessage(
      requestEnvelope("ui.status.register_item", {
        surface: "status",
        local_id: "words",
        zone: "normal",
        value: { kind: "text", text: "12 words" },
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });
    port.postMessage(
      requestEnvelope("ui.sidebar.register_panel", {
        surface: "sidebar_panel",
        local_id: "outline",
        panel_id: "outline",
        title: "Outline",
        allowed_locations: ["right"],
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });
    port.postMessage(
      requestEnvelope("ui.workspace.register_tile", {
        surface: "workspace_tile",
        local_id: "slides.preview",
        tile_id: "slides.preview",
        title: "Slides Preview",
        scope: "document",
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });
    port.postMessage(
      requestEnvelope("ui.auxiliary.register_pane", {
        surface: "auxiliary_pane",
        local_id: "comments",
        pane_id: "comments",
        title: "Comments",
        allowed_locations: ["right", "document_right"],
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });
    port.postMessage(
      requestEnvelope("ui.settings.register_declarative", {
        surface: "settings_declarative",
        local_id: "settings.main",
        settings_id: "settings.main",
        title: "Plugin settings",
        placement: "plugin_settings",
        sections: [{ fields: [{ kind: "text", name: "prefix", label: "Prefix", max_length: 80 }] }],
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });

    expect(statusIds).toEqual([uiId("words")]);
    expect(sidebarIds).toEqual([uiId("outline")]);
    expect(workspaceTileIds).toEqual([uiId("slides.preview")]);
    expect(auxiliaryPaneIds).toEqual([uiId("comments")]);
    expect(settingsIds).toEqual([uiId("settings.main")]);
    expect(iframeMounts).toEqual([
      {
        id: uiId("outline"),
        surface: "sidebar_panel",
        title: "Outline",
        childCount: 0,
      },
      {
        id: uiId("comments"),
        surface: "auxiliary_pane",
        title: "Comments",
        childCount: 0,
      },
    ]);
    expect(iframeUnmounts).toEqual([uiId("outline")]);

    unregister();
    expect(statusIds).toEqual([]);
    expect(sidebarIds).toEqual([]);
    expect(workspaceTileIds).toEqual([]);
    expect(auxiliaryPaneIds).toEqual([]);
    expect(settingsIds).toEqual([]);
  });

  it("renders workspace tile contributions through the sandbox iframe surface", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const panelIds: string[] = [];
    const unmountedIds: string[] = [];
    const iframeMounts: unknown[] = [];
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink: () => true,
        workspaceTileSurface: {
          add(panel) {
            panelIds.push(panel.id);
            expect(panel.tileId).toBe("slides.preview");
            expect(panel.scope).toBe("document");
            expect(panel.preferredOpen).toBe("document_menu");
            expect(
              panel.isAvailable?.({
                resourceKind: "document",
                workspaceId: owner().workspaceId,
                documentId: "document-alpha",
                documentOpen: true,
              }),
            ).toBe(true);
            expect(
              panel.isAvailable?.({
                resourceKind: "workspace",
                workspaceId: owner().workspaceId,
                documentOpen: false,
              }),
            ).toBe(false);
            panel.render(document.createElement("div"), {
              tileInstanceId: "workspace-tile-instance",
              documentId: "document-alpha",
              action: {
                actionId: "workspace-action-one",
                tileId: uiId("slides.registration"),
                tileInstanceId: "workspace-tile-instance",
                documentId: "document-alpha",
                issuedAtMs: Date.now(),
              },
            });
          },
          remove(id) {
            const index = panelIds.indexOf(id);
            if (index >= 0) panelIds.splice(index, 1);
          },
        },
        iframeSurface: {
          mount(options) {
            iframeMounts.push({
              id: options.id,
              mountKey: options.mountKey,
              surface: options.surface,
              title: options.title,
              resource: options.resource,
              childCount: options.container.childElementCount,
            });
          },
          unmount(id) {
            unmountedIds.push(id);
          },
        },
      },
      owner(),
    );
    const { port } = boot(router, ["ui:workspace_tile"]);

    port.postMessage(
      requestEnvelope("ui.workspace.register_tile", {
        surface: "workspace_tile",
        local_id: "slides.registration",
        tile_id: "slides.preview",
        title: "Slides Preview",
        scope: "document",
        when: { kind: "resource_kind", is: "document" },
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });

    expect(panelIds).toEqual([uiId("slides.registration")]);
    expect(iframeMounts).toEqual([
      {
        id: uiId("slides.registration"),
        mountKey: "workspace-tile-instance",
        surface: "workspace_tile",
        title: "Slides Preview",
        resource: {
          tileId: "slides.preview",
          documentId: "document-alpha",
          tileInstanceId: "workspace-tile-instance",
          action: {
            actionId: "workspace-action-one",
            tileId: uiId("slides.registration"),
            tileInstanceId: "workspace-tile-instance",
            documentId: "document-alpha",
            issuedAtMs: expect.any(Number),
          },
        },
        childCount: 0,
      },
    ]);

    port.postMessage(
      requestEnvelope("ui.contribution.unregister", {
        local_id: "slides.registration",
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });
    expect(panelIds).toEqual([]);
    expect(unmountedIds).toContain(uiId("slides.registration"));
  });

  it("passes workspace tile action query descriptors to the sandbox iframe surface", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const workspacePanels: Parameters<PluginUiWorkspaceTileSurface["add"]>[0][] = [];
    const iframeMounts: unknown[] = [];
    const { session, port } = boot(router, ["ui:workspace_tile", "document:read:workspace"], {
      documentScope: { workspaceReadAllowed: true },
    });
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink: () => true,
        workspaceTileSurface: {
          add(panel) {
            workspacePanels.push(panel);
            expect(panel.scope).toBe("workspace");
            expect(panel).not.toHaveProperty("documentQuery");
          },
          remove() {},
        },
        iframeSurface: {
          mount(options) {
            iframeMounts.push({
              id: options.id,
              mountKey: options.mountKey,
              surface: options.surface,
              title: options.title,
              resource: options.resource,
            });
          },
          unmount() {},
        },
      },
      owner(),
      session,
    );

    port.postMessage(
      requestEnvelope("ui.workspace.register_tile", {
        surface: "workspace_tile",
        local_id: "board",
        tile_id: "board",
        title: "Board",
        scope: "workspace",
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });

    port.postMessage(
      requestEnvelope("ui.workspace.register_tile_action", {
        surface: "workspace_tile_action",
        local_id: "board.refresh",
        tile_ref: { kind: "local_tile", local_id: "board" },
        action_id: "refresh",
        title: "Refresh",
        placement: "refresh",
        document_query: {
          scope: "workspace",
          max_documents: 25,
          max_bytes: 4096,
          reason: "Build board",
        },
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });

    const panel = workspacePanels[0];
    expect(panel).toBeDefined();
    const actions = panel.actions?.() ?? [];
    expect(actions).toEqual([
      {
        id: uiId("board.refresh"),
        actionId: "refresh",
        title: "Refresh",
        order: undefined,
        placement: "refresh",
        icon: undefined,
        documentQuery: {
          scope: "workspace",
          max_documents: 25,
          max_bytes: 4096,
          reason: "Build board",
        },
      },
    ]);
    panel.render(document.createElement("div"), {
      tileInstanceId: "workspace-tile-instance",
      action: {
        actionId: "workspace-action-one",
        tileId: uiId("board"),
        tileInstanceId: "workspace-tile-instance",
        kind: "tile_action",
        tileActionId: actions[0]?.actionId,
        documentQuery: actions[0]?.documentQuery,
        issuedAtMs: Date.now(),
      },
    });

    expect(iframeMounts).toEqual([
      {
        id: uiId("board"),
        mountKey: "workspace-tile-instance",
        surface: "workspace_tile",
        title: "Board",
        resource: {
          tileId: "board",
          tileInstanceId: "workspace-tile-instance",
          action: {
            actionId: "workspace-action-one",
            tileId: uiId("board"),
            tileInstanceId: "workspace-tile-instance",
            kind: "tile_action",
            tileActionId: "refresh",
            documentQuery: {
              scope: "workspace",
              max_documents: 25,
              max_bytes: 4096,
              reason: "Build board",
            },
            issuedAtMs: expect.any(Number),
          },
        },
      },
    ]);
  });

  it("materializes command-preferred workspace tiles as Host-owned commands", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const panelIds: string[] = [];
    const removedCommands: string[] = [];
    const openedTiles: { id: string; documentId?: string }[] = [];
    const commands = new Map<
      string,
      { callback?: () => void; checkCallback?: (checking: boolean) => boolean | void }
    >();
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink: () => true,
        resourceContext: {
          workspace: () => ({ resourceKind: "workspace", workspaceId: owner().workspaceId }),
          activeDocument: () => ({
            resourceKind: "document",
            workspaceId: owner().workspaceId,
            documentId: "document-alpha",
            documentOpen: true,
          }),
        },
        commandSurface: {
          add(command) {
            commands.set(command.id, {
              callback: command.callback,
              checkCallback: command.checkCallback,
            });
          },
          remove(id) {
            removedCommands.push(id);
            commands.delete(id);
          },
        },
        workspaceTileSurface: {
          add(panel) {
            panelIds.push(panel.id);
            expect(panel.preferredOpen).toBe("command");
          },
          open(id, documentId) {
            openedTiles.push({ id, documentId });
          },
          remove(id) {
            const index = panelIds.indexOf(id);
            if (index >= 0) panelIds.splice(index, 1);
          },
        },
        iframeSurface: {
          mount() {},
          unmount() {},
        },
      },
      owner(),
    );
    const { port } = boot(router, ["ui:workspace_tile"]);

    port.postMessage(
      requestEnvelope("ui.workspace.register_tile", {
        surface: "workspace_tile",
        local_id: "slides.preview",
        tile_id: "slides.preview",
        title: "Slides Preview",
        scope: "document",
        preferred_open: "command",
        when: { kind: "resource_kind", is: "document" },
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });

    const command = commands.get(uiId("slides.preview"));
    expect(command?.checkCallback?.(true)).toBe(true);
    command?.callback?.();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(openedTiles).toEqual([{ id: uiId("slides.preview"), documentId: "document-alpha" }]);

    port.postMessage(
      requestEnvelope("ui.contribution.unregister", {
        local_id: "slides.preview",
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });
    expect(panelIds).toEqual([]);
    expect(removedCommands).toContain(uiId("slides.preview"));
    expect(commands.has(uiId("slides.preview"))).toBe(false);
  });

  it("renders auxiliary pane contributions through a disposable sandbox iframe surface", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const paneIds: string[] = [];
    const unmountedIds: string[] = [];
    const iframeMounts: unknown[] = [];
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink: () => true,
        auxiliaryPaneSurface: {
          add(pane) {
            paneIds.push(pane.id);
            pane.render(document.createElement("div"));
            pane.hide?.();
          },
          remove(id) {
            const index = paneIds.indexOf(id);
            if (index >= 0) paneIds.splice(index, 1);
          },
        },
        iframeSurface: {
          mount(options) {
            iframeMounts.push({
              id: options.id,
              surface: options.surface,
              title: options.title,
              childCount: options.container.childElementCount,
            });
          },
          unmount(id) {
            unmountedIds.push(id);
          },
        },
      },
      owner(),
    );
    const { port } = boot(router, ["ui:auxiliary_pane"]);

    port.postMessage(
      requestEnvelope("ui.auxiliary.register_pane", {
        surface: "auxiliary_pane",
        local_id: "comments",
        pane_id: "comments",
        title: "Comments",
        allowed_locations: ["right", "document_right"],
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });

    expect(paneIds).toEqual([uiId("comments")]);
    expect(iframeMounts).toEqual([
      {
        id: uiId("comments"),
        surface: "auxiliary_pane",
        title: "Comments",
        childCount: 0,
      },
    ]);
    expect(unmountedIds).toContain(uiId("comments"));
  });

  it("invokes auxiliary pane Host actions through owner-scoped commands", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    registry.register(
      owner(),
      {
        surface: "command",
        local_id: "send.comment",
        title: "Send comment",
        plaintext_request: "active_document",
      },
      ["document:read:active"],
    );
    let paneAction:
      | {
          invoke(): void;
          isAvailable?: () => boolean;
          id: string;
          title: string;
        }
      | undefined;
    const { session, port } = boot(router, ["ui:auxiliary_pane", "document:read:active"]);
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink: () => true,
        plaintextContext: {
          activeDocument: () => ({ documentId: "document-1" }),
        },
        resourceContext: {
          workspace: () => ({ resourceKind: "workspace", workspaceId: owner().workspaceId }),
          activeDocument: () => ({
            resourceKind: "document",
            workspaceId: owner().workspaceId,
            documentId: "document-1",
            documentOpen: true,
          }),
        },
        auxiliaryPaneSurface: {
          add(pane) {
            paneAction = pane.actions?.[0];
          },
          remove() {},
        },
        iframeSurface: {
          mount() {},
          unmount() {},
        },
      },
      owner(),
      session,
    );

    port.postMessage(
      requestEnvelope("ui.auxiliary.register_pane", {
        surface: "auxiliary_pane",
        local_id: "comments",
        pane_id: "comments",
        title: "Comments",
        allowed_locations: ["right", "document_right"],
        actions: [
          {
            action_id: "send",
            title: "Send",
            command_ref: { kind: "local_command", local_id: "send.comment" },
          },
        ],
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });

    expect(paneAction).toMatchObject({
      id: `${uiId("comments")}:send`,
      title: "Send",
    });
    expect(paneAction?.isAvailable?.()).toBe(true);

    const invocationPromise = waitForPortMessage(port);
    paneAction?.invoke();
    await expect(invocationPromise).resolves.toMatchObject({
      kind: "request",
      operation: "ui.command.invoke",
      execution_context_id: expect.any(String),
      payload: {
        contribution_id: uiId("send.comment"),
        local_id: "send.comment",
        payload: {
          action: {
            surface: "auxiliary_pane",
            pane_id: "comments",
            action_id: "send",
          },
        },
      },
    });
  });

  it("disposes auxiliary pane registry entries when Host-owned close is invoked", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const paneIds: string[] = [];
    const unmountedIds: string[] = [];
    let closePane: (() => void) | undefined;
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink: () => true,
        auxiliaryPaneSurface: {
          add(pane) {
            paneIds.push(pane.id);
            closePane = pane.close;
          },
          remove(id) {
            const index = paneIds.indexOf(id);
            if (index >= 0) paneIds.splice(index, 1);
          },
        },
        iframeSurface: {
          mount() {},
          unmount(id) {
            unmountedIds.push(id);
          },
        },
      },
      owner(),
    );
    const { port } = boot(router, ["ui:auxiliary_pane"]);

    port.postMessage(
      requestEnvelope("ui.auxiliary.register_pane", {
        surface: "auxiliary_pane",
        local_id: "comments",
        pane_id: "comments",
        title: "Comments",
        allowed_locations: ["right"],
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });
    expect(registry.list()).toHaveLength(1);

    closePane?.();
    expect(paneIds).toEqual([]);
    expect(unmountedIds).toContain(uiId("comments"));
    expect(registry.list()).toHaveLength(0);

    port.postMessage(
      requestEnvelope("ui.auxiliary.register_pane", {
        surface: "auxiliary_pane",
        local_id: "comments",
        pane_id: "comments",
        title: "Comments",
        allowed_locations: ["right"],
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });
    expect(paneIds).toEqual([uiId("comments")]);
  });

  it("rejects plugin-origin workspace tile open operations", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink: () => true,
        workspaceTileSurface: {
          add() {},
          remove() {},
        },
        iframeSurface: {
          mount() {},
          unmount() {},
        },
      },
      owner(),
    );
    const { port } = boot(router, ["ui:workspace_tile"]);

    port.postMessage(
      requestEnvelope("ui.workspace.register_tile", {
        surface: "workspace_tile",
        local_id: "slides.preview",
        tile_id: "slides.preview",
        title: "Slides Preview",
        scope: "document",
        when: { kind: "document_open" },
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });

    port.postMessage(
      requestEnvelope("ui.workspace.open_tile", {
        local_id: "slides.preview",
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "unknown_operation" },
    });
  });

  it("rejects auxiliary pane registration when the sandbox iframe surface is unavailable", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const panelIds: string[] = [];
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink: () => true,
        workspaceTileSurface: {
          add(panel) {
            panelIds.push(panel.id);
          },
          remove() {},
        },
      },
      owner(),
    );
    const { port } = boot(router, ["ui:workspace_tile"]);

    port.postMessage(
      requestEnvelope("ui.workspace.register_tile", {
        surface: "workspace_tile",
        local_id: "slides.preview",
        tile_id: "slides.preview",
        title: "Slides Preview",
        scope: "document",
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "ui_iframe_surface_unavailable" },
    });
    expect(registry.list()).toHaveLength(0);
    expect(panelIds).toEqual([]);
  });

  it("rejects auxiliary pane registration when the sandbox iframe surface is unavailable", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const paneIds: string[] = [];
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink: () => true,
        auxiliaryPaneSurface: {
          add(pane) {
            paneIds.push(pane.id);
          },
          remove() {},
        },
      },
      owner(),
    );
    const { port } = boot(router, ["ui:auxiliary_pane"]);

    port.postMessage(
      requestEnvelope("ui.auxiliary.register_pane", {
        surface: "auxiliary_pane",
        local_id: "comments",
        pane_id: "comments",
        title: "Comments",
        allowed_locations: ["right"],
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "ui_iframe_surface_unavailable" },
    });
    expect(registry.list()).toHaveLength(0);
    expect(paneIds).toEqual([]);
  });

  it("does not render workspace tile if the resource predicate rejects the target", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const iframeMounts: unknown[] = [];
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink: () => true,
        workspaceTileSurface: {
          add(panel) {
            expect(panel.scope).toBe("workspace");
            expect(panel.preferredOpen).toBe("manual");
            expect(
              panel.isAvailable?.({
                resourceKind: "document",
                workspaceId: owner().workspaceId,
                documentId: "document-alpha",
                documentOpen: true,
              }),
            ).toBe(false);
            expect(
              panel.isAvailable?.({
                resourceKind: "workspace",
                workspaceId: owner().workspaceId,
                documentOpen: false,
              }),
            ).toBe(true);
            const container = document.createElement("div");
            container.append(document.createElement("span"));
            panel.render(container, {
              tileInstanceId: "workspace-tile-instance",
              documentId: "document-alpha",
              action: {
                actionId: "workspace-action-two",
                tileId: uiId("workspace.only"),
                tileInstanceId: "workspace-tile-instance",
                documentId: "document-alpha",
                issuedAtMs: Date.now(),
              },
            });
            expect(container.childElementCount).toBe(0);
          },
          remove() {},
        },
        iframeSurface: {
          mount(options) {
            iframeMounts.push(options);
          },
          unmount() {},
        },
      },
      owner(),
    );
    const { port } = boot(router, ["ui:workspace_tile"]);

    port.postMessage(
      requestEnvelope("ui.workspace.register_tile", {
        surface: "workspace_tile",
        local_id: "workspace.only",
        tile_id: "workspace.only",
        title: "Workspace Only",
        scope: "workspace",
        when: { kind: "resource_kind", is: "workspace" },
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });
    expect(iframeMounts).toEqual([]);
  });

  it("fails closed when workspace tile open invocation audit is denied", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const auditEvents: PluginAuditEvent[] = [];
    let auditCount = 0;
    const capturedPanels: Array<{
      open?: (context: {
        resourceKind: "document";
        workspaceId: string;
        documentId: string;
        documentOpen: boolean;
      }) => boolean | Promise<boolean>;
    }> = [];
    const capturedCommands: Array<{ callback?: () => void }> = [];
    const openedTiles: Array<{ id: string; documentId?: string }> = [];

    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink(event) {
          auditEvents.push(event);
          auditCount += 1;
          return auditCount === 1;
        },
        commandSurface: {
          add(command) {
            capturedCommands.push(command);
          },
          remove() {},
        },
        resourceContext: {
          workspace() {
            return {
              resourceKind: "workspace",
              workspaceId: owner().workspaceId,
              capabilities: ["ui:workspace_tile", "ui:command"],
            };
          },
          activeDocument() {
            return {
              resourceKind: "document",
              workspaceId: owner().workspaceId,
              documentId: "document-alpha",
              documentOpen: true,
              selectionPresent: false,
              capabilities: ["ui:workspace_tile", "ui:command"],
            };
          },
        },
        workspaceTileSurface: {
          add(panel) {
            capturedPanels.push(panel);
          },
          open(id, documentId) {
            openedTiles.push({ id, documentId });
          },
          remove() {},
        },
        iframeSurface: {
          mount() {},
          unmount() {},
        },
      },
      owner(),
    );
    const { port } = boot(router, ["ui:workspace_tile", "ui:command"]);

    port.postMessage(
      requestEnvelope("ui.workspace.register_tile", {
        surface: "workspace_tile",
        local_id: "slides.preview",
        tile_id: "slides.preview",
        title: "Slides Preview",
        scope: "document",
        preferred_open: "command",
        when: { kind: "document_open" },
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });

    const capturedPanel = capturedPanels[0];
    if (!capturedPanel?.open) throw new Error("workspace tile open guard was not registered");
    await expect(
      capturedPanel.open({
        resourceKind: "document",
        workspaceId: owner().workspaceId,
        documentId: "document-alpha",
        documentOpen: true,
      }),
    ).resolves.toBe(false);
    capturedCommands[0]?.callback?.();
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(openedTiles).toEqual([]);
    expect(auditEvents.map((event) => event.type)).toEqual([
      "plugin.ui.registration.accepted",
      "plugin.ui.invocation.accepted",
      "plugin.ui.invocation.accepted",
    ]);
  });

  it("renders iframe status contributions through the sandbox iframe surface", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const statusIds: string[] = [];
    const unmountedIds: string[] = [];
    const iframeMounts: unknown[] = [];
    const statusContainers: HTMLElement[] = [];
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink: () => true,
        statusSurface: {
          add(item) {
            statusIds.push(item.id);
            const container = document.createElement("span");
            document.body.append(container);
            statusContainers.push(container);
            if (item.content.kind === "text") {
              container.textContent = item.content.text;
            } else {
              item.content.render(container);
            }
          },
          remove(id) {
            const index = statusIds.indexOf(id);
            if (index >= 0) statusIds.splice(index, 1);
          },
        },
        iframeSurface: {
          mount(options) {
            iframeMounts.push({
              id: options.id,
              surface: options.surface,
              title: options.title,
              childCount: options.container.childElementCount,
            });
          },
          unmount(id) {
            unmountedIds.push(id);
          },
        },
      },
      owner(),
    );
    const { port } = boot(router, ["ui:statusbar"]);

    port.postMessage(
      requestEnvelope("ui.status.register_item", {
        surface: "status",
        local_id: "sync.status",
        label: "Sync",
        zone: "normal",
        value: { kind: "iframe", panel_id: "sync.status.panel" },
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });

    expect(statusIds).toEqual([uiId("sync.status")]);
    expect(iframeMounts).toEqual([]);
    await vi.waitFor(() => {
      expect(iframeMounts).toEqual([
        {
          id: uiId("sync.status"),
          surface: "status",
          title: "Sync",
          childCount: 0,
        },
      ]);
    });

    port.postMessage(
      requestEnvelope("ui.contribution.unregister", {
        local_id: "sync.status",
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });
    expect(statusIds).toEqual([]);
    expect(unmountedIds).toContain(uiId("sync.status"));
    for (const container of statusContainers) container.remove();
  });

  it("renders settings iframe contributions through the sandbox iframe surface", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const mounts: unknown[] = [];
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink: () => true,
        settingsSurface: {
          add(tab) {
            tab.render(document.createElement("div"));
          },
          remove() {},
        },
        settingsRenderer: renderPluginUiSettingsContribution,
        iframeSurface: {
          mount(options) {
            mounts.push({
              id: options.id,
              surface: options.surface,
              title: options.title,
              iframeCount: options.container.querySelectorAll("iframe").length,
            });
          },
          unmount() {},
        },
      },
      owner(),
    );
    const { port } = boot(router, ["ui:settings_iframe"]);

    port.postMessage(
      requestEnvelope("ui.settings.register_iframe", {
        surface: "settings_iframe",
        local_id: "settings.frame",
        settings_id: "settings.frame",
        title: "Plugin settings",
        placement: "plugin_settings",
        iframe_panel_id: "settings.frame",
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });
    expect(mounts).toEqual([
      {
        id: uiId("settings.frame"),
        surface: "settings_iframe",
        title: "Plugin settings",
        iframeCount: 0,
      },
    ]);
  });

  it("renders declarative settings submit command through Host command dispatch", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    let settingsContainer: HTMLElement | null = null;
    const auditEvents: PluginAuditEvent[] = [];
    const { session, port } = boot(router, ["ui:command", "ui:settings_declarative"]);
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink(event) {
          auditEvents.push(event);
          return true;
        },
        commandSurface: {
          add() {},
          remove() {},
        },
        settingsSurface: {
          add(tab) {
            settingsContainer = document.createElement("div");
            tab.render(settingsContainer);
          },
          remove() {},
        },
        settingsRenderer: renderPluginUiSettingsContribution,
        resourceContext: {
          workspace() {
            return { resourceKind: "workspace", workspaceId: owner().workspaceId };
          },
          activeDocument() {
            return null;
          },
        },
      },
      owner(),
      session,
    );

    port.postMessage(
      requestEnvelope("ui.command.register", {
        surface: "command",
        local_id: "save.settings",
        title: "Save settings",
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });
    port.postMessage(
      requestEnvelope("ui.settings.register_declarative", {
        surface: "settings_declarative",
        local_id: "settings.main",
        settings_id: "settings.main",
        title: "Plugin settings",
        placement: "plugin_settings",
        sections: [
          {
            fields: [
              { kind: "text", name: "prefix", label: "Prefix", max_length: 80 },
              { kind: "checkbox", name: "enabled", label: "Enabled" },
            ],
          },
        ],
        submit_command_ref: { kind: "local_command", local_id: "save.settings" },
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });

    const container = settingsContainer as unknown as HTMLElement;
    assertHTMLElement(container);
    const input = container.querySelector<HTMLInputElement>('input[name="prefix"]');
    const checkbox = container.querySelector<HTMLInputElement>('input[name="enabled"]');
    expect(input).toBeInstanceOf(HTMLInputElement);
    expect(checkbox).toBeInstanceOf(HTMLInputElement);
    if (!input || !checkbox) throw new Error("settings form fields missing");
    input.value = "weekly";
    checkbox.checked = true;

    const messagePromise = waitForPortMessage(port);
    container
      .querySelector<HTMLFormElement>("form")
      ?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));

    const request = (await messagePromise) as PluginHostRpcRequestEnvelope;
    expect(request).toMatchObject({
      kind: "request",
      operation: "ui.command.invoke",
      payload: {
        contribution_id: uiId("save.settings"),
        local_id: "save.settings",
        payload: {
          settings_id: "settings.main",
          values: { prefix: "weekly", enabled: true },
        },
      },
    });
    expect(auditEvents).toContainEqual(
      expect.objectContaining({
        type: "plugin.ui.invocation.accepted",
        correlation: expect.objectContaining({ authority_event_ref: uiId("save.settings") }),
      }),
    );
  });

  it("fails closed when declarative settings submit command is stale", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    let settingsContainer: HTMLElement | null = null;
    const auditEvents: PluginAuditEvent[] = [];
    const { session, port } = boot(router, ["ui:command", "ui:settings_declarative"]);
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink(event) {
          auditEvents.push(event);
          return true;
        },
        commandSurface: {
          add() {},
          remove() {},
        },
        settingsSurface: {
          add(tab) {
            settingsContainer = document.createElement("div");
            tab.render(settingsContainer);
          },
          remove() {},
        },
        settingsRenderer: renderPluginUiSettingsContribution,
        resourceContext: {
          workspace() {
            return { resourceKind: "workspace", workspaceId: owner().workspaceId };
          },
          activeDocument() {
            return null;
          },
        },
      },
      owner(),
      session,
    );

    port.postMessage(
      requestEnvelope("ui.command.register", {
        surface: "command",
        local_id: "save.settings",
        title: "Save settings",
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });
    port.postMessage(
      requestEnvelope("ui.settings.register_declarative", {
        surface: "settings_declarative",
        local_id: "settings.main",
        settings_id: "settings.main",
        title: "Plugin settings",
        placement: "plugin_settings",
        sections: [{ fields: [{ kind: "text", name: "prefix", label: "Prefix", max_length: 80 }] }],
        submit_command_ref: { kind: "local_command", local_id: "save.settings" },
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });
    port.postMessage(requestEnvelope("ui.contribution.unregister", { local_id: "save.settings" }));
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });

    const messages: unknown[] = [];
    port.addEventListener("message", (event) => messages.push(event.data));
    const container = settingsContainer as unknown as HTMLElement;
    assertHTMLElement(container);
    container
      .querySelector<HTMLFormElement>("form")
      ?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(messages).toEqual([]);
    expect(auditEvents).toContainEqual(
      expect.objectContaining({
        type: "plugin.ui.invocation.rejected",
        action: expect.objectContaining({
          result: "denied",
          reason_code: "ui_command_ref_denied",
        }),
      }),
    );
  });

  it("audits declarative modal opening before activating the modal", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const commands: Parameters<PluginUiCommandSurface["add"]>[0][] = [];
    const auditEvents: PluginAuditEvent[] = [];
    const { session, port } = boot(router, ["ui:command", "ui:declarative_modal"]);
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink(event) {
          if (event.type === "plugin.ui.invocation.accepted") {
            expect(getActivePluginUiModalId()).toBeNull();
          }
          auditEvents.push(event);
          return true;
        },
        commandSurface: {
          add(command) {
            commands.push(command);
          },
          remove() {},
        },
        resourceContext: {
          workspace() {
            return { resourceKind: "workspace", workspaceId: owner().workspaceId };
          },
          activeDocument() {
            return null;
          },
        },
      },
      owner(),
      session,
    );

    port.postMessage(
      requestEnvelope("ui.command.register", {
        surface: "command",
        local_id: "open.modal",
        title: "Open modal command",
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });
    port.postMessage(
      requestEnvelope("ui.modal.register_declarative", {
        surface: "declarative_modal",
        local_id: "modal.open",
        modal_id: "modal.open",
        title: "Open modal",
        trigger_command_ref: { kind: "local_command", local_id: "open.modal" },
        body: {
          kind: "schema_form",
          fields: [{ kind: "text", name: "note", label: "Note", max_length: 120 }],
        },
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });

    commands.find((command) => command.id === uiId("modal.open"))?.callback();
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(getActivePluginUiModalId()).toBe(uiId("modal.open"));
    expect(auditEvents).toContainEqual(
      expect.objectContaining({
        type: "plugin.ui.invocation.accepted",
        payloadKind: "ui.contribution",
        operation: "ui.modal.open",
        correlation: expect.objectContaining({ authority_event_ref: uiId("modal.open") }),
        action: expect.objectContaining({ operation: "ui.modal.open", result: "allowed" }),
      }),
    );
  });

  it("rejects iframe modal registration when the sandbox iframe surface is unavailable", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const commands: Parameters<PluginUiCommandSurface["add"]>[0][] = [];
    const { session, port } = boot(router, ["ui:command", "ui:declarative_modal"]);
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink: () => true,
        commandSurface: {
          add(command) {
            commands.push(command);
          },
          remove() {},
        },
      },
      owner(),
      session,
    );

    port.postMessage(
      requestEnvelope("ui.command.register", {
        surface: "command",
        local_id: "open.modal",
        title: "Open modal command",
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });
    port.postMessage(
      requestEnvelope("ui.modal.register_declarative", {
        surface: "declarative_modal",
        local_id: "modal.open",
        modal_id: "modal.open",
        title: "Open modal",
        trigger_command_ref: { kind: "local_command", local_id: "open.modal" },
        body: { kind: "iframe", iframe_panel_id: "modal.frame" },
      }),
    );

    await expect(waitForPortMessage(port)).resolves.toMatchObject({
      kind: "error",
      error: { code: "ui_iframe_surface_unavailable" },
    });
    expect(registry.list("declarative_modal")).toEqual([]);
    expect(commands.map((command) => command.id)).toEqual([uiId("open.modal")]);
  });

  it("keeps declarative modal closed when invocation audit fails", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    const commands: Parameters<PluginUiCommandSurface["add"]>[0][] = [];
    const auditEvents: PluginAuditEvent[] = [];
    const { session, port } = boot(router, ["ui:command", "ui:declarative_modal"]);
    registerPluginHostUiHandlers(
      router,
      {
        registry,
        auditSink(event) {
          auditEvents.push(event);
          return event.type !== "plugin.ui.invocation.accepted";
        },
        commandSurface: {
          add(command) {
            commands.push(command);
          },
          remove() {},
        },
        resourceContext: {
          workspace() {
            return { resourceKind: "workspace", workspaceId: owner().workspaceId };
          },
          activeDocument() {
            return null;
          },
        },
      },
      owner(),
      session,
    );

    port.postMessage(
      requestEnvelope("ui.command.register", {
        surface: "command",
        local_id: "open.modal",
        title: "Open modal command",
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });
    port.postMessage(
      requestEnvelope("ui.modal.register_declarative", {
        surface: "declarative_modal",
        local_id: "modal.open",
        modal_id: "modal.open",
        title: "Open modal",
        trigger_command_ref: { kind: "local_command", local_id: "open.modal" },
        body: {
          kind: "schema_form",
          fields: [{ kind: "text", name: "note", label: "Note", max_length: 120 }],
        },
      }),
    );
    await expect(waitForPortMessage(port)).resolves.toMatchObject({ kind: "response" });

    commands.find((command) => command.id === uiId("modal.open"))?.callback();
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(getActivePluginUiModalId()).toBeNull();
    expect(auditEvents).toContainEqual(
      expect.objectContaining({
        type: "plugin.ui.invocation.accepted",
        correlation: expect.objectContaining({ authority_event_ref: uiId("modal.open") }),
      }),
    );
    expect(auditEvents).toContainEqual(
      expect.objectContaining({
        type: "plugin.ui.invocation.rejected",
        correlation: expect.objectContaining({ authority_event_ref: uiId("modal.open") }),
        action: expect.objectContaining({
          operation: "ui.modal.open",
          result: "denied",
          reason_code: "ui_audit_failed",
        }),
      }),
    );
  });

  it("invokes only an owner-scoped command reference", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    registry.register(owner(), {
      surface: "command",
      local_id: "open.panel",
      title: "Open panel",
    });
    const { session, port } = boot(router, []);
    const messagePromise = waitForPortMessage(port);

    const invokePromise = invokePluginUiCommand(
      session,
      registry,
      owner(),
      { kind: "local_command", local_id: "open.panel" },
      { document_id: "document-1" },
    );
    const request = (await messagePromise) as PluginHostRpcRequestEnvelope;
    expect(request).toMatchObject({
      kind: "request",
      operation: "ui.command.invoke",
      payload: {
        contribution_id: uiId("open.panel"),
        local_id: "open.panel",
        payload: { document_id: "document-1" },
      },
    });

    port.postMessage({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: request.request_id,
      payload: { ok: true },
    });
    await expect(invokePromise).resolves.toEqual({ ok: true });
  });

  it("issues a Host execution context for active-document plaintext command invocations", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    registry.register(owner(), {
      surface: "command",
      local_id: "summarize.active",
      title: "Summarize active",
      plaintext_request: "active_document",
    });
    const { session, port } = boot(router, ["ui:command", "document:read:active"]);
    const messagePromise = waitForPortMessage(port);

    const invokePromise = invokePluginUiCommand(
      session,
      registry,
      owner(),
      { kind: "local_command", local_id: "summarize.active" },
      null,
      undefined,
      { activeDocument: () => ({ documentId: "document-active", maxBytes: 2048 }) },
    );
    const request = (await messagePromise) as PluginHostRpcRequestEnvelope;
    expect(request).toMatchObject({
      kind: "request",
      operation: "ui.command.invoke",
      execution_context_id: expect.any(String),
    });

    port.postMessage({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: request.request_id,
      payload: { ok: true },
    });
    await expect(invokePromise).resolves.toEqual({ ok: true });
  });

  it("issues selection plaintext execution context for command invocations", async () => {
    const registry = createPluginUiContributionRegistry();
    registry.register(owner(), {
      surface: "command",
      local_id: "summarize.selection",
      title: "Summarize selection",
      plaintext_request: "selection",
    });
    const { session, port } = boot(new PluginHostMessageRouter({ windowTarget: undefined }), [
      "ui:command",
      "editor:selection:read",
    ]);

    const messagePromise = waitForPortMessage(port);
    const invokePromise = invokePluginUiCommand(
      session,
      registry,
      owner(),
      { kind: "local_command", local_id: "summarize.selection" },
      null,
      undefined,
      {
        activeDocument: () => null,
        selection: (commandSession) => ({
          executionContextId: commandSession.issueExecutionContext({
            kind: "user_command",
            hostInvocation: { kind: "command", userGesture: true },
            resource: {
              document_id: "document-active",
              editor_id: "editor-active",
              selection_range: { anchor: 1, head: 8 },
            },
            plaintextScope: { kind: "selection", maxBytes: 1024 },
            allowedOperations: ["plaintext.read"],
            expiresAtMs: Date.now() + 30_000,
            singleUse: true,
          }).execution_context_id,
        }),
      },
    );
    const request = (await messagePromise) as PluginHostRpcRequestEnvelope;
    expect(request).toMatchObject({
      kind: "request",
      operation: "ui.command.invoke",
      execution_context_id: expect.any(String),
    });

    port.postMessage({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: request.request_id,
      payload: { ok: true },
    });
    await expect(invokePromise).resolves.toEqual({ ok: true });
  });

  it("issues workspace document query execution context for command invocations", async () => {
    const registry = createPluginUiContributionRegistry();
    registry.register(
      owner(),
      {
        surface: "command",
        local_id: "summarize.workspace",
        title: "Summarize workspace",
        document_query: {
          scope: "workspace",
          max_documents: 25,
          max_bytes: 4096,
          reason: "Summarize project notes",
        },
      },
      ["document:read:workspace"],
      { workspaceReadAllowed: true },
    );
    const { session, port } = boot(
      new PluginHostMessageRouter({ windowTarget: undefined }),
      ["ui:command", "document:read:workspace"],
      {
        documentScope: { workspaceReadAllowed: true },
      },
    );

    const messagePromise = waitForPortMessage(port);
    const invokePromise = invokePluginUiCommand(
      session,
      registry,
      owner(),
      { kind: "local_command", local_id: "summarize.workspace" },
      null,
    );
    const request = (await messagePromise) as PluginHostRpcRequestEnvelope;
    expect(request).toMatchObject({
      kind: "request",
      operation: "ui.command.invoke",
      execution_context_id: expect.any(String),
      payload: {
        payload: {
          document_query: { scope: "workspace", max_documents: 25, max_bytes: 4096 },
        },
      },
    });

    port.postMessage({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: request.request_id,
      payload: { ok: true },
    });
    await expect(invokePromise).resolves.toEqual({ ok: true });
  });

  it("fails closed when command plaintext request needs unavailable Host context", async () => {
    const registry = createPluginUiContributionRegistry();
    registry.register(owner(), {
      surface: "command",
      local_id: "summarize.selection",
      title: "Summarize selection",
      plaintext_request: "selection",
    });
    const { session } = boot(new PluginHostMessageRouter({ windowTarget: undefined }), [
      "ui:command",
      "editor:selection:read",
    ]);

    await expect(
      invokePluginUiCommand(
        session,
        registry,
        owner(),
        { kind: "local_command", local_id: "summarize.selection" },
        null,
      ),
    ).rejects.toMatchObject({ code: "ui_plaintext_context_unavailable" });
  });

  it("issues editor context plaintext execution context for command invocations", async () => {
    const registry = createPluginUiContributionRegistry();
    registry.register(owner(), {
      surface: "command",
      local_id: "explain.context",
      title: "Explain context",
      plaintext_request: "editor_context",
    });
    const { session, port } = boot(new PluginHostMessageRouter({ windowTarget: undefined }), [
      "ui:command",
      "editor:context:read",
    ]);

    const messagePromise = waitForPortMessage(port);
    const invokePromise = invokePluginUiCommand(
      session,
      registry,
      owner(),
      { kind: "local_command", local_id: "explain.context" },
      null,
      undefined,
      {
        activeDocument: () => null,
        editorContext: (commandSession) => ({
          executionContextId: commandSession.issueExecutionContext({
            kind: "user_command",
            hostInvocation: { kind: "command", userGesture: true },
            resource: {
              document_id: "document-active",
              editor_id: "editor-active",
              context_range: { anchor: 0, head: 128 },
            },
            plaintextScope: { kind: "editor_context", maxBytes: 2048 },
            allowedOperations: ["plaintext.read"],
            expiresAtMs: Date.now() + 30_000,
            singleUse: true,
          }).execution_context_id,
        }),
      },
    );
    const request = (await messagePromise) as PluginHostRpcRequestEnvelope;
    expect(request).toMatchObject({
      kind: "request",
      operation: "ui.command.invoke",
      execution_context_id: expect.any(String),
    });

    port.postMessage({
      protocol: PLUGIN_HOST_RPC_PROTOCOL,
      version: PLUGIN_HOST_RPC_VERSION,
      kind: "response",
      request_id: request.request_id,
      payload: { ok: true },
    });
    await expect(invokePromise).resolves.toEqual({ ok: true });
  });

  it("rejects command selection plaintext without the matching permission", async () => {
    const registry = createPluginUiContributionRegistry();
    registry.register(owner(), {
      surface: "command",
      local_id: "summarize.selection",
      title: "Summarize selection",
      plaintext_request: "selection",
    });

    const { session } = boot(new PluginHostMessageRouter({ windowTarget: undefined }), [
      "ui:command",
    ]);

    await expect(
      invokePluginUiCommand(
        session,
        registry,
        owner(),
        { kind: "local_command", local_id: "summarize.selection" },
        null,
        undefined,
        {
          activeDocument: () => null,
          selection: () => ({ executionContextId: "must-not-be-used" }),
        },
      ),
    ).rejects.toMatchObject({ code: "permission_denied" });
  });

  it("rejects command workspace document query registration without workspace authority", async () => {
    const registry = createPluginUiContributionRegistry();

    expect(() =>
      registry.register(
        owner(),
        {
          surface: "command",
          local_id: "summarize.workspace",
          title: "Summarize workspace",
          document_query: { scope: "workspace", max_documents: 25, max_bytes: 4096 },
        },
        [],
        { workspaceReadAllowed: true },
      ),
    ).toThrowError(expect.objectContaining({ code: "permission_denied" }));

    expect(() =>
      registry.register(
        owner(),
        {
          surface: "command",
          local_id: "summarize.workspace",
          title: "Summarize workspace",
          document_query: { scope: "workspace", max_documents: 25, max_bytes: 4096 },
        },
        ["document:read:workspace"],
        {},
      ),
    ).toThrowError(expect.objectContaining({ code: "document_scope_denied" }));
  });

  it("does not send a command invocation when invocation audit fails", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    registry.register(owner(), {
      surface: "command",
      local_id: "open.panel",
      title: "Open panel",
    });
    const { session, port } = boot(router, []);
    const messages: unknown[] = [];
    port.addEventListener("message", (event) => messages.push(event.data));
    port.start();

    await expect(
      invokePluginUiCommand(
        session,
        registry,
        owner(),
        { kind: "local_command", local_id: "open.panel" },
        null,
        () => {
          throw new PluginHostRpcError("ui_audit_failed", "UI contribution audit was rejected");
        },
      ),
    ).rejects.toMatchObject({ code: "ui_audit_failed" });
    expect(messages).toEqual([]);
  });

  it("records rejected UI invocations when a command reference is denied", async () => {
    const { session } = boot(
      new PluginHostMessageRouter({
        windowTarget: { addEventListener() {}, removeEventListener() {} },
        idFactory: createIdFactory(),
      }),
      [],
    );
    const registry = createPluginUiContributionRegistry();
    const rejected: unknown[] = [];

    await expect(
      invokePluginUiCommand(
        session,
        registry,
        owner(),
        { kind: "local_command", local_id: "missing.command" },
        null,
        {
          accepted() {
            throw new Error("accepted audit should not run");
          },
          rejected(entry, ref, reasonCode) {
            rejected.push({ entry, ref, reasonCode });
          },
        },
      ),
    ).rejects.toMatchObject({ code: "ui_command_ref_denied" });

    expect(rejected).toEqual([
      {
        entry: null,
        ref: { kind: "local_command", local_id: "missing.command" },
        reasonCode: "ui_command_ref_denied",
      },
    ]);
  });

  it("records rejected UI invocations before dispatch when the session is closed", async () => {
    const router = new PluginHostMessageRouter({
      windowTarget: { addEventListener() {}, removeEventListener() {} },
      idFactory: createIdFactory(),
    });
    const registry = createPluginUiContributionRegistry();
    registry.register(owner(), {
      surface: "command",
      local_id: "open.panel",
      title: "Open panel",
    });
    const { session, port } = boot(router, []);
    const messages: unknown[] = [];
    port.addEventListener("message", (event) => messages.push(event.data));
    port.start();
    const rejected: unknown[] = [];
    session.close("test");

    await expect(
      invokePluginUiCommand(
        session,
        registry,
        owner(),
        { kind: "local_command", local_id: "open.panel" },
        null,
        {
          accepted() {
            throw new Error("accepted audit should not run");
          },
          rejected(entry, ref, reasonCode) {
            rejected.push({ entryId: entry?.id, ref, reasonCode });
          },
        },
      ),
    ).rejects.toMatchObject({ code: "session_not_connected" });

    expect(rejected).toEqual([
      {
        entryId: uiId("open.panel"),
        ref: { kind: "local_command", local_id: "open.panel" },
        reasonCode: "session_not_connected",
      },
    ]);
    expect(messages).toEqual([]);
  });

  it("validates settings schema shape", () => {
    const contribution: PluginUiContribution = {
      surface: "settings_declarative",
      local_id: "settings.main",
      settings_id: "settings.main",
      title: "Plugin settings",
      placement: "plugin_settings",
      sections: [
        {
          title: "General",
          fields: [
            { kind: "text", name: "prefix", label: "Prefix", max_length: 80 },
            {
              kind: "select",
              name: "mode",
              label: "Mode",
              options: [
                { value: "compact", label: "Compact" },
                { value: "expanded", label: "Expanded" },
              ],
            },
          ],
        },
      ],
    };

    expect(validatePluginUiContribution(contribution)).toEqual(contribution);
  });
});
