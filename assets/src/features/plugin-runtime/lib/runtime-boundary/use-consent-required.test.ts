import { createSignal } from "solid-js";
import { render } from "solid-js/web";
import { afterEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  authState: vi.fn(),
  cryptoWorkerReady: vi.fn(),
  deviceState: vi.fn(),
  get: vi.fn(),
  post: vi.fn(),
  signPluginConsentEvent: vi.fn(),
}));

vi.mock("@/entities/session", () => ({
  authState: mocks.authState,
  cryptoWorkerReady: mocks.cryptoWorkerReady,
  deviceState: mocks.deviceState,
}));

vi.mock("@/shared/api/core", () => ({
  client: {
    GET: mocks.get,
    POST: mocks.post,
  },
  throwIfError: (result: { data?: unknown; error?: unknown }) => {
    if (result.error) throw result.error;
    return result.data ?? result;
  },
  withUserRrpParams: (params: Record<string, unknown> = {}) => params,
}));

vi.mock("@/shared/lib/crypto/trust-store", () => ({
  getPluginConsentPin: vi.fn(async () => null),
  getPluginStatePin: vi.fn(async () => null),
  savePluginConsentPin: vi.fn(async () => undefined),
  savePluginStatePin: vi.fn(async () => undefined),
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: () => ({
    signPluginConsentEvent: mocks.signPluginConsentEvent,
  }),
}));

import {
  buildPluginConsentSubject,
  highRiskConsentDetails,
  listPluginConsentRequired,
  normalizePluginConsentRequiredDescriptor,
  pluginConsentSecurityWarning,
  pluginConsentEventHash,
  pluginConsentDescriptorsMissingLocalPins,
  submitPluginConsentDecision,
  usePluginConsentRequired,
  type PluginConsentRequiredDescriptor,
} from "./use-consent-required";
import type { HybridSignature } from "@/shared/lib/crypto/signature";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictValueBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import type { PluginRuntimeApplicationDescriptor } from "./runtime-types";

const descriptor: PluginConsentRequiredDescriptor = {
  pluginId: "com.example.plugin",
  packageId: "package-one",
  applicationId: "00000000-0000-4000-8000-000000000001",
  activationId: "activation-one",
  ownerScopeKind: "workspace",
  applicationScopeKind: "workspace",
  workspaceId: "workspace-one",
  stateHeadHash: "state-head-one",
  approvalEventHash: "approval-event-one",
  consentHeadHash: null,
  consentEpoch: null,
  version: "1.0.0",
  bundleHash: "bundle-hash-one",
  manifestHash: "manifest-hash-one",
  resourceManifestHash: "resource-manifest-hash-one",
  permissionsHash: "permissions-hash-one",
  endpointHash: "endpoint-hash-one",
  rendererSlotsHash: "renderer-slots-hash-one",
  documentScopeHash: "document-scope-hash-one",
  signerDeviceId: "approval-device-one",
  signerUserId: "approval-user-one",
  documentScope: null,
  title: "Example Plugin",
  author: "Example Author",
  permissions: ["document:read:active"],
  networkEndpoints: [],
  highRiskConsents: [],
};
type ConsentRequiredEntryForTest = Parameters<typeof normalizePluginConsentRequiredDescriptor>[0];

afterEach(() => {
  vi.useRealTimers();
  document.body.replaceChildren();
  vi.clearAllMocks();
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

describe("plugin consent required flow", () => {
  it("uses low-frequency polling instead of the previous 15s consent loop", async () => {
    vi.useFakeTimers();
    mocks.authState.mockReturnValue({ user: { id: "user-one" } });
    mocks.deviceState.mockReturnValue({ deviceId: "device-one" });
    mocks.get.mockResolvedValue({ data: { applications: [] } });

    const root = document.createElement("div");
    const dispose = render(
      () =>
        usePluginConsentRequired(() => "workspace-one", {
          runtimeApplications: () => [],
        }).view(),
      root,
    );

    try {
      await Promise.resolve();
      await Promise.resolve();
      expect(mocks.get).toHaveBeenCalledTimes(1);
      expect(mocks.get.mock.calls[0]?.[0]).toContain("consent-required");

      await vi.advanceTimersByTimeAsync(15_000);
      expect(mocks.get).toHaveBeenCalledTimes(1);

      await vi.advanceTimersByTimeAsync(105_000);
      expect(mocks.get).toHaveBeenCalledTimes(2);
    } finally {
      dispose();
    }
  });

  it("does not fetch consent descriptors while the startup gate is disabled", async () => {
    mocks.authState.mockReturnValue({ user: { id: "user-one" } });
    mocks.deviceState.mockReturnValue({ deviceId: "device-one" });
    mocks.get.mockResolvedValue({ data: { applications: [] } });

    const root = document.createElement("div");
    let setEnabled!: (value: boolean) => void;
    const dispose = render(() => {
      const [enabled, updateEnabled] = createSignal(false);
      setEnabled = updateEnabled;
      return usePluginConsentRequired(() => "workspace-one", { enabled }).view();
    }, root);

    try {
      await Promise.resolve();
      expect(mocks.get).not.toHaveBeenCalled();

      setEnabled(true);
      await Promise.resolve();
      await Promise.resolve();

      expect(mocks.get).toHaveBeenCalledTimes(2);
      expect(mocks.get.mock.calls[0]?.[0]).toContain("consent-required");
      expect(mocks.get.mock.calls[1]?.[0]).toContain("plugin-runtime");
    } finally {
      dispose();
    }
  });

  it("builds an append-only consent subject from the required descriptor", () => {
    expect(
      buildPluginConsentSubject(descriptor, {
        userId: "user-one",
        deviceId: "device-one",
        decision: "allow",
      }),
    ).toMatchObject({
      plugin_id: "com.example.plugin",
      package_id: "package-one",
      application_id: "00000000-0000-4000-8000-000000000001",
      activation_id: "activation-one",
      owner_scope_kind: "workspace",
      application_scope_kind: "workspace",
      workspace_id: "workspace-one",
      previous_event_hash: "GENESIS",
      consent_epoch: 1,
      decision: "allow",
      signer_user_id: "approval-user-one",
      signer_device_id: "approval-device-one",
      resource_manifest_hash: "resource-manifest-hash-one",
      permissions_hash: "permissions-hash-one",
      endpoint_hash: "endpoint-hash-one",
      document_scope_hash: "document-scope-hash-one",
    });
  });

  it("builds user-owned application consent with descriptor scope identity", () => {
    expect(
      buildPluginConsentSubject(
        {
          ...descriptor,
          ownerScopeKind: "user",
          applicationScopeKind: "workspace",
        },
        {
          userId: "user-one",
          deviceId: "device-one",
          decision: "allow",
        },
      ),
    ).toMatchObject({
      owner_scope_kind: "user",
      application_scope_kind: "workspace",
      resource_manifest_hash: "resource-manifest-hash-one",
    });
  });

  it("renders required artifact identity and security warning in the consent dialog", async () => {
    const entry = consentRequiredEntryForTest();
    expect(normalizePluginConsentRequiredDescriptor(entry)).toHaveLength(1);
    vi.spyOn(window, "scrollTo").mockImplementation(() => undefined);
    mocks.authState.mockReturnValue({ user: { id: "user-one" } });
    mocks.deviceState.mockReturnValue({ deviceId: "device-one" });
    mocks.cryptoWorkerReady.mockReturnValue(true);
    mocks.get.mockImplementation(async (path: string) => ({
      data: {
        applications: path.includes("consent-required") ? [entry] : [],
      },
    }));

    const root = document.createElement("div");
    document.body.append(root);
    const dispose = render(() => usePluginConsentRequired(() => "workspace-one").view(), root);
    await flushMicrotasks();
    expect(mocks.get).toHaveBeenCalledTimes(2);

    const text = document.body.textContent ?? "";
    expect(text).toContain("Example Plugin");
    expect(text).toContain("Example Author");
    expect(text).toContain("1.0.0");
    expect(text).toContain("bundle-h");
    expect(text).toContain("document:read:active");
    expect(text).toContain("network:fetch");
    expect(text).toContain(pluginConsentSecurityWarning());

    dispose();
  });

  it("keeps local approval trust internal when allowing consent from the dialog", async () => {
    const trustStore = await import("@/shared/lib/crypto/trust-store");
    const getPluginStatePin = vi.mocked(trustStore.getPluginStatePin);
    const savePluginStatePin = vi.mocked(trustStore.savePluginStatePin);
    const entry = consentRequiredEntryForTest();
    const signature = {
      protocol: "refmd.hybrid-signature",
      signing_key_id: "signing-key-one",
    } as HybridSignature;
    vi.spyOn(window, "scrollTo").mockImplementation(() => undefined);
    mocks.authState.mockReturnValue({ user: { id: "user-one" } });
    mocks.deviceState.mockReturnValue({
      deviceId: "device-one",
      deviceKeyCheckpointSequence: 1,
      deviceKeyCheckpointHash: "checkpoint-one",
    });
    mocks.cryptoWorkerReady.mockReturnValue(true);
    mocks.get.mockImplementation(async (path: string) => ({
      data: {
        applications: path.includes("consent-required") ? [entry] : [],
      },
    }));
    mocks.signPluginConsentEvent.mockResolvedValue({ signature });
    mocks.post.mockImplementation(
      async (_path: string, options: { body?: Record<string, unknown> }) => ({
        data: {
          consent_event: {
            event_hash: options.body?.event_hash,
            decision: options.body?.decision,
            consent_epoch: options.body?.consent_epoch,
          },
        },
      }),
    );
    getPluginStatePin.mockResolvedValueOnce(null).mockResolvedValue({
      workspaceId: "workspace-one",
      packageId: "package-one",
      applicationId: "00000000-0000-4000-8000-000000000001",
      activationId: "activation-one",
      latestEventHash: "state-head-one",
      bundleHash: "bundle-hash-one",
      approvalEventHash: "approval-event-one",
      updatedAtMs: 1,
    });

    const root = document.createElement("div");
    document.body.append(root);
    const dispose = render(() => usePluginConsentRequired(() => "workspace-one").view(), root);
    await flushMicrotasks();

    const trustButton = Array.from(document.querySelectorAll("button")).find(
      (button) => button.textContent?.trim() === "Trust on this device",
    );
    expect(trustButton).toBeUndefined();
    const allowButton = Array.from(document.querySelectorAll("button")).find(
      (button) => button.textContent?.trim() === "Allow",
    );
    expect(allowButton).toBeDefined();
    allowButton?.click();
    await flushMicrotasks();
    await flushMicrotasks();

    expect(savePluginStatePin).toHaveBeenCalledWith({
      workspaceId: "workspace-one",
      packageId: "package-one",
      applicationId: "00000000-0000-4000-8000-000000000001",
      activationId: "activation-one",
      latestEventHash: "state-head-one",
      bundleHash: "bundle-hash-one",
      approvalEventHash: "approval-event-one",
      updatedAtMs: expect.any(Number),
    });
    expect(mocks.signPluginConsentEvent).toHaveBeenCalledWith({
      consent: expect.objectContaining({ decision: "allow" }),
      keyCheckpointSequence: 1,
      keyCheckpointHash: "checkpoint-one",
    });
    expect(mocks.post).toHaveBeenCalled();

    dispose();
  });

  it("renders revoke for consent with an existing event head", async () => {
    const entry = consentRequiredEntryForTest({
      consent_head_hash: "consent-head-one",
      consent_epoch: 1,
    });
    expect(normalizePluginConsentRequiredDescriptor(entry)).toHaveLength(1);
    vi.spyOn(window, "scrollTo").mockImplementation(() => undefined);
    mocks.authState.mockReturnValue({ user: { id: "user-one" } });
    mocks.deviceState.mockReturnValue({ deviceId: "device-one" });
    mocks.cryptoWorkerReady.mockReturnValue(true);
    mocks.get.mockImplementation(async (path: string) => ({
      data: {
        applications: path.includes("consent-required") ? [entry] : [],
      },
    }));

    const root = document.createElement("div");
    document.body.append(root);
    const dispose = render(() => usePluginConsentRequired(() => "workspace-one").view(), root);
    await flushMicrotasks();

    expect(document.body.textContent ?? "").toContain("Revoke");

    dispose();
  });

  it("dismisses the consent prompt without recording a decision", async () => {
    const entry = consentRequiredEntryForTest();
    vi.spyOn(window, "scrollTo").mockImplementation(() => undefined);
    mocks.authState.mockReturnValue({ user: { id: "user-one" } });
    mocks.deviceState.mockReturnValue({ deviceId: "device-one" });
    mocks.cryptoWorkerReady.mockReturnValue(true);
    mocks.get.mockImplementation(async (path: string) => ({
      data: {
        applications: path.includes("consent-required") ? [entry] : [],
      },
    }));

    const root = document.createElement("div");
    document.body.append(root);
    const dispose = render(() => usePluginConsentRequired(() => "workspace-one").view(), root);
    await flushMicrotasks();

    expect(document.body.textContent ?? "").toContain("Example Plugin");
    const closeButton = Array.from(document.querySelectorAll("button")).find(
      (button) => button.textContent?.trim() === "Close",
    );
    expect(closeButton).toBeDefined();
    closeButton?.click();
    await flushMicrotasks();

    expect(document.body.textContent ?? "").not.toContain("Example Plugin");
    expect(mocks.post).not.toHaveBeenCalled();

    dispose();
  });

  it("clears stale consent descriptors immediately when runtime applications refresh", async () => {
    const entry = consentRequiredEntryForTest();
    vi.spyOn(window, "scrollTo").mockImplementation(() => undefined);
    mocks.authState.mockReturnValue({ user: { id: "user-one" } });
    mocks.deviceState.mockReturnValue({ deviceId: "device-one" });
    mocks.cryptoWorkerReady.mockReturnValue(true);
    mocks.get.mockImplementation(async (path: string) => ({
      data: {
        applications: path.includes("consent-required") ? [entry] : [],
      },
    }));

    const root = document.createElement("div");
    document.body.append(root);
    const dispose = render(() => usePluginConsentRequired(() => "workspace-one").view(), root);
    await flushMicrotasks();

    expect(document.body.textContent ?? "").toContain("Example Plugin");

    let resolveRefresh: (() => void) | undefined;
    mocks.get.mockImplementation((path: string) => {
      if (path.includes("consent-required")) {
        return new Promise((resolve) => {
          resolveRefresh = () => resolve({ data: { applications: [] } });
        });
      }
      return Promise.resolve({ data: { applications: [] } });
    });

    window.dispatchEvent(
      new CustomEvent("refmd-plugin-runtime-applications-refresh", {
        detail: { workspaceId: "workspace-one" },
      }),
    );

    expect(document.body.textContent ?? "").not.toContain("Example Plugin");

    resolveRefresh?.();
    await flushMicrotasks();
    expect(document.body.textContent ?? "").not.toContain("Example Plugin");

    dispose();
  });

  it("summarizes high-risk plaintext network authority for consent display", () => {
    expect(
      highRiskConsentDetails({
        ...descriptor,
        permissions: ["document:read:workspace", "network:fetch"],
        documentScope: { workspaceReadAllowed: true },
        networkEndpoints: [
          {
            url: "https://api.example.com/export",
            routes: ["proxy"],
            maxRequestBytes: 1024,
            maxResponseBytes: 2048,
          },
        ],
        highRiskConsents: ["plaintext_network_egress", "workspace_network_egress"],
      }),
    ).toEqual([
      "Plaintext-capable plugin may send received plaintext to declared endpoints.",
      "Workspace-wide plaintext scope can be exported to declared network endpoints.",
      "Workspace document source limit: up to 500 documents and 1048576 plaintext bytes per invocation.",
      "Endpoint https://api.example.com/export; routes: proxy; request limit: 1024 bytes; response limit: 2048 bytes",
      "Proxy route uses the configured proxy operator. Proxy operator and target endpoint can process target URL, method, request headers/body, response status/headers/body, timing, size, credential use, and plaintext included in the request or response.",
    ]);
  });

  it("discloses configured proxy operator visibility in consent details", () => {
    expect(
      highRiskConsentDetails({
        ...descriptor,
        permissions: ["document:read:active", "network:fetch"],
        networkEndpoints: [
          {
            url: "https://api.example.com/summarize",
            routes: ["proxy"],
          },
        ],
        highRiskConsents: ["plaintext_network_egress"],
      }),
    ).toContain(
      "Proxy route uses the configured proxy operator. Proxy operator and target endpoint can process target URL, method, request headers/body, response status/headers/body, timing, size, credential use, and plaintext included in the request or response.",
    );
  });

  it("identifies the effective workspace proxy operator in consent details", () => {
    expect(
      highRiskConsentDetails(
        {
          ...descriptor,
          permissions: ["document:read:active", "network:fetch"],
          networkEndpoints: [
            {
              url: "https://api.example.com/summarize",
              routes: ["proxy"],
            },
          ],
          highRiskConsents: ["plaintext_network_egress"],
        },
        {
          proxy: {
            id: "workspace-proxy",
            label: "Workspace Proxy",
            origin: "https://proxy.example/refmd",
            scope: "workspace",
            operatorLabel: "Example NetOps",
          },
        },
      ),
    ).toContain(
      "Proxy route uses Workspace Proxy (https://proxy.example/refmd; workspace scope; id: workspace-proxy; operator: Example NetOps). Proxy operator and target endpoint can process target URL, method, request headers/body, response status/headers/body, timing, size, credential use, and plaintext included in the request or response.",
    );
  });

  it("summarizes plaintext document write authority for consent display", () => {
    expect(
      highRiskConsentDetails({
        ...descriptor,
        permissions: ["document:read:active", "document:write"],
        highRiskConsents: ["plaintext_document_write"],
      }),
    ).toContain(
      "Plaintext-capable plugin may write encrypted document updates whose size, frequency, and timing remain observable.",
    );
  });

  it("summarizes plaintext cache storage authority for consent display", () => {
    expect(
      highRiskConsentDetails({
        ...descriptor,
        permissions: ["document:read:active", "storage:write:cache"],
        highRiskConsents: ["plaintext_cache_storage"],
      }),
    ).toContain(
      "Plaintext-capable plugin may store derived plaintext data in the encrypted local cache.",
    );
  });

  it("rejects consent-required descriptors when displayed fields do not match semantic hashes", () => {
    const entry = {
      plugin_id: "com.example.plugin",
      package_id: "package-one",
      application_id: "00000000-0000-4000-8000-000000000001",
      activation_id: "activation-one",
      owner_scope_kind: "workspace",
      application_scope_kind: "workspace",
      user_id: "user-one",
      device_id: "device-one",
      workspace_id: "workspace-one",
      state_head_hash: "state-head-one",
      approval_event_hash: "approval-event-one",
      consent_head_hash: null,
      consent_epoch: null,
      version: "1.0.0",
      bundle_hash: "bundle-hash-one",
      manifest_hash: "manifest-hash-one",
      resource_manifest_hash: "resource-manifest-hash-one",
      permissions: ["document:read:active"],
      network_endpoints: [],
      renderer_slots: [],
      document_scopes: [{ kind: "active" }],
      permissions_hash: semanticHashForTest(["document:read:active"]),
      endpoint_hash: semanticHashForTest([]),
      renderer_slots_hash: semanticHashForTest([]),
      document_scope_hash: semanticHashForTest([{ kind: "active" }]),
      signer_device_id: "approval-device-one",
      signer_user_id: "approval-user-one",
      title: "Example Plugin",
    };

    expect(normalizePluginConsentRequiredDescriptor(entry)).toHaveLength(1);
    expect(
      normalizePluginConsentRequiredDescriptor({
        ...entry,
        permissions_hash: semanticHashForTest(["document:read:workspace"]),
      }),
    ).toEqual([]);
  });

  it("rejects allow before signing when the plugin state pin is missing", async () => {
    const sign = vi.fn(async () => ({ signature: {} as HybridSignature }));
    const appendConsent = vi.fn(async (body) => ({
      consent_event: {
        event_hash: body.event_hash as string,
        decision: "allow",
        consent_epoch: 1,
      },
    }));
    const saveConsentPin = vi.fn(async () => undefined);

    await expect(
      submitPluginConsentDecision(descriptor, "allow", {
        userId: "user-one",
        deviceId: "device-one",
        sign,
        appendConsent,
        getStatePin: vi.fn(async () => null),
        saveConsentPin,
        nowMs: () => 123,
      }),
    ).rejects.toThrow("plugin_state_pin_required");

    expect(sign).not.toHaveBeenCalled();
    expect(appendConsent).not.toHaveBeenCalled();
    expect(saveConsentPin).not.toHaveBeenCalled();
  });

  it("appends signed consent and stores the local consent pin after allow with matching state pin", async () => {
    const appendConsent = vi.fn(async (body) => ({
      consent_event: {
        event_hash: body.event_hash as string,
        decision: "allow",
        consent_epoch: 1,
      },
    }));
    const saveConsentPin = vi.fn(async () => undefined);
    const signature = {
      protocol: "refmd.hybrid-signature",
      signing_key_id: "signing-key-one",
    } as HybridSignature;

    await submitPluginConsentDecision(descriptor, "allow", {
      userId: "user-one",
      deviceId: "device-one",
      sign: vi.fn(async (consent) => {
        expect(pluginConsentEventHash(consent)).toEqual(expect.any(String));
        return { signature };
      }),
      appendConsent,
      getStatePin: vi.fn(async () => ({
        workspaceId: descriptor.workspaceId,
        packageId: descriptor.packageId,
        applicationId: descriptor.applicationId,
        activationId: descriptor.activationId,
        latestEventHash: descriptor.stateHeadHash,
        bundleHash: descriptor.bundleHash,
        approvalEventHash: descriptor.approvalEventHash,
        updatedAtMs: 1,
      })),
      saveConsentPin,
      nowMs: () => 123,
    });

    expect(appendConsent).toHaveBeenCalledWith(
      expect.objectContaining({
        decision: "allow",
        event_hash: expect.any(String),
        hybrid_signature: signature,
      }),
    );
    expect(saveConsentPin).toHaveBeenCalledWith({
      workspaceId: "workspace-one",
      packageId: "package-one",
      applicationId: "00000000-0000-4000-8000-000000000001",
      activationId: "activation-one",
      userId: "user-one",
      consentEpoch: 1,
      latestEventHash: expect.any(String),
      updatedAtMs: 123,
    });
  });

  it("does not require a runtime state pin when the member denies consent", async () => {
    const appendConsent = vi.fn(async (body) => ({
      consent_event: {
        event_hash: body.event_hash as string,
        decision: "deny",
        consent_epoch: 1,
      },
    }));

    await submitPluginConsentDecision(descriptor, "deny", {
      userId: "user-one",
      deviceId: "device-one",
      sign: vi.fn(async () => ({ signature: {} as HybridSignature })),
      appendConsent,
      getStatePin: vi.fn(async () => null),
      saveConsentPin: vi.fn(async () => undefined),
      nowMs: () => 123,
    });

    expect(appendConsent).toHaveBeenCalledWith(
      expect.objectContaining({
        decision: "deny",
        event_hash: expect.any(String),
      }),
    );
  });

  it("does not require a runtime state pin when the member revokes consent", async () => {
    const revokedDescriptor = {
      ...descriptor,
      consentHeadHash: "consent-head-one",
      consentEpoch: 1,
    };
    const getStatePin = vi.fn(async () => null);
    const appendConsent = vi.fn(async (body) => ({
      consent_event: {
        event_hash: body.event_hash as string,
        decision: "revoke",
        consent_epoch: 2,
      },
    }));
    const saveConsentPin = vi.fn(async () => undefined);

    await submitPluginConsentDecision(revokedDescriptor, "revoke", {
      userId: "user-one",
      deviceId: "device-one",
      sign: vi.fn(async () => ({ signature: {} as HybridSignature })),
      appendConsent,
      getStatePin,
      saveConsentPin,
      nowMs: () => 123,
    });

    expect(getStatePin).not.toHaveBeenCalled();
    expect(appendConsent).toHaveBeenCalledWith(
      expect.objectContaining({
        decision: "revoke",
        previous_event_hash: "consent-head-one",
        consent_epoch: 2,
        event_hash: expect.any(String),
      }),
    );
    expect(saveConsentPin).toHaveBeenCalledWith(
      expect.objectContaining({
        consentEpoch: 2,
        latestEventHash: expect.any(String),
      }),
    );
  });

  it("surfaces server-allowed plugin descriptors when local runtime pins are missing", async () => {
    await expect(
      pluginConsentDescriptorsMissingLocalPins([descriptor], "user-one", {
        getStatePin: vi.fn(async () => null),
        getConsentPin: vi.fn(async () => null),
      }),
    ).resolves.toEqual([descriptor]);
  });

  it("reuses loaded runtime applications instead of fetching plugin runtime twice", async () => {
    const runtimeApplication: PluginRuntimeApplicationDescriptor = {
      pluginId: descriptor.pluginId,
      packageId: descriptor.packageId,
      applicationId: descriptor.applicationId,
      activationId: descriptor.activationId,
      ownerScopeKind: descriptor.ownerScopeKind,
      applicationScopeKind: descriptor.applicationScopeKind,
      workspaceId: descriptor.workspaceId,
      userId: "user-one",
      deviceId: "device-one",
      stateHeadHash: descriptor.stateHeadHash,
      approvalEventHash: descriptor.approvalEventHash,
      consentHeadHash: "consent-head-one",
      consentEpoch: 1,
      version: descriptor.version,
      bundleHash: descriptor.bundleHash,
      manifestHash: descriptor.manifestHash,
      resourceManifestHash: descriptor.resourceManifestHash,
      permissionsHash: descriptor.permissionsHash,
      endpointHash: descriptor.endpointHash,
      rendererSlotsHash: descriptor.rendererSlotsHash,
      documentScopeHash: descriptor.documentScopeHash,
      signerDeviceId: descriptor.signerDeviceId,
      signerUserId: descriptor.signerUserId,
      capabilityGrantId: "capability-one",
      title: descriptor.title,
      author: descriptor.author,
      permissions: ["document:read:active"],
      networkEndpoints: [],
      rendererSlots: [],
      highRiskConsents: [],
    };
    mocks.authState.mockReturnValue({ user: { id: "user-one" } });
    mocks.get.mockImplementation(async (path: string) => ({
      data: {
        applications: path.includes("consent-required") ? [] : [consentRequiredEntryForTest()],
      },
    }));

    await expect(
      listPluginConsentRequired("workspace-one", { runtimeApplications: [runtimeApplication] }),
    ).resolves.toEqual([
      expect.objectContaining({
        applicationId: descriptor.applicationId,
        consentHeadHash: "consent-head-one",
      }),
    ]);

    expect(mocks.get).toHaveBeenCalledTimes(1);
    expect(mocks.get.mock.calls[0]?.[0]).toContain("consent-required");
  });

  it("does not resurface server-allowed plugin descriptors with matching local pins", async () => {
    const allowedDescriptor = {
      ...descriptor,
      consentHeadHash: "consent-head-one",
      consentEpoch: 1,
    };

    await expect(
      pluginConsentDescriptorsMissingLocalPins([allowedDescriptor], "user-one", {
        getStatePin: vi.fn(async () => ({
          workspaceId: allowedDescriptor.workspaceId,
          packageId: allowedDescriptor.packageId,
          applicationId: allowedDescriptor.applicationId,
          activationId: allowedDescriptor.activationId,
          latestEventHash: allowedDescriptor.stateHeadHash,
          bundleHash: allowedDescriptor.bundleHash,
          approvalEventHash: allowedDescriptor.approvalEventHash,
          updatedAtMs: 1,
        })),
        getConsentPin: vi.fn(async () => ({
          workspaceId: allowedDescriptor.workspaceId,
          packageId: allowedDescriptor.packageId,
          applicationId: allowedDescriptor.applicationId,
          activationId: allowedDescriptor.activationId,
          userId: "user-one",
          consentEpoch: 1,
          latestEventHash: "consent-head-one",
          updatedAtMs: 1,
        })),
      }),
    ).resolves.toEqual([]);
  });

  it("resurfaces server-allowed plugin descriptors when either local pin is missing", async () => {
    const allowedDescriptor = {
      ...descriptor,
      consentHeadHash: "consent-head-one",
      consentEpoch: 1,
    };

    await expect(
      pluginConsentDescriptorsMissingLocalPins([allowedDescriptor], "user-one", {
        getStatePin: vi.fn(async () => null),
        getConsentPin: vi.fn(async () => ({
          workspaceId: allowedDescriptor.workspaceId,
          packageId: allowedDescriptor.packageId,
          applicationId: allowedDescriptor.applicationId,
          activationId: allowedDescriptor.activationId,
          userId: "user-one",
          consentEpoch: 1,
          latestEventHash: "consent-head-one",
          updatedAtMs: 1,
        })),
      }),
    ).resolves.toEqual([allowedDescriptor]);

    await expect(
      pluginConsentDescriptorsMissingLocalPins([allowedDescriptor], "user-one", {
        getStatePin: vi.fn(async () => ({
          workspaceId: allowedDescriptor.workspaceId,
          packageId: allowedDescriptor.packageId,
          applicationId: allowedDescriptor.applicationId,
          activationId: allowedDescriptor.activationId,
          latestEventHash: allowedDescriptor.stateHeadHash,
          bundleHash: allowedDescriptor.bundleHash,
          approvalEventHash: allowedDescriptor.approvalEventHash,
          updatedAtMs: 1,
        })),
        getConsentPin: vi.fn(async () => null),
      }),
    ).resolves.toEqual([allowedDescriptor]);
  });

  it("resurfaces server-allowed plugin descriptors with mismatched local pins", async () => {
    const allowedDescriptor = {
      ...descriptor,
      consentHeadHash: "consent-head-one",
      consentEpoch: 1,
    };

    await expect(
      pluginConsentDescriptorsMissingLocalPins([allowedDescriptor], "user-one", {
        getStatePin: vi.fn(async () => ({
          workspaceId: allowedDescriptor.workspaceId,
          packageId: allowedDescriptor.packageId,
          applicationId: allowedDescriptor.applicationId,
          activationId: allowedDescriptor.activationId,
          latestEventHash: "older-state-head",
          bundleHash: "older-bundle-hash",
          approvalEventHash: "older-state-head",
          updatedAtMs: 1,
        })),
        getConsentPin: vi.fn(async () => ({
          workspaceId: allowedDescriptor.workspaceId,
          packageId: allowedDescriptor.packageId,
          applicationId: allowedDescriptor.applicationId,
          activationId: allowedDescriptor.activationId,
          userId: "user-one",
          consentEpoch: 1,
          latestEventHash: "consent-head-one",
          updatedAtMs: 1,
        })),
      }),
    ).resolves.toEqual([allowedDescriptor]);

    await expect(
      pluginConsentDescriptorsMissingLocalPins([allowedDescriptor], "user-one", {
        getStatePin: vi.fn(async () => ({
          workspaceId: allowedDescriptor.workspaceId,
          packageId: allowedDescriptor.packageId,
          applicationId: allowedDescriptor.applicationId,
          activationId: allowedDescriptor.activationId,
          latestEventHash: allowedDescriptor.stateHeadHash,
          bundleHash: "older-bundle-hash",
          approvalEventHash: allowedDescriptor.approvalEventHash,
          updatedAtMs: 1,
        })),
        getConsentPin: vi.fn(async () => ({
          workspaceId: allowedDescriptor.workspaceId,
          packageId: allowedDescriptor.packageId,
          applicationId: allowedDescriptor.applicationId,
          activationId: allowedDescriptor.activationId,
          userId: "user-one",
          consentEpoch: 1,
          latestEventHash: "consent-head-one",
          updatedAtMs: 1,
        })),
      }),
    ).resolves.toEqual([allowedDescriptor]);

    await expect(
      pluginConsentDescriptorsMissingLocalPins([allowedDescriptor], "user-one", {
        getStatePin: vi.fn(async () => ({
          workspaceId: allowedDescriptor.workspaceId,
          packageId: allowedDescriptor.packageId,
          applicationId: allowedDescriptor.applicationId,
          activationId: allowedDescriptor.activationId,
          latestEventHash: allowedDescriptor.stateHeadHash,
          bundleHash: allowedDescriptor.bundleHash,
          approvalEventHash: allowedDescriptor.approvalEventHash,
          updatedAtMs: 1,
        })),
        getConsentPin: vi.fn(async () => ({
          workspaceId: allowedDescriptor.workspaceId,
          packageId: allowedDescriptor.packageId,
          applicationId: allowedDescriptor.applicationId,
          activationId: allowedDescriptor.activationId,
          userId: "user-one",
          consentEpoch: 1,
          latestEventHash: "older-consent-head",
          updatedAtMs: 1,
        })),
      }),
    ).resolves.toEqual([allowedDescriptor]);

    await expect(
      pluginConsentDescriptorsMissingLocalPins([allowedDescriptor], "user-one", {
        getStatePin: vi.fn(async () => ({
          workspaceId: allowedDescriptor.workspaceId,
          packageId: allowedDescriptor.packageId,
          applicationId: allowedDescriptor.applicationId,
          activationId: allowedDescriptor.activationId,
          latestEventHash: allowedDescriptor.stateHeadHash,
          bundleHash: allowedDescriptor.bundleHash,
          approvalEventHash: allowedDescriptor.approvalEventHash,
          updatedAtMs: 1,
        })),
        getConsentPin: vi.fn(async () => ({
          workspaceId: allowedDescriptor.workspaceId,
          packageId: allowedDescriptor.packageId,
          applicationId: allowedDescriptor.applicationId,
          activationId: allowedDescriptor.activationId,
          userId: "user-one",
          consentEpoch: 0,
          latestEventHash: "consent-head-one",
          updatedAtMs: 1,
        })),
      }),
    ).resolves.toEqual([allowedDescriptor]);
  });

  it("rejects allow when an existing state pin does not match the descriptor", async () => {
    const appendConsent = vi.fn(async (body) => ({
      consent_event: {
        event_hash: body.event_hash as string,
        decision: "allow",
        consent_epoch: 1,
      },
    }));
    await expect(
      submitPluginConsentDecision(descriptor, "allow", {
        userId: "user-one",
        deviceId: "device-one",
        sign: vi.fn(async () => ({ signature: {} as HybridSignature })),
        appendConsent,
        getStatePin: vi.fn(async () => ({
          workspaceId: descriptor.workspaceId,
          packageId: descriptor.packageId,
          applicationId: descriptor.applicationId,
          activationId: descriptor.activationId,
          latestEventHash: "older-state-head",
          bundleHash: "older-bundle-hash",
          approvalEventHash: "older-state-head",
          updatedAtMs: 1,
        })),
        saveConsentPin: vi.fn(async () => undefined),
        nowMs: () => 123,
      }),
    ).rejects.toThrow("plugin_state_pin_mismatch");

    expect(appendConsent).not.toHaveBeenCalled();
  });
});

function consentRequiredEntryForTest(
  overrides: Partial<ConsentRequiredEntryForTest> = {},
): ConsentRequiredEntryForTest {
  return {
    plugin_id: "com.example.plugin",
    package_id: "package-one",
    application_id: "00000000-0000-4000-8000-000000000001",
    activation_id: "activation-one",
    owner_scope_kind: "workspace",
    application_scope_kind: "workspace",
    workspace_id: "workspace-one",
    state_head_hash: "state-head-one",
    approval_event_hash: "approval-event-one",
    consent_head_hash: null,
    consent_epoch: null,
    version: "1.0.0",
    bundle_hash: "bundle-hash-one",
    manifest_hash: "manifest-hash-one",
    resource_manifest_hash: "resource-manifest-hash-one",
    permissions: ["document:read:active", "network:fetch"],
    network_endpoints: [
      {
        id: "api",
        url: "https://api.example.com/export",
        routes: ["proxy"],
      },
    ],
    renderer_slots: [],
    document_scopes: [{ kind: "active" }],
    permissions_hash: semanticHashForTest(["document:read:active", "network:fetch"]),
    endpoint_hash: semanticHashForTest([
      {
        id: "api",
        url: "https://api.example.com/export",
        routes: ["proxy"],
      },
    ]),
    renderer_slots_hash: semanticHashForTest([]),
    document_scope_hash: semanticHashForTest([{ kind: "active" }]),
    signer_device_id: "approval-device-one",
    signer_user_id: "approval-user-one",
    title: "Example Plugin",
    author: "Example Author",
    ...overrides,
  };
}

function semanticHashForTest(value: StrictJsonValue): string {
  return blake3Base64Url(canonicalizeStrictValueBytes(value));
}

async function flushMicrotasks(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
  await Promise.resolve();
  await new Promise((resolve) => setTimeout(resolve, 0));
}
