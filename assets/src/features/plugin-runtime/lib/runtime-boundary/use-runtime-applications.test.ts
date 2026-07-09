import { createRoot, createSignal, type Accessor } from "solid-js";
import { afterEach, describe, expect, it, vi } from "vite-plus/test";
import { purgePluginApplicationLocalData } from "../storage/host-storage";
import { runBeforeSessionCleanup } from "@/shared/lib/auth/session-cleanup";
import {
  handlePluginRuntimeSecurityNotification,
  listPluginRuntimeApplications,
  normalizeDocumentScope,
  normalizeNetworkEndpoints,
  reconcilePluginRuntimeNotifications,
  usePluginRuntimeApplications,
} from "./use-runtime-applications";
import type { PluginRuntimeApplicationDescriptor } from "./runtime-types";
import { normalizeRendererSlots } from "./renderer-slot-normalization";
import {
  beginPluginRuntimeWorkspaceRevocation,
  releasePluginRuntimeWorkspaceRevocation,
  waitForPluginRuntimeWorkspaceIdle,
} from "./runtime-workspace-revocation";

const mocks = vi.hoisted(() => ({
  authState: vi.fn(),
  deviceState: vi.fn(),
  get: vi.fn(),
}));

vi.mock("@/entities/session", () => ({
  authState: mocks.authState,
  deviceState: mocks.deviceState,
}));

vi.mock("@/shared/api/core", () => ({
  client: {
    GET: mocks.get,
  },
  throwIfError: (result: { data?: unknown; error?: unknown }) => {
    if (result.error) throw result.error;
    return result.data ?? result;
  },
  withUserRrpParams: (params: Record<string, unknown> = {}) => params,
}));

vi.mock("../storage/host-storage", () => ({
  purgePluginApplicationLocalData: vi.fn(async () => undefined),
}));

afterEach(() => {
  vi.useRealTimers();
  vi.clearAllMocks();
  mocks.authState.mockReturnValue(null);
  mocks.deviceState.mockReturnValue(null);
  delete window.__refmdPluginRuntimeDebug;
});

describe("plugin runtime application descriptors", () => {
  it("uses low-frequency polling instead of the previous 15s startup loop", async () => {
    vi.useFakeTimers();
    mocks.authState.mockReturnValue({
      user: { id: "user-one", email: "user@example.test", name: "User One" },
      sessionId: "session-one",
      expiresAt: null,
      identityHybridSigningPublicKeyMaterial: null,
      identityEcdhPublic: null,
    });
    mocks.deviceState.mockReturnValue({
      deviceId: "device-one",
      deviceSigningKeyId: null,
      deviceHybridSigningPublicKeyMaterial: null,
      deviceEcdhPublic: null,
    });
    mocks.get.mockResolvedValue({ data: { applications: [] } });

    const dispose = createRoot((disposeRoot) => {
      const [workspaceId] = createSignal<string | null>("workspace-one");
      usePluginRuntimeApplications(workspaceId);
      return disposeRoot;
    });

    try {
      await Promise.resolve();
      expect(mocks.get).toHaveBeenCalledTimes(1);

      await vi.advanceTimersByTimeAsync(15_000);
      expect(mocks.get).toHaveBeenCalledTimes(1);

      await vi.advanceTimersByTimeAsync(105_000);
      expect(mocks.get).toHaveBeenCalledTimes(2);
    } finally {
      dispose();
    }
  });

  it("does not fetch runtime descriptors while the startup gate is disabled", async () => {
    mocks.authState.mockReturnValue({
      user: { id: "user-one", email: "user@example.test", name: "User One" },
      sessionId: "session-one",
      expiresAt: null,
      identityHybridSigningPublicKeyMaterial: null,
      identityEcdhPublic: null,
    });
    mocks.deviceState.mockReturnValue({
      deviceId: "device-one",
      deviceSigningKeyId: null,
      deviceHybridSigningPublicKeyMaterial: null,
      deviceEcdhPublic: null,
    });
    mocks.get.mockResolvedValue({ data: { applications: [] } });

    let setEnabled!: (value: boolean) => void;
    const dispose = createRoot((disposeRoot) => {
      const [workspaceId] = createSignal<string | null>("workspace-one");
      const [enabled, updateEnabled] = createSignal(false);
      setEnabled = updateEnabled;
      usePluginRuntimeApplications(workspaceId, undefined, undefined, { enabled });
      return disposeRoot;
    });

    try {
      await Promise.resolve();
      expect(mocks.get).not.toHaveBeenCalled();

      setEnabled(true);
      await Promise.resolve();
      await Promise.resolve();

      expect(mocks.get).toHaveBeenCalledTimes(1);
      expect(mocks.get.mock.calls[0]?.[0]).toContain("plugin-runtime");
    } finally {
      dispose();
    }
  });

  it("does not republish stale runtime applications when an in-flight refresh completes after session cleanup", async () => {
    let resolveRuntimeList!: (value: unknown) => void;
    mocks.authState.mockReturnValue({
      user: { id: "user-one", email: "user@example.test", name: "User One" },
      sessionId: "session-one",
      expiresAt: null,
      identityHybridSigningPublicKeyMaterial: null,
      identityEcdhPublic: null,
    });
    mocks.deviceState.mockReturnValue({
      deviceId: "device-one",
      deviceSigningKeyId: null,
      deviceHybridSigningPublicKeyMaterial: null,
      deviceEcdhPublic: null,
    });
    mocks.get.mockReturnValue(
      new Promise((resolve) => {
        resolveRuntimeList = resolve;
      }),
    );

    let applications!: Accessor<readonly PluginRuntimeApplicationDescriptor[]>;
    const dispose = createRoot((disposeRoot) => {
      const [workspaceId] = createSignal<string | null>("workspace-one");
      applications = usePluginRuntimeApplications(workspaceId);
      return disposeRoot;
    });

    try {
      await Promise.resolve();
      expect(mocks.get).toHaveBeenCalledTimes(1);

      await runBeforeSessionCleanup({ secure: true });
      expect(applications()).toEqual([]);
      expect(window.__refmdPluginRuntimeDebug?.applications).toEqual([]);

      resolveRuntimeList({
        data: {
          applications: [
            {
              plugin_id: "io.refmd.storage-demo",
              package_id: "package-one",
              application_id: "application-one",
              activation_id: "activation-one",
              owner_scope_kind: "workspace",
              application_scope_kind: "workspace",
              workspace_id: "workspace-one",
              state_head_hash: "state-one",
              consent_head_hash: "consent-one",
              consent_epoch: 1,
              bundle_hash: "bundle-one",
              approval_event_hash: "approval-one",
              capability_grant_id: "capability-one",
              permissions: [],
              network_endpoints: [],
              renderer_slots: [],
              high_risk_consents: [],
            },
          ],
        },
      });
      await Promise.resolve();
      await Promise.resolve();

      expect(applications()).toEqual([]);
      expect(window.__refmdPluginRuntimeDebug?.applications).toEqual([]);
    } finally {
      dispose();
    }
  });

  it("drains in-flight descriptor fetches and skips new fetches while workspace revocation is active", async () => {
    let resolveRuntimeList!: (value: unknown) => void;
    mocks.authState.mockReturnValue({
      user: { id: "user-one", email: "user@example.test", name: "User One" },
      sessionId: "session-one",
      expiresAt: null,
      identityHybridSigningPublicKeyMaterial: null,
      identityEcdhPublic: null,
    });
    mocks.deviceState.mockReturnValue({
      deviceId: "device-one",
      deviceSigningKeyId: null,
      deviceHybridSigningPublicKeyMaterial: null,
      deviceEcdhPublic: null,
    });
    mocks.get.mockReturnValueOnce(
      new Promise((resolve) => {
        resolveRuntimeList = resolve;
      }),
    );

    const request = listPluginRuntimeApplications("workspace-one");
    await Promise.resolve();
    expect(mocks.get).toHaveBeenCalledTimes(1);

    beginPluginRuntimeWorkspaceRevocation("workspace-one");
    try {
      let idle = false;
      const idleRequest = waitForPluginRuntimeWorkspaceIdle("workspace-one").then(() => {
        idle = true;
      });
      await Promise.resolve();
      expect(idle).toBe(false);

      resolveRuntimeList({
        data: {
          applications: [
            {
              plugin_id: "io.refmd.storage-demo",
              package_id: "package-one",
              application_id: "application-one",
              activation_id: "activation-one",
              owner_scope_kind: "workspace",
              application_scope_kind: "workspace",
              workspace_id: "workspace-one",
              state_head_hash: "state-one",
              consent_head_hash: "consent-one",
              consent_epoch: 1,
              bundle_hash: "bundle-one",
              approval_event_hash: "approval-one",
              capability_grant_id: "capability-one",
              permissions: [],
              network_endpoints: [],
              renderer_slots: [],
              high_risk_consents: [],
            },
          ],
        },
      });

      await expect(request).resolves.toHaveLength(1);
      await idleRequest;
      expect(idle).toBe(true);

      mocks.get.mockClear();
      await expect(listPluginRuntimeApplications("workspace-one")).resolves.toEqual([]);
      expect(mocks.get).not.toHaveBeenCalled();
    } finally {
      releasePluginRuntimeWorkspaceRevocation("workspace-one");
    }
  });

  it("preserves document scopes consumed by Host capability enforcement", () => {
    expect(
      normalizeDocumentScope({
        workspaceReadAllowed: true,
        activeDocumentReadAllowed: true,
        selectedDocumentsReadAllowed: true,
        activeDocumentId: "doc-active",
        selectedDocumentIds: ["doc-selected"],
        allowedDocumentIds: ["doc-allowed"],
      }),
    ).toEqual({
      workspaceReadAllowed: true,
      activeDocumentReadAllowed: true,
      selectedDocumentsReadAllowed: true,
      activeDocumentId: "doc-active",
      selectedDocumentIds: ["doc-selected"],
      allowedDocumentIds: ["doc-allowed"],
    });
  });

  it("normalizes manifest endpoint policies for runtime-owned network handlers", () => {
    expect(
      normalizeNetworkEndpoints([
        {
          id: "github-rest",
          url: "https://api.github.com/repos/refmdio/refmd/issues",
          methods: ["GET"],
          routes: ["proxy"],
          headers: ["accept"],
          bodySchema: "none",
          maxRequestBytes: 1024,
          maxResponseBytes: 2048,
        },
      ]),
    ).toEqual([
      {
        id: "github-rest",
        url: "https://api.github.com/repos/refmdio/refmd/issues",
        methods: ["GET"],
        routes: ["proxy"],
        headers: ["accept"],
        bodySchema: "none",
        maxRequestBytes: 1024,
        maxResponseBytes: 2048,
      },
    ]);
  });

  it("rejects runtime endpoint descriptors with non-proxy routes", () => {
    for (const routes of [
      ["direct"],
      ["auto"],
      ["extension"],
      ["direct", "proxy"],
      ["proxy", "extension"],
      ["unknown"],
      [],
      undefined,
    ]) {
      expect(() =>
        normalizeNetworkEndpoints([
          {
            id: "github-rest",
            url: "https://api.github.com/repos/refmdio/refmd/issues",
            methods: ["GET"],
            ...(routes === undefined ? {} : { routes }),
          },
        ]),
      ).toThrow("plugin_runtime_network_route_invalid");
    }
  });

  it("normalizes manifest renderer slots for runtime-owned renderer handlers", () => {
    expect(
      normalizeRendererSlots([
        { kind: "block", type: "chart" },
        { kind: "inline", type: "code" },
        { kind: "inline", type: "mention" },
        { kind: "document", type: "markdown" },
      ]),
    ).toEqual([
      { kind: "block", type: "chart" },
      { kind: "inline", type: "code" },
    ]);
  });

  it("closes matching plugin runtimes when runtime security notifications arrive", async () => {
    const router = {
      closeByBundle: vi.fn(),
      closeByCapabilityGrant: vi.fn(),
      closeByActivation: vi.fn(),
      closeByApplication: vi.fn(),
      closeByWorkspace: vi.fn(),
    };
    const runtimeBoundary = {
      closeByBundle: vi.fn(),
      closeByCapabilityGrant: vi.fn(),
      closeByActivation: vi.fn(),
      closeByApplication: vi.fn(),
      closeByWorkspace: vi.fn(),
    };
    const refetch = vi.fn();

    expect(
      await handlePluginRuntimeSecurityNotification(
        {
          type: "plugin.runtime_revoked",
          action_ref: {
            workspace_id: "workspace-one",
            application_id: "application-one",
            bundle_hash: "bundle-one",
          },
        },
        router,
        "workspace-one",
        refetch,
        undefined,
        runtimeBoundary,
      ),
    ).toBe(true);

    expect(runtimeBoundary.closeByApplication).toHaveBeenCalledWith(
      "application-one",
      "plugin_runtime_revoked",
    );
    expect(router.closeByApplication).toHaveBeenCalledWith(
      "application-one",
      "plugin_runtime_revoked",
    );
    expect(refetch).toHaveBeenCalledTimes(1);

    expect(
      await handlePluginRuntimeSecurityNotification(
        {
          type: "plugin.runtime_revoked",
          action_ref: {
            workspace_id: "workspace-two",
            application_id: "application-two",
          },
        },
        router,
        "workspace-one",
        refetch,
        undefined,
        runtimeBoundary,
      ),
    ).toBe(false);
    expect(router.closeByApplication).toHaveBeenCalledTimes(1);
    expect(runtimeBoundary.closeByApplication).toHaveBeenCalledTimes(1);
  });

  it("purges local plugin data when cleanup-bearing runtime notifications arrive", async () => {
    const router = {
      closeByBundle: vi.fn(),
      closeByCapabilityGrant: vi.fn(),
      closeByActivation: vi.fn(),
      closeByApplication: vi.fn(),
      closeByWorkspace: vi.fn(),
    };
    const runtimeBoundary = {
      closeByBundle: vi.fn(),
      closeByCapabilityGrant: vi.fn(),
      closeByActivation: vi.fn(),
      closeByApplication: vi.fn(),
      closeByWorkspace: vi.fn(),
    };
    const refetch = vi.fn();

    for (const type of ["plugin.runtime_uninstalled", "plugin.runtime_activation_deleted"]) {
      await expect(
        handlePluginRuntimeSecurityNotification(
          {
            type,
            action_ref: {
              workspace_id: "workspace-one",
              package_id: "package-one",
              application_id: "application-one",
              activation_id: "activation-one",
            },
          },
          router,
          "workspace-one",
          refetch,
          { userId: "user-one", deviceId: "device-one" },
          runtimeBoundary,
        ),
      ).resolves.toBe(true);
    }

    expect(runtimeBoundary.closeByApplication).toHaveBeenCalledWith(
      "application-one",
      "plugin_runtime_uninstalled",
    );
    expect(runtimeBoundary.closeByActivation).toHaveBeenCalledWith(
      "activation-one",
      "plugin_runtime_activation_deleted",
    );
    expect(router.closeByApplication).toHaveBeenCalledWith(
      "application-one",
      "plugin_runtime_uninstalled",
    );
    expect(router.closeByActivation).toHaveBeenCalledWith(
      "activation-one",
      "plugin_runtime_activation_deleted",
    );
    expect(purgePluginApplicationLocalData).toHaveBeenCalledTimes(2);
    expect(purgePluginApplicationLocalData).toHaveBeenLastCalledWith({
      workspaceId: "workspace-one",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-one",
      userId: "user-one",
      deviceId: "device-one",
    });
  });

  it("reconciles missed plugin runtime invalidations from durable notifications", async () => {
    const router = {
      closeByBundle: vi.fn(),
      closeByCapabilityGrant: vi.fn(),
      closeByActivation: vi.fn(),
      closeByApplication: vi.fn(),
      closeByWorkspace: vi.fn(),
    };
    const runtimeBoundary = {
      closeByBundle: vi.fn(),
      closeByCapabilityGrant: vi.fn(),
      closeByActivation: vi.fn(),
      closeByApplication: vi.fn(),
      closeByWorkspace: vi.fn(),
    };
    const refetch = vi.fn();

    expect(
      await reconcilePluginRuntimeNotifications(
        [
          {
            id: "notification-one",
            type: "plugin.runtime_updated",
            severity: "warning",
            action_ref: {
              workspace_id: "workspace-one",
              bundle_hash: "bundle-one",
            },
          },
          {
            id: "notification-two",
            type: "device.pending_approval",
            severity: "action_required",
            action_ref: {},
          },
        ],
        router,
        "workspace-one",
        refetch,
        runtimeBoundary,
      ),
    ).toBe(1);

    expect(runtimeBoundary.closeByBundle).toHaveBeenCalledWith(
      "workspace-one",
      "bundle-one",
      "plugin_runtime_updated",
    );
    expect(router.closeByBundle).toHaveBeenCalledWith(
      "workspace-one",
      "bundle-one",
      "plugin_runtime_updated",
    );
    expect(refetch).toHaveBeenCalledTimes(1);
  });
});
