import { createRoot, createSignal, type Setter } from "solid-js";
import { describe, expect, it, vi } from "vite-plus/test";
import type { PluginHostRuntimeController } from "../runtime-path/controller";
import type { PluginRuntimePath } from "../runtime-path/runtime-path";
import { getPluginHostMessageRouter } from "../host-rpc/host-rpc";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import {
  canonicalizeStrictBytes,
  canonicalizeStrictValueBytes,
  type StrictJsonValue,
} from "@/shared/lib/crypto/jcs";
import {
  buildPluginBundleApprovalTranscript,
  buildPluginConsentEventTranscript,
  computeSigningKeyId,
  generateHybridSigningPrivateKeyMaterial,
  publicKeyMaterialFromPrivate,
  signPluginBundleApprovalSignature,
  signPluginConsentEventSignature,
} from "@/shared/lib/crypto/signature";
import { assertApprovalAuthorityFromVerifiedLineage } from "./runtime-approval-authority";
import { assertRuntimeBundleManifestAuthority, verifyRuntimeBundleProof } from "./runtime-proof";
import { saveVerifiedPluginRuntimePins } from "./runtime-pins";
import { useThirdPartyPluginRuntimeBoundary } from "./use-runtime-boundary";
import type {
  LoadedPluginRuntimeBundle,
  PluginRuntimeApplicationDescriptor,
} from "./runtime-types";

function createRuntimePathStub(
  destroy: (reason?: string) => void,
  session: Partial<PluginRuntimePath["runtime"]["session"]> = {},
): PluginRuntimePath {
  const closeCallbacks = new Set<(reason: string) => void>();
  return {
    runtime: {
      iframe: document.createElement("iframe"),
      session: {
        onClose(callback: (reason: string) => void) {
          closeCallbacks.add(callback);
          return () => closeCallbacks.delete(callback);
        },
        ...session,
      } as PluginRuntimePath["runtime"]["session"],
      destroy,
    },
    unregisterHandlers: vi.fn(),
    destroy,
  };
}

describe("useThirdPartyPluginRuntimeBoundary", () => {
  it("does not start a runtime path until a workspace is available", async () => {
    const createRuntimePath = vi.fn<PluginHostRuntimeController["createRuntimePath"]>();
    const controller: PluginHostRuntimeController = {
      router: getPluginHostMessageRouter(),
      createRuntimePath,
    };

    const dispose = createRoot((disposeRoot) => {
      const [workspaceId] = createSignal<string | null>(null);
      useThirdPartyPluginRuntimeBoundary(controller, workspaceId);
      return disposeRoot;
    });
    await Promise.resolve();

    expect(createRuntimePath).not.toHaveBeenCalled();
    expect(document.querySelector("[data-refmd-plugin-runtime-boundary]")).toBeNull();
    dispose();
  });

  it("does not create a runtime path without an installed plugin descriptor", async () => {
    const createRuntimePath = vi.fn<PluginHostRuntimeController["createRuntimePath"]>();
    const controller: PluginHostRuntimeController = {
      router: getPluginHostMessageRouter(),
      createRuntimePath,
    };

    const dispose = createRoot((disposeRoot) => {
      const [workspaceId] = createSignal<string | null>("workspace-one");
      useThirdPartyPluginRuntimeBoundary(controller, workspaceId);
      return disposeRoot;
    });
    await Promise.resolve();

    expect(createRuntimePath).not.toHaveBeenCalled();
    expect(document.querySelector("[data-refmd-plugin-runtime-boundary]")).toBeNull();
    dispose();
  });

  it("loads pinned bundle metadata before creating a sandbox runtime path", async () => {
    const firstDestroy = vi.fn((_?: string) => undefined);
    const secondDestroy = vi.fn((_?: string) => undefined);
    const createRuntimePath = vi
      .fn<PluginHostRuntimeController["createRuntimePath"]>()
      .mockResolvedValueOnce(createRuntimePathStub(firstDestroy))
      .mockResolvedValueOnce(createRuntimePathStub(secondDestroy));
    const controller: PluginHostRuntimeController = {
      router: getPluginHostMessageRouter(),
      createRuntimePath,
    };
    let setWorkspaceId!: Setter<string | null>;
    let setDescriptors!: Setter<readonly PluginRuntimeApplicationDescriptor[]>;
    const loadBundle = vi.fn(async (descriptor): Promise<LoadedPluginRuntimeBundle> => {
      return {
        pluginId: descriptor.pluginId,
        packageId: "package-one",
        applicationId: descriptor.applicationId,
        activationId: "activation-one",
        ownerScopeKind: "workspace",
        userId: "user-one",
        deviceId: "device-one",
        workspaceId: descriptor.workspaceId,
        bundleHash: `bundle-${descriptor.workspaceId}`,
        manifestHash: `manifest-${descriptor.workspaceId}`,
        consentEpoch: descriptor.workspaceId === "workspace-one" ? 1 : 2,
        sandboxDocumentUrl: `/api/plugin-runtime/sandbox-documents/${descriptor.applicationId}`,
        bootNonce: `boot-${descriptor.applicationId}`,
        frameGeneration: descriptor.workspaceId === "workspace-one" ? 1 : 2,
        permissions: descriptor.permissions ?? [],
        documentScope: descriptor.documentScope,
        networkEndpoints: descriptor.networkEndpoints ?? [],
        rendererSlots: descriptor.rendererSlots ?? [],
        highRiskConsents: descriptor.highRiskConsents ?? [],
      };
    });
    const firstDescriptor: PluginRuntimeApplicationDescriptor = {
      pluginId: "com.example.runtime",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-one",
      ownerScopeKind: "workspace",
      userId: "user-one",
      deviceId: "device-one",
      workspaceId: "workspace-one",
      stateHeadHash: "state-one",
      consentHeadHash: "consent-one",
      capabilityGrantId: "capability-grant-one",
      permissions: ["network:fetch"],
      highRiskConsents: ["plaintext_network_egress"],
      documentScope: {
        activeDocumentId: "doc-active",
        selectedDocumentIds: ["doc-selected"],
        allowedDocumentIds: ["doc-allowed"],
        workspaceReadAllowed: true,
      },
      networkEndpoints: [
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
      ],
      rendererSlots: [{ kind: "block", type: "chart" }],
    };
    const secondDescriptor: PluginRuntimeApplicationDescriptor = {
      ...firstDescriptor,
      applicationId: "application-two",
      activationId: "activation-one",
      ownerScopeKind: "workspace",
      userId: "user-one",
      deviceId: "device-one",
      workspaceId: "workspace-two",
      stateHeadHash: "state-two",
      consentHeadHash: "consent-two",
      capabilityGrantId: "capability-grant-two",
    };

    const dispose = createRoot((disposeRoot) => {
      const [workspaceId, setCurrentWorkspaceId] = createSignal<string | null>("workspace-one");
      const [descriptors, setCurrentDescriptors] = createSignal<
        readonly PluginRuntimeApplicationDescriptor[]
      >([firstDescriptor]);
      setWorkspaceId = setCurrentWorkspaceId;
      setDescriptors = setCurrentDescriptors;
      useThirdPartyPluginRuntimeBoundary(
        controller,
        workspaceId,
        document,
        descriptors,
        loadBundle,
        () => ({
          id: "workspace-proxy",
          label: "Workspace Proxy",
          origin: "https://proxy.example/refmd",
          scope: "workspace",
        }),
      );
      return disposeRoot;
    });
    await Promise.resolve();
    await Promise.resolve();

    expect(createRuntimePath).toHaveBeenCalledTimes(1);
    expect(loadBundle).toHaveBeenCalledWith(firstDescriptor);
    const firstOptions = createRuntimePath.mock.calls[0]?.[0];
    expect(firstOptions?.workspaceId).toBe("workspace-one");
    expect(firstOptions?.pluginId).toBe("com.example.runtime");
    expect(firstOptions?.bundleHash).toBe("bundle-workspace-one");
    expect(firstOptions?.sandboxDocumentUrl).toBe(
      "/api/plugin-runtime/sandbox-documents/application-one",
    );
    expect(firstOptions?.bootNonce).toBe("boot-application-one");
    expect(firstOptions?.handlers).toEqual([]);
    expect(firstOptions?.documentScope).toEqual(firstDescriptor.documentScope);
    expect(firstOptions?.rendererSlots).toEqual([{ kind: "block", type: "chart" }]);
    expect(firstOptions?.highRiskConsents).toEqual(["plaintext_network_egress"]);
    expect(firstOptions?.frameGeneration).toBe(1);
    const networkServices = firstOptions?.networkServices;
    expect(networkServices).toBeDefined();
    await expect(
      Promise.resolve(networkServices?.endpointPolicy({} as never, "github-rest")),
    ).resolves.toMatchObject({ id: "github-rest" });
    await expect(
      Promise.resolve(networkServices?.endpointPolicy({} as never, "missing")),
    ).resolves.toBeNull();
    await expect(
      Promise.resolve(
        networkServices?.proxyRegistration?.(
          { workspaceId: "workspace-one" } as never,
          { id: "github-rest" } as never,
        ),
      ),
    ).resolves.toMatchObject({
      id: "workspace-proxy",
      label: "Workspace Proxy",
      origin: "https://proxy.example/refmd",
      scope: "workspace",
    });
    expect(firstOptions?.capabilityId).toEqual(expect.any(String));
    expect(firstOptions?.capabilityId).not.toBe(firstDescriptor.capabilityGrantId);
    expect(firstOptions?.capabilityGrantId).toBe(firstDescriptor.capabilityGrantId);
    expect(firstOptions?.container.hasAttribute("data-refmd-plugin-runtime-boundary")).toBe(true);
    expect(firstOptions?.container.hidden).toBe(false);
    expect(firstOptions?.container.getAttribute("aria-hidden")).toBe("true");
    expect(firstOptions?.container.style.display).toBe("");
    expect(firstOptions?.container.style.position).toBe("fixed");
    expect(firstOptions?.container.style.pointerEvents).toBe("none");
    expect(document.body.contains(firstOptions?.container ?? null)).toBe(true);
    const firstContext = {
      workspaceId: "workspace-one",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-one",
      ownerScopeKind: "workspace",
      bundleHash: "bundle-workspace-one",
      userId: "user-one",
      deviceId: "device-one",
      manifestHash: "manifest-workspace-one",
      capabilityGrantId: "capability-grant-one",
      consentEpoch: 1,
    } as Parameters<NonNullable<typeof firstOptions.validateSession>>[0];
    const firstRequest = {
      workspace_id: "workspace-one",
      package_id: "package-one",
      application_id: "application-one",
      activation_id: "activation-one",
      owner_scope_kind: "workspace",
      user_id: "user-one",
      device_id: "device-one",
      bundle_hash: "bundle-workspace-one",
      manifest_hash: "manifest-workspace-one",
      capability_grant_id: "capability-grant-one",
      consent_epoch: 1,
    } as Parameters<NonNullable<typeof firstOptions.validateSession>>[1];
    expect(firstOptions?.validateSession?.(firstContext, firstRequest)).toBeNull();

    setWorkspaceId("workspace-two");
    setDescriptors([secondDescriptor]);
    await Promise.resolve();
    await Promise.resolve();

    expect(firstDestroy).toHaveBeenCalledWith("application_removed");
    expect(document.body.contains(firstOptions?.container ?? null)).toBe(false);
    expect(createRuntimePath).toHaveBeenCalledTimes(2);
    const secondOptions = createRuntimePath.mock.calls[1]?.[0];
    expect(secondOptions?.workspaceId).toBe("workspace-two");
    expect(secondOptions?.applicationId).toBe("application-two");
    expect(secondOptions?.frameGeneration).toBe(2);
    expect(secondOptions?.capabilityId).toEqual(expect.any(String));
    expect(secondOptions?.capabilityId).not.toBe(firstOptions?.capabilityId);
    expect(document.body.contains(secondOptions?.container ?? null)).toBe(true);

    dispose();

    expect(secondDestroy).toHaveBeenCalledWith("workspace_cleanup");
    expect(document.body.contains(secondOptions?.container ?? null)).toBe(false);
  });

  it("destroys active sandbox boundaries immediately through runtime invalidation", async () => {
    const destroy = vi.fn((_?: string) => undefined);
    const createRuntimePath = vi
      .fn<PluginHostRuntimeController["createRuntimePath"]>()
      .mockImplementation(async (options) =>
        createRuntimePathStub(destroy, {
          workspaceId: options.workspaceId,
          bundleHash: options.bundleHash,
          capabilityGrantId: options.capabilityGrantId,
        }),
      );
    const controller: PluginHostRuntimeController = {
      router: getPluginHostMessageRouter(),
      createRuntimePath,
    };
    const descriptor: PluginRuntimeApplicationDescriptor = {
      pluginId: "com.example.runtime",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-one",
      ownerScopeKind: "workspace",
      userId: "user-one",
      deviceId: "device-one",
      workspaceId: "workspace-one",
      stateHeadHash: "state-one",
      consentHeadHash: "consent-one",
      capabilityGrantId: "capability-grant-one",
    };
    const loadBundle = vi.fn(async (): Promise<LoadedPluginRuntimeBundle> => {
      return {
        pluginId: descriptor.pluginId,
        packageId: "package-one",
        applicationId: descriptor.applicationId,
        activationId: "activation-one",
        ownerScopeKind: "workspace",
        userId: "user-one",
        deviceId: "device-one",
        workspaceId: descriptor.workspaceId,
        bundleHash: "bundle-one",
        manifestHash: "manifest-one",
        consentEpoch: 1,
        sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/application-one",
        bootNonce: "boot-application-one",
        frameGeneration: 1,
        permissions: [],
        networkEndpoints: [],
        rendererSlots: [],
        highRiskConsents: [],
      };
    });

    let invalidation!: ReturnType<typeof useThirdPartyPluginRuntimeBoundary>;
    const dispose = createRoot((disposeRoot) => {
      const [workspaceId] = createSignal<string | null>("workspace-one");
      const [descriptors] = createSignal<readonly PluginRuntimeApplicationDescriptor[]>([
        descriptor,
      ]);
      invalidation = useThirdPartyPluginRuntimeBoundary(
        controller,
        workspaceId,
        document,
        descriptors,
        loadBundle,
      );
      return disposeRoot;
    });
    await Promise.resolve();
    await Promise.resolve();

    const container = createRuntimePath.mock.calls[0]?.[0].container;
    expect(document.body.contains(container ?? null)).toBe(true);

    await invalidation.closeByCapabilityGrant("capability-grant-one", "plugin_runtime_revoked");

    expect(destroy).toHaveBeenCalledWith("plugin_runtime_revoked");
    expect(document.body.contains(container ?? null)).toBe(false);
    dispose();
  });

  it("does not restart a revoked application from a stale descriptor", async () => {
    const firstDestroy = vi.fn((_?: string) => undefined);
    const secondDestroy = vi.fn((_?: string) => undefined);
    const createRuntimePath = vi
      .fn<PluginHostRuntimeController["createRuntimePath"]>()
      .mockResolvedValueOnce(createRuntimePathStub(firstDestroy))
      .mockResolvedValueOnce(createRuntimePathStub(secondDestroy));
    const controller: PluginHostRuntimeController = {
      router: getPluginHostMessageRouter(),
      createRuntimePath,
    };
    const descriptor: PluginRuntimeApplicationDescriptor = {
      pluginId: "com.example.runtime",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-one",
      ownerScopeKind: "workspace",
      userId: "user-one",
      deviceId: "device-one",
      workspaceId: "workspace-one",
      stateHeadHash: "state-one",
      consentHeadHash: "consent-one",
      capabilityGrantId: "capability-grant-one",
    };
    const loadBundle = vi.fn(async (current): Promise<LoadedPluginRuntimeBundle> => {
      return {
        pluginId: current.pluginId,
        packageId: current.packageId,
        applicationId: current.applicationId,
        activationId: current.activationId,
        ownerScopeKind: current.ownerScopeKind,
        userId: current.userId,
        deviceId: current.deviceId,
        workspaceId: current.workspaceId,
        bundleHash: `bundle-${current.stateHeadHash}`,
        manifestHash: `manifest-${current.stateHeadHash}`,
        consentEpoch: current.stateHeadHash === "state-one" ? 1 : 2,
        sandboxDocumentUrl: `/api/plugin-runtime/sandbox-documents/${current.applicationId}`,
        bootNonce: `boot-${current.stateHeadHash}`,
        frameGeneration: current.stateHeadHash === "state-one" ? 1 : 2,
        permissions: [],
        networkEndpoints: [],
        rendererSlots: [],
        highRiskConsents: [],
      };
    });
    let setDescriptors!: Setter<readonly PluginRuntimeApplicationDescriptor[]>;
    let invalidation!: ReturnType<typeof useThirdPartyPluginRuntimeBoundary>;

    const dispose = createRoot((disposeRoot) => {
      const [workspaceId] = createSignal<string | null>("workspace-one");
      const [descriptors, setCurrentDescriptors] = createSignal<
        readonly PluginRuntimeApplicationDescriptor[]
      >([descriptor]);
      setDescriptors = setCurrentDescriptors;
      invalidation = useThirdPartyPluginRuntimeBoundary(
        controller,
        workspaceId,
        document,
        descriptors,
        loadBundle,
      );
      return disposeRoot;
    });
    await Promise.resolve();
    await Promise.resolve();

    expect(loadBundle).toHaveBeenCalledTimes(1);
    expect(createRuntimePath).toHaveBeenCalledTimes(1);
    const firstContainer = createRuntimePath.mock.calls[0]?.[0].container;
    expect(document.body.contains(firstContainer ?? null)).toBe(true);

    await invalidation.closeByApplication("application-one", "plugin_application_deleted");
    expect(firstDestroy).toHaveBeenCalledWith("plugin_application_deleted");
    expect(document.body.contains(firstContainer ?? null)).toBe(false);

    setDescriptors([{ ...descriptor }]);
    await Promise.resolve();
    await Promise.resolve();

    expect(loadBundle).toHaveBeenCalledTimes(1);
    expect(createRuntimePath).toHaveBeenCalledTimes(1);

    setDescriptors([{ ...descriptor, stateHeadHash: "state-two" }]);
    await Promise.resolve();
    await Promise.resolve();

    expect(loadBundle).toHaveBeenCalledTimes(2);
    expect(createRuntimePath).toHaveBeenCalledTimes(2);
    expect(createRuntimePath.mock.calls[1]?.[0].frameGeneration).toBe(2);

    dispose();
    expect(secondDestroy).toHaveBeenCalledWith("workspace_cleanup");
  });

  it("starts a same-application replacement after bundle update changes bundle authority", async () => {
    const firstDestroy = vi.fn((_?: string) => undefined);
    const secondDestroy = vi.fn((_?: string) => undefined);
    const createRuntimePath = vi
      .fn<PluginHostRuntimeController["createRuntimePath"]>()
      .mockResolvedValueOnce(createRuntimePathStub(firstDestroy))
      .mockResolvedValueOnce(createRuntimePathStub(secondDestroy));
    const controller: PluginHostRuntimeController = {
      router: getPluginHostMessageRouter(),
      createRuntimePath,
    };
    const descriptor: PluginRuntimeApplicationDescriptor = {
      pluginId: "com.example.runtime",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-one",
      ownerScopeKind: "workspace",
      applicationScopeKind: "workspace",
      userId: "user-one",
      deviceId: "device-one",
      workspaceId: "workspace-one",
      stateHeadHash: "state-one",
      consentHeadHash: "consent-one",
      consentEpoch: 1,
      capabilityGrantId: "capability-grant-one",
      bundleHash: "bundle-one",
      manifestHash: "manifest-one",
      resourceManifestHash: "resources-one",
      permissionsHash: "permissions-one",
      endpointHash: "endpoints-one",
      rendererSlotsHash: "renderers-one",
      documentScopeHash: "document-scope-one",
      approvalEventHash: "approval-one",
    };
    const replacementDescriptor: PluginRuntimeApplicationDescriptor = {
      ...descriptor,
      bundleHash: "bundle-two",
      manifestHash: "manifest-two",
      resourceManifestHash: "resources-two",
      permissionsHash: "permissions-two",
      endpointHash: "endpoints-two",
      rendererSlotsHash: "renderers-two",
      documentScopeHash: "document-scope-two",
      approvalEventHash: "approval-two",
    };
    const loadBundle = vi.fn(async (current): Promise<LoadedPluginRuntimeBundle> => {
      return {
        pluginId: current.pluginId,
        packageId: current.packageId,
        applicationId: current.applicationId,
        activationId: current.activationId,
        ownerScopeKind: current.ownerScopeKind,
        userId: current.userId,
        deviceId: current.deviceId,
        workspaceId: current.workspaceId,
        bundleHash: current.bundleHash ?? "bundle-missing",
        manifestHash: current.manifestHash ?? "manifest-missing",
        consentEpoch: current.consentEpoch ?? 1,
        sandboxDocumentUrl: `/api/plugin-runtime/sandbox-documents/${current.applicationId}`,
        bootNonce: `boot-${current.bundleHash ?? "missing"}`,
        frameGeneration: current.bundleHash === "bundle-two" ? 2 : 1,
        permissions: [],
        networkEndpoints: [],
        rendererSlots: [],
        highRiskConsents: [],
      };
    });
    let setDescriptors!: Setter<readonly PluginRuntimeApplicationDescriptor[]>;
    let invalidation!: ReturnType<typeof useThirdPartyPluginRuntimeBoundary>;

    const dispose = createRoot((disposeRoot) => {
      const [workspaceId] = createSignal<string | null>("workspace-one");
      const [descriptors, setCurrentDescriptors] = createSignal<
        readonly PluginRuntimeApplicationDescriptor[]
      >([descriptor]);
      setDescriptors = setCurrentDescriptors;
      invalidation = useThirdPartyPluginRuntimeBoundary(
        controller,
        workspaceId,
        document,
        descriptors,
        loadBundle,
      );
      return disposeRoot;
    });
    await Promise.resolve();
    await Promise.resolve();

    expect(loadBundle).toHaveBeenCalledTimes(1);
    expect(createRuntimePath).toHaveBeenCalledTimes(1);

    await invalidation.closeByApplication("application-one", "plugin_bundle_updated");
    expect(firstDestroy).toHaveBeenCalledWith("plugin_bundle_updated");

    setDescriptors([{ ...descriptor }]);
    await Promise.resolve();
    await Promise.resolve();

    expect(loadBundle).toHaveBeenCalledTimes(1);
    expect(createRuntimePath).toHaveBeenCalledTimes(1);

    setDescriptors([replacementDescriptor]);
    await Promise.resolve();
    await Promise.resolve();

    expect(loadBundle).toHaveBeenCalledTimes(2);
    expect(createRuntimePath).toHaveBeenCalledTimes(2);
    const replacementOptions = createRuntimePath.mock.calls[1]?.[0];
    expect(replacementOptions?.bundleHash).toBe("bundle-two");
    expect(replacementOptions?.manifestHash).toBe("manifest-two");
    expect(replacementOptions?.frameGeneration).toBe(2);

    dispose();
    expect(secondDestroy).toHaveBeenCalledWith("workspace_cleanup");
  });

  it("removes a closed runtime session from the active boundary and restarts the descriptor", async () => {
    const firstDestroy = vi.fn((_?: string) => undefined);
    const secondDestroy = vi.fn((_?: string) => undefined);
    const firstCloseCallbacks = new Set<(reason: string) => void>();
    const firstPath = createRuntimePathStub(firstDestroy, {
      onClose(callback: (reason: string) => void) {
        firstCloseCallbacks.add(callback);
        return () => firstCloseCallbacks.delete(callback);
      },
    });
    const createRuntimePath = vi
      .fn<PluginHostRuntimeController["createRuntimePath"]>()
      .mockResolvedValueOnce(firstPath)
      .mockResolvedValueOnce(createRuntimePathStub(secondDestroy));
    const controller: PluginHostRuntimeController = {
      router: getPluginHostMessageRouter(),
      createRuntimePath,
    };
    const descriptor: PluginRuntimeApplicationDescriptor = {
      pluginId: "com.example.runtime",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-one",
      ownerScopeKind: "workspace",
      userId: "user-one",
      deviceId: "device-one",
      workspaceId: "workspace-one",
      stateHeadHash: "state-one",
      consentHeadHash: "consent-one",
      capabilityGrantId: "capability-grant-one",
    };
    const loadBundle = vi.fn(async (): Promise<LoadedPluginRuntimeBundle> => {
      return {
        pluginId: descriptor.pluginId,
        packageId: descriptor.packageId,
        applicationId: descriptor.applicationId,
        activationId: descriptor.activationId,
        ownerScopeKind: descriptor.ownerScopeKind,
        userId: descriptor.userId,
        deviceId: descriptor.deviceId,
        workspaceId: descriptor.workspaceId,
        bundleHash: "bundle-one",
        manifestHash: "manifest-one",
        consentEpoch: 1,
        sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/application-one",
        bootNonce: "boot-application-one",
        frameGeneration: 1,
        permissions: [],
        networkEndpoints: [],
        rendererSlots: [],
        highRiskConsents: [],
      };
    });
    let setDescriptors!: Setter<readonly PluginRuntimeApplicationDescriptor[]>;

    const dispose = createRoot((disposeRoot) => {
      const [workspaceId] = createSignal<string | null>("workspace-one");
      const [descriptors, setCurrentDescriptors] = createSignal<
        readonly PluginRuntimeApplicationDescriptor[]
      >([descriptor]);
      setDescriptors = setCurrentDescriptors;
      useThirdPartyPluginRuntimeBoundary(
        controller,
        workspaceId,
        document,
        descriptors,
        loadBundle,
      );
      return disposeRoot;
    });
    await Promise.resolve();
    await Promise.resolve();

    expect(createRuntimePath).toHaveBeenCalledTimes(1);
    const firstContainer = createRuntimePath.mock.calls[0]?.[0].container;
    expect(document.body.contains(firstContainer ?? null)).toBe(true);

    for (const callback of Array.from(firstCloseCallbacks)) callback("frame_navigation");

    expect(firstDestroy).not.toHaveBeenCalled();
    expect(document.body.contains(firstContainer ?? null)).toBe(false);

    setDescriptors([{ ...descriptor }]);
    await Promise.resolve();
    await Promise.resolve();

    expect(loadBundle).toHaveBeenCalledTimes(2);
    expect(createRuntimePath).toHaveBeenCalledTimes(2);
    const secondContainer = createRuntimePath.mock.calls[1]?.[0].container;
    expect(document.body.contains(secondContainer ?? null)).toBe(true);

    dispose();
    expect(secondDestroy).toHaveBeenCalledWith("workspace_cleanup");
  });

  it("starts a new descriptor after an unmatched application close", async () => {
    const destroy = vi.fn((_?: string) => undefined);
    const createRuntimePath = vi
      .fn<PluginHostRuntimeController["createRuntimePath"]>()
      .mockResolvedValue(createRuntimePathStub(destroy));
    const controller: PluginHostRuntimeController = {
      router: getPluginHostMessageRouter(),
      createRuntimePath,
    };
    const descriptor: PluginRuntimeApplicationDescriptor = {
      pluginId: "com.example.runtime",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-two",
      ownerScopeKind: "workspace",
      userId: "user-one",
      deviceId: "device-one",
      workspaceId: "workspace-one",
      stateHeadHash: "state-two",
      consentHeadHash: "consent-two",
      capabilityGrantId: "capability-grant-two",
    };
    const loadBundle = vi.fn(async (current): Promise<LoadedPluginRuntimeBundle> => {
      return {
        pluginId: current.pluginId,
        packageId: current.packageId,
        applicationId: current.applicationId,
        activationId: current.activationId,
        ownerScopeKind: current.ownerScopeKind,
        userId: current.userId,
        deviceId: current.deviceId,
        workspaceId: current.workspaceId,
        bundleHash: "bundle-two",
        manifestHash: "manifest-two",
        consentEpoch: 2,
        sandboxDocumentUrl: `/api/plugin-runtime/sandbox-documents/${current.applicationId}`,
        bootNonce: "boot-two",
        frameGeneration: 2,
        permissions: [],
        networkEndpoints: [],
        rendererSlots: [],
        highRiskConsents: [],
      };
    });
    let setDescriptors!: Setter<readonly PluginRuntimeApplicationDescriptor[]>;
    let invalidation!: ReturnType<typeof useThirdPartyPluginRuntimeBoundary>;

    const dispose = createRoot((disposeRoot) => {
      const [workspaceId] = createSignal<string | null>("workspace-one");
      const [descriptors, setCurrentDescriptors] = createSignal<
        readonly PluginRuntimeApplicationDescriptor[]
      >([]);
      setDescriptors = setCurrentDescriptors;
      invalidation = useThirdPartyPluginRuntimeBoundary(
        controller,
        workspaceId,
        document,
        descriptors,
        loadBundle,
      );
      return disposeRoot;
    });
    await Promise.resolve();

    await invalidation.closeByApplication("application-one", "plugin_runtime_activation_deleted");
    setDescriptors([descriptor]);
    await Promise.resolve();
    await Promise.resolve();

    expect(loadBundle).toHaveBeenCalledTimes(1);
    expect(createRuntimePath).toHaveBeenCalledTimes(1);

    dispose();
    expect(destroy).toHaveBeenCalledWith("workspace_cleanup");
  });

  it("does not revoke a replacement activation when an old activation close arrives late", async () => {
    const firstDestroy = vi.fn((_?: string) => undefined);
    const secondDestroy = vi.fn((_?: string) => undefined);
    const createRuntimePath = vi
      .fn<PluginHostRuntimeController["createRuntimePath"]>()
      .mockResolvedValueOnce(
        createRuntimePathStub(firstDestroy, { activationId: "activation-one" }),
      )
      .mockResolvedValueOnce(
        createRuntimePathStub(secondDestroy, { activationId: "activation-two" }),
      );
    const controller: PluginHostRuntimeController = {
      router: getPluginHostMessageRouter(),
      createRuntimePath,
    };
    const firstDescriptor: PluginRuntimeApplicationDescriptor = {
      pluginId: "com.example.runtime",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-one",
      ownerScopeKind: "workspace",
      userId: "user-one",
      deviceId: "device-one",
      workspaceId: "workspace-one",
      stateHeadHash: "state-one",
      consentHeadHash: "consent-one",
      capabilityGrantId: "capability-grant-one",
    };
    const secondDescriptor: PluginRuntimeApplicationDescriptor = {
      ...firstDescriptor,
      activationId: "activation-two",
      stateHeadHash: "state-two",
      consentHeadHash: "consent-two",
      capabilityGrantId: "capability-grant-two",
    };
    const loadBundle = vi.fn(async (current): Promise<LoadedPluginRuntimeBundle> => {
      return {
        pluginId: current.pluginId,
        packageId: current.packageId,
        applicationId: current.applicationId,
        activationId: current.activationId,
        ownerScopeKind: current.ownerScopeKind,
        userId: current.userId,
        deviceId: current.deviceId,
        workspaceId: current.workspaceId,
        bundleHash: "bundle-one",
        manifestHash: "manifest-one",
        consentEpoch: current.activationId === "activation-one" ? 1 : 2,
        sandboxDocumentUrl: `/api/plugin-runtime/sandbox-documents/${current.applicationId}`,
        bootNonce: `boot-${current.activationId}`,
        frameGeneration: current.activationId === "activation-one" ? 1 : 2,
        permissions: [],
        networkEndpoints: [],
        rendererSlots: [],
        highRiskConsents: [],
      };
    });
    let setDescriptors!: Setter<readonly PluginRuntimeApplicationDescriptor[]>;
    let invalidation!: ReturnType<typeof useThirdPartyPluginRuntimeBoundary>;

    const dispose = createRoot((disposeRoot) => {
      const [workspaceId] = createSignal<string | null>("workspace-one");
      const [descriptors, setCurrentDescriptors] = createSignal<
        readonly PluginRuntimeApplicationDescriptor[]
      >([firstDescriptor]);
      setDescriptors = setCurrentDescriptors;
      invalidation = useThirdPartyPluginRuntimeBoundary(
        controller,
        workspaceId,
        document,
        descriptors,
        loadBundle,
      );
      return disposeRoot;
    });
    await Promise.resolve();
    await Promise.resolve();

    setDescriptors([secondDescriptor]);
    await Promise.resolve();
    await Promise.resolve();

    expect(firstDestroy).toHaveBeenCalledWith("application_changed");
    expect(createRuntimePath).toHaveBeenCalledTimes(2);

    await invalidation.closeByActivation("activation-one", "plugin_runtime_activation_deleted");
    setDescriptors([secondDescriptor]);
    await Promise.resolve();
    await Promise.resolve();

    expect(secondDestroy).not.toHaveBeenCalledWith("plugin_runtime_activation_deleted");
    expect(loadBundle).toHaveBeenCalledTimes(2);
    expect(createRuntimePath).toHaveBeenCalledTimes(2);

    dispose();
    expect(secondDestroy).toHaveBeenCalledWith("workspace_cleanup");
  });

  it("drops superseded startup attempts without logging runtime boundary errors", async () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const staleStartupError = Object.assign(new Error("superseded"), {
      code: "runtime_startup_superseded",
    });
    const createRuntimePath = vi
      .fn<PluginHostRuntimeController["createRuntimePath"]>()
      .mockRejectedValue(staleStartupError);
    const controller: PluginHostRuntimeController = {
      router: getPluginHostMessageRouter(),
      createRuntimePath,
    };
    const descriptor: PluginRuntimeApplicationDescriptor = {
      pluginId: "com.example.runtime",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-one",
      ownerScopeKind: "workspace",
      userId: "user-one",
      deviceId: "device-one",
      workspaceId: "workspace-one",
      stateHeadHash: "state-one",
      consentHeadHash: "consent-one",
      capabilityGrantId: "capability-grant-one",
    };
    const loadBundle = vi.fn(async (): Promise<LoadedPluginRuntimeBundle> => {
      return {
        pluginId: descriptor.pluginId,
        packageId: descriptor.packageId,
        applicationId: descriptor.applicationId,
        activationId: descriptor.activationId,
        ownerScopeKind: descriptor.ownerScopeKind,
        userId: descriptor.userId,
        deviceId: descriptor.deviceId,
        workspaceId: descriptor.workspaceId,
        bundleHash: "bundle-one",
        manifestHash: "manifest-one",
        consentEpoch: 1,
        sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/application-one",
        bootNonce: "boot-application-one",
        frameGeneration: 1,
        permissions: [],
        networkEndpoints: [],
        rendererSlots: [],
        highRiskConsents: [],
      };
    });

    const dispose = createRoot((disposeRoot) => {
      const [workspaceId] = createSignal<string | null>("workspace-one");
      const [descriptors] = createSignal<readonly PluginRuntimeApplicationDescriptor[]>([
        descriptor,
      ]);
      useThirdPartyPluginRuntimeBoundary(
        controller,
        workspaceId,
        document,
        descriptors,
        loadBundle,
      );
      return disposeRoot;
    });
    await Promise.resolve();
    await Promise.resolve();

    expect(createRuntimePath).toHaveBeenCalledTimes(1);
    expect(document.querySelector("[data-refmd-plugin-runtime-boundary]")).toBeNull();
    expect(consoleError).not.toHaveBeenCalled();

    dispose();
    consoleError.mockRestore();
  });

  it("drops superseded bundle load failures without logging runtime boundary errors", async () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const createRuntimePath = vi.fn<PluginHostRuntimeController["createRuntimePath"]>();
    const controller: PluginHostRuntimeController = {
      router: getPluginHostMessageRouter(),
      createRuntimePath,
    };
    const descriptor: PluginRuntimeApplicationDescriptor = {
      pluginId: "com.example.runtime",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-one",
      ownerScopeKind: "workspace",
      userId: "user-one",
      deviceId: "device-one",
      workspaceId: "workspace-one",
      stateHeadHash: "state-one",
      consentHeadHash: "consent-one",
      capabilityGrantId: "capability-grant-one",
    };
    let rejectLoad!: (error: unknown) => void;
    const loadBundle = vi.fn(
      () =>
        new Promise<LoadedPluginRuntimeBundle>((_resolve, reject) => {
          rejectLoad = reject;
        }),
    );
    let setRuntimeDescriptors!: Setter<readonly PluginRuntimeApplicationDescriptor[]>;

    const dispose = createRoot((disposeRoot) => {
      const [workspaceId] = createSignal<string | null>("workspace-one");
      const [descriptors, setDescriptors] = createSignal<
        readonly PluginRuntimeApplicationDescriptor[]
      >([descriptor]);
      setRuntimeDescriptors = setDescriptors;
      useThirdPartyPluginRuntimeBoundary(
        controller,
        workspaceId,
        document,
        descriptors,
        loadBundle,
      );
      return disposeRoot;
    });
    await Promise.resolve();
    await Promise.resolve();

    expect(loadBundle).toHaveBeenCalledTimes(1);
    setRuntimeDescriptors([]);
    await Promise.resolve();
    await Promise.resolve();

    rejectLoad(new TypeError("Failed to fetch"));
    await Promise.resolve();
    await Promise.resolve();

    expect(loadBundle).toHaveBeenCalledTimes(1);
    expect(createRuntimePath).not.toHaveBeenCalled();
    expect(consoleError).not.toHaveBeenCalled();

    dispose();
    consoleError.mockRestore();
  });

  it("retries transient runtime bundle load failures before logging boundary errors", async () => {
    vi.useFakeTimers();
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const destroy = vi.fn((_?: string) => undefined);
    const createRuntimePath = vi
      .fn<PluginHostRuntimeController["createRuntimePath"]>()
      .mockResolvedValue(createRuntimePathStub(destroy));
    const controller: PluginHostRuntimeController = {
      router: getPluginHostMessageRouter(),
      createRuntimePath,
    };
    const descriptor: PluginRuntimeApplicationDescriptor = {
      pluginId: "com.example.runtime",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-one",
      ownerScopeKind: "workspace",
      userId: "user-one",
      deviceId: "device-one",
      workspaceId: "workspace-one",
      stateHeadHash: "state-one",
      consentHeadHash: "consent-one",
      capabilityGrantId: "capability-grant-one",
    };
    const loadBundle = vi
      .fn<() => Promise<LoadedPluginRuntimeBundle>>()
      .mockRejectedValueOnce(new TypeError("Failed to fetch"))
      .mockRejectedValueOnce(new TypeError("Failed to fetch"))
      .mockRejectedValueOnce(new TypeError("Failed to fetch"))
      .mockResolvedValue({
        pluginId: descriptor.pluginId,
        packageId: descriptor.packageId,
        applicationId: descriptor.applicationId,
        activationId: descriptor.activationId,
        ownerScopeKind: descriptor.ownerScopeKind,
        userId: descriptor.userId,
        deviceId: descriptor.deviceId,
        workspaceId: descriptor.workspaceId,
        bundleHash: "bundle-one",
        manifestHash: "manifest-one",
        consentEpoch: 1,
        sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/application-one",
        bootNonce: "boot-application-one",
        frameGeneration: 1,
        permissions: [],
        networkEndpoints: [],
        rendererSlots: [],
        highRiskConsents: [],
      });

    const dispose = createRoot((disposeRoot) => {
      const [workspaceId] = createSignal<string | null>("workspace-one");
      const [descriptors] = createSignal<readonly PluginRuntimeApplicationDescriptor[]>([
        descriptor,
      ]);
      useThirdPartyPluginRuntimeBoundary(
        controller,
        workspaceId,
        document,
        descriptors,
        loadBundle,
      );
      return disposeRoot;
    });
    await Promise.resolve();
    await Promise.resolve();

    expect(loadBundle).toHaveBeenCalledTimes(1);
    expect(createRuntimePath).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(250);
    await Promise.resolve();
    await Promise.resolve();

    expect(loadBundle).toHaveBeenCalledTimes(2);
    expect(createRuntimePath).not.toHaveBeenCalled();
    expect(consoleError).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1_000);
    await Promise.resolve();
    await Promise.resolve();

    expect(loadBundle).toHaveBeenCalledTimes(3);
    expect(createRuntimePath).not.toHaveBeenCalled();
    expect(consoleError).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(2_500);
    await Promise.resolve();
    await Promise.resolve();

    expect(loadBundle).toHaveBeenCalledTimes(4);
    expect(createRuntimePath).toHaveBeenCalledTimes(1);
    expect(consoleError).not.toHaveBeenCalled();

    dispose();
    consoleError.mockRestore();
    vi.useRealTimers();
  });

  it("deduplicates duplicate in-flight runtime starts for the same descriptor", async () => {
    const destroy = vi.fn((_?: string) => undefined);
    let resolveRuntimePath!: () => void;
    const runtimePathPromise = new Promise<PluginRuntimePath>((resolve) => {
      resolveRuntimePath = () => resolve(createRuntimePathStub(destroy));
    });
    const createRuntimePath = vi
      .fn<PluginHostRuntimeController["createRuntimePath"]>()
      .mockReturnValue(runtimePathPromise);
    const controller: PluginHostRuntimeController = {
      router: getPluginHostMessageRouter(),
      createRuntimePath,
    };
    const descriptor: PluginRuntimeApplicationDescriptor = {
      pluginId: "com.example.runtime",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-one",
      ownerScopeKind: "workspace",
      userId: "user-one",
      deviceId: "device-one",
      workspaceId: "workspace-one",
      stateHeadHash: "state-one",
      consentHeadHash: "consent-one",
      capabilityGrantId: "capability-grant-one",
    };
    const loadBundle = vi.fn(async (): Promise<LoadedPluginRuntimeBundle> => {
      return {
        pluginId: descriptor.pluginId,
        packageId: descriptor.packageId,
        applicationId: descriptor.applicationId,
        activationId: descriptor.activationId,
        ownerScopeKind: descriptor.ownerScopeKind,
        userId: descriptor.userId,
        deviceId: descriptor.deviceId,
        workspaceId: descriptor.workspaceId,
        bundleHash: "bundle-one",
        manifestHash: "manifest-one",
        consentEpoch: 1,
        sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/application-one",
        bootNonce: "boot-application-one",
        frameGeneration: 1,
        permissions: [],
        networkEndpoints: [],
        rendererSlots: [],
        highRiskConsents: [],
      };
    });
    let setDescriptors!: Setter<readonly PluginRuntimeApplicationDescriptor[]>;

    const dispose = createRoot((disposeRoot) => {
      const [workspaceId] = createSignal<string | null>("workspace-one");
      const [descriptors, setCurrentDescriptors] = createSignal<
        readonly PluginRuntimeApplicationDescriptor[]
      >([descriptor]);
      setDescriptors = setCurrentDescriptors;
      useThirdPartyPluginRuntimeBoundary(
        controller,
        workspaceId,
        document,
        descriptors,
        loadBundle,
      );
      return disposeRoot;
    });
    await Promise.resolve();
    await Promise.resolve();

    expect(createRuntimePath).toHaveBeenCalledTimes(1);

    setDescriptors([{ ...descriptor }]);
    await Promise.resolve();
    await Promise.resolve();

    expect(createRuntimePath).toHaveBeenCalledTimes(1);
    resolveRuntimePath();
    await Promise.resolve();
    await Promise.resolve();

    const options = createRuntimePath.mock.calls[0]?.[0];
    expect(options?.startupSignal?.aborted).toBe(false);
    dispose();
    expect(destroy).toHaveBeenCalledWith("workspace_cleanup");
  });

  it("aborts pending runtime starts for authority-revocation invalidation routes", async () => {
    const cases = [
      {
        name: "workspace",
        async close(invalidation: ReturnType<typeof useThirdPartyPluginRuntimeBoundary>) {
          await invalidation.closeByWorkspace("workspace-one", "workspace_left");
        },
      },
      {
        name: "bundle",
        async close(invalidation: ReturnType<typeof useThirdPartyPluginRuntimeBoundary>) {
          await invalidation.closeByBundle("workspace-one", "bundle-one", "plugin_bundle_updated");
        },
      },
      {
        name: "capability grant",
        async close(invalidation: ReturnType<typeof useThirdPartyPluginRuntimeBoundary>) {
          await invalidation.closeByCapabilityGrant(
            "capability-grant-one",
            "plugin_consent_revoked",
          );
        },
      },
      {
        name: "application",
        async close(invalidation: ReturnType<typeof useThirdPartyPluginRuntimeBoundary>) {
          await invalidation.closeByApplication(
            "application-application",
            "plugin_application_disabled",
          );
        },
      },
    ];

    for (const testCase of cases) {
      const destroy = vi.fn((_?: string) => undefined);
      let resolveRuntimePath!: () => void;
      const runtimePathPromise = new Promise<PluginRuntimePath>((resolve) => {
        resolveRuntimePath = () =>
          resolve(
            createRuntimePathStub(destroy, {
              workspaceId: "workspace-one",
              bundleHash: "bundle-one",
              capabilityGrantId: "capability-grant-one",
            }),
          );
      });
      const createRuntimePath = vi
        .fn<PluginHostRuntimeController["createRuntimePath"]>()
        .mockReturnValue(runtimePathPromise);
      const controller: PluginHostRuntimeController = {
        router: getPluginHostMessageRouter(),
        createRuntimePath,
      };
      const descriptor: PluginRuntimeApplicationDescriptor = {
        pluginId: "com.example.runtime",
        packageId: "package-one",
        applicationId: `application-${testCase.name.replaceAll(" ", "-")}`,
        activationId: "activation-one",
        ownerScopeKind: "workspace",
        userId: "user-one",
        deviceId: "device-one",
        workspaceId: "workspace-one",
        stateHeadHash: "state-one",
        consentHeadHash: "consent-one",
        capabilityGrantId: "capability-grant-one",
      };
      const loadBundle = vi.fn(async (): Promise<LoadedPluginRuntimeBundle> => {
        return {
          pluginId: descriptor.pluginId,
          packageId: descriptor.packageId,
          applicationId: descriptor.applicationId,
          activationId: descriptor.activationId,
          ownerScopeKind: descriptor.ownerScopeKind,
          userId: descriptor.userId,
          deviceId: descriptor.deviceId,
          workspaceId: descriptor.workspaceId,
          bundleHash: "bundle-one",
          manifestHash: "manifest-one",
          consentEpoch: 1,
          sandboxDocumentUrl: `/api/plugin-runtime/sandbox-documents/${descriptor.applicationId}`,
          bootNonce: `boot-${descriptor.applicationId}`,
          frameGeneration: 1,
          permissions: [],
          networkEndpoints: [],
          rendererSlots: [],
          highRiskConsents: [],
        };
      });
      let invalidation!: ReturnType<typeof useThirdPartyPluginRuntimeBoundary>;
      let setDescriptors!: Setter<readonly PluginRuntimeApplicationDescriptor[]>;

      const dispose = createRoot((disposeRoot) => {
        const [workspaceId] = createSignal<string | null>("workspace-one");
        const [descriptors, setCurrentDescriptors] = createSignal<
          readonly PluginRuntimeApplicationDescriptor[]
        >([descriptor]);
        setDescriptors = setCurrentDescriptors;
        invalidation = useThirdPartyPluginRuntimeBoundary(
          controller,
          workspaceId,
          document,
          descriptors,
          loadBundle,
        );
        return disposeRoot;
      });
      await Promise.resolve();
      await Promise.resolve();

      expect(createRuntimePath, testCase.name).toHaveBeenCalledTimes(1);
      const options = createRuntimePath.mock.calls[0]?.[0];
      expect(options?.startupSignal?.aborted, testCase.name).toBe(false);

      await testCase.close(invalidation);

      expect(options?.startupSignal?.aborted, testCase.name).toBe(true);
      expect(window.__refmdPluginRuntimeBoundaryDebug?.revoked, testCase.name).toContainEqual({
        applicationId: descriptor.applicationId,
        descriptorKey: expect.any(String),
      });

      setDescriptors([{ ...descriptor }]);
      await Promise.resolve();
      await Promise.resolve();

      expect(createRuntimePath, testCase.name).toHaveBeenCalledTimes(1);
      resolveRuntimePath();
      await Promise.resolve();
      await Promise.resolve();

      expect(destroy, testCase.name).toHaveBeenCalledWith("runtime_startup_superseded");
      dispose();
      delete window.__refmdPluginRuntimeBoundaryDebug;
    }
  });

  it("uses verified bundle authority instead of descriptor authority when creating runtime paths", async () => {
    const destroy = vi.fn((_?: string) => undefined);
    const createRuntimePath = vi
      .fn<PluginHostRuntimeController["createRuntimePath"]>()
      .mockResolvedValue(createRuntimePathStub(destroy));
    const controller: PluginHostRuntimeController = {
      router: getPluginHostMessageRouter(),
      createRuntimePath,
    };
    const descriptor: PluginRuntimeApplicationDescriptor = {
      pluginId: "com.example.runtime",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-one",
      ownerScopeKind: "workspace",
      userId: "user-one",
      deviceId: "device-one",
      workspaceId: "workspace-one",
      stateHeadHash: "state-one",
      consentHeadHash: "consent-one",
      capabilityGrantId: "capability-grant-one",
      permissions: ["document:read:workspace", "network:fetch"],
      documentScope: { workspaceReadAllowed: true },
      networkEndpoints: [
        {
          id: "unapproved",
          url: "https://unapproved.example.com",
          methods: ["POST"],
          routes: ["proxy"],
          headers: [],
          bodySchema: "none",
          maxRequestBytes: 1024,
          maxResponseBytes: 1024,
        },
      ],
      rendererSlots: [{ kind: "block", type: "unapproved" }],
      highRiskConsents: ["workspace_network_egress"],
    };
    const loadBundle = vi.fn(async (): Promise<LoadedPluginRuntimeBundle> => {
      return {
        pluginId: descriptor.pluginId,
        packageId: "package-one",
        applicationId: descriptor.applicationId,
        activationId: "activation-one",
        ownerScopeKind: "workspace",
        userId: "user-one",
        deviceId: "device-one",
        workspaceId: descriptor.workspaceId,
        bundleHash: "bundle-one",
        manifestHash: "manifest-one",
        consentEpoch: 1,
        sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/application-one",
        bootNonce: "boot-application-one",
        frameGeneration: 1,
        permissions: ["document:read:active"],
        documentScope: { activeDocumentReadAllowed: true },
        networkEndpoints: [],
        rendererSlots: [
          { kind: "inline", type: "approved" },
          { kind: "inline", type: "code" },
        ],
        highRiskConsents: [],
      };
    });

    const dispose = createRoot((disposeRoot) => {
      const [workspaceId] = createSignal<string | null>("workspace-one");
      const [descriptors] = createSignal<readonly PluginRuntimeApplicationDescriptor[]>([
        descriptor,
      ]);
      useThirdPartyPluginRuntimeBoundary(
        controller,
        workspaceId,
        document,
        descriptors,
        loadBundle,
      );
      return disposeRoot;
    });
    await Promise.resolve();
    await Promise.resolve();

    expect(createRuntimePath).toHaveBeenCalledTimes(1);
    const options = createRuntimePath.mock.calls[0]?.[0];
    expect(options?.permissions).toEqual(["document:read:active"]);
    expect(options?.documentScope).toEqual({ activeDocumentReadAllowed: true });
    expect(options?.rendererSlots).toEqual([{ kind: "inline", type: "code" }]);
    expect(options?.highRiskConsents).toEqual([]);
    await expect(
      Promise.resolve(options?.networkServices?.endpointPolicy({} as never, "unapproved")),
    ).resolves.toBeNull();

    dispose();
  });

  it("fails active runtime session validation when descriptor authority changes", async () => {
    const destroy = vi.fn((_?: string) => undefined);
    const createRuntimePath = vi
      .fn<PluginHostRuntimeController["createRuntimePath"]>()
      .mockResolvedValue(createRuntimePathStub(destroy));
    const controller: PluginHostRuntimeController = {
      router: getPluginHostMessageRouter(),
      createRuntimePath,
    };
    let setDescriptors!: Setter<readonly PluginRuntimeApplicationDescriptor[]>;
    const descriptor: PluginRuntimeApplicationDescriptor = {
      pluginId: "com.example.runtime",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-one",
      ownerScopeKind: "workspace",
      userId: "user-one",
      deviceId: "device-one",
      workspaceId: "workspace-one",
      stateHeadHash: "state-one",
      consentHeadHash: "consent-one",
      capabilityGrantId: "capability-grant-one",
    };
    const loadBundle = vi.fn(async (): Promise<LoadedPluginRuntimeBundle> => {
      return {
        pluginId: descriptor.pluginId,
        packageId: "package-one",
        applicationId: descriptor.applicationId,
        activationId: "activation-one",
        ownerScopeKind: "workspace",
        userId: "user-one",
        deviceId: "device-one",
        workspaceId: descriptor.workspaceId,
        bundleHash: "bundle-one",
        manifestHash: "manifest-one",
        consentEpoch: 1,
        sandboxDocumentUrl: "/api/plugin-runtime/sandbox-documents/application-one",
        bootNonce: "boot-application-one",
        frameGeneration: 1,
        permissions: [],
        networkEndpoints: [],
        rendererSlots: [],
        highRiskConsents: [],
      };
    });

    const dispose = createRoot((disposeRoot) => {
      const [workspaceId] = createSignal<string | null>("workspace-one");
      const [descriptors, setCurrentDescriptors] = createSignal<
        readonly PluginRuntimeApplicationDescriptor[]
      >([descriptor]);
      setDescriptors = setCurrentDescriptors;
      useThirdPartyPluginRuntimeBoundary(
        controller,
        workspaceId,
        document,
        descriptors,
        loadBundle,
      );
      return disposeRoot;
    });
    await Promise.resolve();
    await Promise.resolve();

    const options = createRuntimePath.mock.calls[0]?.[0];
    const context = {
      workspaceId: "workspace-one",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-one",
      ownerScopeKind: "workspace",
      bundleHash: "bundle-one",
      userId: "user-one",
      deviceId: "device-one",
      manifestHash: "manifest-one",
      capabilityGrantId: "capability-grant-one",
      consentEpoch: 1,
    } as Parameters<NonNullable<typeof options.validateSession>>[0];
    const request = {
      workspace_id: "workspace-one",
      package_id: "package-one",
      application_id: "application-one",
      activation_id: "activation-one",
      owner_scope_kind: "workspace",
      user_id: "user-one",
      device_id: "device-one",
      bundle_hash: "bundle-one",
      manifest_hash: "manifest-one",
      capability_grant_id: "capability-grant-one",
      consent_epoch: 1,
    } as Parameters<NonNullable<typeof options.validateSession>>[1];

    expect(options?.validateSession?.(context, request)).toBeNull();
    setDescriptors([{ ...descriptor, stateHeadHash: "state-two" }]);
    expect(options?.validateSession?.(context, request)).toMatchObject({
      code: "plugin_runtime_stale",
    });
    setDescriptors([{ ...descriptor, capabilityGrantId: "capability-grant-two" }]);
    expect(options?.validateSession?.(context, request)).toMatchObject({
      code: "plugin_runtime_stale",
    });
    setDescriptors([]);
    expect(options?.validateSession?.(context, request)).toMatchObject({
      code: "plugin_runtime_revoked",
    });

    dispose();
  });

  it("rejects runtime bundle envelopes without a valid approval and consent proof", async () => {
    const descriptor: PluginRuntimeApplicationDescriptor = {
      pluginId: "com.example.runtime",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-one",
      ownerScopeKind: "workspace",
      userId: "user-one",
      deviceId: "device-one",
      workspaceId: "workspace-one",
      stateHeadHash: "state-one",
      consentHeadHash: "consent-one",
      capabilityGrantId: "capability-grant-one",
    };
    const resourceManifestHash = semanticHashForTest([]);
    const approvalSubject = {
      plugin_id: descriptor.pluginId,
      package_id: "package-one",
      application_id: descriptor.applicationId,
      activation_id: "activation-one",
      owner_scope_kind: "workspace",
      owner_workspace_id: descriptor.workspaceId,
      application_scope_kind: "workspace",
      user_id: "user-one",
      device_id: "device-one",
      workspace_id: descriptor.workspaceId,
      bundle_hash: "bundle-hash",
      manifest_hash: "manifest-hash",
      main_js_hash: "main-js-hash",
      styles_css_hash: "styles-css-hash",
      resource_manifest_hash: resourceManifestHash,
      permissions_hash: "permissions-hash",
      endpoint_hash: "endpoint-hash",
      renderer_slots_hash: "renderer-slots-hash",
      document_scope_hash: "document-scope-hash",
      approver_user_id: "user-one",
      approver_device_id: "device-one",
      approval_epoch: 1,
    } as StrictJsonValue;
    const consentSubject = {
      bundle_hash: "bundle-hash",
      manifest_hash: "manifest-hash",
      resource_manifest_hash: resourceManifestHash,
      permissions_hash: "permissions-hash",
      endpoint_hash: "endpoint-hash",
      document_scope_hash: "document-scope-hash",
      decision: "allow",
    } as StrictJsonValue;

    await expect(
      verifyRuntimeBundleProof(
        descriptor,
        {
          plugin_id: descriptor.pluginId,
          package_id: "package-one",
          application_id: descriptor.applicationId,
          activation_id: "activation-one",
          owner_scope_kind: "workspace",
          workspace_id: descriptor.workspaceId,
          state_head_hash: descriptor.stateHeadHash,
          bundle_hash: "bundle-hash",
          manifest_hash: "manifest-hash",
          main_js_hash: "main-js-hash",
          styles_css_hash: "styles-css-hash",
          resource_manifest_hash: resourceManifestHash,
          resource_manifest: [],
          permissions_hash: "permissions-hash",
          endpoint_hash: "endpoint-hash",
          renderer_slots_hash: "renderer-slots-hash",
          document_scope_hash: "document-scope-hash",
          approval_event_hash: hashSubject(approvalSubject),
          consent_event_hash: descriptor.consentHeadHash,
          consent_epoch: 1,
          approval_proof: {
            event_hash: hashSubject(approvalSubject),
            subject: approvalSubject,
            actor: { signer_kind: "device", user_id: "user-one", device_id: "device-one" },
            hybrid_signature: {} as never,
            signing_key_id: "signing-key-one",
            approval_authority: {
              kind: "key_directory_membership",
              scope_kind: "workspace",
              workspace_id: descriptor.workspaceId,
              user_id: "user-one",
              device_id: "device-one",
              signing_key_id: "signing-key-one",
              event_head_sequence: 2,
              event_head_hash: "event-head-hash",
              checkpoint_sequence: 1,
              checkpoint_hash: "checkpoint-hash",
            },
          },
          consent_proof: {
            event_hash: descriptor.consentHeadHash,
            subject: consentSubject,
            actor: { signer_kind: "device", user_id: "user-one", device_id: "device-one" },
            hybrid_signature: {} as never,
            signing_key_id: "signing-key-one",
          },
          manifest_json_bytes: "",
          main_js: "",
          styles_css: "",
          resources: [],
        },
        localPins(descriptor, "bundle-hash", hashSubject(approvalSubject), 1),
        async () => null,
        acceptsApprovalAuthority,
      ),
    ).rejects.toThrow("consent_hash_mismatch");
  });

  it("rejects runtime bundle consent proofs for a different member", async () => {
    const { descriptor, envelope, publicKeyMaterial, privateKeyMaterial } = signedRuntimeEnvelope();
    const consentSubject = {
      ...(envelope.consent_proof.subject as Record<string, StrictJsonValue>),
      user_id: "user-two",
    } as StrictJsonValue;
    const consentEventHash = hashSubject(consentSubject);
    const consentTranscript = buildPluginConsentEventTranscript({
      actor: {
        ...(envelope.consent_proof.actor as Record<string, StrictJsonValue>),
        user_id: "user-two",
      } as StrictJsonValue,
      consent: consentSubject,
    });
    const mismatchedDescriptor = { ...descriptor, consentHeadHash: consentEventHash };
    const mismatchedEnvelope = {
      ...envelope,
      consent_event_hash: consentEventHash,
      consent_proof: {
        ...envelope.consent_proof,
        event_hash: consentEventHash,
        subject: consentSubject,
        actor: {
          ...(envelope.consent_proof.actor as Record<string, StrictJsonValue>),
          user_id: "user-two",
        } as StrictJsonValue,
        hybrid_signature: signPluginConsentEventSignature({
          transcript: consentTranscript,
          privateKeyMaterial,
        }),
      },
    };

    await expect(
      verifyRuntimeBundleProof(
        mismatchedDescriptor,
        mismatchedEnvelope,
        localPins(mismatchedDescriptor, envelope.bundle_hash, envelope.approval_event_hash, 1),
        async () => publicKeyMaterial,
        acceptsApprovalAuthority,
      ),
    ).rejects.toThrow("consent_user_id_mismatch");
  });

  it("rejects runtime bundle consent proofs signed by a different actor than the subject", async () => {
    const { descriptor, envelope, publicKeyMaterial } = signedRuntimeEnvelope();
    const actor = {
      ...(envelope.consent_proof.actor as Record<string, StrictJsonValue>),
      user_id: "user-two",
    } as StrictJsonValue;

    await expect(
      verifyRuntimeBundleProof(
        descriptor,
        {
          ...envelope,
          consent_proof: {
            ...envelope.consent_proof,
            actor,
          },
        },
        localPins(descriptor, envelope.bundle_hash, envelope.approval_event_hash, 1),
        async () => publicKeyMaterial,
        acceptsApprovalAuthority,
      ),
    ).rejects.toThrow("consent_actor_mismatch");
  });

  it("requires local plugin pins before accepting runtime bundle proofs", async () => {
    const { descriptor, envelope, publicKeyMaterial } = signedRuntimeEnvelope();

    await expect(
      verifyRuntimeBundleProof(descriptor, envelope, null as never, async () => publicKeyMaterial),
    ).rejects.toThrow("plugin_state_pin_required");

    await expect(
      verifyRuntimeBundleProof(
        { ...descriptor, stateHeadHash: "server-newer-state" },
        envelope,
        localPins(descriptor, envelope.bundle_hash, envelope.approval_event_hash, 1),
        async () => publicKeyMaterial,
        acceptsApprovalAuthority,
      ),
    ).rejects.toThrow("state_pin_mismatch");
  });

  it("saves verified runtime state and consent pins after proof validation", async () => {
    const { descriptor, envelope } = signedRuntimeEnvelope();
    const saveState = vi.fn(async () => undefined);
    const saveConsent = vi.fn(async () => undefined);

    await expect(
      saveVerifiedPluginRuntimePins(descriptor, envelope, "user-one", 123, {
        saveState,
        saveConsent,
      }),
    ).resolves.toBeUndefined();

    expect(saveState).toHaveBeenCalledWith({
      workspaceId: descriptor.workspaceId,
      packageId: descriptor.packageId,
      applicationId: descriptor.applicationId,
      activationId: "activation-one",
      latestEventHash: descriptor.stateHeadHash,
      bundleHash: envelope.bundle_hash,
      approvalEventHash: envelope.approval_event_hash,
      updatedAtMs: 123,
    });
    expect(saveConsent).toHaveBeenCalledWith({
      workspaceId: descriptor.workspaceId,
      packageId: descriptor.packageId,
      applicationId: descriptor.applicationId,
      activationId: "activation-one",
      userId: "user-one",
      consentEpoch: envelope.consent_epoch,
      latestEventHash: descriptor.consentHeadHash,
      updatedAtMs: 123,
    });
  });

  it("does not save runtime pins when verified response heads do not match the descriptor", async () => {
    const { descriptor, envelope } = signedRuntimeEnvelope();
    const saveState = vi.fn(async () => undefined);
    const saveConsent = vi.fn(async () => undefined);

    await expect(
      saveVerifiedPluginRuntimePins(
        { ...descriptor, stateHeadHash: "stale-state" },
        envelope,
        "user-one",
        123,
        {
          saveState,
          saveConsent,
        },
      ),
    ).rejects.toThrow("state_head_mismatch");

    expect(saveState).not.toHaveBeenCalled();
    expect(saveConsent).not.toHaveBeenCalled();
  });

  it("rejects runtime bundle manifest sections that do not match approved semantic hashes", () => {
    const { envelope } = signedRuntimeEnvelope();
    const manifest = {
      id: "com.example.runtime",
      version: "1.0.0",
      permissions: ["document:read:active"],
      network: { endpoints: [] },
      rendererSlots: [],
      documentScopes: [{ kind: "active" }],
    } satisfies StrictJsonValue;
    const matchingEnvelope = {
      ...envelope,
      manifest_json_bytes: base64Text(JSON.stringify(manifest)),
      permissions_hash: semanticHashForTest(manifest.permissions),
      endpoint_hash: semanticHashForTest(manifest.network.endpoints),
      renderer_slots_hash: semanticHashForTest(manifest.rendererSlots),
      document_scope_hash: semanticHashForTest(manifest.documentScopes),
    };

    expect(assertRuntimeBundleManifestAuthority(matchingEnvelope).authority.permissions).toEqual([
      "document:read:active",
    ]);
    expect(() =>
      assertRuntimeBundleManifestAuthority({
        ...matchingEnvelope,
        permissions_hash: semanticHashForTest(["document:read:workspace"]),
      }),
    ).toThrow("permissions_hash_mismatch");
  });

  it("resolves runtime proof signer keys from trusted local state", async () => {
    const { descriptor, envelope, publicKeyMaterial } = signedRuntimeEnvelope();
    const pins = localPins(descriptor, envelope.bundle_hash, envelope.approval_event_hash, 1);

    await expect(
      verifyRuntimeBundleProof(
        descriptor,
        envelope,
        pins,
        async () => null,
        acceptsApprovalAuthority,
      ),
    ).rejects.toThrow("runtime_proof_signer_untrusted");

    await expect(
      verifyRuntimeBundleProof(
        descriptor,
        envelope,
        pins,
        async () => publicKeyMaterial,
        acceptsApprovalAuthority,
      ),
    ).resolves.toBeUndefined();
  });

  it("requires admin or owner approval authority evidence before loading a runtime bundle", async () => {
    const { descriptor, envelope, publicKeyMaterial } = signedRuntimeEnvelope();
    const pins = localPins(descriptor, envelope.bundle_hash, envelope.approval_event_hash, 1);

    await expect(
      verifyRuntimeBundleProof(
        descriptor,
        {
          ...envelope,
          approval_proof: {
            ...envelope.approval_proof,
            approval_authority: undefined,
          },
        },
        pins,
        async () => publicKeyMaterial,
        acceptsApprovalAuthority,
      ),
    ).rejects.toThrow("approval_authority_required");

    await expect(
      verifyRuntimeBundleProof(
        descriptor,
        {
          ...envelope,
          approval_proof: {
            ...envelope.approval_proof,
            approval_authority: {
              scope_kind: "workspace",
              workspace_id: descriptor.workspaceId,
              user_id: "00000000-0000-4000-8000-000000000002",
              role: "admin",
            },
          },
        },
        pins,
        async () => publicKeyMaterial,
        acceptsApprovalAuthority,
      ),
    ).rejects.toThrow("approval_authority_untrusted_role");

    await expect(
      verifyRuntimeBundleProof(
        descriptor,
        envelope,
        pins,
        async () => publicKeyMaterial,
        async () => {
          throw new Error("approval_authority_lineage_required");
        },
      ),
    ).rejects.toThrow("approval_authority_lineage_required");
  });

  it("accepts user-owned package approval authority for workspace runtime admission", async () => {
    const {
      descriptor,
      envelope,
      publicKeyMaterial,
      privateKeyMaterial,
      signingKeyId,
      userId,
      deviceId,
    } = signedRuntimeEnvelope();
    const approvalSubject: Record<string, StrictJsonValue> = {
      ...(envelope.approval_proof.subject as Record<string, StrictJsonValue>),
      owner_scope_kind: "user",
      owner_user_id: userId,
    };
    delete approvalSubject.owner_workspace_id;
    delete approvalSubject.application_scope_kind;
    delete approvalSubject.workspace_id;
    const approvalActor = {
      ...(envelope.approval_proof.actor as Record<string, StrictJsonValue>),
      key_scope_kind: "user",
      key_scope_id: userId,
    } as StrictJsonValue;
    const approvalEventHash = hashSubject(approvalSubject as StrictJsonValue);
    const consentSubject = {
      ...(envelope.consent_proof.subject as Record<string, StrictJsonValue>),
      owner_scope_kind: "user",
    } as StrictJsonValue;
    const consentEventHash = hashSubject(consentSubject);
    const approvalTranscript = buildPluginBundleApprovalTranscript({
      actor: approvalActor,
      approval: approvalSubject as StrictJsonValue,
    });
    const consentTranscript = buildPluginConsentEventTranscript({
      actor: envelope.consent_proof.actor,
      consent: consentSubject,
    });
    const userDescriptor = {
      ...descriptor,
      ownerScopeKind: "user",
      consentHeadHash: consentEventHash,
    };
    const userEnvelope = {
      ...envelope,
      owner_scope_kind: "user",
      approval_event_hash: approvalEventHash,
      consent_event_hash: consentEventHash,
      approval_proof: {
        ...envelope.approval_proof,
        event_hash: approvalEventHash,
        subject: approvalSubject as StrictJsonValue,
        actor: approvalActor,
        signing_key_id: signingKeyId,
        hybrid_signature: signPluginBundleApprovalSignature({
          transcript: approvalTranscript,
          privateKeyMaterial,
        }),
        approval_authority: {
          kind: "key_directory_membership",
          scope_kind: "user",
          owner_user_id: userId,
          user_id: userId,
          device_id: deviceId,
          signing_key_id: signingKeyId,
          event_head_sequence: 2,
          event_head_hash: "user-event-head-hash",
          checkpoint_sequence: 1,
          checkpoint_hash: "user-checkpoint-hash",
        },
      },
      consent_proof: {
        ...envelope.consent_proof,
        event_hash: consentEventHash,
        subject: consentSubject,
        actor: envelope.consent_proof.actor,
        signing_key_id: signingKeyId,
        hybrid_signature: signPluginConsentEventSignature({
          transcript: consentTranscript,
          privateKeyMaterial,
        }),
      },
    };

    await expect(
      verifyRuntimeBundleProof(
        userDescriptor,
        userEnvelope,
        localPins(userDescriptor, userEnvelope.bundle_hash, approvalEventHash, 1),
        async () => publicKeyMaterial,
        acceptsApprovalAuthority,
      ),
    ).resolves.toBeUndefined();
  });

  it("rejects non-canonical approval subject owner fields", async () => {
    const { descriptor, envelope, publicKeyMaterial } = signedRuntimeEnvelope();
    const pins = localPins(descriptor, envelope.bundle_hash, envelope.approval_event_hash, 1);

    await expect(
      verifyRuntimeBundleProof(
        descriptor,
        {
          ...envelope,
          approval_proof: {
            ...envelope.approval_proof,
            subject: {
              ...(envelope.approval_proof.subject as Record<string, StrictJsonValue>),
              owner_user_id: null,
            } as unknown as StrictJsonValue,
          },
        },
        pins,
        async () => publicKeyMaterial,
        acceptsApprovalAuthority,
      ),
    ).rejects.toThrow("approval_subject_null_field");

    await expect(
      verifyRuntimeBundleProof(
        { ...descriptor, ownerScopeKind: "user" },
        {
          ...envelope,
          approval_proof: {
            ...envelope.approval_proof,
            subject: {
              ...(envelope.approval_proof.subject as Record<string, StrictJsonValue>),
              owner_scope_kind: "user",
              owner_user_id: "user-one",
            } as StrictJsonValue,
          },
        },
        pins,
        async () => publicKeyMaterial,
        acceptsApprovalAuthority,
      ),
    ).rejects.toThrow("approval_subject_forbidden_field");
  });

  it("replays verified workspace membership and signing key state for approval authority", () => {
    const { envelope, publicKeyMaterial } = signedRuntimeEnvelope();
    const authority = envelope.approval_proof.approval_authority as Record<string, StrictJsonValue>;
    const memberEvent = keyDirectoryEvent({
      scope_kind: "workspace",
      scope_id: "workspace-one",
      sequence: 2,
      event_type: "member_added",
      body: {
        user_id: "00000000-0000-4000-8000-000000000002",
        base_role: "admin",
      },
    });
    const checkpointPayload = {
      scope_kind: "workspace",
      scope_id: "workspace-one",
      sequence: 1,
      covered_event_head: {
        head_sequence: 2,
        head_hash: hashSubject(memberEvent.payload as StrictJsonValue),
      },
      device_keys: [
        {
          key_id: envelope.approval_proof.signing_key_id,
          key_material: publicKeyMaterial,
          valid_from: {
            scope_kind: "workspace",
            scope_id: "workspace-one",
            event_sequence: 1,
            event_hash: "device-event-hash",
          },
        },
      ],
    };

    expect(() =>
      assertApprovalAuthorityFromVerifiedLineage(authority, checkpointPayload, [memberEvent]),
    ).not.toThrow();

    const viewerEvent = keyDirectoryEvent({
      ...memberEvent.payload,
      body: {
        user_id: "00000000-0000-4000-8000-000000000002",
        base_role: "viewer",
      },
    });
    expect(() =>
      assertApprovalAuthorityFromVerifiedLineage(
        {
          ...authority,
          event_head_hash: hashSubject(viewerEvent.payload as StrictJsonValue),
        },
        {
          ...checkpointPayload,
          covered_event_head: {
            head_sequence: 2,
            head_hash: hashSubject(viewerEvent.payload as StrictJsonValue),
          },
        },
        [viewerEvent],
      ),
    ).toThrow("approval_authority_role_forbidden");

    const demotionEvent = keyDirectoryEvent({
      scope_kind: "workspace",
      scope_id: "workspace-one",
      sequence: 3,
      event_type: "member_role_changed",
      body: {
        user_id: "00000000-0000-4000-8000-000000000002",
        base_role: "viewer",
      },
    });
    expect(() =>
      assertApprovalAuthorityFromVerifiedLineage(
        {
          ...authority,
          event_head_sequence: 3,
          event_head_hash: hashSubject(demotionEvent.payload as StrictJsonValue),
        },
        {
          ...checkpointPayload,
          covered_event_head: {
            head_sequence: 3,
            head_hash: hashSubject(demotionEvent.payload as StrictJsonValue),
          },
        },
        [memberEvent, demotionEvent],
      ),
    ).toThrow("approval_authority_role_forbidden");

    expect(() =>
      assertApprovalAuthorityFromVerifiedLineage(
        authority,
        {
          ...checkpointPayload,
          device_keys: [
            {
              ...(checkpointPayload.device_keys[0] as Record<string, unknown>),
              revoked_at: {
                scope_kind: "workspace",
                scope_id: "workspace-one",
                event_sequence: 2,
                event_hash: "revocation-event-hash",
              },
            },
          ],
        },
        [memberEvent],
      ),
    ).toThrow("key_directory_signer_revoked");
  });

  it("replays verified user key-directory state for user-owned approval authority", () => {
    const { envelope, publicKeyMaterial, userId, deviceId, signingKeyId } = signedRuntimeEnvelope();
    const authority: Record<string, StrictJsonValue> = {
      ...(envelope.approval_proof.approval_authority as Record<string, StrictJsonValue>),
      scope_kind: "user",
      owner_user_id: userId,
      user_id: userId,
      device_id: deviceId,
      signing_key_id: signingKeyId,
      event_head_hash: "user-event-head-hash",
    };
    delete authority.workspace_id;
    const event = keyDirectoryEvent({
      scope_kind: "user",
      scope_id: userId,
      sequence: 2,
      event_type: "device_registered",
      body: {
        user_id: userId,
      },
    });
    const checkpointPayload = {
      scope_kind: "user",
      scope_id: userId,
      sequence: 1,
      covered_event_head: {
        head_sequence: 2,
        head_hash: hashSubject(event.payload as StrictJsonValue),
      },
      device_keys: [
        {
          key_id: signingKeyId,
          key_material: publicKeyMaterial,
          valid_from: {
            scope_kind: "user",
            scope_id: userId,
            event_sequence: 1,
            event_hash: "device-event-hash",
          },
        },
      ],
    };

    expect(() =>
      assertApprovalAuthorityFromVerifiedLineage(
        {
          ...authority,
          event_head_hash: hashSubject(event.payload as StrictJsonValue),
        },
        checkpointPayload,
        [event],
      ),
    ).not.toThrow();

    expect(() =>
      assertApprovalAuthorityFromVerifiedLineage(
        {
          ...authority,
          user_id: "00000000-0000-4000-8000-000000000099",
          event_head_hash: hashSubject(event.payload as StrictJsonValue),
        },
        checkpointPayload,
        [event],
      ),
    ).toThrow("approval_authority_user_mismatch");
  });
});

function hashSubject(subject: StrictJsonValue): string {
  return blake3Base64Url(canonicalizeStrictBytes(subject));
}

function semanticHashForTest(value: StrictJsonValue): string {
  return blake3Base64Url(canonicalizeStrictValueBytes(value));
}

function base64Text(value: string): string {
  return globalThis.btoa(value);
}

function localPins(
  descriptor: PluginRuntimeApplicationDescriptor,
  bundleHash: string,
  approvalEventHash: string,
  consentEpoch: number,
) {
  return {
    state: {
      workspaceId: descriptor.workspaceId,
      packageId: descriptor.packageId,
      applicationId: descriptor.applicationId,
      activationId: "activation-one",
      latestEventHash: descriptor.stateHeadHash,
      bundleHash,
      approvalEventHash,
      updatedAtMs: 1,
    },
    consent: {
      workspaceId: descriptor.workspaceId,
      packageId: descriptor.packageId,
      applicationId: descriptor.applicationId,
      activationId: "activation-one",
      userId: descriptor.userId,
      consentEpoch,
      latestEventHash: descriptor.consentHeadHash,
      updatedAtMs: 1,
    },
  };
}

async function acceptsApprovalAuthority(): Promise<void> {
  return undefined;
}

function keyDirectoryEvent(
  payload: Record<string, unknown>,
): Parameters<typeof assertApprovalAuthorityFromVerifiedLineage>[2][number] {
  return {
    payload,
    signatures: [
      {
        signer: { signer_kind: "device" },
        signature: {} as never,
      },
    ],
  };
}

function signedRuntimeEnvelope() {
  const deviceId = "00000000-0000-4000-8000-000000000001";
  const userId = "00000000-0000-4000-8000-000000000002";
  const privateKeyMaterial = generateHybridSigningPrivateKeyMaterial("device", deviceId);
  const publicKeyMaterial = publicKeyMaterialFromPrivate(privateKeyMaterial);
  const signingKeyId = computeSigningKeyId(publicKeyMaterial);
  const bundleHash = hashSubject({ label: "bundle" });
  const manifestHash = hashSubject({ label: "manifest" });
  const mainJsHash = hashSubject({ label: "main-js" });
  const stylesCssHash = hashSubject({ label: "styles-css" });
  const resourceManifestHash = hashSubject({ label: "resources" });
  const permissionsHash = hashSubject({ label: "permissions" });
  const endpointHash = hashSubject({ label: "endpoint" });
  const rendererSlotsHash = hashSubject({ label: "renderer-slots" });
  const documentScopeHash = hashSubject({ label: "document-scope" });
  const archiveHash = hashSubject({ label: "archive" });
  const actor = {
    signer_kind: "device",
    user_id: userId,
    device_id: deviceId,
    signing_key_id: signingKeyId,
    key_scope_kind: "workspace",
    key_scope_id: "workspace-one",
    key_checkpoint_sequence: 1,
    key_checkpoint_hash: hashSubject({ label: "workspace-checkpoint" }),
  } as StrictJsonValue;
  const descriptor: PluginRuntimeApplicationDescriptor = {
    pluginId: "com.example.runtime",
    packageId: "package-one",
    applicationId: "application-one",
    activationId: "activation-one",
    ownerScopeKind: "workspace",
    userId,
    deviceId,
    workspaceId: "workspace-one",
    stateHeadHash: "state-one",
    consentHeadHash: "",
    capabilityGrantId: "capability-grant-one",
  };
  const approvalSubject = {
    plugin_id: descriptor.pluginId,
    package_id: "package-one",
    application_scope_kind: "workspace",
    workspace_id: descriptor.workspaceId,
    owner_scope_kind: "workspace",
    owner_workspace_id: descriptor.workspaceId,
    version: "1.0.0",
    source_kind: "local_upload",
    source_url_hash: "NO_SOURCE_URL",
    archive_hash: archiveHash,
    bundle_hash: bundleHash,
    manifest_hash: manifestHash,
    main_js_hash: mainJsHash,
    styles_css_hash: stylesCssHash,
    resource_manifest_hash: resourceManifestHash,
    permissions_hash: permissionsHash,
    endpoint_hash: endpointHash,
    renderer_slots_hash: rendererSlotsHash,
    document_scope_hash: documentScopeHash,
    approver_user_id: userId,
    approver_device_id: deviceId,
    approval_epoch: 1,
    previous_approval_event_hash: "GENESIS",
    created_at_ms: 1_775_000_000_000,
  } as StrictJsonValue;
  const consentSubject = {
    application_id: descriptor.applicationId,
    activation_id: "activation-one",
    owner_scope_kind: "workspace",
    application_scope_kind: "workspace",
    plugin_id: descriptor.pluginId,
    package_id: "package-one",
    version: "1.0.0",
    workspace_id: descriptor.workspaceId,
    bundle_hash: bundleHash,
    manifest_hash: manifestHash,
    resource_manifest_hash: resourceManifestHash,
    permissions_hash: permissionsHash,
    endpoint_hash: endpointHash,
    document_scope_hash: documentScopeHash,
    signer_device_id: deviceId,
    signer_user_id: userId,
    user_id: userId,
    device_id: deviceId,
    consent_epoch: 1,
    previous_event_hash: "GENESIS",
    decision: "allow",
  } as StrictJsonValue;
  const consentHeadHash = hashSubject(consentSubject);
  const approvalEventHash = hashSubject(approvalSubject);
  const runtimeDescriptor = { ...descriptor, consentHeadHash };
  const approvalTranscript = buildPluginBundleApprovalTranscript({
    actor,
    approval: approvalSubject,
  });
  const consentTranscript = buildPluginConsentEventTranscript({
    actor,
    consent: consentSubject,
  });

  return {
    descriptor: runtimeDescriptor,
    privateKeyMaterial,
    publicKeyMaterial,
    signingKeyId,
    userId,
    deviceId,
    envelope: {
      plugin_id: runtimeDescriptor.pluginId,
      package_id: "package-one",
      application_id: runtimeDescriptor.applicationId,
      activation_id: "activation-one",
      owner_scope_kind: "workspace",
      user_id: "user-one",
      device_id: "device-one",
      workspace_id: runtimeDescriptor.workspaceId,
      state_head_hash: runtimeDescriptor.stateHeadHash,
      bundle_hash: bundleHash,
      manifest_hash: manifestHash,
      main_js_hash: mainJsHash,
      styles_css_hash: stylesCssHash,
      resource_manifest_hash: resourceManifestHash,
      resource_manifest: [],
      permissions_hash: permissionsHash,
      endpoint_hash: endpointHash,
      renderer_slots_hash: rendererSlotsHash,
      document_scope_hash: documentScopeHash,
      approval_event_hash: approvalEventHash,
      consent_event_hash: consentHeadHash,
      consent_epoch: 1,
      approval_proof: {
        event_hash: approvalEventHash,
        subject: approvalSubject,
        actor,
        hybrid_signature: signPluginBundleApprovalSignature({
          transcript: approvalTranscript,
          privateKeyMaterial,
        }),
        signing_key_id: signingKeyId,
        approval_authority: {
          kind: "key_directory_membership",
          scope_kind: "workspace",
          workspace_id: runtimeDescriptor.workspaceId,
          user_id: userId,
          device_id: deviceId,
          signing_key_id: signingKeyId,
          event_head_sequence: 2,
          event_head_hash: hashSubject({
            scope_kind: "workspace",
            scope_id: runtimeDescriptor.workspaceId,
            sequence: 2,
            event_type: "member_added",
            body: {
              user_id: userId,
              base_role: "admin",
            },
          } as StrictJsonValue),
          checkpoint_sequence: 1,
          checkpoint_hash: "checkpoint-hash",
        },
      },
      consent_proof: {
        event_hash: consentHeadHash,
        subject: consentSubject,
        actor,
        hybrid_signature: signPluginConsentEventSignature({
          transcript: consentTranscript,
          privateKeyMaterial,
        }),
        signing_key_id: signingKeyId,
      },
      manifest_json_bytes: "",
      main_js: "",
      styles_css: "",
      resources: [],
    },
  };
}
