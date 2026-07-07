import { describe, expect, it, vi } from "vite-plus/test";
import type { PluginActivationInfo, PluginApplicationInfo, PluginPackageInfo } from "@/shared/api";
import {
  canManagePluginApplicationPolicy,
  canApplyPluginPackage,
  purgeDeletedApplicationLocalData,
  purgeDeletedActivationLocalData,
  saveApplicationActivationPluginStatePin,
  saveAppliedPluginStatePin,
  savePromotedPluginStatePin,
  saveRuntimeDescriptorPluginStatePin,
  scopeChoiceLabel,
  runWithPluginRuntimeApplicationRevocation,
  upsertPluginActivation,
  upsertPluginApplication,
  upsertPluginPackage,
} from "./CommunityPluginsSection";

const packageInfo: PluginPackageInfo = {
  id: "package-one",
  plugin_id: "plugin.example",
  version: "1.0.0",
  owner_scope_kind: "workspace",
  owner_workspace_id: "workspace-one",
  current_bundle_id: "bundle-one",
  state_head_hash: "approval-event-one",
  bundle_hash: "bundle-hash-one",
  resource_manifest_hash: "resource-hash-one",
};

const application: PluginApplicationInfo = {
  id: "application-one",
  package_id: "package-one",
  plugin_id: "plugin.example",
  workspace_id: "workspace-one",
  application_scope_kind: "workspace",
  application_mode: "ui",
  workspace_policy_result: "allowed",
  enabled: true,
  consent_epoch: 0,
  state_head_hash: "approval-event-one",
  current_bundle_id: "bundle-one",
};

const activation: PluginActivationInfo = {
  id: "activation-one",
  application_id: "application-one",
  workspace_id: "workspace-one",
  package_id: "package-one",
  plugin_id: "plugin.example",
  bundle_hash: "bundle-hash-one",
  user_id: "user-one",
  device_id: "device-one",
  activation_scope_kind: "device",
  enabled: true,
};

describe("canApplyPluginPackage", () => {
  it("allows workspace owners and admins to apply a pinned workspace package", () => {
    expect(canApplyPluginPackage(packageInfo, "owner")).toBe(true);
    expect(canApplyPluginPackage(packageInfo, "admin")).toBe(true);
  });

  it("prevents non-admin workspace members from applying workspace packages", () => {
    expect(canApplyPluginPackage(packageInfo, "editor")).toBe(false);
    expect(canApplyPluginPackage(packageInfo, "viewer")).toBe(false);
    expect(canApplyPluginPackage(packageInfo, null)).toBe(false);
  });

  it("allows personal packages and rejects packages without a pinned current bundle", () => {
    expect(canApplyPluginPackage({ ...packageInfo, owner_scope_kind: "user" })).toBe(true);
    expect(canApplyPluginPackage({ ...packageInfo, current_bundle_id: null })).toBe(false);
  });
});

describe("canManagePluginApplicationPolicy", () => {
  it("allows workspace owners and admins to change plugin policy", () => {
    expect(canManagePluginApplicationPolicy(application, "owner")).toBe(true);
    expect(canManagePluginApplicationPolicy(application, "admin")).toBe(true);
  });

  it("hides plugin policy controls from non-admin workspace roles", () => {
    expect(canManagePluginApplicationPolicy(application, "editor")).toBe(false);
    expect(canManagePluginApplicationPolicy(application, "viewer")).toBe(false);
    expect(canManagePluginApplicationPolicy(application, null)).toBe(false);
  });
});

describe("runWithPluginRuntimeApplicationRevocation", () => {
  it("begins before the destructive action and releases after success", async () => {
    const events: string[] = [];
    const begin = vi.fn((applicationId: string) => events.push(`begin:${applicationId}`));
    const release = vi.fn((applicationId: string) => events.push(`release:${applicationId}`));

    await expect(
      runWithPluginRuntimeApplicationRevocation(
        "application-one",
        {
          beginRuntimeApplicationRevocation: begin,
          releaseRuntimeApplicationRevocation: release,
        },
        async () => {
          events.push("close-runtime");
          return "done";
        },
      ),
    ).resolves.toBe("done");

    expect(begin).toHaveBeenCalledWith("application-one");
    expect(release).toHaveBeenCalledWith("application-one");
    expect(events).toEqual(["begin:application-one", "close-runtime", "release:application-one"]);
  });

  it("releases destructive revocation after action failure", async () => {
    const events: string[] = [];

    await expect(
      runWithPluginRuntimeApplicationRevocation(
        "application-one",
        {
          beginRuntimeApplicationRevocation: () => events.push("begin"),
          releaseRuntimeApplicationRevocation: () => events.push("release"),
        },
        async () => {
          events.push("close-runtime");
          throw new Error("mutation_failed");
        },
      ),
    ).rejects.toThrow("mutation_failed");

    expect(events).toEqual(["begin", "close-runtime", "release"]);
  });
});

describe("plugin management query cache helpers", () => {
  it("replaces existing promoted package, application, and activation entries", () => {
    const promotedPackage = {
      ...packageInfo,
      current_bundle_id: "bundle-two",
      state_head_hash: "approval-event-two",
    };
    const promotedApplication = {
      ...application,
      workspace_policy_result: "needs_admin_review" as const,
      state_head_hash: "approval-event-two",
      current_bundle_id: "bundle-two",
    };
    const promotedActivation = {
      ...activation,
      bundle_hash: "bundle-hash-two",
    };

    expect(upsertPluginPackage([packageInfo], promotedPackage)).toEqual([promotedPackage]);
    expect(upsertPluginApplication([application], promotedApplication)).toEqual([
      promotedApplication,
    ]);
    expect(upsertPluginActivation([activation], promotedActivation)).toEqual([promotedActivation]);
  });

  it("prepends promoted entries when the corresponding query cache is empty", () => {
    expect(upsertPluginPackage(undefined, packageInfo)).toEqual([packageInfo]);
    expect(upsertPluginApplication(undefined, application)).toEqual([application]);
    expect(upsertPluginActivation(undefined, activation)).toEqual([activation]);
  });
});

describe("saveAppliedPluginStatePin", () => {
  it("persists the approved package state for the applied activation", async () => {
    const saveStatePin = vi.fn(async () => undefined);

    await saveAppliedPluginStatePin(
      packageInfo,
      { ...application, state_head_hash: "application-state-one" },
      activation,
      1234,
      saveStatePin,
    );

    expect(saveStatePin).toHaveBeenCalledWith({
      workspaceId: "workspace-one",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-one",
      latestEventHash: "application-state-one",
      bundleHash: "bundle-hash-one",
      approvalEventHash: "approval-event-one",
      updatedAtMs: 1234,
    });
  });

  it("rejects incomplete apply state before writing a pin", async () => {
    const saveStatePin = vi.fn(async () => undefined);

    await expect(
      saveAppliedPluginStatePin(
        packageInfo,
        { ...application, state_head_hash: null },
        activation,
        1234,
        saveStatePin,
      ),
    ).rejects.toThrow("plugin_application_state_missing");
    await expect(
      saveAppliedPluginStatePin(
        { ...packageInfo, bundle_hash: null },
        application,
        { ...activation, bundle_hash: null },
        1234,
        saveStatePin,
      ),
    ).rejects.toThrow("plugin_bundle_hash_missing");
    await expect(
      saveAppliedPluginStatePin(packageInfo, application, undefined, 1234, saveStatePin),
    ).rejects.toThrow("plugin_activation_missing");

    expect(saveStatePin).not.toHaveBeenCalled();
  });
});

describe("savePromotedPluginStatePin", () => {
  it("persists a trust pin when promotion also applies the plugin runtime", async () => {
    const saveStatePin = vi.fn(async () => undefined);

    await savePromotedPluginStatePin(
      { package: packageInfo, application, activation },
      1234,
      saveStatePin,
    );

    expect(saveStatePin).toHaveBeenCalledWith({
      workspaceId: "workspace-one",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-one",
      latestEventHash: "approval-event-one",
      bundleHash: "bundle-hash-one",
      approvalEventHash: "approval-event-one",
      updatedAtMs: 1234,
    });
  });

  it("does not write a pin for package-only promotion responses", async () => {
    const saveStatePin = vi.fn(async () => undefined);

    await savePromotedPluginStatePin({ package: packageInfo }, 1234, saveStatePin);

    expect(saveStatePin).not.toHaveBeenCalled();
  });
});

describe("saveRuntimeDescriptorPluginStatePin", () => {
  it("persists the approved runtime descriptor state for the current activation", async () => {
    const saveStatePin = vi.fn(async () => undefined);

    await saveRuntimeDescriptorPluginStatePin(
      {
        pluginId: "plugin.example",
        packageId: "package-one",
        applicationId: "application-one",
        activationId: "activation-one",
        ownerScopeKind: "workspace",
        applicationScopeKind: "workspace",
        workspaceId: "workspace-one",
        userId: "user-one",
        deviceId: "device-one",
        stateHeadHash: "approval-event-one",
        consentHeadHash: "consent-event-one",
        bundleHash: "bundle-hash-one",
        approvalEventHash: "approval-event-one",
        capabilityGrantId: "capability-one",
      },
      1234,
      saveStatePin,
    );

    expect(saveStatePin).toHaveBeenCalledWith({
      workspaceId: "workspace-one",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-one",
      latestEventHash: "approval-event-one",
      bundleHash: "bundle-hash-one",
      approvalEventHash: "approval-event-one",
      updatedAtMs: 1234,
    });
  });
});

describe("saveApplicationActivationPluginStatePin", () => {
  it("persists state from an installed application and current activation", async () => {
    const saveStatePin = vi.fn(async () => undefined);

    await saveApplicationActivationPluginStatePin(application, activation, 1234, saveStatePin);

    expect(saveStatePin).toHaveBeenCalledWith({
      workspaceId: "workspace-one",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-one",
      latestEventHash: "approval-event-one",
      bundleHash: "bundle-hash-one",
      approvalEventHash: "approval-event-one",
      updatedAtMs: 1234,
    });
  });
});

describe("purgeDeletedActivationLocalData", () => {
  it("uses activation cleanup metadata when the application is not in the current workspace map", async () => {
    const purge = vi.fn(async () => undefined);

    await purgeDeletedActivationLocalData(
      {
        ...activation,
        application_id: "application-workspace-two",
        workspace_id: "workspace-two",
        package_id: "package-two",
      },
      undefined,
      "device-one",
      purge,
    );

    expect(purge).toHaveBeenCalledWith({
      workspaceId: "workspace-two",
      packageId: "package-two",
      applicationId: "application-workspace-two",
      activationId: "activation-one",
      userId: "user-one",
      deviceId: "device-one",
    });
  });

  it("falls back to application metadata and rejects incomplete cleanup context", async () => {
    const purge = vi.fn(async () => undefined);

    await purgeDeletedActivationLocalData(
      {
        ...activation,
        workspace_id: null,
        package_id: null,
      },
      application,
      "device-one",
      purge,
    );

    expect(purge).toHaveBeenCalledWith({
      workspaceId: "workspace-one",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-one",
      userId: "user-one",
      deviceId: "device-one",
    });

    await expect(
      purgeDeletedActivationLocalData(
        {
          ...activation,
          workspace_id: null,
          package_id: null,
        },
        undefined,
        "device-one",
        purge,
      ),
    ).rejects.toThrow("plugin_activation_cleanup_context_missing");
  });
});

describe("purgeDeletedApplicationLocalData", () => {
  it("purges local data for each current-device activation on application deletion", async () => {
    const purge = vi.fn(async () => undefined);

    await purgeDeletedApplicationLocalData(
      application,
      [
        activation,
        {
          ...activation,
          id: "activation-two",
          application_id: "other-application",
        },
      ],
      "device-one",
      purge,
    );

    expect(purge).toHaveBeenCalledTimes(1);
    expect(purge).toHaveBeenCalledWith({
      workspaceId: "workspace-one",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-one",
      userId: "user-one",
      deviceId: "device-one",
    });
  });

  it("uses activation device metadata and rejects incomplete cleanup context", async () => {
    const purge = vi.fn(async () => undefined);

    await purgeDeletedApplicationLocalData(
      application,
      [{ ...activation, device_id: "activation-device" }],
      undefined,
      purge,
    );

    expect(purge).toHaveBeenCalledWith({
      workspaceId: "workspace-one",
      packageId: "package-one",
      applicationId: "application-one",
      activationId: "activation-one",
      userId: "user-one",
      deviceId: "activation-device",
    });

    await expect(
      purgeDeletedApplicationLocalData(
        application,
        [{ ...activation, device_id: null }],
        undefined,
        purge,
      ),
    ).rejects.toThrow("plugin_application_cleanup_context_missing");
  });
});

describe("scopeChoiceLabel", () => {
  it("uses user-facing ownership choices instead of internal owner-scope labels", () => {
    expect(scopeChoiceLabel("user")).toBe("Use for myself");
    expect(scopeChoiceLabel("workspace")).toBe("Share with workspace");
  });
});
