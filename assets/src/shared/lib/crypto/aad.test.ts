import { describe, expect, it } from "vitest";
import { buildPluginStorageAad } from "./aad";
import { canonicalizeStrictValueBytes } from "./jcs";

describe("AAD builders", () => {
  it("builds plugin synced-storage AAD with the stable storage contract shape", () => {
    expect(
      buildPluginStorageAad({
        scope: "document",
        workspaceId: "workspace-one",
        packageId: "package-one",
        applicationId: "application-one",
        activationId: "activation-one",
        pluginId: "com.example.plugin",
        scopeId: "document-one",
        key: "index",
      }),
    ).toEqual(
      canonicalizeStrictValueBytes({
        protocol: "refmd",
        version: 1,
        purpose: "plugin_data",
        plugin_id: "com.example.plugin",
        package_id: "package-one",
        application_id: "application-one",
        activation_id: "activation-one",
        workspace_id: "workspace-one",
        scope: "document",
        scope_id: "document-one",
        key: "index",
      }),
    );
  });
});
