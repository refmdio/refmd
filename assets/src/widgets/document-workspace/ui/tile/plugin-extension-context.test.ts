import { describe, expect, it } from "vitest";
import type {
  PluginEditorContributionEntry,
  PluginUiRegistryEntry,
} from "@/features/plugin-runtime";
import {
  createDocumentPluginResourceContext,
  createWorkspaceTilePluginResourceContext,
  pluginEditorContributionMatchesWorkspace,
  pluginUiEntryResourceContext,
} from "./plugin-extension-context";

function owner(workspaceId = "workspace-alpha") {
  return {
    pluginId: "plugin.example",
    packageId: "package.example",
    workspaceId,
    applicationId: "application.example",
    activationId: "activation.example",
    ownerScopeKind: "workspace" as const,
    userId: "user.example",
    deviceId: "device.example",
    bundleHash: "bundle-hash",
    manifestHash: "manifest-hash",
    frameGeneration: 1,
    consentEpoch: 1,
    capabilityGrantId: "capability-grant",
  };
}

function uiEntry(workspaceId = "workspace-alpha"): PluginUiRegistryEntry {
  return {
    id: "plugin:application.example:activation.example:menu.open",
    owner: owner(workspaceId),
    capabilities: ["document:read:active"],
    contribution: {
      surface: "menu_item",
      local_id: "menu.open",
      placement: "document_tab_menu",
      title: "Open",
      command_ref: { kind: "local_command", local_id: "open" },
    },
  };
}

function editorEntry(workspaceId = "workspace-alpha"): PluginEditorContributionEntry {
  return {
    owner: owner(workspaceId),
    session: null,
    descriptor: {
      kind: "diagnostics",
      id: "diagnostics",
      title: "Diagnostics",
      input: "editor_context",
    },
  };
}

describe("document workspace plugin extension context", () => {
  it("fails closed when document workspace identity is unavailable", () => {
    expect(
      createDocumentPluginResourceContext({
        workspaceId: null,
        documentId: "document-one",
        selectionPresent: false,
        capabilities: [],
      }),
    ).toBeNull();
    expect(
      createWorkspaceTilePluginResourceContext({
        workspaceId: undefined,
        documentId: "document-one",
        selectionPresent: false,
      }),
    ).toBeNull();
    expect(
      pluginUiEntryResourceContext(uiEntry(), {
        workspaceId: null,
        documentId: "document-one",
        selectionPresent: false,
      }),
    ).toBeNull();
    expect(pluginEditorContributionMatchesWorkspace(editorEntry(), null)).toBe(false);
  });

  it("binds document plugin contexts and editor entries to the proven workspace", () => {
    expect(
      pluginUiEntryResourceContext(uiEntry(), {
        workspaceId: "workspace-alpha",
        documentId: "document-one",
        selectionPresent: true,
      }),
    ).toEqual({
      resourceKind: "document",
      workspaceId: "workspace-alpha",
      documentId: "document-one",
      documentOpen: true,
      selectionPresent: true,
      capabilities: ["document:read:active"],
    });
    expect(
      pluginEditorContributionMatchesWorkspace(editorEntry("workspace-alpha"), "workspace-alpha"),
    ).toBe(true);
    expect(
      pluginEditorContributionMatchesWorkspace(editorEntry("workspace-beta"), "workspace-alpha"),
    ).toBe(false);
  });
});
