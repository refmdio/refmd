import { createRoot } from "solid-js";
import { afterEach, describe, expect, it, vi } from "vitest";
import { setCurrentWorkspaceId } from "@/entities/workspace";
import { workspaceManager } from "@/features/panel";
import type { App } from "@/shared/lib/workspace/app";
import {
  hydrateCorePluginPreferences,
  loadCorePlugins,
  syncCorePlugins,
  unloadCorePlugins,
} from "@/features/plugin-runtime";
import { useCorePluginLifecycle } from "./use-core-plugin-lifecycle";

const pluginRuntime = vi.hoisted(() => ({
  hydrateCorePluginPreferences: vi.fn(),
  loadCorePlugins: vi.fn(),
  registerCorePlugins: vi.fn(),
  syncCorePlugins: vi.fn(),
  unloadCorePlugins: vi.fn(),
}));

vi.mock("@/features/plugin-runtime", () => pluginRuntime);
vi.mock("@/app/core-plugins/command-palette/index", () => ({
  loadCommandPalette: vi.fn(),
  unloadCommandPalette: vi.fn(),
}));
vi.mock("@/app/core-plugins/document-tree/index", () => ({
  loadDocumentTree: vi.fn(),
  unloadDocumentTree: vi.fn(),
}));
vi.mock("@/app/core-plugins/word-count/index", () => ({
  loadWordCount: vi.fn(),
  unloadWordCount: vi.fn(),
}));

const EDITOR_COMMAND_IDS = [
  "editor:switch-mode",
  "editor:split-horizontal",
  "editor:split-vertical",
  "editor:close-panel",
  "editor:switch-to-split",
];

function documentWorkspace() {
  return {
    focusedPanelId: vi.fn(() => "panel-1"),
    switchPanelType: vi.fn(),
    splitPanel: vi.fn(),
    closePanel: vi.fn(),
    switchToSplit: vi.fn(),
  };
}

function editorCommands() {
  return workspaceManager
    .listCommands()
    .filter((command) => EDITOR_COMMAND_IDS.includes(command.id));
}

describe("core plugin lifecycle", () => {
  afterEach(() => {
    setCurrentWorkspaceId(null);
    workspaceManager.reset();
    vi.clearAllMocks();
  });

  it("registers built-in editor commands with workspace-scoped owners", async () => {
    vi.mocked(hydrateCorePluginPreferences).mockResolvedValue(undefined);
    const app = { workspace: workspaceManager } as unknown as App;
    let dispose: (() => void) | undefined;

    createRoot((disposeRoot) => {
      dispose = disposeRoot;
      useCorePluginLifecycle(app, documentWorkspace() as never);
    });

    setCurrentWorkspaceId("workspace-alpha");

    await vi.waitFor(() => expect(editorCommands()).toHaveLength(5));

    for (const command of editorCommands()) {
      expect(command.owner).toMatchObject({
        kind: "built_in",
        workspaceId: "workspace-alpha",
        ownerId: "editor",
      });
      expect(command.owner.kind).toBe("built_in");
      if (command.owner.kind === "built_in") {
        expect(command.owner.generation).toEqual(expect.any(Number));
      }
    }

    await vi.waitFor(() => expect(loadCorePlugins).toHaveBeenCalledWith(app, "workspace-alpha"));

    setCurrentWorkspaceId("workspace-beta");

    await vi.waitFor(() => {
      expect(editorCommands()).toHaveLength(5);
      expect(
        editorCommands().every((command) => command.owner.workspaceId === "workspace-beta"),
      ).toBe(true);
    });
    expect(syncCorePlugins).toHaveBeenCalledWith(app, "workspace-beta");

    dispose?.();

    expect(editorCommands()).toEqual([]);
    expect(unloadCorePlugins).toHaveBeenCalled();
  });

  it("removes built-in editor commands when workspace lifecycle unloads", async () => {
    vi.mocked(hydrateCorePluginPreferences).mockResolvedValue(undefined);
    const app = { workspace: workspaceManager } as unknown as App;
    let dispose: (() => void) | undefined;

    createRoot((disposeRoot) => {
      dispose = disposeRoot;
      useCorePluginLifecycle(app, documentWorkspace() as never);
    });

    setCurrentWorkspaceId("workspace-alpha");
    await vi.waitFor(() => expect(editorCommands()).toHaveLength(5));
    await vi.waitFor(() => expect(loadCorePlugins).toHaveBeenCalledWith(app, "workspace-alpha"));

    setCurrentWorkspaceId(null);

    await vi.waitFor(() => expect(editorCommands()).toEqual([]));
    expect(unloadCorePlugins).toHaveBeenCalled();

    dispose?.();
  });
});
