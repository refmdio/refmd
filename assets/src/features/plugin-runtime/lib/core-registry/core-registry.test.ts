import { afterEach, describe, expect, it, vi } from "vitest";
import type { App } from "@/shared/lib/workspace/app";
import {
  hydrateCorePluginPreferences,
  isCorePluginEnabled,
  loadCorePlugins,
  registerCorePlugins,
  setCorePluginEnabled,
  syncCorePlugins,
  unloadCorePlugins,
} from "./core-registry";

const cryptoWorker = vi.hoisted(() => ({
  loadStoredDsk: vi.fn(),
  loadUiStateWithDsk: vi.fn(),
  storeUiStateWithDsk: vi.fn(),
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: () => cryptoWorker,
}));

const app = {} as App;

describe("core plugin registry", () => {
  afterEach(() => {
    unloadCorePlugins();
    vi.clearAllMocks();
  });

  it("keeps loaded core plugin state scoped to the active workspace", () => {
    const events: string[] = [];
    registerCorePlugins([
      {
        id: "documents",
        name: "Documents",
        description: "Documents",
        defaultEnabled: true,
        load: () => events.push("load"),
        unload: () => events.push("unload"),
      },
    ]);

    loadCorePlugins(app, "workspace-one");
    loadCorePlugins(app, "workspace-one");
    syncCorePlugins(app, "workspace-two");

    expect(events).toEqual(["load", "unload", "load"]);

    unloadCorePlugins("workspace-two");
    expect(events).toEqual(["load", "unload", "load", "unload"]);
  });

  it("hydrates core plugin preferences from Host-managed encrypted local state", async () => {
    cryptoWorker.loadStoredDsk.mockResolvedValue(true);
    cryptoWorker.loadUiStateWithDsk.mockResolvedValue(
      new TextEncoder().encode(
        JSON.stringify({
          protocol: "refmd.core-plugin-preferences",
          version: 1,
          disabled: ["documents"],
          enabled: ["outline"],
        }),
      ),
    );

    registerCorePlugins([
      {
        id: "documents",
        name: "Documents",
        description: "Documents",
        defaultEnabled: true,
        load: vi.fn(),
        unload: vi.fn(),
      },
      {
        id: "outline",
        name: "Outline",
        description: "Outline",
        defaultEnabled: false,
        load: vi.fn(),
        unload: vi.fn(),
      },
    ]);

    await hydrateCorePluginPreferences("workspace-hydrate");

    expect(isCorePluginEnabled("documents", "workspace-hydrate")).toBe(false);
    expect(isCorePluginEnabled("outline", "workspace-hydrate")).toBe(true);
    expect(cryptoWorker.loadUiStateWithDsk).toHaveBeenCalledWith({
      storageKey: "refmd-core-plugins:workspace-hydrate",
      aadRecord: {
        kind: "core_plugin_preferences",
        workspace_id: "workspace-hydrate",
      },
    });
  });

  it("persists core plugin preference changes through Host-managed encrypted local state", async () => {
    cryptoWorker.loadStoredDsk.mockResolvedValue(true);
    cryptoWorker.storeUiStateWithDsk.mockResolvedValue(undefined);

    registerCorePlugins([
      {
        id: "documents",
        name: "Documents",
        description: "Documents",
        defaultEnabled: true,
        load: vi.fn(),
        unload: vi.fn(),
      },
    ]);

    setCorePluginEnabled("documents", "workspace-save", false, app);
    await vi.waitFor(() => expect(cryptoWorker.storeUiStateWithDsk).toHaveBeenCalledTimes(1));

    const call = cryptoWorker.storeUiStateWithDsk.mock.calls[0]?.[0];
    expect(call).toMatchObject({
      storageKey: "refmd-core-plugins:workspace-save",
      aadRecord: {
        kind: "core_plugin_preferences",
        workspace_id: "workspace-save",
      },
    });
    expect(JSON.parse(new TextDecoder().decode(call.plaintext))).toEqual({
      protocol: "refmd.core-plugin-preferences",
      version: 1,
      disabled: ["documents"],
      enabled: [],
    });
  });
});
