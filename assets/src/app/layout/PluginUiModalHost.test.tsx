import { render } from "solid-js/web";
import { afterEach, describe, expect, it } from "vite-plus/test";
import { PluginUiModalHost } from "./PluginUiModalHost";
import {
  closePluginUiModal,
  getDefaultPluginUiContributionRegistry,
  openPluginUiModal,
  pluginUiCommandId,
  pluginUiOwnerSurfaceId,
  setPluginUiModalIframeSurface,
} from "@/features/plugin-runtime";
import type { PluginHostRpcHandlerOwnerDescriptor } from "@/features/plugin-runtime";
import { workspaceManager } from "@/features/panel";

const owner: PluginHostRpcHandlerOwnerDescriptor = {
  pluginId: "plugin.example",
  packageId: "package-one",
  workspaceId: "workspace-one",
  applicationId: "00000000-0000-4000-8000-000000000001",
  activationId: "activation-one",
  ownerScopeKind: "workspace",
  userId: "user-one",
  deviceId: "device-one",
  bundleHash: "bundle-hash-one",
  manifestHash: "manifest-hash-one",
  frameGeneration: 1,
  consentEpoch: 1,
  capabilityGrantId: "capability-grant-one",
};

describe("PluginUiModalHost", () => {
  afterEach(() => {
    closePluginUiModal();
    document.body.replaceChildren();
  });

  it("mounts declarative iframe modal bodies through the managed iframe surface", async () => {
    const registry = getDefaultPluginUiContributionRegistry();
    registry.register(owner, {
      surface: "command",
      local_id: "open.modal",
      title: "Open modal",
    });
    const modalId = registry.register(owner, {
      surface: "declarative_modal",
      local_id: "modal.frame",
      modal_id: "modal.frame",
      title: "Plugin modal",
      trigger_command_ref: { kind: "local_command", local_id: "open.modal" },
      body: { kind: "iframe", iframe_panel_id: "modal.frame" },
    });
    const mounts: Array<{ id: string; surface: string; title: string }> = [];
    const unmounts: string[] = [];
    const releaseSurface = setPluginUiModalIframeSurface(owner, {
      mount(options) {
        mounts.push({ id: options.id, surface: options.surface, title: options.title });
      },
      unmount(id) {
        unmounts.push(id);
      },
    });
    const root = document.createElement("div");
    document.body.append(root);
    const dispose = render(() => <PluginUiModalHost />, root);

    openPluginUiModal(modalId);
    await Promise.resolve();

    expect(mounts).toEqual([
      {
        id: pluginUiOwnerSurfaceId(owner, "modal.frame"),
        surface: "declarative_modal",
        title: "Plugin modal",
      },
    ]);

    closePluginUiModal();
    dispose();
    releaseSurface();
    registry.clearOwner(owner);

    expect(unmounts).toContain(pluginUiOwnerSurfaceId(owner, "modal.frame"));
  });

  it("submits schema form values to the owner command", async () => {
    const registry = getDefaultPluginUiContributionRegistry();
    registry.register(owner, {
      surface: "command",
      local_id: "save.modal",
      title: "Save modal",
    });
    const modalId = registry.register(owner, {
      surface: "declarative_modal",
      local_id: "modal.form",
      modal_id: "modal.form",
      title: "Plugin modal",
      trigger_command_ref: { kind: "local_command", local_id: "save.modal" },
      submit_command_ref: { kind: "local_command", local_id: "save.modal" },
      body: {
        kind: "schema_form",
        fields: [
          { kind: "text", name: "title", label: "Title", max_length: 80 },
          { kind: "textarea", name: "notes", label: "Notes", max_length: 200 },
          { kind: "checkbox", name: "enabled", label: "Enabled" },
          {
            kind: "select",
            name: "tone",
            label: "Tone",
            options: [
              { value: "info", label: "Info" },
              { value: "warning", label: "Warning" },
            ],
          },
        ],
      },
    });
    const entry = registry.list("declarative_modal").find((candidate) => candidate.id === modalId);
    expect(entry).toBeTruthy();
    const commandId = pluginUiCommandId(entry!, { kind: "local_command", local_id: "save.modal" });
    const payloads: unknown[] = [];
    workspaceManager.addCommand({
      id: commandId,
      name: "Save modal",
      owner: { kind: "third_party", ...owner, manifestHash: owner.manifestHash ?? "" },
      callback(payload) {
        payloads.push(payload);
      },
    });
    const root = document.createElement("div");
    document.body.append(root);
    const dispose = render(() => <PluginUiModalHost />, root);

    openPluginUiModal(modalId);
    await Promise.resolve();
    const title = document.querySelector<HTMLInputElement>('input[name="title"]');
    const notes = document.querySelector<HTMLTextAreaElement>('textarea[name="notes"]');
    const enabled = document.querySelector<HTMLInputElement>('input[name="enabled"]');
    const tone = document.querySelector<HTMLSelectElement>('select[name="tone"]');
    expect(title).toBeTruthy();
    expect(notes).toBeTruthy();
    expect(enabled).toBeTruthy();
    expect(tone).toBeTruthy();
    title!.value = "Roadmap";
    notes!.value = "Ship the plugin";
    enabled!.checked = true;
    tone!.value = "warning";

    document.querySelectorAll("button").forEach((button) => {
      if (button.textContent === "Submit") button.click();
    });

    expect(payloads).toEqual([
      {
        modal_id: "modal.form",
        values: {
          title: "Roadmap",
          notes: "Ship the plugin",
          enabled: true,
          tone: "warning",
        },
      },
    ]);

    dispose();
    workspaceManager.removeCommand(commandId);
    registry.clearOwner(owner);
  });
});
