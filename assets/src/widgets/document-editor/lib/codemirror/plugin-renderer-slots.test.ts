import { EditorState } from "@codemirror/state";
import { EditorView } from "@codemirror/view";
import { markdown } from "@codemirror/lang-markdown";
import { afterEach, describe, expect, it, vi } from "vite-plus/test";
import {
  getDefaultPluginRendererSlotRegistry,
  type PluginRendererMountParams,
} from "@/features/plugin-runtime";
import { pluginRendererSlotExtension } from "./plugin-renderer-slots";

const owner = {
  pluginId: "plugin.example",
  packageId: "package-1",
  workspaceId: "workspace-1",
  applicationId: "application-1",
  activationId: "activation-1",
  ownerScopeKind: "workspace",
  userId: "user-1",
  deviceId: "device-1",
  bundleHash: "bundle-hash-1",
  manifestHash: "manifest-hash-1",
  frameGeneration: 1,
  consentEpoch: 1,
  capabilityGrantId: "grant-1",
};

const cleanupFns: (() => void)[] = [];

afterEach(() => {
  for (const cleanup of cleanupFns.splice(0).reverse()) cleanup();
});

function createContainer(): HTMLElement {
  const container = document.createElement("div");
  document.body.append(container);
  cleanupFns.push(() => container.remove());
  return container;
}

function createView(doc: string): EditorView {
  const container = createContainer();
  const view = new EditorView({
    state: EditorState.create({
      doc,
      extensions: [
        markdown(),
        pluginRendererSlotExtension({ documentId: "document-1", workspaceId: "workspace-1" }),
      ],
    }),
    parent: container,
  });
  let destroyed = false;
  cleanupFns.push(() => {
    if (!destroyed) view.destroy();
  });
  const destroy = view.destroy.bind(view);
  view.destroy = () => {
    destroyed = true;
    destroy();
  };
  return view;
}

describe("plugin renderer CodeMirror slots", () => {
  it("mounts Host-owned block and inline renderer widgets while replacing visible markdown source", () => {
    const disposers: Array<ReturnType<typeof vi.fn>> = [];
    const mount = vi.fn((params: PluginRendererMountParams) => {
      const dispose = vi.fn();
      disposers.push(dispose);
      params.container.textContent = `rendered:${params.source}`;
      return { dispose };
    });
    cleanupFns.push(
      getDefaultPluginRendererSlotRegistry().register(
        owner,
        [
          { kind: "block", type: "diagram" },
          { kind: "inline", type: "code" },
        ],
        mount,
      ),
    );

    const view = createView(
      ["Inline `status:ok` value.", "", "```diagram", "source: alpha", "```", ""].join("\n"),
    );

    expect(mount).toHaveBeenCalledWith(
      expect.objectContaining({
        slot: { kind: "inline", type: "code" },
        workspaceId: "workspace-1",
        documentId: "document-1",
        source: "status:ok",
      }),
    );
    expect(mount).toHaveBeenCalledWith(
      expect.objectContaining({
        slot: { kind: "block", type: "diagram" },
        workspaceId: "workspace-1",
        documentId: "document-1",
        source: "source: alpha",
      }),
    );
    expect(document.querySelector(".refmd-plugin-renderer-inline-slot")).toBeInstanceOf(
      HTMLElement,
    );
    expect(document.querySelector(".refmd-plugin-renderer-block-slot")).toBeInstanceOf(HTMLElement);
    const hiddenSourceLines = Array.from(
      view.dom.querySelectorAll(".cm-line.refmd-plugin-renderer-source-hidden"),
    );
    expect(hiddenSourceLines.map((line) => line.textContent).join("\n")).toContain(
      "```diagram\nsource: alpha",
    );
    const visibleEditorText = Array.from(view.dom.querySelectorAll(".cm-line"))
      .filter((line) => !line.classList.contains("refmd-plugin-renderer-source-hidden"))
      .map((line) => line.textContent ?? "")
      .join("\n");
    expect(visibleEditorText).toContain("rendered:status:ok");
    expect(visibleEditorText).toContain("rendered:source: alpha");
    expect(visibleEditorText).not.toContain("`status:ok`");
    expect(visibleEditorText).not.toContain("```diagram");
    expect(view.state.doc.toString()).toContain("```diagram\nsource: alpha\n```");

    view.destroy();
    expect(disposers).toHaveLength(2);
    for (const dispose of disposers) expect(dispose).toHaveBeenCalledOnce();
  });

  it("falls back to normal markdown source when no renderer slot matches", () => {
    const view = createView(["`plain`", "", "```plain", "plain code", "```"].join("\n"));

    expect(document.querySelector(".refmd-plugin-renderer-slot")).toBeNull();
    expect(view.state.doc.toString()).toContain("plain code");
  });
});
