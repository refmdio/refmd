import { afterEach, describe, expect, it, vi } from "vite-plus/test";
import * as Y from "yjs";
import { Awareness } from "y-protocols/awareness";
import { EditorState } from "prosemirror-state";
import { EditorView } from "prosemirror-view";
import { getDefaultPluginRendererSlotRegistry } from "@/features/plugin-runtime";
import { markdownSchema } from "./schema";
import { setupCollabPlugins } from "./plugin-collab";
import { pluginRendererSlotPlugin } from "./plugin-renderer-slots";
import { proseMirrorDocToMarkdown } from "./markdown-to";

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

afterEach(async () => {
  await flushMicrotasks();
  for (const cleanup of cleanupFns.splice(0).reverse()) cleanup();
  await flushMicrotasks();
});

function flushMicrotasks(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

function createContainer(): HTMLElement {
  const container = document.createElement("div");
  document.body.append(container);
  cleanupFns.push(() => container.remove());
  return container;
}

describe("plugin renderer ProseMirror slots", () => {
  it("mounts a Host-owned renderer slot for matching code block language", async () => {
    const mounted = { dispose: vi.fn() };
    const mount = vi.fn(() => mounted);
    cleanupFns.push(
      getDefaultPluginRendererSlotRegistry().register(
        owner,
        [{ kind: "block", type: "diagram" }],
        mount,
      ),
    );
    const container = createContainer();
    const view = new EditorView(container, {
      state: EditorState.create({
        doc: markdownSchema.node("doc", null, [
          markdownSchema.nodes.code_block.create(
            { language: "diagram" },
            markdownSchema.text("source: alpha"),
          ),
        ]),
        plugins: [
          pluginRendererSlotPlugin({ documentId: "document-1", workspaceId: "workspace-1" }),
        ],
      }),
    });
    cleanupFns.push(() => view.destroy());
    await flushMicrotasks();

    expect(mount).toHaveBeenCalledWith(
      expect.objectContaining({
        slot: { kind: "block", type: "diagram" },
        workspaceId: "workspace-1",
        documentId: "document-1",
        source: "source: alpha",
      }),
    );
    expect(container.querySelector(".refmd-plugin-renderer-slot")).toBeInstanceOf(HTMLElement);
    expect(container.querySelector("pre code")?.textContent).toBe("source: alpha");
    expect(proseMirrorDocToMarkdown(view.state.doc)).toContain("source: alpha");

    view.destroy();
    expect(mounted.dispose).toHaveBeenCalled();
  });

  it("keeps an existing block renderer mounted across unrelated registry updates", async () => {
    const mounted = { dispose: vi.fn() };
    const mount = vi.fn(() => mounted);
    cleanupFns.push(
      getDefaultPluginRendererSlotRegistry().register(
        owner,
        [{ kind: "block", type: "diagram" }],
        mount,
      ),
    );
    const container = createContainer();
    const view = new EditorView(container, {
      state: EditorState.create({
        doc: markdownSchema.node("doc", null, [
          markdownSchema.nodes.code_block.create(
            { language: "diagram" },
            markdownSchema.text("source: alpha"),
          ),
        ]),
        plugins: [
          pluginRendererSlotPlugin({ documentId: "document-1", workspaceId: "workspace-1" }),
        ],
      }),
    });
    cleanupFns.push(() => view.destroy());
    await flushMicrotasks();

    expect(mount).toHaveBeenCalledTimes(1);

    const otherMounted = { dispose: vi.fn() };
    const unregisterOther = getDefaultPluginRendererSlotRegistry().register(
      {
        ...owner,
        pluginId: "plugin.other",
        packageId: "package-2",
        applicationId: "application-2",
        activationId: "activation-2",
      },
      [{ kind: "block", type: "other" }],
      vi.fn(() => otherMounted),
    );
    cleanupFns.push(unregisterOther);
    await flushMicrotasks();

    expect(mount).toHaveBeenCalledTimes(1);
    expect(mounted.dispose).not.toHaveBeenCalled();
  });

  it("falls back to a normal code block when no renderer slot matches", () => {
    const container = createContainer();
    const view = new EditorView(container, {
      state: EditorState.create({
        doc: markdownSchema.node("doc", null, [
          markdownSchema.nodes.code_block.create(
            { language: "plain" },
            markdownSchema.text("plain code"),
          ),
        ]),
        plugins: [
          pluginRendererSlotPlugin({ documentId: "document-1", workspaceId: "workspace-1" }),
        ],
      }),
    });
    cleanupFns.push(() => view.destroy());

    expect(container.querySelector(".refmd-plugin-renderer-slot")).toBeNull();
    expect(container.querySelector("pre code")?.textContent).toBe("plain code");
  });

  it("falls back to a normal code block for forbidden or invalid renderer languages", () => {
    for (const language of ["markdown", "md", "full-document", "PlantUML"]) {
      const container = createContainer();
      let view: EditorView | null = null;

      expect(() => {
        view = new EditorView(container, {
          state: EditorState.create({
            doc: markdownSchema.node("doc", null, [
              markdownSchema.nodes.code_block.create(
                { language },
                markdownSchema.text(`${language} code`),
              ),
            ]),
            plugins: [
              pluginRendererSlotPlugin({ documentId: "document-1", workspaceId: "workspace-1" }),
            ],
          }),
        });
      }).not.toThrow();

      if (view) cleanupFns.push(() => view?.destroy());
      expect(container.querySelector(".refmd-plugin-renderer-slot")).toBeNull();
      expect(container.querySelector("pre code")?.textContent).toBe(`${language} code`);
    }
  });

  it("does not replace source block ownership with renderer DOM", async () => {
    cleanupFns.push(
      getDefaultPluginRendererSlotRegistry().register(
        owner,
        [{ kind: "block", type: "diagram" }],
        vi.fn(() => ({ dispose: vi.fn() })),
      ),
    );
    const container = createContainer();
    const view = new EditorView(container, {
      state: EditorState.create({
        doc: markdownSchema.node("doc", null, [
          markdownSchema.nodes.code_block.create(
            { language: "diagram" },
            markdownSchema.text("source: alpha\ntarget: rendered-output"),
          ),
        ]),
        plugins: [
          pluginRendererSlotPlugin({ documentId: "document-1", workspaceId: "workspace-1" }),
        ],
      }),
    });
    cleanupFns.push(() => view.destroy());

    await flushMicrotasks();

    expect(container.querySelector(".refmd-plugin-renderer-block-slot")).toBeInstanceOf(
      HTMLElement,
    );
    expect(container.querySelector(".refmd-plugin-renderer-source-hidden")).toBeInstanceOf(
      HTMLElement,
    );
    expect(container.querySelector("pre code")?.textContent).toContain("rendered-output");
    expect(proseMirrorDocToMarkdown(view.state.doc)).toContain("rendered-output");
  });

  it("mounts a Host-owned inline renderer slot for inline code while hiding source text", async () => {
    const mounted = { dispose: vi.fn() };
    const mount = vi.fn(() => mounted);
    cleanupFns.push(
      getDefaultPluginRendererSlotRegistry().register(
        owner,
        [{ kind: "inline", type: "code" }],
        mount,
      ),
    );
    const container = createContainer();
    const view = new EditorView(container, {
      state: EditorState.create({
        doc: markdownSchema.node("doc", null, [
          markdownSchema.nodes.paragraph.create(null, [
            markdownSchema.text("before "),
            markdownSchema.text("status:ok", [markdownSchema.marks.code.create()]),
            markdownSchema.text(" after"),
          ]),
        ]),
        plugins: [
          pluginRendererSlotPlugin({ documentId: "document-1", workspaceId: "workspace-1" }),
        ],
      }),
    });
    cleanupFns.push(() => view.destroy());

    await flushMicrotasks();

    expect(mount).toHaveBeenCalledWith(
      expect.objectContaining({
        slot: { kind: "inline", type: "code" },
        workspaceId: "workspace-1",
        documentId: "document-1",
        source: "status:ok",
      }),
    );
    expect(container.querySelector(".refmd-plugin-renderer-inline-slot")).toBeInstanceOf(
      HTMLElement,
    );
    const hiddenSource = container.querySelector(".refmd-plugin-renderer-source-hidden");
    expect(hiddenSource).toBeInstanceOf(HTMLElement);
    expect(hiddenSource?.textContent).toBe("status:ok");
    expect(proseMirrorDocToMarkdown(view.state.doc)).toContain("`status:ok`");

    view.destroy();
    expect(mounted.dispose).toHaveBeenCalled();
  });

  it("falls back to normal inline code when no inline renderer slot matches", async () => {
    const container = createContainer();
    const view = new EditorView(container, {
      state: EditorState.create({
        doc: markdownSchema.node("doc", null, [
          markdownSchema.nodes.paragraph.create(null, [
            markdownSchema.text("plain ", [markdownSchema.marks.code.create()]),
          ]),
        ]),
        plugins: [
          pluginRendererSlotPlugin({ documentId: "document-1", workspaceId: "workspace-1" }),
        ],
      }),
    });
    cleanupFns.push(() => view.destroy());

    await flushMicrotasks();

    expect(container.querySelector(".refmd-plugin-renderer-inline-slot")).toBeNull();
    expect(container.querySelector("code")?.textContent).toBe("plain ");
  });

  it("preserves rendered code block content while syncing shared markdown text", async () => {
    const mounted = { dispose: vi.fn() };
    cleanupFns.push(
      getDefaultPluginRendererSlotRegistry().register(
        owner,
        [{ kind: "block", type: "diagram" }],
        vi.fn(() => mounted),
      ),
    );
    const yDoc = new Y.Doc();
    const awareness = new Awareness(yDoc);
    const collab = setupCollabPlugins({
      yDoc,
      schema: markdownSchema,
      awareness,
    });
    const container = createContainer();
    let collabDestroyed = false;
    const view = new EditorView(container, {
      state: EditorState.create({
        doc: collab.doc,
        plugins: [
          ...collab.plugins,
          pluginRendererSlotPlugin({ documentId: "document-1", workspaceId: "workspace-1" }),
        ],
      }),
    });
    cleanupFns.push(() => {
      if (!collabDestroyed) collab.destroy();
    });

    const markdown = [
      "# Renderer Slot Check",
      "",
      "```diagram",
      "source: alpha",
      "target: rendered-output",
      "```",
      "",
    ].join("\n");

    const yText = yDoc.getText("content");
    yDoc.transact(() => {
      yText.insert(0, markdown);
    });
    await flushMicrotasks();
    await flushMicrotasks();

    expect(proseMirrorDocToMarkdown(view.state.doc)).toContain("rendered-output");
    expect(yText.toJSON()).toContain("rendered-output");
    await flushMicrotasks();
    collab.destroy();
    collabDestroyed = true;
    await flushMicrotasks();
  });

  it("preserves code block content when the ProseMirror bridge boots from shared markdown text", () => {
    const yDoc = new Y.Doc();
    const yText = yDoc.getText("content");
    const markdown = [
      "# Renderer Slot Check",
      "",
      "```diagram",
      "source: alpha",
      "target: rendered-output",
      "```",
      "",
    ].join("\n");
    yText.insert(0, markdown);

    const collab = setupCollabPlugins({
      yDoc,
      schema: markdownSchema,
      awareness: new Awareness(yDoc),
    });
    cleanupFns.push(() => collab.destroy());

    expect(proseMirrorDocToMarkdown(collab.doc)).toContain("rendered-output");
    expect(yText.toJSON()).toContain("rendered-output");
  });
});
