import { afterEach, describe, expect, it } from "vite-plus/test";
import { EditorState, TextSelection } from "prosemirror-state";
import { EditorView } from "prosemirror-view";
import * as Y from "yjs";
import { Awareness, applyAwarenessUpdate, encodeAwarenessUpdate } from "y-protocols/awareness";
import { ORIGIN_INIT, syncCmCursor } from "@pm-cm/yjs";
import { markdownToProseMirrorDoc } from "./markdown-from";
import { markdownSchema } from "./schema";
import { setupCollabPlugins } from "./plugin-collab";
import { createLocalProseMirrorBridgeDoc } from "./shared-text-bridge";

const cleanupFns: (() => void)[] = [];

function flushTimers(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

async function flushAwarenessDecorations(): Promise<void> {
  await flushTimers();
  await flushTimers();
}

function cleanupEditorView(view: EditorView): void {
  view.destroy();
  // y-prosemirror batches plugin meta updates with setTimeout and does not
  // cancel already queued callbacks when a test destroys the view.
  (view as unknown as { dispatch: (_tr: unknown) => void }).dispatch = () => {};
}

function createWysiwygView(sharedDoc: Y.Doc, awareness: Awareness): EditorView {
  const localBridgeDoc = createLocalProseMirrorBridgeDoc(sharedDoc);
  cleanupFns.push(localBridgeDoc.dispose);
  const collab = setupCollabPlugins({
    yDoc: localBridgeDoc.yDoc,
    schema: markdownSchema,
    awareness,
    cursorText: sharedDoc.getText("content"),
  });
  cleanupFns.push(collab.destroy);

  const container = document.createElement("div");
  document.body.append(container);
  const view = new EditorView(container, {
    state: EditorState.create({
      schema: markdownSchema,
      doc: collab.doc,
      plugins: collab.plugins,
    }),
  });
  cleanupFns.push(() => cleanupEditorView(view));
  return view;
}

afterEach(async () => {
  await flushAwarenessDecorations();
  for (const cleanup of cleanupFns.splice(0).reverse()) cleanup();
  document.body.replaceChildren();
});

describe("createLocalProseMirrorBridgeDoc", () => {
  it("keeps pm-cm ProseMirror XML out of the shared document", () => {
    const sharedDoc = new Y.Doc();
    cleanupFns.push(() => sharedDoc.destroy());
    sharedDoc.getText("content").insert(0, "# Title");

    const localBridgeDoc = createLocalProseMirrorBridgeDoc(sharedDoc);
    cleanupFns.push(localBridgeDoc.dispose);
    const awareness = new Awareness(localBridgeDoc.yDoc);
    cleanupFns.push(() => awareness.destroy());
    const collab = setupCollabPlugins({
      yDoc: localBridgeDoc.yDoc,
      schema: markdownSchema,
      awareness,
      cursorText: sharedDoc.getText("content"),
    });
    cleanupFns.push(collab.destroy);

    collab.bridge.syncToSharedText(
      markdownToProseMirrorDoc("# Title\n\nUpdated from WYSIWYG", markdownSchema),
    );

    expect(sharedDoc.getText("content").toJSON()).toContain("Updated from WYSIWYG");
    expect(sharedDoc.getXmlFragment("prosemirror").length).toBe(0);
    expect(localBridgeDoc.yDoc.getXmlFragment("prosemirror").length).toBeGreaterThan(0);
  });

  it("does not mirror pm-cm bootstrap text changes back to the shared document", () => {
    const sharedDoc = new Y.Doc();
    cleanupFns.push(() => sharedDoc.destroy());
    const originalMarkdown = "Initial shared text";
    sharedDoc.getText("content").insert(0, originalMarkdown);
    let sharedChangeCount = 0;
    sharedDoc.getText("content").observe(() => {
      sharedChangeCount++;
    });

    const localBridgeDoc = createLocalProseMirrorBridgeDoc(sharedDoc);
    cleanupFns.push(localBridgeDoc.dispose);
    localBridgeDoc.yDoc.transact(() => {
      localBridgeDoc.yText.delete(0, localBridgeDoc.yText.length);
      localBridgeDoc.yText.insert(0, "Bootstrap canonical text");
    }, ORIGIN_INIT);

    expect(localBridgeDoc.yText.toJSON()).toBe("Bootstrap canonical text");
    expect(sharedDoc.getText("content").toJSON()).toBe(originalMarkdown);
    expect(sharedChangeCount).toBe(0);
  });

  it("mirrors remote shared text changes into the local ProseMirror bridge", () => {
    const sharedDoc = new Y.Doc();
    cleanupFns.push(() => sharedDoc.destroy());
    sharedDoc.getText("content").insert(0, "Initial");

    const localBridgeDoc = createLocalProseMirrorBridgeDoc(sharedDoc);
    cleanupFns.push(localBridgeDoc.dispose);

    const sharedText = sharedDoc.getText("content");
    sharedDoc.transact(() => {
      sharedText.delete(0, sharedText.length);
      sharedText.insert(0, "Remote update");
    }, "remote");

    expect(localBridgeDoc.yText.toJSON()).toBe("Remote update");
  });

  it("does not render the local awareness client as a remote WYSIWYG cursor", async () => {
    const sharedDoc = new Y.Doc();
    cleanupFns.push(() => sharedDoc.destroy());
    sharedDoc.getText("content").insert(0, "Local cursor text");

    const localBridgeDoc = createLocalProseMirrorBridgeDoc(sharedDoc);
    cleanupFns.push(localBridgeDoc.dispose);
    const awareness = new Awareness(sharedDoc);
    cleanupFns.push(() => awareness.destroy());
    awareness.setLocalStateField("user", {
      name: "Local User",
      color: "#5b8def",
    });
    const collab = setupCollabPlugins({
      yDoc: localBridgeDoc.yDoc,
      schema: markdownSchema,
      awareness,
    });
    cleanupFns.push(collab.destroy);

    const container = document.createElement("div");
    document.body.append(container);
    const view = new EditorView(container, {
      state: EditorState.create({
        schema: markdownSchema,
        doc: collab.doc,
        plugins: collab.plugins,
      }),
    });
    cleanupFns.push(() => cleanupEditorView(view));

    syncCmCursor(view, 1);
    await flushAwarenessDecorations();

    expect(awareness.clientID).not.toBe(localBridgeDoc.yDoc.clientID);
    expect(container.querySelector(".ProseMirror-yjs-cursor")).toBeNull();

    awareness.setLocalStateField("pmCursor", null);
    await flushAwarenessDecorations();
  });

  it("renders same-user remote WYSIWYG cursor from another device", async () => {
    const sharedDoc = new Y.Doc();
    cleanupFns.push(() => sharedDoc.destroy());
    sharedDoc.getText("content").insert(0, "Cross-mode cursor text");

    const receiverAwareness = new Awareness(sharedDoc);
    cleanupFns.push(() => receiverAwareness.destroy());
    receiverAwareness.setLocalStateField("user", {
      userId: "same-user",
      name: "Same User",
      color: "#5b8def",
    });
    const receiverView = createWysiwygView(sharedDoc, receiverAwareness);

    const senderSharedDoc = new Y.Doc();
    cleanupFns.push(() => senderSharedDoc.destroy());
    Y.applyUpdate(senderSharedDoc, Y.encodeStateAsUpdate(sharedDoc));
    const senderAwareness = new Awareness(senderSharedDoc);
    cleanupFns.push(() => senderAwareness.destroy());
    senderAwareness.setLocalStateField("user", {
      userId: "same-user",
      name: "Same User",
      color: "#5b8def",
    });
    const senderView = createWysiwygView(senderSharedDoc, senderAwareness);

    syncCmCursor(senderView, 1);
    await flushAwarenessDecorations();

    const update = encodeAwarenessUpdate(senderAwareness, [senderAwareness.clientID]);
    applyAwarenessUpdate(receiverAwareness, update, "remote");
    await flushAwarenessDecorations();

    expect(senderAwareness.clientID).not.toBe(receiverAwareness.clientID);
    expect(receiverView.dom.querySelector(".ProseMirror-yjs-cursor")).not.toBeNull();
  });

  it("broadcasts WYSIWYG selection as a shared Markdown cursor", async () => {
    const sharedDoc = new Y.Doc();
    cleanupFns.push(() => sharedDoc.destroy());
    const sharedText = sharedDoc.getText("content");
    sharedText.insert(0, "Cross-mode cursor text");

    const awareness = new Awareness(sharedDoc);
    cleanupFns.push(() => awareness.destroy());
    awareness.setLocalStateField("user", {
      userId: "same-user",
      name: "Same User",
      color: "#5b8def",
    });
    const view = createWysiwygView(sharedDoc, awareness);

    view.focus();
    const targetPos = Math.max(1, view.state.doc.content.size - 1);
    view.dispatch(view.state.tr.setSelection(TextSelection.create(view.state.doc, targetPos)));
    await flushAwarenessDecorations();

    const cursor = awareness.getLocalState()?.cursor as
      | {
          anchor?: Y.RelativePosition;
          head?: Y.RelativePosition;
        }
      | undefined;
    expect(cursor?.anchor).toBeDefined();
    expect(cursor?.head).toBeDefined();

    const anchor = cursor?.anchor
      ? Y.createAbsolutePositionFromRelativePosition(cursor.anchor, sharedDoc)
      : null;
    const head = cursor?.head
      ? Y.createAbsolutePositionFromRelativePosition(cursor.head, sharedDoc)
      : null;

    expect(anchor?.type).toBe(sharedText);
    expect(head?.type).toBe(sharedText);
    expect(anchor?.index).toBeGreaterThan(0);
    expect(head?.index).toBeGreaterThan(0);
  });

  it("renders same-user remote Markdown cursor in WYSIWYG", async () => {
    const sharedDoc = new Y.Doc();
    cleanupFns.push(() => sharedDoc.destroy());
    const sharedText = sharedDoc.getText("content");
    sharedText.insert(0, "Cross-mode cursor text");

    const receiverAwareness = new Awareness(sharedDoc);
    cleanupFns.push(() => receiverAwareness.destroy());
    receiverAwareness.setLocalStateField("user", {
      userId: "same-user",
      name: "Same User",
      color: "#5b8def",
    });
    const receiverView = createWysiwygView(sharedDoc, receiverAwareness);

    const senderSharedDoc = new Y.Doc();
    cleanupFns.push(() => senderSharedDoc.destroy());
    Y.applyUpdate(senderSharedDoc, Y.encodeStateAsUpdate(sharedDoc));
    const senderSharedText = senderSharedDoc.getText("content");
    const senderAwareness = new Awareness(senderSharedDoc);
    cleanupFns.push(() => senderAwareness.destroy());
    senderAwareness.setLocalStateField("user", {
      userId: "same-user",
      name: "Same User",
      color: "#5b8def",
    });
    senderAwareness.setLocalStateField("cursor", {
      anchor: Y.createRelativePositionFromTypeIndex(senderSharedText, 1),
      head: Y.createRelativePositionFromTypeIndex(senderSharedText, 1),
    });

    const update = encodeAwarenessUpdate(senderAwareness, [senderAwareness.clientID]);
    applyAwarenessUpdate(receiverAwareness, update, "remote");
    await flushAwarenessDecorations();

    expect(senderAwareness.clientID).not.toBe(receiverAwareness.clientID);
    expect(receiverView.dom.querySelector(".ProseMirror-yjs-cursor")).not.toBeNull();
  });

  it("ignores malformed remote Markdown cursor payloads in WYSIWYG", async () => {
    const sharedDoc = new Y.Doc();
    cleanupFns.push(() => sharedDoc.destroy());
    sharedDoc.getText("content").insert(0, "Cross-mode cursor text");

    const receiverAwareness = new Awareness(sharedDoc);
    cleanupFns.push(() => receiverAwareness.destroy());
    const receiverView = createWysiwygView(sharedDoc, receiverAwareness);

    const senderSharedDoc = new Y.Doc();
    cleanupFns.push(() => senderSharedDoc.destroy());
    Y.applyUpdate(senderSharedDoc, Y.encodeStateAsUpdate(sharedDoc));
    const senderAwareness = new Awareness(senderSharedDoc);
    cleanupFns.push(() => senderAwareness.destroy());
    senderAwareness.setLocalStateField("user", {
      userId: "same-user",
      name: "Same User",
      color: "#5b8def",
    });
    senderAwareness.setLocalStateField("cursor", {
      anchor: {},
      head: {},
    });

    const update = encodeAwarenessUpdate(senderAwareness, [senderAwareness.clientID]);
    applyAwarenessUpdate(receiverAwareness, update, "remote");
    await flushAwarenessDecorations();

    expect(receiverView.dom.querySelector(".ProseMirror-yjs-cursor")).toBeNull();
  });
});
