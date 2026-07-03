import { afterEach, describe, expect, it } from "vitest";
import * as Y from "yjs";
import { Awareness } from "y-protocols/awareness";
import { ORIGIN_INIT } from "@pm-cm/yjs";
import { markdownToProseMirrorDoc } from "./markdown-from";
import { markdownSchema } from "./schema";
import { setupCollabPlugins } from "./plugin-collab";
import { createLocalProseMirrorBridgeDoc } from "./shared-text-bridge";

const cleanupFns: (() => void)[] = [];

afterEach(() => {
  for (const cleanup of cleanupFns.splice(0).reverse()) cleanup();
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
    });
    cleanupFns.push(collab.destroy);

    collab.bridge.syncToSharedText(
      markdownToProseMirrorDoc("# Title\n\nUpdated from WYSIWYG", markdownSchema),
    );

    expect(sharedDoc.getText("content").toString()).toContain("Updated from WYSIWYG");
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

    expect(localBridgeDoc.yText.toString()).toBe("Bootstrap canonical text");
    expect(sharedDoc.getText("content").toString()).toBe(originalMarkdown);
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

    expect(localBridgeDoc.yText.toString()).toBe("Remote update");
  });
});
