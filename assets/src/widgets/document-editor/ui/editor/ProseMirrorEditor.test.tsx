import { render } from "solid-js/web";
import { afterEach, describe, expect, it } from "vite-plus/test";
import {
  acquireDocumentState,
  clearAllDocumentStates,
  resetDocumentState,
} from "@/features/editor";
import { ProseMirrorEditor } from "./ProseMirrorEditor";

const cleanupFns: (() => void)[] = [];

function flush(ms = 0): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(assertion: () => void | Promise<void>, timeout = 1_500): Promise<void> {
  const startedAt = Date.now();
  let lastError: unknown;

  while (Date.now() - startedAt < timeout) {
    try {
      await assertion();
      return;
    } catch (error) {
      lastError = error;
      await flush(16);
    }
  }

  throw lastError;
}

afterEach(() => {
  for (const cleanup of cleanupFns.splice(0).reverse()) cleanup();
  document.body.replaceChildren();
  clearAllDocumentStates({ flushCache: false });
});

describe("ProseMirrorEditor remote content reconciliation", () => {
  it("reconciles a remote shared text deletion to an empty editable document", async () => {
    const stateKey = `pm-empty-source-${Date.now()}`;
    const { yDoc } = await acquireDocumentState("doc-empty-source", "workspace", stateKey);
    const sharedText = yDoc.getText("content");
    sharedText.insert(0, "# Title\n\nBody");
    cleanupFns.push(() => resetDocumentState(stateKey, { flushCache: false }));

    const dispose = render(
      () => (
        <ProseMirrorEditor
          documentId="doc-empty-source"
          panelId="panel-empty-source"
          stateKey={stateKey}
          workspaceId="workspace"
        />
      ),
      document.body,
    );
    cleanupFns.push(dispose);

    await waitFor(() => {
      expect(document.querySelector(".ProseMirror")?.textContent).toContain("Title");
    });

    yDoc.transact(() => {
      sharedText.delete(0, sharedText.length);
    }, "remote-test");
    window.dispatchEvent(
      new CustomEvent("refmd:document-remote-content-ready", {
        detail: { stateKey },
      }),
    );

    await waitFor(() => {
      const editor = document.querySelector<HTMLElement>('.ProseMirror[contenteditable="true"]');
      expect((editor?.textContent ?? "").trim()).toBe("");
      expect(editor?.getAttribute("data-refmd-wysiwyg-blank-editor")).toBe("true");
    });
  });
});
