import { createCollabPlugins, createYjsBridge, type YjsBridgeHandle } from "@pm-cm/yjs";
import type { Awareness } from "y-protocols/awareness";
import type * as Y from "yjs";
import type { Node, Schema } from "prosemirror-model";
import type { Plugin } from "prosemirror-state";
import { normalizeMarkdown } from "@/shared/lib/markdown/normalize";
import { markdownToProseMirrorDoc } from "./markdown-from";
import { proseMirrorDocToMarkdown } from "./markdown-to";
import { textAwarenessCursorPlugin } from "./plugin-text-awareness-cursor";

function createSerialize(_schema: Schema) {
  return (doc: Node): string => {
    return proseMirrorDocToMarkdown(doc);
  };
}

function createParse(schema: Schema) {
  return (text: string): Node => {
    return markdownToProseMirrorDoc(text, schema);
  };
}

interface CollabSetup {
  plugins: Plugin[];
  doc: Node;
  bridge: YjsBridgeHandle;
  destroy: () => void;
}

export function setupCollabPlugins(opts: {
  yDoc: Y.Doc;
  schema: Schema;
  awareness: Awareness;
  cursorText?: Y.Text;
  textFieldName?: string;
  xmlFieldName?: string;
}): CollabSetup {
  const {
    yDoc,
    schema,
    awareness,
    cursorText,
    textFieldName = "content",
    xmlFieldName = "prosemirror",
  } = opts;
  const sharedText = yDoc.getText(textFieldName);
  const cursorSharedText = cursorText ?? sharedText;
  const sharedProseMirror = yDoc.getXmlFragment(xmlFieldName);
  const serialize = createSerialize(schema);
  const parse = createParse(schema);
  const bridge = createYjsBridge({
    doc: yDoc,
    sharedText,
    sharedProseMirror,
    schema,
    serialize,
    parse,
    normalize: normalizeMarkdown,
  });
  const disableYProseMirrorCursorDecorations = (): boolean => false;
  const { plugins, doc } = createCollabPlugins(schema, {
    sharedProseMirror,
    awareness,
    bridge,
    sharedText: cursorSharedText,
    cursorSync: true,
    serialize,
    yCursorPluginOpts: {
      // Remote WYSIWYG cursors are relative to per-device local bridge docs.
      // Render the shared Markdown Y.Text cursor instead.
      awarenessStateFilter: disableYProseMirrorCursorDecorations,
    },
  });
  return {
    plugins: [
      ...plugins,
      textAwarenessCursorPlugin({
        awareness,
        serialize,
        sharedText: cursorSharedText,
      }),
    ],
    doc,
    bridge,
    destroy: () => {
      bridge.dispose();
    },
  };
}
