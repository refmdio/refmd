import { createCollabPlugins, createYjsBridge, type YjsBridgeHandle } from "@pm-cm/yjs";
import type { Awareness } from "y-protocols/awareness";
import type * as Y from "yjs";
import type { Node, Schema } from "prosemirror-model";
import type { Plugin } from "prosemirror-state";
import { normalizeMarkdown } from "@/shared/lib/markdown/normalize";
import { markdownToProseMirrorDoc } from "./markdown-from";
import { proseMirrorDocToMarkdown } from "./markdown-to";

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
  textFieldName?: string;
  xmlFieldName?: string;
}): CollabSetup {
  const { yDoc, schema, awareness, textFieldName = "content", xmlFieldName = "prosemirror" } = opts;
  const sharedText = yDoc.getText(textFieldName);
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
  const { plugins, doc } = createCollabPlugins(schema, {
    sharedProseMirror,
    awareness,
    bridge,
    sharedText,
    cursorSync: true,
    serialize,
  });
  return {
    plugins,
    doc,
    bridge,
    destroy: () => {
      bridge.dispose();
    },
  };
}
