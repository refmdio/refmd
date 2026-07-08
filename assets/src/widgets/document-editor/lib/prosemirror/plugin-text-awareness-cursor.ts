import { buildCursorMap, reverseCursorMapLookup, type Serialize } from "@pm-cm/yjs";
import type { Node as ProseMirrorNode } from "prosemirror-model";
import { Plugin, PluginKey } from "prosemirror-state";
import { Decoration, DecorationSet, type EditorView } from "prosemirror-view";
import type { Awareness } from "y-protocols/awareness";
import * as Y from "yjs";

type AwarenessCursor = {
  anchor?: unknown;
  head?: unknown;
};

type AwarenessUser = {
  color?: unknown;
  name?: unknown;
};

type AwarenessState = {
  cursor?: AwarenessCursor | null;
  user?: AwarenessUser;
};

const awarenessCursorPluginKey = new PluginKey<DecorationSet>("refmd-text-awareness-cursor");
const VALID_HEX_COLOR_RE = /^#[0-9a-fA-F]{6}$/;

function createCursorElement(user: { color: string; name: string }): HTMLElement {
  const cursor = document.createElement("span");
  cursor.className = "ProseMirror-yjs-cursor";
  cursor.style.borderColor = user.color;
  cursor.style.backgroundColor = user.color;

  const label = document.createElement("div");
  label.textContent = user.name;
  cursor.append(label);
  return cursor;
}

function userPresentation(
  user: AwarenessUser | undefined,
  clientId: number,
): {
  color: string;
  name: string;
} {
  const color =
    typeof user?.color === "string" && VALID_HEX_COLOR_RE.test(user.color) ? user.color : "#ffa500";
  const name =
    typeof user?.name === "string" && user.name.trim().length > 0 ? user.name : `User: ${clientId}`;
  return { color, name };
}

function absoluteSharedTextIndex(
  position: unknown,
  yDoc: Y.Doc,
  sharedText: Y.Text,
): number | null {
  if (!position || typeof position !== "object") return null;

  try {
    const fromDirectPosition = Y.createAbsolutePositionFromRelativePosition(
      position as Y.RelativePosition,
      yDoc,
    );
    if (fromDirectPosition?.type === sharedText) return fromDirectPosition.index;
  } catch {
    // Ignore malformed remote awareness payloads.
  }

  try {
    const fromJsonPosition = Y.createAbsolutePositionFromRelativePosition(
      Y.createRelativePositionFromJSON(position),
      yDoc,
    );
    return fromJsonPosition?.type === sharedText ? fromJsonPosition.index : null;
  } catch {
    return null;
  }
}

function clampProseMirrorPosition(position: number, doc: ProseMirrorNode): number {
  return Math.max(0, Math.min(position, Math.max(doc.content.size - 1, 0)));
}

function createDecorations(
  stateDoc: ProseMirrorNode,
  awareness: Awareness,
  sharedText: Y.Text,
  serialize: Serialize,
): DecorationSet {
  const yDoc = sharedText.doc;
  if (!yDoc) return DecorationSet.empty;

  let cursorMap: ReturnType<typeof buildCursorMap> | null = null;
  try {
    cursorMap = buildCursorMap(stateDoc, serialize);
  } catch {
    return DecorationSet.empty;
  }

  const decorations: Decoration[] = [];
  awareness.getStates().forEach((rawState, clientId) => {
    if (clientId === awareness.clientID) return;

    const state = rawState as AwarenessState;
    const cursor = state.cursor;
    if (!cursor?.anchor || !cursor.head) return;

    const anchorOffset = absoluteSharedTextIndex(cursor.anchor, yDoc, sharedText);
    const headOffset = absoluteSharedTextIndex(cursor.head, yDoc, sharedText);
    if (anchorOffset === null || headOffset === null) return;

    const mappedAnchor = reverseCursorMapLookup(cursorMap, anchorOffset);
    const mappedHead = reverseCursorMapLookup(cursorMap, headOffset);
    if (mappedAnchor === null || mappedHead === null) return;

    const anchor = clampProseMirrorPosition(mappedAnchor, stateDoc);
    const head = clampProseMirrorPosition(mappedHead, stateDoc);
    const user = userPresentation(state.user, clientId);
    const from = Math.min(anchor, head);
    const to = Math.max(anchor, head);

    decorations.push(
      Decoration.widget(head, () => createCursorElement(user), {
        key: `text-awareness-${clientId}`,
        side: 10,
      }),
    );
    if (from !== to) {
      decorations.push(
        Decoration.inline(
          from,
          to,
          {
            class: "ProseMirror-yjs-selection",
            style: `background-color: ${user.color}70`,
          },
          {
            inclusiveEnd: true,
            inclusiveStart: false,
          },
        ),
      );
    }
  });

  return DecorationSet.create(stateDoc, decorations);
}

export function textAwarenessCursorPlugin(opts: {
  awareness: Awareness;
  serialize: Serialize;
  sharedText: Y.Text;
}): Plugin {
  const { awareness, serialize, sharedText } = opts;
  return new Plugin({
    key: awarenessCursorPluginKey,
    state: {
      init(_, state) {
        return createDecorations(state.doc, awareness, sharedText, serialize);
      },
      apply(tr, previous, _oldState, newState) {
        const awarenessUpdated = tr.getMeta(awarenessCursorPluginKey) === true;
        if (tr.docChanged || awarenessUpdated) {
          return createDecorations(newState.doc, awareness, sharedText, serialize);
        }
        return previous.map(tr.mapping, tr.doc);
      },
    },
    props: {
      decorations(state) {
        return awarenessCursorPluginKey.getState(state);
      },
    },
    view(view: EditorView) {
      const listener = () => {
        view.dispatch(view.state.tr.setMeta(awarenessCursorPluginKey, true));
      };
      awareness.on("change", listener);
      return {
        destroy() {
          awareness.off("change", listener);
        },
      };
    },
  });
}
