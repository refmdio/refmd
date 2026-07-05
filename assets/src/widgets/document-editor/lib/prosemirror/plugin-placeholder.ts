import { Plugin } from "prosemirror-state";
import { Decoration, DecorationSet } from "prosemirror-view";
import { isBlankProseMirrorDocument } from "./blank-document";

export function placeholderPlugin(): Plugin {
  return new Plugin({
    props: {
      decorations(state) {
        const { doc, selection } = state;
        const decorations: Decoration[] = [];

        if (isBlankProseMirrorDocument(doc) && doc.firstChild) {
          decorations.push(
            Decoration.node(0, doc.firstChild!.nodeSize, {
              "data-placeholder": "Start writing, or type / for blocks",
              "data-placeholder-detail":
                "Add headings, tables, tasks, code, and more from the slash menu.",
              class: "is-empty is-doc-empty",
            }),
          );
          return DecorationSet.create(doc, decorations);
        }

        const $pos = selection.$anchor;
        if (
          $pos.parent.content.size === 0 &&
          $pos.parent.isTextblock &&
          !$pos.parent.type.spec.code
        ) {
          const before = $pos.before();
          const placeholder =
            $pos.parent.type.name === "heading"
              ? `Heading ${$pos.parent.attrs.level}`
              : "Type '/' for commands";

          decorations.push(
            Decoration.node(before, before + $pos.parent.nodeSize, {
              "data-placeholder": placeholder,
              class: "is-empty",
            }),
          );
        }

        return DecorationSet.create(doc, decorations);
      },
    },
  });
}
