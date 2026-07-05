import { Plugin } from "prosemirror-state";
import type { Node as ProseMirrorNode } from "prosemirror-model";
import type { EditorView } from "prosemirror-view";

function isTaskListItem(node: ProseMirrorNode): boolean {
  return node.type.name === "list_item" && typeof node.attrs.checked === "boolean";
}

function findTaskListItemAtDom(
  view: EditorView,
  listItemEl: HTMLElement,
): { node: ProseMirrorNode; pos: number } | null {
  let result: { node: ProseMirrorNode; pos: number } | null = null;
  view.state.doc.descendants((node, pos) => {
    if (!isTaskListItem(node)) return true;
    if (view.nodeDOM(pos) === listItemEl) {
      result = { node, pos };
      return false;
    }
    return true;
  });
  return result;
}

function toggleTaskItem(view: EditorView, node: ProseMirrorNode, nodePos: number) {
  const checked = node.attrs.checked === true;
  view.dispatch(
    view.state.tr.setNodeMarkup(nodePos, undefined, {
      ...node.attrs,
      checked: !checked,
    }),
  );
  view.focus();
}

function findTaskListItemAtSelection(
  view: EditorView,
): { node: ProseMirrorNode; pos: number } | null {
  const { $from } = view.state.selection;
  for (let depth = $from.depth; depth > 0; depth -= 1) {
    const node = $from.node(depth);
    if (isTaskListItem(node)) return { node, pos: $from.before(depth) };
  }
  return null;
}

export function taskListPlugin(): Plugin {
  return new Plugin({
    props: {
      handleKeyDown(view, event) {
        if (event.key !== "Enter" || (!event.metaKey && !event.ctrlKey)) return false;

        const item = findTaskListItemAtSelection(view);
        if (!item) return false;

        event.preventDefault();
        toggleTaskItem(view, item.node, item.pos);
        return true;
      },
      handleDOMEvents: {
        click(view, event) {
          const target = event.target;
          if (!(target instanceof HTMLInputElement) || target.type !== "checkbox") return false;

          const listItemEl = target.closest<HTMLElement>("li[data-checked]");
          if (!listItemEl || !view.dom.contains(listItemEl)) return false;

          const item = findTaskListItemAtDom(view, listItemEl);
          if (!item) return false;

          event.preventDefault();
          toggleTaskItem(view, item.node, item.pos);
          return true;
        },
      },
    },
  });
}
